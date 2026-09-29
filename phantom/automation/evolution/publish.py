"""evolution/publish.py — branch + PR with hard governance.

publish() runs ONLY after the full gate passed. Governance (agreed):
  * branch  auto-evolution/<proposal-id>  on this repo
  * PR into dev, body = PROPOSAL.md + gate results + test output
  * max 2 PRs/day, token from PHANTOM_EVOLUTION_TOKEN (repo-scoped to
    the auto-evolution/* namespace in the operator's GitHub settings)
  * never self-merges; no token -> the branch stays local with exact
    push instructions (fallback path, nothing silently dropped)
"""

from __future__ import annotations

import json
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[3]
BRANCH_NS = "auto-evolution/"
BASE_BRANCH = "dev"
GH_API = "https://api.github.com"


@dataclass
class PublishResult:
    ok: bool
    detail: str = ""
    branch: str = ""
    pr_url: str = ""


def publish(pid: str, author_result, state,
            run_git: Optional[callable] = None) -> PublishResult:
    git = run_git or _git
    branch = f"{BRANCH_NS}{pid}"

    # collect the exact files the author produced
    files: List[str] = [p for p in (author_result.cap_relpath,
                                    author_result.test_relpath,
                                    author_result.proposal_relpath) if p]
    if not files:
        return PublishResult(False, "no authored files to publish", branch)

    proposal_md = _read_or("", PROJECT_ROOT / author_result.proposal_relpath) \
        if author_result.proposal_relpath else ""
    gate_md = _gate_markdown(author_result)

    # 1. worktree on the evolution branch (no checkout of the user's tree)
    ok, out = git("rev-parse", "--verify", branch)
    if not ok:
        ok, out = git("branch", branch)
        if not ok:
            return PublishResult(False, f"cannot create branch: {out}",
                                 branch)
    ok, worktree = git("worktree", "add", str(_wt_dir(pid)), branch)
    if not ok:
        return PublishResult(False, f"worktree failed: {worktree}", branch)

    try:
        # 2. copy authored files into the worktree
        for rel in files:
            src = PROJECT_ROOT / rel
            dst = Path(worktree.strip()) / rel
            if not src.exists():
                return PublishResult(False, f"authored file missing: {rel}",
                                     branch)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())

        # 3. commit on the branch
        ok, out = git("-C", str(_wt_dir(pid)), "add", "-A")
        ok, out = git("-C", str(_wt_dir(pid)), "commit",
                      "-m", f"learned capability: {pid}",
                      "-m", f"Authored by the phantom evolution loop "
                            f"(proposal {pid}). Reviewed via PR; "
                            "never self-merged.")
        if not ok:
            return PublishResult(False, f"commit failed: {out}", branch)

        # 4. push (token-scoped) — or leave local with instructions.
        # P1-4: claim the PR slot ATOMICALLY, right before the push. The
        # old can_pr()+count_pr() pair (~check~...~count~) let concurrent
        # workers over-admit past the 2/day budget; reserving here also
        # means a failure BEFORE this point never spends a slot.
        if not state.reserve_pr_slot():
            return PublishResult(False, "daily PR budget exhausted "
                                 "(2/day) — branch kept local", branch)
        token = _token()
        if not token:
            return PublishResult(
                True, f"branch {branch} committed locally; no "
                "PHANTOM_EVOLUTION_TOKEN — push manually: "
                f"git push origin {branch}", branch)
        ok, out = _push_with_token(token, branch)
        if not ok:
            return PublishResult(False, f"push failed: {out}", branch)

        # 5. open the PR
        pr = _open_pr(token, branch, pid, proposal_md, gate_md)
        return PublishResult(True, f"PR opened: {pr}", branch, pr)
    finally:
        git("worktree", "remove", "--force", str(_wt_dir(pid)))


def _wt_dir(pid: str) -> Path:
    return PROJECT_ROOT / "data" / "evolution" / f"wt-{pid}"


def _git(*args: str):
    try:
        proc = subprocess.run(["git", *args], capture_output=True,
                              text=True, timeout=60, cwd=str(PROJECT_ROOT))
        return proc.returncode == 0, (proc.stdout or proc.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


def _token() -> str:
    import os
    return os.environ.get("PHANTOM_EVOLUTION_TOKEN", "").strip()


def _push_with_token(token: str, branch: str):
    """P1-6: push with the token OUT of the URL and OUT of argv.

    Both the old URL form (`https://x-access-token:TOKEN@github.com/...`)
    and the first header form (`-c http.extraHeader=Authorization: Basic
    TOKEN`) put the credential in the child's ARGV, where `ps` / Task
    Manager read it. A git credential helper reads the secret from the
    environment instead: the helper string in argv is a fixed literal, the
    token lives only in the subprocess env, and git's own output is redacted
    before it is returned. There is deliberately NO token-bearing fallback."""
    import os
    env = dict(os.environ)
    env["PHANTOM_PUSH_TOKEN"] = token
    helper = ("!f() { echo username=x-access-token; "
              "echo password=$PHANTOM_PUSH_TOKEN; }; f")
    try:
        proc = subprocess.run(
            ["git", "-c", f"credential.helper={helper}",
             "push", "origin", f"{branch}:{branch}"],
            capture_output=True, text=True, timeout=60,
            cwd=str(PROJECT_ROOT), env=env)
        text = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode == 0, text.replace(token, "***").strip()[-200:]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


def _remote_repo() -> str:
    ok, out = _git("remote", "get-url", "origin")
    if not ok:
        return ""
    import re
    m = re.search(r"github\.com[:/](.+?)(?:\.git)?$", out)
    return m.group(1) if m else ""


def _open_pr(token: str, branch: str, pid: str, proposal_md: str,
             gate_md: str) -> str:
    repo = _remote_repo()
    if not repo:
        return "pushed (remote not GitHub — open the PR manually)"
    body = (proposal_md or f"# Learned capability {pid}\n") + "\n---\n" + gate_md
    payload = json.dumps({
        "title": f"[auto-evolution] learned capability {pid}",
        "head": branch, "base": BASE_BRANCH, "body": body[:60000],
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{GH_API}/repos/{repo}/pulls", data=payload, method="POST",
        headers={"Authorization": f"token {token}",
                 "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8"))
            return data.get("html_url", "PR opened")
    except Exception as exc:  # noqa: BLE001
        return f"pushed; PR creation failed ({exc}) — open it manually"


def _gate_markdown(author_result) -> str:
    lines = ["## Gate results (full gate, lab included)"]
    for g in author_result.gate_history:
        icon = "✅" if g.get("ok") else "❌"
        lines.append(f"- {icon} **{g.get('stage')}** — "
                     f"{g.get('detail', '')[:300]}")
    lines.append("")
    lines.append(f"- attempts used: {author_result.attempts}")
    lines.append("- _Machine-authored code: review the diff before merge._")
    return "\n".join(lines)


def _read_or(default: str, p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return default
