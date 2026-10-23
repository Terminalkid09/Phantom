"""evolution/publish.py — branch + PR with hard governance.

publish() runs ONLY after the full gate passed. Governance (agreed):
  * branch  auto-evolution/<proposal-id>  on this repo
  * PR into dev, body = PROPOSAL.md + gate results + test output
  * max 2 PRs/day
  * the ONLY publish target is Terminalkid09/Phantom (pinned below); a
    fork/redirect is refused, never silently followed
  * authentication is the OPERATOR'S local `gh` login (or the local git
    credential helper). No shared personal token is read, written, or
    committed; no token ever appears in argv or an environment dump
  * the PR is ALWAYS a draft (`gh pr create --draft`) and is never merged
    by the loop; without local auth the branch stays local with the exact
    push/draft-PR commands (fallback path, nothing silently dropped)
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[3]
BRANCH_NS = "auto-evolution/"
BASE_BRANCH = "dev"
# Hard pin: publishing anywhere else (a fork, a redirect, a changed origin)
# is a governance failure, not a configuration choice.
PINNED_REPO = "Terminalkid09/Phantom"


@dataclass
class PublishResult:
    ok: bool
    detail: str = ""
    branch: str = ""
    pr_url: str = ""


def publish(pid: str, author_result, state,
            run_git: Optional[callable] = None,
            run_gh: Optional[callable] = None) -> PublishResult:
    git = run_git or _git
    gh = run_gh or _gh
    branch = f"{BRANCH_NS}{pid}"

    remote = _remote_repo(git)
    if remote.lower() != PINNED_REPO.lower():
        return PublishResult(
            False,
            f"refusing to publish: origin is '{remote or 'unknown'}', "
            f"but evolution may only target {PINNED_REPO}", branch)

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
    # `git worktree add` prints status text ("HEAD is now at ...") on some
    # Git builds; its output is NOT the worktree path. Use the deterministic
    # path we passed in, otherwise Windows treats the log line as a filename
    # and every publish dies with WinError 123 before copying a single file.
    wt_path = str(_wt_dir(pid))
    ok, out = git("worktree", "add", wt_path, branch)
    if not ok:
        return PublishResult(False, f"worktree failed: {out}", branch)

    try:
        # 2. copy authored files into the worktree
        for rel in files:
            src = PROJECT_ROOT / rel
            dst = Path(wt_path) / rel
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

        # 4. Only an authenticated operator may publish. Check BEFORE the
        # push and BEFORE spending a PR slot: without local `gh` auth the
        # branch stays local and the operator gets the exact commands,
        # rather than a pushed branch that can never get its draft PR.
        auth_ok, auth_why = _local_gh_auth(gh)
        if not auth_ok:
            return PublishResult(
                True,
                f"branch {branch} committed locally; no local GitHub auth "
                f"({auth_why[-300:]}). Push and open the draft PR manually: "
                f"git push origin {branch} && gh pr create --draft "
                f"--repo {PINNED_REPO} --base {BASE_BRANCH} --head {branch}",
                branch)

        # push with the operator's LOCAL git credentials. There is no
        # shared token: `gh auth setup-git` / the OS credential manager owns
        # the secret, and this process never reads it.
        # P1-4: claim the PR slot ATOMICALLY, right before the push. The
        # old can_pr()+count_pr() pair (~check~...~count~) let concurrent
        # workers over-admit past the 2/day budget; reserving here also
        # means a failure BEFORE this point never spends a slot.
        if not state.reserve_pr_slot():
            return PublishResult(False, "daily PR budget exhausted "
                                 "(2/day) \u2014 branch kept local", branch)
        ok, out = _push_branch(git, branch)
        if not ok:
            return PublishResult(False, f"push failed: {out}", branch)

        # 5. open a DRAFT PR with the operator's `gh` login. The body is a
        # reviewable dossier, not the raw authoring transcript. This module
        # has no merge path at all.
        verified = bool(getattr(author_result, "verified", True))
        body = _dossier(pid, branch, author_result, proposal_md, gate_md,
                        verified)
        pr, why = _open_draft_pr(gh, branch, pid, body, verified)
        label = "" if verified else " (UNVERIFIED \u2014 lab unreachable)"
        if pr:
            return PublishResult(True, f"draft PR opened{label}: {pr}",
                                 branch, pr)
        return PublishResult(
            False,
            f"branch {branch} pushed to {PINNED_REPO}, but no draft PR was "
            f"opened: {why}. Create it manually with: gh pr create --draft "
            f"--repo {PINNED_REPO} --base {BASE_BRANCH} --head {branch}",
            branch)
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


def _push_branch(git, branch: str):
    """Push with the operator's existing git credential helper.

    `origin` was verified to be the pinned Phantom repository before this
    call. No token is read here, so none can leak into the branch, argv, a
    commit, or the PR body.
    """
    # Refuse an HTTP redirect as well: a renamed/moved origin must not
    # silently send a machine-authored branch to a different repository.
    return git("-c", "http.followRedirects=false", "push", "origin",
               f"{branch}:{branch}")


def _gh(*args: str, input_text: Optional[str] = None,
        timeout: int = 45) -> Tuple[bool, str]:
    """Run the operator's local `gh` CLI (never a shared token)."""
    try:
        proc = subprocess.run(
            ["gh", *args], input=input_text, capture_output=True,
            text=True, timeout=timeout, cwd=str(PROJECT_ROOT))
        text = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode == 0, text.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


def _remote_repo(git=None) -> str:
    git = git or _git
    ok, out = git("remote", "get-url", "origin")
    if not ok:
        return ""
    m = re.search(r"github\.com[:/](.+?)(?:\.git)?$", out.strip())
    return m.group(1) if m else ""


def _local_gh_auth(gh) -> Tuple[bool, str]:
    """Is this operator's local `gh` authenticated for github.com?

    No token is read from the environment or a config file: `gh auth
    status` only reports whether ITS OWN credential store is usable.
    """
    return gh("auth", "status", "--hostname", "github.com")


def _open_draft_pr(gh, branch: str, pid: str, body: str,
                   verified: bool) -> Tuple[str, str]:
    """Create a DRAFT PR in the pinned repo with the operator's gh auth.

    Governance: this module has no merge call, no "ready for review" path,
    and no fallback that creates a non-draft PR.
    """
    ok, auth = _local_gh_auth(gh)
    if not ok:
        return "", f"gh is not authenticated for this operator: {auth[-300:]}"
    title = _pr_title(pid, verified)
    ok, out = gh(
        "pr", "create", "--draft", "--repo", PINNED_REPO,
        "--base", BASE_BRANCH, "--head", branch,
        "--title", title, "--body-file", "-",
        input_text=body[:60000])
    if not ok:
        return "", out[-500:]
    m = re.search(r"https://github\.com/\S+/pull/\d+", out)
    return (m.group(0) if m else out.splitlines()[-1].strip() if out else
            "draft PR created"), ""


def _pr_title(pid: str, verified: bool = True) -> str:
    """The title carries the verification state so it is readable in the
    PR LIST, where the dossier body is not."""
    if verified:
        return f"[auto-evolution] learned capability {pid}"
    return f"[auto-evolution] UNVERIFIED learned capability {pid}"


def _dossier(pid: str, branch: str, author_result, proposal_md: str,
             gate_md: str, verified: bool) -> str:
    """The PR body as a REVIEWABLE DOSSIER, not a raw transcript.

    A machine-authored PR is only approvable if the reviewer can see, in
    one place: what it closes, what it wrote, how it was gated, whether it
    was PROVEN, what it can touch, how to revert it, and what to check.
    The unverified variant carries a loud banner and an unchecked box, so
    an unproven artifact can never be mistaken for a proven one.
    """
    cap = getattr(author_result, "cap_relpath", "") or "-"
    test = getattr(author_result, "test_relpath", "") or "-"
    prop = getattr(author_result, "proposal_relpath", "") or "-"
    attempts = getattr(author_result, "attempts", 0)
    banner = ""
    verification = ("- [x] full gate including the lab dry-run "
                    "(on the authoring machine)")
    if not verified:
        banner = (
            "> ## ⚠️ NOT VERIFIED\n"
            "> The LAB stage could not run (no lab reachable on this "
            "machine).\n"
            "> The static/registry/unit stages passed, but the capability "
            "has **not been proven against a lab**.\n"
            "> Do NOT merge until you run the full gate (lab included) "
            "locally.\n"
            "> Nothing auto-loads before merge, and the beta loader "
            "refuses\n> any candidate whose lab proof is missing.\n\n")
        verification = ("- [ ] **NOT VERIFIED** — lab unreachable; run the "
                        "lab gate before merge")
    return (
        f"# Learned capability `{pid}`\n\n{banner}"
        f"## Failure it closes\n"
        f"A stable, uncovered failure pattern — see `{prop}` (the triage "
        f"case: signature, cause, attempts, evidence).\n\n"
        f"## What was authored\n"
        f"- capability: `{cap}`\n- test: `{test}`\n"
        f"- proposal doc: `{prop}`\n- attempts used: {attempts}\n\n"
        f"{gate_md}\n\n"
        f"## Verification\n{verification}\n\n"
        f"## Blast radius\n"
        f"- NEW files only (capability + test + proposal); the evolution "
        f"sandbox refuses writes outside its three roots\n"
        f"- the live tree is untouched: this branch lives in its own worktree\n"
        f"- the engine is never edited by the loop\n\n"
        f"## Revert\n"
        f"Close this PR / delete `{branch}`; nothing auto-loads before "
        f"merge.\n\n"
        f"## Review checklist\n"
        f"- [ ] the gate above is green on YOUR machine (lab included)\n"
        f"- [ ] the capability stays inside its declared categories\n"
        f"- [ ] the registry/lockfile was not touched\n\n"
        f"---\n\n{proposal_md or ''}")


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
