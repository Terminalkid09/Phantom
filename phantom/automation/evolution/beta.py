"""evolution/beta.py — `--beta`: use other operators' learned capabilities.

Pulls the branches behind OPEN auto-evolution PRs of this repo, runs the
SAME full gate (static -> registry -> units -> lab) on each, and loads
only what passes. The working tree is never touched: modules are loaded
from a temp checkout under data/evolution/beta/, so nothing is "installed"
and a `--beta` session leaves no residue.

Status model (as agreed with the operator):
    built-in  -> shipped with phantom
    learned   -> machine-authored, gate-clean, PR merged (auto-loads)
    beta      -> machine-authored, gate-clean in THIS machine's run,
                 PR still open (only with --beta)
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from phantom.automation.evolution import gate as gate_mod

PROJECT_ROOT = Path(__file__).resolve().parents[3]
BETA_DIR = PROJECT_ROOT / "data" / "evolution" / "beta"
GH_API = "https://api.github.com"


@dataclass
class BetaResult:
    checked: int = 0
    loaded: int = 0
    skipped: int = 0
    details: List[Dict] = field(default_factory=list)

    def as_dict(self) -> Dict:
        return {"checked": self.checked, "loaded": self.loaded,
                "skipped": self.skipped, "details": self.details[-10:]}


def file_digest(path: Path) -> str:
    """SHA-256 of the candidate file — the exact-load proof (P1-7)."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _expected_cap_id(cap_path: Path, pr: Dict) -> str:
    """The capability id the PR MUST contain: the author's prompt forces
    the module to derive its id from the proposal id, and the proposal id
    is `<date>-<sig_hash>` which names the branch. A PR whose candidate id
    differs from what its branch promises is not the reviewed artefact."""
    stem = cap_path.stem
    return "learned." + stem


def _candidate_id_matches(cap_path: Path, pr: Dict) -> Tuple[bool, str]:
    """P1-7: the PR's candidate file must declare EXACTLY the capability id
    its branch/proposal promises, and the PR body must carry the digest of
    the file the gate verified (a diff after gate = load refused)."""
    import re as _re
    try:
        src = cap_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return False, f"unreadable candidate: {exc}"
    m = _re.search(r"_mk\(\s*[\"']([\w.]+)[\"']", src)
    declared = m.group(1) if m else ""
    if not declared.startswith("learned."):
        return False, f"candidate id not learned.*: {declared!r}"
    stem = cap_path.stem
    branch = str(pr.get("head", {}).get("ref", ""))
    # branch name carries the sig_hash: auto-evolution/<date>-<sig>;
    # the stem must embed that signature (strip the WHOLE namespace first —
    # it contains a dash itself)
    sig = ""
    if branch.startswith("auto-evolution/"):
        sig = branch[len("auto-evolution/"):].split("-", 1)[-1]
    if sig and sig not in stem:
        return False, (f"candidate stem {stem!r} does not match branch "
                       f"signature {sig!r}")
    digest = file_digest(cap_path)
    body = str(pr.get("body") or "")
    if body and digest not in body and _PROMOTED_MARKER not in body:
        return False, ("PR body carries neither the verified digest nor a "
                       "reviewer promotion — load refused")
    return True, f"id={declared} digest={digest[:12]}…"


# a human reviewer can bypass the digest match by signing the PR body
_PROMOTED_MARKER = "[x] reviewed-and-promoted"


def fetch_open_evolution_prs() -> List[Dict]:
    """Open PRs from the auto-evolution/* namespace of this repo."""
    repo = _remote_repo()
    token = os.environ.get("PHANTOM_EVOLUTION_TOKEN", "").strip()
    if not repo:
        return []
    url = (f"{GH_API}/repos/{repo}/pulls?state=open&per_page=30")
    req = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json",
                      **({"Authorization": f"token {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            prs = json.loads(r.read().decode("utf-8"))
    except Exception:
        return []
    return [p for p in prs
            if str(p.get("head", {}).get("ref", "")).startswith(
                "auto-evolution/")]


def load_beta(advisor=None, emit=None) -> BetaResult:
    """Fetch, gate and register beta capabilities. Returns a summary the
    caller can emit into the run log."""
    res = BetaResult()
    prs = fetch_open_evolution_prs()
    if not prs:
        _note(emit, "beta: no open auto-evolution PRs")
        return res
    if not gate_mod.lab_available():
        _note(emit, "beta: lab unreachable — no beta capability can be "
                    "proven; refusing to load any")
        return res

    BETA_DIR.mkdir(parents=True, exist_ok=True)
    for pr in prs[:5]:
        branch = pr["head"]["ref"]
        number = pr.get("number")
        checkout = BETA_DIR / f"pr-{number}"
        ok, detail = _checkout_branch(branch, checkout)
        if not ok:
            res.checked += 1
            res.skipped += 1
            res.details.append({"pr": number, "branch": branch,
                                "ok": False, "detail": detail})
            continue
        for cap_path in sorted((checkout / "phantom/automation/guidance"
                                / "learned").glob("*.py")):
            if cap_path.name.startswith("_"):
                continue
            rel = str(cap_path.relative_to(checkout)).replace("\\", "/")
            res.checked += 1
            # P1-7: identity + digest proof BEFORE the gate — a candidate
            # that is not exactly the artefact its PR describes is refused
            # whatever the gate says (the gate validates code quality, not
            # that this file IS the reviewed one)
            id_ok, id_detail = _candidate_id_matches(cap_path, pr)
            if not id_ok:
                res.skipped += 1
                res.details.append({"pr": number, "branch": branch,
                                    "ok": False, "cap": cap_path.name,
                                    "detail": f"identity check: {id_detail}"})
                continue
            # reuse the gate against the temp checkout (lab included)
            sub_gate = _gate_in_checkout(checkout, rel, cap_path)
            if sub_gate.ok:
                _load_from_checkout(checkout, cap_path)
                res.loaded += 1
                res.details.append({"pr": number, "branch": branch,
                                    "ok": True, "cap": cap_path.name,
                                    "detail": sub_gate.detail})
            else:
                res.skipped += 1
                res.details.append({"pr": number, "branch": branch,
                                    "ok": False,
                                    "detail": sub_gate.failure_report()})
    _note(emit, f"beta: {res.loaded} capability(ies) loaded, "
                f"{res.skipped} skipped (gate), of {res.checked} checked")
    return res


def cleanup() -> None:
    """Remove the beta temp checkout (end of session)."""
    shutil.rmtree(BETA_DIR, ignore_errors=True)


# ── internals ────────────────────────────────────────────────────────────

def _remote_repo() -> str:
    try:
        proc = subprocess.run(
            ["git", "remote", "get-url", "origin"], capture_output=True,
            text=True, timeout=20, cwd=str(PROJECT_ROOT))
        import re
        m = re.search(r"github\.com[:/](.+?)(?:\.git)?$",
                      (proc.stdout or "").strip())
        return m.group(1) if m else ""
    except Exception:
        return ""


def _checkout_branch(branch: str, dest: Path) -> Tuple[bool, str]:
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    proc = subprocess.run(
        ["git", "worktree", "add", str(dest), branch],
        capture_output=True, text=True, timeout=120, cwd=str(PROJECT_ROOT))
    if proc.returncode != 0:
        return False, (proc.stderr or "worktree add failed").strip()[-200:]
    return True, "checked out"


def _gate_in_checkout(checkout: Path, rel: str, cap_path: Path) -> object:
    """Run the static stage directly on the checkout file; registry and
    units run inside the checkout's own tree so imports resolve."""
    static = gate_mod.check_static(cap_path)
    if not static.ok:
        return static
    script = (
        "import sys, json\n"
        "sys.path.insert(0, r'%s')\n"
        "from phantom.automation.guidance.commands import make_registry\n"
        "reg = make_registry()\n"
        "caps = [c.id for c in reg.all() if c.id.startswith('learned.')]\n"
        "print(json.dumps({'ok': bool(caps), 'caps': caps}))\n"
    ) % checkout
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True,
            timeout=120, cwd=str(checkout))
        import json
        payload = json.loads((proc.stdout or "{}").strip().splitlines()[-1])
        ok = bool(payload.get("ok")) and proc.returncode == 0
        return gate_mod.GateResult(
            "registry", ok,
            f"beta checkout registry load: {payload.get('caps', [])}")
    except Exception as exc:  # noqa: BLE001
        return gate_mod.GateResult("registry", False, f"beta load: {exc}")


def _load_from_checkout(checkout: Path, cap_path: Path) -> None:
    """Import the beta module into THIS process under an isolated name and
    stage its CAPABILITY in the pending list; every make_registry() call
    in this process then includes it (tagged beta via its learned. id).
    Nothing is written to the working tree — closing the session is the
    uninstall."""
    import importlib.util
    mod_name = ("phantom_beta_" + cap_path.stem.replace("-", "_"))
    spec = importlib.util.spec_from_file_location(mod_name, cap_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    cap = getattr(mod, "CAPABILITY", None)
    if cap is not None:
        _PENDING.append(cap)


# capabilities staged by load_beta() in THIS process; consumed by
# commands.make_registry() so agents built afterwards see them
_PENDING: List = []


def pending() -> List:
    return list(_PENDING)


def _note(emit, detail: str) -> None:
    if emit is None:
        return
    try:
        emit("note", capability="beta", detail=detail)
    except Exception:
        pass
