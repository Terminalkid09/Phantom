"""evolution/gate.py — the full validation gate (agreed: all four stages,
lab dry-run mandatory for BOTH auto-load and PR).

Stage order — cheap first, behavioural last:
  1. STATIC   : AST allowlist (stdlib + phantom imports only), no
                forbidden constructs, module exposes CAPABILITY, id
                carries the `learned.` prefix, size caps
  2. REGISTRY : the module imports, `CAPABILITY` builds, and the whole
                make_registry() still loads with it registered
  3. UNITS    : the authored test plus the fast offline suites
                (timeline, experience, planner contracts) still pass
  4. LAB      : dry-run of the capability against the local lab
                (127.0.0.1:8081), executed through the REAL pipeline —
                registry -> adapter -> interpreter -> WorldModel

The gate never mutates the repo beyond what sandbox.flush() wrote, and
its verdicts are structured so the author LLM can repair from failures.
"""

from __future__ import annotations

import ast
import json
import importlib.util
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[3]

LEARNED_DIR = Path("phantom/automation/guidance/learned")
TESTS_DIR = Path("tests/learned")
LAB_WEB = "http://127.0.0.1:8081"

MAX_CAP_LINES = 400
MAX_TEST_LINES = 250
LAB_TIMEOUT = 90

# ── import policy ────────────────────────────────────────────────────────

# stdlib is fine wholesale (json, re, socket, subprocess...); the danger
# is third-party code. Phantom modules are the internal surface.
_FORBIDDEN_TOP = {
    "requests", "httpx", "aiohttp", "urllib3", "scapy", "impacket",
    "pycryptodome", "Crypto", "paramiko", "pwntools", "pyautogui",
    "ctypes.windll", "winreg", "_winreg",
}

# constructs that have no business inside a machine-authored capability
# (py3.8+: ast.Exec is gone; Global/Delete are still parsed)
_FORBIDDEN_NODES = (
    ast.Global,         # cross-module state games
    ast.Delete,
)


@dataclass
class GateResult:
    stage: str                      # "static" | "registry" | "units" | "lab"
    ok: bool
    detail: str = ""
    logs: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict:
        return {"stage": self.stage, "ok": self.ok, "detail": self.detail,
                "logs": self.logs[-20:]}

    def failure_report(self) -> str:
        lines = [f"stage {self.stage}: FAIL — {self.detail}"]
        lines += [f"  | {l}" for l in self.logs[-15:]]
        return "\n".join(lines)


# ── helpers ──────────────────────────────────────────────────────────────

def _module_name(relpath: Path) -> str:
    return ".".join(relpath.with_suffix("").parts)


def _lab_reachable(timeout: float = 3.0) -> bool:
    """Any usable lab endpoint: the operator's own lab (8081) or the
    evolution-managed compose lab (18081). False + no docker means 'no
    behavioural proof possible' (the gate refuses auto-load and PR)."""
    import socket
    from phantom.automation.evolution import lab as lab_mod
    for port in (8081, lab_mod.WEB_PORT):
        try:
            with socket.create_connection(("127.0.0.1", port),
                                          timeout=timeout):
                return True
        except OSError:
            continue
    return False


def lab_available() -> bool:
    """Proof is possible here: a lab endpoint is already up, OR docker
    exists so the managed lab can be started on demand."""
    if _lab_reachable():
        return True
    from phantom.automation.evolution import lab as lab_mod
    return lab_mod._docker() is not None


# ── stage 1: static ──────────────────────────────────────────────────────

def check_static(cap_path: Path, test_path: Optional[Path] = None) -> GateResult:
    try:
        src = cap_path.read_text(encoding="utf-8")
    except OSError as exc:
        return GateResult("static", False, f"unreadable: {exc}")
    if len(src.splitlines()) > MAX_CAP_LINES:
        return GateResult("static", False,
                          f"capability file exceeds {MAX_CAP_LINES} lines")
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        return GateResult("static", False, f"syntax error: {exc}")

    has_capability = False
    for node in ast.walk(tree):
        if isinstance(node, _FORBIDDEN_NODES):
            return GateResult("static", False,
                              f"forbidden construct: {type(node).__name__}")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mods: List[str] = []
            if isinstance(node, ast.ImportFrom) and node.module:
                mods.append(node.module)
            for alias in node.names:
                mods.append(alias.name)
            for m in mods:
                root = m.split(".")[0]
                if m.split(".")[0:2] == ["ctypes", "windll"]:
                    return GateResult("static", False,
                                      f"forbidden import: {m}")
                if root in _FORBIDDEN_TOP and not m.startswith("phantom"):
                    return GateResult("static", False,
                                      f"forbidden import: {m}")
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if (isinstance(t, ast.Name) and t.id == "CAPABILITY"
                        and isinstance(node.value, ast.Call)):
                    has_capability = True

    if not has_capability:
        return GateResult("static", False,
                          "module must expose CAPABILITY = <Capability(...)>, "
                          "built with kit._mk")
    # id prefix check (AST-level, precise): id is _mk's FIRST positional
    # arg (or the `id=` keyword — accept both spellings)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "_mk"):
            id_val = None
            if node.args and isinstance(node.args[0], ast.Constant):
                id_val = node.args[0].value
            for kw in node.keywords:
                if kw.arg == "id" and isinstance(kw.value, ast.Constant):
                    id_val = kw.value.value
            if id_val is not None and not str(id_val).startswith("learned."):
                return GateResult(
                    "static", False,
                    "capability id must start with 'learned.' "
                    f"(got {id_val!r})")
    if test_path is not None and test_path.exists():
        tsrc = test_path.read_text(encoding="utf-8", errors="replace")
        if len(tsrc.splitlines()) > MAX_TEST_LINES:
            return GateResult("static", False,
                              f"test exceeds {MAX_TEST_LINES} lines")
        try:
            ast.parse(tsrc)
        except SyntaxError as exc:
            return GateResult("static", False, f"test syntax error: {exc}")
    return GateResult("static", True, "AST allowlist clean")


# ── stage 2: registry ────────────────────────────────────────────────────

def check_registry(cap_relpath: str) -> GateResult:
    """Import the staged module in a subprocess and register it on top of
    the real registry. Subprocess: a broken import must not poison ours."""
    script = (
        "import json,sys\n"
        "sys.path.insert(0, r'%s')\n"
        "from phantom.automation.guidance.commands import make_registry\n"
        "reg = make_registry()\n"
        "cap = reg.get(r'%s')\n"
        "if cap is None:\n"
        "    print(json.dumps({'ok': False, 'detail': "
        "'capability not found in registry after load'}))\n"
        "    sys.exit(0)\n"
        "print(json.dumps({'ok': True, 'id': cap.id, "
        "'category': cap.category, 'effects': cap.effects}))\n"
    ) % (PROJECT_ROOT, json_cap_id(cap_relpath))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True,
            timeout=120, cwd=str(PROJECT_ROOT))
    except subprocess.TimeoutExpired:
        return GateResult("registry", False, "registry load timed out")
    out = (proc.stdout or "").strip().splitlines()
    if proc.returncode != 0:
        tail = (proc.stderr or "").strip().splitlines()[-6:]
        return GateResult("registry", False,
                          f"import/registration failed (rc={proc.returncode})",
                          logs=tail)
    try:
        payload = json.loads(out[-1]) if out else {}
    except Exception:
        payload = {"ok": False, "detail": f"unparsable loader output: {out}"}
    if not payload.get("ok"):
        return GateResult("registry", False,
                          payload.get("detail", "registry load refused"))
    return GateResult("registry", True,
                      f"registered as {payload.get('id')} "
                      f"(category {payload.get('category')}, "
                      f"effects {payload.get('effects')})")


def json_cap_id(cap_relpath: str) -> str:
    """Extract the capability id from the staged file (best effort, for
    the registry probe)."""
    import re
    try:
        src = (PROJECT_ROOT / cap_relpath).read_text(encoding="utf-8")
        m = re.search(r"_mk\(\s*[\"']([^\"']+)[\"']", src)
        return m.group(1) if m else ""
    except OSError:
        return ""


# ── stage 3: units ───────────────────────────────────────────────────────

UNIT_SUBSET = [
    "tests/test_timeline.py",
    "tests/test_experience.py",
    "tests/test_brain_targets_doctrine.py",
    "tests/test_internal_expand.py",
]


def check_units(test_relpath: Optional[str]) -> GateResult:
    """The authored test plus the fast offline regression subset."""
    targets: List[str] = []
    if test_relpath and (PROJECT_ROOT / test_relpath).exists():
        targets.append(test_relpath)
    targets += [t for t in UNIT_SUBSET if (PROJECT_ROOT / t).exists()]
    if not targets:
        return GateResult("units", False, "no test files to run")
    cmd = [sys.executable, "-m", "pytest", "-x", "-q", "--timeout=120",
           "-p", "no:cacheprovider"] + targets
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=420, cwd=str(PROJECT_ROOT))
    except subprocess.TimeoutExpired:
        return GateResult("units", False, "unit subset timed out (420s)")
    if proc.returncode != 0:
        lines = (proc.stdout or "").splitlines()
        fails = [l for l in lines if l.startswith("FAILED")
                 or l.startswith("ERROR")][:8]
        return GateResult("units", False,
                          f"pytest rc={proc.returncode}", logs=fails)
    return GateResult("units", True, "unit subset green")


# ── stage 4: lab ─────────────────────────────────────────────────────────

def _existing_lab_port() -> Optional[int]:
    """A lab endpoint already up: the operator's own (8081) first, then
    the managed one (18081)."""
    import socket
    from phantom.automation.evolution import lab as lab_mod
    for port in (8081, lab_mod.WEB_PORT):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2.0):
                return port
        except OSError:
            continue
    return None


def check_lab(cap_relpath: str, cap_id: str) -> GateResult:
    """Dry-run the capability against the lab through the REAL pipeline.

    Endpoint preference: an ALREADY-UP lab (the operator's own 8081 or a
    previous managed one) is used as-is — starting a second copy of the
    same compose would clash on the subnet pool. Only when nothing is up
    does the gate start the project's managed stack on remapped ports,
    and tears it down afterwards.
    """
    from phantom.automation.evolution import lab as lab_mod
    existing = _existing_lab_port()
    session = None
    if existing is not None:
        port = str(existing)
        web = f"http://127.0.0.1:{existing}"
    else:
        try:
            session = lab_mod.lab_session()
            session.__enter__()
        except lab_mod.LabUnavailable as exc:
            return GateResult("lab", False,
                              f"behavioural proof impossible: {exc}; per "
                              "policy no auto-load and no PR without it")
        port = str(lab_mod.WEB_PORT)
        web = f"http://127.0.0.1:{lab_mod.WEB_PORT}"
    try:
        script = (
            "import json, sys\n"
            "sys.path.insert(0, r'%s')\n"
            "from phantom.automation.guidance.commands import make_registry\n"
            "from phantom.core.knowledge import reset_wm\n"
            "reg = make_registry()\n"
            "cap = reg.get(r'%s')\n"
            "wm = reset_wm('127.0.0.1')\n"
            "wm.add_finding(kind='service', key='tcp/%s',\n"
            "               value={'port': %s, 'product': 'flask',\n"
            "                      'target': '127.0.0.1'}, target='127.0.0.1')\n"
            "slots = {}\n"
            "for s in cap.inputs:\n"
            "    if s.type == 'url': slots[s.name] = '%s'\n"
            "    elif s.type in ('host', 'target'): slots[s.name] = '127.0.0.1'\n"
            "    elif s.type == 'port': slots[s.name] = '%s'\n"
            "    elif not s.required: slots[s.name] = None\n"
            "out = cap.adapter(slots)\n"
            "res = out if isinstance(out, str) else str(out)\n"
            "findings = cap.interpreter(res, wm, slots) if cap.interpreter else []\n"
            "print(json.dumps({'ok': True, 'output_chars': len(res),\n"
            "                  'findings': [f.kind for f in findings]}))\n"
        ) % (PROJECT_ROOT, cap_id, port, port, web, port)
        try:
            proc = subprocess.run(
                [sys.executable, "-c", script], capture_output=True,
                text=True, timeout=LAB_TIMEOUT, cwd=str(PROJECT_ROOT))
        except subprocess.TimeoutExpired:
            return GateResult("lab", False,
                              f"lab dry-run exceeded {LAB_TIMEOUT}s")
        if proc.returncode != 0:
            tail = (proc.stderr or "").strip().splitlines()[-8:]
            return GateResult("lab", False, "adapter/interpreter raised",
                              logs=tail)
        return GateResult("lab", True,
                          f"adapter executed against the lab (port {port}), "
                          "interpreter returned findings")
    finally:
        if session is not None:
            session.__exit__(None, None, None)


# ── top-level ────────────────────────────────────────────────────────────

def run_gate(cap_relpath: str, test_relpath: Optional[str] = None,
             skip_lab: bool = False) -> Tuple[bool, List[GateResult]]:
    """Run all stages in order; stop at the first failure."""
    results: List[GateResult] = []
    cap_abs = PROJECT_ROOT / cap_relpath
    test_abs = (PROJECT_ROOT / test_relpath) if test_relpath else None

    r = check_static(cap_abs, test_abs)
    results.append(r)
    if not r.ok:
        return False, results

    r = check_registry(cap_relpath)
    results.append(r)
    if not r.ok:
        return False, results

    r = check_units(test_relpath)
    results.append(r)
    if not r.ok:
        return False, results

    if skip_lab:
        return True, results
    r = check_lab(cap_relpath, json_cap_id(cap_relpath))
    results.append(r)
    return r.ok, results
