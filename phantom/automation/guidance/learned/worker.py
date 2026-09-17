"""worker.py — subprocess execution for machine-authored capabilities.

A learned module is NEVER imported in the main process (see descriptor.py).
Everything it contributes runs here, in a short-lived subprocess:

  * the adapter (`run(slots)` or `CAPABILITY.adapter`);
  * the interpreter (`CAPABILITY.interpreter`) — findings come back as
    JSON data, so no learned code touches the agent's world model;
  * the module's own callable preconditions, re-checked against a JSON
    snapshot of the world before the run.

Isolation properties:
  * fresh interpreter, no agent internals, no C2 state;
  * PHANTOM_* environment variables stripped (no operator secrets);
  * hard wall-clock timeout that kills the whole process tree;
  * stdout capped (no memory blowout from a runaway probe).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# The worker boots the module, builds a read-only world snapshot, honours
# the module's own preconditions, runs the adapter, then serialises the
# findings as DATA. Nothing but JSON crosses back.
_WORKER_SCRIPT = r'''
import importlib.util, json, sys

class _SnapshotWM:
    """Read-only WorldModel view built from JSON (no agent state)."""

    def __init__(self, data):
        self.target = data.get("target", "")
        self.target_type = data.get("target_type", "ip")
        self._findings = {}
        for f in data.get("findings", []) or []:
            kind = str(f.get("kind", ""))
            key = str(f.get("key", ""))
            if kind:
                self._findings[(kind, key)] = _F(
                    kind, key, f.get("value"), float(f.get("confidence", 0.5) or 0.5),
                    str(f.get("source", "snapshot")), str(f.get("evidence", "")),
                    str(f.get("target", "") or self.target))

    def find(self, kind, **attrs):
        out = []
        for (k, _key), f in self._findings.items():
            if k != kind:
                continue
            if attrs:
                v = f.value if isinstance(f.value, dict) else {}
                if not all(v.get(a) == b for a, b in attrs.items()):
                    continue
            out.append(f)
        return out

    def get(self, kind, key):
        return self._findings.get((kind, key))

    def has_any(self, kind):
        return any(k == kind for (k, _) in self._findings)

    def all_findings(self):
        return list(self._findings.values())

    def trust(self, kind, key):
        f = self.get(kind, key)
        return f is not None and f.confidence >= 0.7

    def add_finding(self, *a, **k):        # read-only snapshot: no-op
        return None

    def record_action(self, *a, **k):
        return None


class _F:
    def __init__(self, kind, key, value, confidence, source, evidence, target):
        self.kind, self.key, self.value = kind, key, value
        self.confidence, self.source = confidence, source
        self.evidence, self.target = evidence, target


def _finding_to_dict(f):
    return {"kind": getattr(f, "kind", ""), "key": getattr(f, "key", ""),
            "value": getattr(f, "value", None),
            "confidence": float(getattr(f, "confidence", 0.5) or 0.5),
            "source": str(getattr(f, "source", "learned")),
            "evidence": str(getattr(f, "evidence", ""))[:800],
            "target": str(getattr(f, "target", ""))}


def main() -> int:
    mod_path = sys.argv[1]
    slots = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    world = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    spec = importlib.util.spec_from_file_location("learned_worker_mod", mod_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["learned_worker_mod"] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException as exc:
        print(json.dumps({"ok": False, "reason": f"import failed: {exc}"}))
        return 0

    cap = getattr(mod, "CAPABILITY", None)
    wm = _SnapshotWM(world or {})

    # the module's OWN preconditions, evaluated here (not in the agent)
    precs = list(getattr(cap, "preconditions", []) or []) if cap is not None else []
    for p in precs:
        try:
            if not p(wm):
                print(json.dumps({"ok": False, "blocked": True,
                                  "reason": "module precondition not met"}))
                return 0
        except Exception as exc:
            print(json.dumps({"ok": False, "blocked": True,
                              "reason": f"precondition error: {exc}"}))
            return 0

    fn = getattr(mod, "run", None)
    if fn is None and cap is not None:
        adapter = getattr(cap, "adapter", None)
        if adapter is not None:
            fn = lambda slots_: adapter(wm, slots_) if _accepts_two(adapter) else adapter(slots_)
    if fn is None:
        print(json.dumps({"ok": False, "reason": "no run() and no adapter"}))
        return 0
    try:
        out = fn(slots)
    except BaseException as exc:
        print(json.dumps({"ok": False, "reason": f"adapter failed: {exc}"}))
        return 0
    text = out if isinstance(out, str) else json.dumps(out)

    findings = []
    interp = getattr(cap, "interpreter", None) if cap is not None else None
    if interp is not None:
        try:
            for f in (interp(text, wm, slots) or []):
                findings.append(_finding_to_dict(f))
        except BaseException:
            findings = []          # an interpreter must never break the run
    print(json.dumps({"ok": True, "output": text, "findings": findings}))
    return 0


def _accepts_two(adapter) -> bool:
    try:
        import inspect
        return len(inspect.signature(adapter).parameters) >= 2
    except Exception:
        return False


if __name__ == "__main__":
    sys.exit(main())
'''

MAX_OUTPUT = 200_000
_BOOT_NAME = "_worker_boot.py"


def _worker_env() -> Dict[str, str]:
    """PHANTOM_* secrets are stripped: the worker needs none of them."""
    env = dict(os.environ)
    for key in list(env):
        if key.upper().startswith("PHANTOM_"):
            env.pop(key, None)
    return env


def _boot_script(module_path: Path) -> Path:
    boot = module_path.parent / _BOOT_NAME
    if not boot.exists():
        boot.write_text(_WORKER_SCRIPT, encoding="utf-8")
    return boot


def _spawn(script: Path, module_path: Path, slots: Optional[Dict[str, Any]],
           world: Optional[Dict[str, Any]]):
    cmd = [sys.executable, str(script), str(module_path),
           json.dumps(dict(slots or {})), json.dumps(dict(world or {}))]
    kwargs: Dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, text=True, env=_worker_env(), **kwargs)


def run_learned_task(module_path: str, slots: Optional[Dict[str, Any]] = None,
                     world: Optional[Dict[str, Any]] = None,
                     timeout: float = 30.0) -> Dict[str, Any]:
    """Run adapter + interpreter out of process.

    Returns a dict: {ok, output, findings, blocked, reason}. Never raises.
    """
    p = Path(module_path)
    if not p.is_file():
        return {"ok": False, "reason": f"learned module not found: {module_path}",
                "output": "", "findings": []}
    try:
        proc = _spawn(_boot_script(p), p, slots, world)
    except OSError as exc:
        return {"ok": False, "reason": f"worker spawn failed: {exc}",
                "output": "", "findings": []}
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        from phantom.core.executor import _kill_process_tree
        _kill_process_tree(proc)
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:
            out, err = "", ""
        return {"ok": False, "reason": "worker timeout", "blocked": False,
                "output": ((out or "")[:MAX_OUTPUT] + "\nWORKER-TIMEOUT"),
                "findings": []}
    lines = [ln for ln in (out or "").strip().splitlines() if ln.strip()]
    if not lines:
        return {"ok": False, "reason": (err or "worker produced no output")[:400],
                "output": "", "findings": []}
    try:
        data = json.loads(lines[-1])
    except ValueError:
        return {"ok": False, "reason": "worker returned non-JSON",
                "output": (out or "")[:MAX_OUTPUT], "findings": []}
    if proc.returncode != 0 and not data.get("ok"):
        return {"ok": False, "blocked": bool(data.get("blocked")),
                "reason": str(data.get("reason", "worker failed"))[:400],
                "output": "", "findings": []}
    return {
        "ok": bool(data.get("ok")),
        "blocked": bool(data.get("blocked")),
        "reason": str(data.get("reason", "")),
        "output": str(data.get("output", ""))[:MAX_OUTPUT],
        "findings": data.get("findings", []) or [],
    }


def run_learned_adapter(module_path: str, slots: Optional[Dict[str, Any]] = None,
                        timeout: float = 30.0) -> tuple:
    """Backward-compatible (ok, output) wrapper around run_learned_task."""
    res = run_learned_task(module_path, slots, None, timeout)
    return bool(res.get("ok")), (str(res.get("output", "")) or
                                 str(res.get("reason", "")))
