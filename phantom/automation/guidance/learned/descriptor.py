"""descriptor.py — read a learned module's metadata WITHOUT importing it.

A-2 (security sweep): the loader used to `importlib.import_module()` every
file in this package at boot to read `CAPABILITY`. Importing executes the
module body — machine-authored code — in the MAIN process, with the
operator's memory, environment and C2 state. The static gate is not a
sandbox (stdlib is allowed wholesale), so that import WAS the boundary and
it was the wrong one.

This module reads the descriptor in a short-lived subprocess:
  * fresh interpreter, no agent/C2 state, PHANTOM_* env stripped;
  * the module body runs there (where it can do no harm to this process);
  * only JSON data crosses back — never Python objects, never callables.

The adapter/interpreter continue to run in the task worker (worker.py), so
no learned code ever executes in the main process.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

_DESCRIPTOR_SCRIPT = r'''
import importlib.util, json, sys

def _slot(s):
    return {"name": getattr(s, "name", ""), "type": getattr(s, "type", ""),
            "required": bool(getattr(s, "required", False)),
            "description": getattr(s, "description", "")}

def main() -> int:
    mod_path = sys.argv[1]
    spec = importlib.util.spec_from_file_location("learned_descriptor_mod", mod_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["learned_descriptor_mod"] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException as exc:                 # module body must not be trusted
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))
        return 0
    cap = getattr(mod, "CAPABILITY", None)
    if cap is None:
        print(json.dumps({"ok": False, "error": "no CAPABILITY object"}))
        return 0
    requires = getattr(cap, "requires", None) or []
    if not isinstance(requires, (list, tuple)):
        requires = []
    payload = {
        "ok": True,
        "id": str(getattr(cap, "id", "")),
        "category": str(getattr(cap, "category", "")),
        "description": str(getattr(cap, "description", "")),
        "exec_class": str(getattr(cap, "exec_class", "shell_command")),
        "effects": [str(e) for e in (getattr(cap, "effects", []) or [])],
        "opsec_cost": float(getattr(cap, "opsec_cost", 1.0) or 1.0),
        "detection_risk": float(getattr(cap, "detection_risk", 0.1) or 0.1),
        "stealth_level": str(getattr(cap, "stealth_level", "passive")),
        "forceful": bool(getattr(cap, "forceful", False)),
        "timeout": int(getattr(cap, "timeout", 30) or 30),
        "banner": str(getattr(cap, "banner", "")),
        "tools": [str(t) for t in (getattr(cap, "tools", []) or [])],
        "inputs": [_slot(s) for s in (getattr(cap, "inputs", []) or [])],
        "requires": [str(r) for r in requires],
        "has_preconditions": bool(getattr(cap, "preconditions", None)),
        "has_interpreter": getattr(cap, "interpreter", None) is not None,
    }
    print(json.dumps(payload))
    return 0

if __name__ == "__main__":
    sys.exit(main())
'''

_BOOT_NAME = "_descriptor_boot.py"


def _worker_env() -> Dict[str, str]:
    """Environment for the descriptor worker: PHANTOM_* secrets removed."""
    env = dict(os.environ)
    for key in list(env):
        if key.upper().startswith("PHANTOM_"):
            env.pop(key, None)
    return env


def describe(module_path: str, timeout: float = 20.0) -> Optional[Dict[str, Any]]:
    """Return the module's descriptor as a plain dict, or None on failure."""
    p = Path(module_path)
    if not p.is_file():
        return None
    boot = p.parent / _BOOT_NAME
    if not boot.exists():
        boot.write_text(_DESCRIPTOR_SCRIPT, encoding="utf-8")
    kwargs: Dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(
            [sys.executable, str(boot), str(p)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, text=True,
            env=_worker_env(), **kwargs)
    except OSError:
        return None
    try:
        out, _err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            from phantom.core.executor import _kill_process_tree
            _kill_process_tree(proc)
        except Exception:
            proc.kill()
        return None
    line = (out or "").strip().splitlines()
    if not line:
        return None
    try:
        data = json.loads(line[-1])
    except ValueError:
        return None
    if not data.get("ok"):
        return None
    return data
