"""capabilities.py — the backend announces which components are available.

The architecture is a modular monolith: one shared kernel plus three
components (``core`` manual shell, ``c2`` + beacon, ``automode``). A
distribution or an enterprise deployment may ship only a subset — "only
the manual core", "only the C2", or the full stack. The frontend must not
guess: it asks the backend which sections to enable, and a packaging build
simply ships fewer modules.

Availability has two sources, evaluated in order:

1. ``PHANTOM_COMPONENTS`` (comma-separated allowlist). When set, ONLY the
   listed components are enabled — this is the explicit enterprise switch
   (``PHANTOM_COMPONENTS=core`` ships the manual core alone).
2. Otherwise, a component is enabled when its module imports. In a build
   where the module is not shipped, the import fails and the section is
   reported unavailable instead of breaking the UI.

The kernel (``core``) is never absent: it owns session/scope/audit/state
and every other component depends on it.
"""
from __future__ import annotations

import importlib
import os
from typing import Dict, Optional

CORE = "core"
C2 = "c2"
AUTOMODE = "automode"

# Order matters: it is the canonical list the frontend renders (and the
# order in which sections appear in the single Electron shell).
COMPONENTS = (CORE, C2, AUTOMODE)

# Component -> module that must import for the component to be present.
_MODULES = {
    C2: "phantom.core.c2_server",
    AUTOMODE: "phantom.core.automode",
}

_ENV = "PHANTOM_COMPONENTS"


def _allowlist() -> Optional[set]:
    """The explicit component allowlist, or None when unset (= auto)."""
    raw = str(os.getenv(_ENV, "")).strip()
    if not raw:
        return None
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def _importable(module: str) -> bool:
    try:
        importlib.import_module(module)
        return True
    except Exception:
        return False


def available() -> Dict[str, bool]:
    """Which components this build exposes, in canonical order."""
    allow = _allowlist()
    out: Dict[str, bool] = {CORE: True}
    for comp in COMPONENTS:
        if comp == CORE:
            continue
        if allow is not None and comp not in allow:
            out[comp] = False
            continue
        module = _MODULES.get(comp)
        out[comp] = _importable(module) if module else True
    return out


def is_enabled(component: str) -> bool:
    """Whether one component is available (unknown names are False)."""
    return bool(available().get(str(component).strip().lower(), False))


def enabled_names() -> list:
    """The names of the enabled components, in canonical order."""
    caps = available()
    return [c for c in COMPONENTS if caps.get(c)]
