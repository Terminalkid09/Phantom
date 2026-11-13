"""learned/ — machine-authored capabilities, loaded WITHOUT importing them.

A-2 (security sweep): the loader used to call `importlib.import_module()` on
every file in this package at boot. Importing executes the module body in
the MAIN process — the operator's memory, environment and (transitively)
C2 state. The static gate is not a sandbox: it allows stdlib wholesale
(subprocess, socket, os), so the import itself was the boundary, and it was
the wrong one.

Now the module body runs in a short-lived subprocess (`descriptor.describe`)
that returns JSON metadata only. The reconstructed `Capability` carries:
  * no adapter   — the adapter runs in the task worker (worker.py);
  * no interpreter — the interpreter runs in the task worker too, and the
    findings come back as data;
  * declarative `requires` — preconditions the planner can evaluate in this
    process without executing any learned code.

Anything a learned module wants to do, it does in a subprocess.
"""

from __future__ import annotations

import logging
import pkgutil
from typing import Any, Dict, List

log = logging.getLogger(__name__)

# Loaded capability ids are stamped into plans/reports; keep the prefix
# reserved so nothing else can forge learned provenance.
LEARNED_PREFIX = "learned."


def _requires_predicate(spec: str):
    """Build an in-process precondition from a declarative requirement.

    Grammar:
      "service"                  -> any finding of that kind
      "service:tcp/445"          -> an exact (kind, key)
      "service:port=445"         -> a value-attribute match
    """
    text = (spec or "").strip()
    if not text:
        return lambda wm: True
    if ":" not in text:
        return lambda wm: wm.has_any(text)
    kind, _, rest = text.partition(":")
    if "=" in rest:
        attr, _, value = rest.partition("=")
        return lambda wm: bool(wm.find(kind, **{attr: value}))
    return lambda wm: wm.get(kind, rest) is not None


def _capability_from_descriptor(data: Dict[str, Any], source_path: str):
    """Rebuild a Capability from JSON metadata — no module code executed."""
    from phantom.automation.guidance import commands as _commands

    inputs = []
    for slot in data.get("inputs", []) or []:
        try:
            inputs.append(_commands.InputSlot(
                name=str(slot.get("name", "")),
                type=str(slot.get("type", "")),
                required=bool(slot.get("required", False)),
                description=str(slot.get("description", "")),
            ))
        except Exception:
            continue
    requires = [str(r) for r in (data.get("requires", []) or [])]
    cap = _commands.Capability(
        id=str(data.get("id", "")),
        category=str(data.get("category", "")),
        description=str(data.get("description", "")),
        exec_class=str(data.get("exec_class", "shell_command")),
        inputs=inputs,
        preconditions=[_requires_predicate(r) for r in requires],
        requires=requires,
        effects=[str(e) for e in (data.get("effects", []) or [])],
        adapter=None,            # runs in the worker, never here
        interpreter=None,        # runs in the worker, findings come back as data
        opsec_cost=float(data.get("opsec_cost", 1.0) or 1.0),
        detection_risk=float(data.get("detection_risk", 0.1) or 0.1),
        stealth_level=str(data.get("stealth_level", "passive")),
        forceful=bool(data.get("forceful", False)),
        timeout=int(data.get("timeout", 30) or 30),
        banner=str(data.get("banner", "")) or str(data.get("description", "")),
        tools=[str(t) for t in (data.get("tools", []) or [])],
    )
    cap.source_module = source_path            # type: ignore[attr-defined]
    # the module's own callable preconditions could not be read as data; the
    # worker re-checks them against a world snapshot before running (see
    # worker.run_learned_task) and the agent treats a miss as "blocked".
    cap.needs_runtime_precheck = bool(          # type: ignore[attr-defined]
        data.get("has_preconditions"))
    cap.has_interpreter = bool(data.get("has_interpreter"))  # type: ignore[attr-defined]
    return cap


def load_learned() -> List[Any]:
    """Read every learned module's descriptor OUT OF PROCESS; return the
    reconstructed capabilities. Import order is alphabetical/deterministic.
    A module whose descriptor cannot be read is skipped with a warning —
    one broken learned file must never take the whole auto-mode down.
    """
    from phantom.automation.guidance.learned.descriptor import describe

    capacities: List[Any] = []
    for mod in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        if mod.name in ("worker", "descriptor") or mod.name.startswith("_"):
            continue
        path = _module_file(mod.name)
        if not path:
            continue
        try:
            data = describe(path)
        except Exception as exc:  # noqa: BLE001 — never break the boot
            log.warning("learned descriptor %s failed: %s", mod.name, exc)
            continue
        if not data:
            log.warning("learned module %s: descriptor unavailable — skipped",
                        mod.name)
            continue
        cap_id = str(data.get("id", ""))
        if not cap_id.startswith(LEARNED_PREFIX):
            log.warning("learned module %s: capability id %r lacks the %s "
                        "prefix — skipped", mod.name, cap_id or "?", LEARNED_PREFIX)
            continue
        try:
            capacities.append(_capability_from_descriptor(data, path))
        except Exception as exc:  # noqa: BLE001
            log.warning("learned module %s: bad descriptor (%s) — skipped",
                        mod.name, exc)
    return capacities


def _module_file(name: str) -> str:
    import importlib.machinery as _mach
    try:
        spec = _mach.PathFinder.find_spec(name, __path__)
    except Exception:
        return ""
    return (spec.origin or "") if spec else ""
