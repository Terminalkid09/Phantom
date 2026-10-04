"""
drivers.py — runtime tool registration from declarative manifests.

The built-in capability set is code: every adapter is a Python function in
``guidance/kit.py``, so adding a tool the planner has never seen meant
editing that file and shipping a release. The toolbelt could already
re-rank a KNOWN tool from config (``toolbelt.extra``), but it still had to
be a tool an existing adapter could already drive.

This module removes that ceiling. A **driver** is a small JSON manifest
that describes a tool AND how to run it AND how to read its output:

    {
      "id": "dnscan_subdomains",
      "tool": "dnscan",
      "category": "recon",
      "description": "Passive subdomain discovery",
      "effects": ["hostname"],
      "command": "dnscan -d {target} -r 6 -w -o -",
      "markers": [
        {"prefix": "DNSCAN:", "kind": "hostname",
         "key": "hostname:{name}", "fields": ["name"]}
      ],
      "requires": ["target"],
      "opsec_cost": 0.2, "detection_risk": 0.05,
      "stealth_level": "passive", "timeout": 60
    }

Phantom scans the driver directories at registry-build time and turns each
valid manifest into a real ``Capability`` — with a SYNTHESIZED adapter (the
declared command template) and interpreter (the declared markers). The
"adapter is the only source of a command" invariant holds: the template IS
that adapter, just expressed as data.

Safety posture:
  * discovery is OFF unless a driver directory actually holds a manifest —
    a fresh checkout is byte-for-byte the built-in capability set;
  * a manifest can never shadow a built-in id (the registry refuses the
    collision loudly, exactly like a learned capability);
  * malformed manifests are dropped, never fatal — a bad file must not take
    the whole planner down;
  * drivers may only use the DECLARED preconditions grammar, so nothing in
    the manifest is executed while planning.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

# Capability categories the agent knows how to dispatch. A driver outside
# this set would register but never execute, so it is rejected up front.
_KNOWN_CATEGORIES = (
    "recon", "osint", "service", "creds", "exploit", "lateral",
    "persistence", "beacon", "exfil", "social", "post", "ad", "hunt",
)

# Directories scanned, in order. A packaged set ships next to the package;
# the operator's own manifests live in the (gitignored) data dir or in the
# directories named by ``toolbelt.drivers_dir`` / ``PHANTOM_DRIVERS_DIR``.
_PACKAGED_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "drivers")


@dataclass(frozen=True)
class ToolDriver:
    """One declarative tool: how to run it and how to read it back."""

    id: str
    tool: str
    category: str
    description: str
    command: str
    effects: Tuple[str, ...] = ()
    markers: Tuple[Dict[str, Any], ...] = ()
    requires: Tuple[str, ...] = ()
    inputs: Tuple[Dict[str, Any], ...] = ()
    opsec_cost: float = 1.0
    detection_risk: float = 0.1
    stealth_level: str = "passive"
    timeout: int = 60
    rank: int = 50
    styles: Tuple[str, ...] = ("default", "stealth", "speed", "aggressive")
    requires_service: Tuple[str, ...] = ()
    source_path: str = ""


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_str_tuple(value: Any) -> Tuple[str, ...]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return ()
    out: List[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in out:
            out.append(text)
    return tuple(out)


def parse_driver(data: Any, source_path: str = "") -> Optional[ToolDriver]:
    """Validate one manifest dict -> ToolDriver, or None when unusable.

    Strict on the fields an EXECUTABLE capability needs (id, tool,
    category, command, a non-empty effects list); lenient on the rest, so a
    minimal manifest is enough and the optional knobs default sensibly.
    """
    if not isinstance(data, dict):
        return None
    cap_id = str(data.get("id") or "").strip()
    tool = str(data.get("tool") or "").strip()
    category = str(data.get("category") or "").strip().lower()
    command = str(data.get("command") or "").strip()
    effects = _as_str_tuple(data.get("effects"))
    if not cap_id or not tool or not command or not effects:
        return None
    if category not in _KNOWN_CATEGORIES:
        return None
    # the command MUST refer to the target or a declared slot; a template
    # that consumes nothing is a constant string, not a driver.
    if "{" not in command:
        return None

    markers: List[Dict[str, Any]] = []
    raw_markers = data.get("markers") or []
    if isinstance(raw_markers, dict):
        raw_markers = [raw_markers]
    if isinstance(raw_markers, (list, tuple)):
        for m in raw_markers:
            if not isinstance(m, dict):
                continue
            prefix = str(m.get("prefix") or "").strip()
            kind = str(m.get("kind") or "").strip()
            if not prefix or not kind:
                continue
            markers.append({
                "prefix": prefix, "kind": kind,
                "key": str(m.get("key") or "").strip(),
                "fields": _as_str_tuple(m.get("fields")),
                "confidence": _as_float(m.get("confidence"), 0.6),
            })

    inputs: List[Dict[str, Any]] = []
    raw_inputs = data.get("inputs") or []
    if isinstance(raw_inputs, (list, tuple)):
        for slot in raw_inputs:
            if not isinstance(slot, dict):
                continue
            name = str(slot.get("name") or "").strip()
            if not name:
                continue
            inputs.append({
                "name": name,
                "type": str(slot.get("type") or "str"),
                "required": bool(slot.get("required", False)),
                "description": str(slot.get("description") or ""),
            })

    return ToolDriver(
        id=cap_id, tool=tool, category=category,
        description=str(data.get("description") or cap_id),
        command=command, effects=effects, markers=tuple(markers),
        requires=_as_str_tuple(data.get("requires")),
        inputs=tuple(inputs),
        opsec_cost=_as_float(data.get("opsec_cost"), 1.0),
        detection_risk=_as_float(data.get("detection_risk"), 0.1),
        stealth_level=str(data.get("stealth_level") or "passive").lower(),
        timeout=_as_int(data.get("timeout"), 60),
        rank=_as_int(data.get("rank"), 50),
        styles=_as_str_tuple(data.get("styles")) or
               ("default", "stealth", "speed", "aggressive"),
        requires_service=_as_str_tuple(data.get("requires_service")),
        source_path=source_path,
    )


def driver_dirs() -> List[str]:
    """Every directory that may hold driver manifests, deduped, in order."""
    dirs: List[str] = []

    def add(path: Any) -> None:
        text = str(path or "").strip()
        if text and text not in dirs:
            dirs.append(text)

    add(_PACKAGED_DIR)
    try:
        from phantom.utils.paths import data_dir
        add(os.path.join(data_dir(), "drivers"))
    except Exception:
        pass
    try:
        from phantom.utils import config as cfg
        if cfg.get_bool("toolbelt.drivers", True):
            raw = cfg.get("toolbelt.drivers_dir", "", env=None)
            for part in str(raw or "").split(os.pathsep):
                add(part)
        else:
            # drivers disabled: drop everything but the packaged set
            dirs = [_PACKAGED_DIR]
    except Exception:
        pass
    for part in str(os.environ.get("PHANTOM_DRIVERS_DIR", "") or "").split(os.pathsep):
        add(part)
    return dirs


def load_drivers() -> List[ToolDriver]:
    """Every valid manifest across the driver dirs, deduped by id (first
    directory wins). A malformed file is skipped, never fatal."""
    seen: Dict[str, ToolDriver] = {}
    for directory in driver_dirs():
        if not os.path.isdir(directory):
            continue
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            if not name.lower().endswith(".json"):
                continue
            path = os.path.join(directory, name)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                continue
            manifest = data.get("driver") if isinstance(data, dict) and \
                isinstance(data.get("driver"), dict) else data
            drv = parse_driver(manifest, path)
            if drv is None or drv.id in seen:
                continue
            seen[drv.id] = drv
    return [seen[k] for k in sorted(seen)]


# ── manifest -> live Capability ────────────────────────────────────────────

def _fill_template(template: str, wm, slots: Dict[str, Any]) -> str:
    """Interpolate ``{field}`` from the slot values (plus ``target``)."""
    values: Dict[str, Any] = dict(slots or {})
    values.setdefault("target", getattr(wm, "target", ""))
    values.setdefault("host", getattr(wm, "target", ""))
    try:
        return template.format(**values)
    except KeyError as exc:
        raise ValueError(
            f"driver command needs an unset field {exc} "
            f"(declare it under 'inputs' or supply it as a slot)") from exc
    except (IndexError, ValueError) as exc:
        raise ValueError(f"driver command template is invalid: {exc}") from exc


def _driver_adapter(drv: ToolDriver):
    def _adapter(wm, slots):
        return _fill_template(drv.command, wm, slots or {})
    return _adapter


def _parse_marker(line: str, prefix: str) -> Dict[str, str]:
    if not line.startswith(prefix):
        return {}
    kv: Dict[str, str] = {}
    for chunk in line[len(prefix):].split():
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


def _driver_interp(drv: ToolDriver):
    def _interp(output: str, wm, slots) -> List[Finding]:
        from phantom.automation.belief import Finding
        findings: List[Finding] = []
        for line in (output or "").splitlines():
            for marker in drv.markers:
                kv = _parse_marker(line, marker["prefix"])
                if not kv:
                    continue
                fields = marker.get("fields") or tuple(kv)
                value = {f: kv.get(f, "") for f in fields}
                key_tmpl = marker.get("key") or ""
                try:
                    key = key_tmpl.format(**(dict(kv, target=wm.target)))
                except (KeyError, IndexError, ValueError):
                    key = f"{marker['kind']}:{kv.get('key', '')}" \
                        if kv.get("key") else marker["kind"]
                findings.append(Finding(
                    kind=marker["kind"], key=key or marker["kind"],
                    value=value, confidence=float(marker.get("confidence", 0.6)),
                    source=drv.id, target=wm.target))
                break   # one marker per line
        return findings
    return _interp


def driver_capability(drv: ToolDriver):
    """Build a live ``Capability`` from a driver manifest.

    The synthesized adapter/interpreter ARE the driver's declared template
    and markers, so no code in the manifest runs during planning.
    """
    from phantom.automation.guidance import commands as _commands
    from phantom.automation.guidance.learned import _requires_predicate

    def _prep(spec: str):
        # the learned grammar is finding-KEY based; a driver's command
        # template interpolates the engagement TARGET, so "target" is the
        # natural way to say "needs a non-empty target" — map it explicitly
        # rather than demanding a (non-existent) `target` finding.
        if (spec or "").strip().lower() == "target":
            return lambda wm: bool(getattr(wm, "target", ""))
        return _requires_predicate(spec)

    inputs = []
    for slot in drv.inputs:
        inputs.append(_commands.InputSlot(
            name=slot["name"], type=slot["type"],
            required=slot["required"], description=slot["description"]))
    cap = _commands.Capability(
        id=drv.id, category=drv.category, description=drv.description,
        exec_class="shell_command", inputs=inputs,
        preconditions=[_prep(r) for r in drv.requires],
        requires=list(drv.requires),
        effects=list(drv.effects),
        adapter=_driver_adapter(drv),
        interpreter=_driver_interp(drv) if drv.markers else None,
        opsec_cost=drv.opsec_cost, detection_risk=drv.detection_risk,
        stealth_level=drv.stealth_level, timeout=drv.timeout,
        banner=drv.description, tools=[drv.tool],
    )
    # marks this as a runtime-DISCOVERED capability: the planner's reverse
    # index consults discovered caps for a fact that no static source lists,
    # and the coverage audit (which pins the static set) ignores them.
    cap.discovered = True            # type: ignore[attr-defined]
    cap.source_path = drv.source_path  # type: ignore[attr-defined]
    return cap


def load_driver_capabilities() -> List[Any]:
    """All discovered drivers as capabilities (never fatal)."""
    out: List[Any] = []
    for drv in load_drivers():
        try:
            out.append(driver_capability(drv))
        except Exception:
            continue
    return out


def driver_summary() -> List[Dict[str, Any]]:
    """Plain-data view for the CLI / doctor (never executes anything)."""
    out: List[Dict[str, Any]] = []
    for drv in load_drivers():
        out.append({
            "id": drv.id, "tool": drv.tool, "category": drv.category,
            "effects": list(drv.effects), "source": drv.source_path,
        })
    return out
