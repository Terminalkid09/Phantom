"""
interpreters.py — the report phase's "interpreters".

Raw tool output -> typed findings does not apply to reporting (there is
no command output to parse); the interpreter role is filled by the
agent-state extractors that feed the raw/client builders.
"""

from __future__ import annotations

from typing import Any, Dict


def extract_findings(agent: Any) -> Dict[str, Any]:
    """Snapshot the agent's world-model findings for the raw report."""
    wm = getattr(agent, "wm", None)
    if wm is None:
        return {}
    out: Dict[str, Any] = {}
    for f in getattr(wm, "findings", []) or []:
        out.setdefault(f.kind, []).append({
            "key": f.key,
            "value": f.value,
            "confidence": getattr(f, "confidence", None),
            "source": getattr(f, "source", ""),
        })
    return out


def extract_events(agent: Any) -> list:
    """Snapshot the agent's decision/event stream for the raw report."""
    return list(getattr(agent, "events", []) or [])