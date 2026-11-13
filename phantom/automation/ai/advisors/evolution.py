"""evolution.py — triage text for the self-improvement loop.

The loop already owns the gate and the PR. This advisor only turns a bundle
of failure cases into a readable signature/cause/next-probe, so a human can
see WHY a capability is worth authoring. It never writes code, never names a
file to modify, and on any failure it falls back to a deterministic grouping
the operator can still read.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..router import ask

_MAX = 400


def _clip(text: Any) -> str:
    return " ".join(str(text or "").split())[: _MAX]


def _view(case: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "task": _clip(case.get("task")),
        "goal": _clip(case.get("goal")),
        "stall": _clip(case.get("stall")),
        "kind": _clip(case.get("kind")),
        "note": _clip(case.get("note")),
        "failures": case.get("failures", 0),
    }


def _fallback(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic grouping by (goal, stall/kind), most frequent first."""
    groups: Dict[tuple, int] = {}
    for case in cases:
        key = (_clip(case.get("goal")) or "unknown",
               _clip(case.get("stall")) or _clip(case.get("kind")) or "unknown")
        groups[key] = groups.get(key, 0) + 1
    ordered = sorted(groups.items(), key=lambda item: (-item[1], item[0]))
    if not ordered:
        return {"summary": "no failure cases supplied", "causes": [],
                "proposal": "", "source": "deterministic"}
    lines = [f"{count}x {goal} stalled at {stall}"
             for (goal, stall), count in ordered[:5]]
    return {
        "summary": _clip("; ".join(lines)),
        "causes": [f"{stall}" for (_goal, stall), _n in ordered[:5]],
        "proposal": _clip(
            "author a bounded capability for the most frequent signature; "
            "keep the same gate and human review"),
        "source": "deterministic",
    }


def summarize_cases(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    """AI triage when available, deterministic grouping otherwise."""
    cases = [c for c in (cases or []) if isinstance(c, dict)]
    if not cases:
        return _fallback([])
    payload = {"cases": [_view(c) for c in cases][:30]}
    result = ask("evolution", payload, schema="evolution")
    if not result.ok:
        out = _fallback(cases)
        out["error"] = result.error
        return out
    data = result.data
    return {
        "summary": _clip(data.get("summary")),
        "causes": [_clip(c) for c in (data.get("causes") or [])][:8],
        "proposal": _clip(data.get("proposal")),
        "source": "ai",
        "model": result.model,
    }
