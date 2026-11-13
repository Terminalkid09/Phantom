"""planner_features.py — the ONE feature definition for the planner ranker.

The trainer (``training.planner_ranker``) imports this module instead of
re-implementing it, and the runtime advisor uses the same function.  Weights
are keyed by feature NAME, so two definitions that disagree by one field would
not raise: they would multiply the wrong term.  Keeping one function removes
that failure mode.

The vector is deliberately small and declarative: the facts the planner
already has on every capability (category, stealth level, effects, opsec cost,
detection risk, ``forceful``), the decision context (goal, fact, stealthy
profile, noise breaker, known facts, already tried) and the capability id.
Interactions with goal / stealth / noise are explicit features, so a linear
model can express "passive first under stealth" instead of one global order.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence


def candidate_row(cap: Any) -> Dict[str, Any]:
    """The candidate-table row for one planner capability (data only)."""
    return {
        "id": str(getattr(cap, "id", "") or ""),
        "category": str(getattr(cap, "category", "") or ""),
        "stealth_level": str(getattr(cap, "stealth_level", "") or ""),
        "opsec_cost": round(float(getattr(cap, "opsec_cost", 0.0) or 0.0), 3),
        "detection_risk": round(
            float(getattr(cap, "detection_risk", 0.0) or 0.0), 3),
        "forceful": bool(getattr(cap, "forceful", False)),
        "effects": sorted(str(e) for e in (getattr(cap, "effects", ()) or ())),
    }


def _tags(candidate: Dict[str, Any]) -> List[str]:
    tags = [f"category:{candidate.get('category', '')}",
            f"stealth:{candidate.get('stealth_level', '')}",
            f"id:{candidate.get('id', '')}"]
    tags.extend(f"effect:{effect}" for effect in candidate.get("effects") or [])
    return [tag for tag in tags if not tag.endswith(":")]


def features(payload: Dict[str, Any], cid: str) -> Dict[str, float]:
    """The feature dictionary for ONE candidate in ONE decision context."""
    candidate = None
    for row in payload.get("candidates") or []:
        if isinstance(row, dict) and str(row.get("id")) == str(cid):
            candidate = row
            break
    if candidate is None:
        return {}

    out: Dict[str, float] = {}
    goal = str(payload.get("goal") or "")
    fact = str(payload.get("fact") or payload.get("fact_to_produce") or "")
    stealthy = (str(payload.get("profile") or "").lower()
                in ("stealth", "paranoid"))
    noise = bool(payload.get("noise_breaker"))
    known = {str(x) for x in payload.get("known_facts") or []}
    effects = {str(e) for e in candidate.get("effects") or []}

    out[f"goal:{goal}"] = 1.0
    out[f"fact:{fact}"] = 1.0
    out["profile_stealth"] = 1.0 if stealthy else 0.0
    out["noise_breaker"] = 1.0 if noise else 0.0

    for tag in _tags(candidate):
        out[tag] = 1.0
        if goal:
            out[f"goal={goal}|{tag}"] = 1.0
        if stealthy:
            out[f"stealthy|{tag}"] = 1.0
        if noise:
            out[f"noise|{tag}"] = 1.0

    out["num:opsec_cost"] = float(candidate.get("opsec_cost") or 0.0)
    out["num:detection_risk"] = float(candidate.get("detection_risk") or 0.0)
    out["num:forceful"] = 1.0 if candidate.get("forceful") else 0.0
    out["num:effects"] = float(len(effects))
    out["num:known_effects"] = float(len(effects & known))
    tried = {str(x) for x in payload.get("already_tried") or []}
    out["num:tried"] = 1.0 if str(cid) in tried else 0.0
    if stealthy:
        out["stealthy|num:opsec_cost"] = out["num:opsec_cost"]
        out["stealthy|num:detection_risk"] = out["num:detection_risk"]
        out["stealthy|num:forceful"] = out["num:forceful"]
    return {key: value for key, value in out.items() if value}


def contexts(payload: Dict[str, Any]) -> Dict[str, Dict[str, float]]:
    """``{candidate_id: features}`` for every row in the payload."""
    return {
        str(row.get("id")): features(payload, str(row.get("id")))
        for row in payload.get("candidates") or []
        if isinstance(row, dict) and row.get("id")
    }


def rows_for(capabilities: Sequence[Any]) -> List[Dict[str, Any]]:
    """Candidate rows in the runtime's canonical shape."""
    return [candidate_row(cap) for cap in capabilities or []]
