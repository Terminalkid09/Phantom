"""planning.py — the AI's proposals about WHICH capability to run next.

This is the capability-level counterpart of ``advisors.exploit``: the exploit
advisor ranks access candidates inside one stage, while the planner chooses
between capabilities (scan, web_creds, ssh_login, beacon_deploy, ...). Until
now the planner had no AI seam at all, so “AI on” and “AI off” produced the
same plan on every lab run — the model was answering questions nobody asked.

The phase is called ``planner`` and it is deliberately separate from
``exploit``: the two are asked different questions, and a manifest promoted
for one has no business steering the other.

The output is proposals, never authority. ``ai.arbiter.Arbiter`` decides
whether a proposal is accepted, using the eligible set, the learned trust
level and the hard invariants (no new move, no unready move). A failure here
returns ``[]`` and the deterministic plan continues.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

from phantom.automation.ai.arbiter import Proposal


def _row(cap: Any) -> Dict[str, Any]:
    """Facts about one move — never a command, a path or a payload."""
    return {
        "id": str(getattr(cap, "id", "") or ""),
        "category": str(getattr(cap, "category", "") or ""),
        "stealth_level": str(getattr(cap, "stealth_level", "") or ""),
        "opsec_cost": round(float(getattr(cap, "opsec_cost", 0.0) or 0.0), 2),
        "detection_risk": round(
            float(getattr(cap, "detection_risk", 0.0) or 0.0), 2),
        "effects": [str(e) for e in (getattr(cap, "effects", ()) or ())],
    }


def payload(wm: Any, fact: str, capabilities: Sequence[Any],
            goal: str = "") -> Dict[str, Any]:
    """The request body for the ``planner`` phase (data only)."""
    return {
        "goal": str(goal or ""),
        "target_type": str(getattr(wm, "target_type", "") or ""),
        "fact_to_produce": str(fact or ""),
        "known_facts": sorted(
            str(getattr(f, "kind", "")) for f in
            (getattr(wm, "findings", []) or []))[:40],
        "candidates": [_row(c) for c in capabilities],
    }


def propose(wm: Any, fact: str, capabilities: Sequence[Any],
            goal: str = "") -> List[Proposal]:
    """Ask the phase model for a confidence-ranked order over ``capabilities``.

    Never raises. ``integrated`` is served in-process by a promoted ranker when
    one exists for this phase; otherwise the router reports why it could not
    answer, and the empty list is an honest abstention the arbiter records.
    """
    if not capabilities:
        return []
    try:
        from phantom.automation.ai import config as ai_config
        from phantom.automation.ai import linear, router
    except Exception:
        return []
    if ai_config.mode("planner") == "off":
        return []
    rows = payload(wm, fact, capabilities, goal)
    allowed = {str(getattr(c, "id", "") or "") for c in capabilities}

    if ai_config.mode("planner") == "integrated":
        # In-process first: a promoted capability ranker needs no endpoint and
        # cannot be affected by whatever owns port 8080 on this box.
        try:
            ranker = linear.promoted("planner")
        except Exception:
            ranker = None
        if ranker is not None:
            ids = ranker.rank([str(getattr(c, "id", "") or "")
                               for c in capabilities])
            if not ids:
                return []
            # Confidence from the SPREAD of the learned scores: a model whose
            # weights do not separate these moves has no opinion to express,
            # and saying 0.9 anyway is how a decorative AI looks confident.
            scores = [ranker.score(cid, {}) for cid in ids]
            spread = max(scores) - min(scores) if len(scores) > 1 else 0.0
            confidence = max(0.0, min(1.0, 0.5 + spread))
            return [Proposal(cid, confidence, "promoted capability ranker")
                    for cid in ids if cid in allowed]

    result = router.ask("planner", rows, schema="planner")
    if not getattr(result, "ok", False):
        return []
    data = getattr(result, "data", {}) or {}
    ranked = data.get("ranked")
    if not isinstance(ranked, list):
        return []
    out: List[Proposal] = []
    for row in ranked:
        if not isinstance(row, dict):
            continue
        cid = str(row.get("id") or row.get("capability_id") or "").strip()
        if not cid or cid not in allowed:
            continue                # closed registry: unknown ids are dropped
        out.append(Proposal(cid, row.get("confidence", 0.0),
                            str(row.get("reason", "") or "")))
    return out
