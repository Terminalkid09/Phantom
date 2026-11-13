"""osint.py — same-person PROPOSALS, never a confirmation.

``identity_confidence`` owns the verdict: it requires independent signals
and has a confirmed threshold. A model cannot see all of that evidence, so
its contribution is a ranked HYPOTHESIS over candidates the caller already
holds. Two hard limits make that safe:

* the returned ``(handle, platform)`` must exist in the candidate list the
  caller supplied — the model can only reorder/label what is already there;
* confidence is clamped to ``0.79``, just below the confirmed threshold, so
  no model output can ever become a same-person proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..router import ask

# Just below identity_confidence.CONFIRMED_THRESHOLD (0.80).
MAX_CONFIDENCE = 0.79


@dataclass
class OsintAdvice:
    ok: bool = False
    links: List[Dict[str, Any]] = field(default_factory=list)
    model: str = ""
    error: str = ""


def _handle(item: Dict[str, Any]) -> str:
    return str(item.get("handle") or item.get("username") or "").strip().lstrip("@")


def _platform(item: Dict[str, Any]) -> str:
    return str(item.get("platform") or "").strip().lower()


def _candidate_view(item: Dict[str, Any]) -> Dict[str, Any]:
    """Only fields the model needs; no contact data, no raw history."""
    return {
        "handle": _handle(item),
        "platform": _platform(item),
        "bio": str(item.get("bio") or "")[:400],
        "link": str(item.get("link") or "")[:300],
        "full_name": str(item.get("full_name") or "")[:120],
        "interests": [str(x)[:40] for x in (item.get("interests") or [])][:8],
    }


def propose_links(primary: Dict[str, Any],
                  candidates: List[Dict[str, Any]]) -> OsintAdvice:
    """Ask the OSINT phase to rank existing candidates. Never adds one."""
    pairs = {(_handle(c).lower(), _platform(c)) for c in candidates
             if _handle(c) and _platform(c)}
    if not pairs:
        return OsintAdvice(False, [], "", "no candidates to rank")
    payload = {
        "primary": _candidate_view(primary),
        "candidates": [_candidate_view(c) for c in candidates][:30],
    }
    result = ask("osint", payload, schema="osint")
    if not result.ok:
        return OsintAdvice(False, [], result.model, result.error)

    links: List[Dict[str, Any]] = []
    for row in result.data.get("links") or []:
        if not isinstance(row, dict):
            continue
        key = (_handle(row).lower(), _platform(row))
        if key not in pairs:
            continue                      # a pair the caller never supplied
        try:
            confidence = float(row.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        links.append({
            "handle": _handle(row),
            "platform": _platform(row),
            "confidence": round(max(0.0, min(MAX_CONFIDENCE, confidence)), 3),
            "reason": str(row.get("reason") or "")[:400],
            "signals": [str(s)[:80] for s in (row.get("signals") or [])][:8],
        })
    # Deterministic order: the model's ordering is a hint, ties break on the
    # pair so two runs cannot disagree silently.
    links.sort(key=lambda link: (-link["confidence"], link["platform"],
                                 link["handle"]))
    return OsintAdvice(True, links, result.model, "")
