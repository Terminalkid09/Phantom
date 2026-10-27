"""finding.py — a second pair of eyes on what was observed.

Findings arrive from many parsers; the deterministic pipeline decides what
they mean. This advisor only points at what looks inconsistent and what is
worth verifying next. It cannot add a finding, change a confidence, or
trigger a capability: the caller decides whether to act on a suggestion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from phantom.automation.ai.router import ask
from phantom.automation.ai.schemas import FINDING_KINDS


@dataclass
class FindingAdvice:
    ok: bool = False
    anomalies: List[Dict[str, str]] = field(default_factory=list)
    next_checks: List[str] = field(default_factory=list)
    model: str = ""
    error: str = ""


def _compact(finding) -> Dict[str, Any]:
    value = getattr(finding, "value", None)
    if isinstance(value, dict):
        summary = ", ".join(f"{k}={value[k]}" for k in sorted(value)[:6])
    else:
        summary = str(value or "")
    return {
        "kind": str(getattr(finding, "kind", "") or ""),
        "key": str(getattr(finding, "key", "") or ""),
        "summary": summary[:200],
        "confidence": round(float(getattr(finding, "confidence", 0.0) or 0.0),
                            3),
    }


def advise(findings: Sequence[Any], *,
           context: Optional[str] = None) -> FindingAdvice:
    """Ask for anomalies/next checks over findings the caller already has."""
    rows = [_compact(f) for f in findings if getattr(f, "kind", "") in
            FINDING_KINDS and str(getattr(f, "key", "") or "").strip()]
    if not rows:
        return FindingAdvice(False, [], [], "", "no usable findings")
    payload = {"findings": rows[:40],
               "context": " ".join(str(context or "").split())[:500]}
    result = ask("finding", payload, schema="finding")
    if not result.ok:
        return FindingAdvice(False, [], [], result.model,
                             result.error or "advisor failed")

    known = {(row["kind"], row["key"]) for row in rows}
    anomalies: List[Dict[str, str]] = []
    data = result.data if isinstance(result.data, dict) else {}
    for item in data.get("findings") or []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "")
        key = str(item.get("key") or "")
        if (kind, key) not in known:
            continue        # never invent a finding the caller did not have
        anomalies.append({
            "kind": kind, "key": key,
            "why": " ".join(str(item.get("note") or "").split())[:300],
        })
    next_checks = [x for x in (data.get("next") or []) if isinstance(x, str)]
    return FindingAdvice(True, anomalies, [x[:200] for x in next_checks[:10]],
                         result.model, "")
