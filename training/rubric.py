"""rubric.py — a real, deterministic rubric for the social phase.

``training.eval --phase social`` used to report 0 by design: a generated
message has no exact match, and a rubric needs a callable. That made the phase
un-measurable — the smoke adapter was recorded as "not measured, not promoted"
with no number at all (2026-10-26), so there was nothing to improve and
nothing to compare against a baseline.

The rubric is deliberately not a second opinion about tone. The tells that
DISQUALIFY a draft come from ``phantom.automation.social.pretext_score`` (the
same scorer the campaign path refuses a message on), and every golden
criterion maps to one deterministic check over the draft plus its context.
A criterion with no check scores 0 — an unverifiable criterion is not a
passed one — and the unmet list says which, so a poor score is auditable
rather than mysterious.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List

from phantom.automation.social.pretext_score import (  # single source of truth
    _CREDENTIAL, _GENERIC, _URGENCY)

_URL = re.compile(r"(https?://|www\.|t\.me/|bit\.ly/|\b[\w-]+\.(com|net|org)/)",
                  re.IGNORECASE)
_PLACEHOLDER = re.compile(r"[{<][a-z_ ]+[}>]")
_ASK = ("?",)


def _text(prediction: Any) -> str:
    if isinstance(prediction, dict):
        return str(prediction.get("value") or prediction.get("text") or "")
    return str(prediction or "")


def _sentences(text: str) -> List[str]:
    return [s for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s]


def _first_sentence(text: str) -> str:
    parts = _sentences(text)
    return parts[0] if parts else text


def _low(text: str) -> str:
    return " ".join(str(text or "").lower().split())


def _context_value(context: Dict[str, Any], key: str) -> str:
    return _low(context.get(key) or "")


def _likes(text: str, pattern: str) -> bool:
    return bool(pattern) and pattern in text


def _mentions(text: str, value: str) -> bool:
    value = _low(value)
    return bool(value) and value in text


def _no_tells(text: str, tells) -> bool:
    return not any(tell in text for tell in tells)


def _asks_one_question(text: str, _context: Dict[str, Any]) -> bool:
    return sum(text.count(mark) for mark in _ASK) == 1


def _natural_tone(text: str, _context: Dict[str, Any]) -> bool:
    """Human-looking: a plausible length, no template remnants, no shouting."""
    stripped = text.strip()
    if not 15 <= len(stripped) <= 600:
        return False
    if _PLACEHOLDER.search(stripped):
        return False
    words = [w for w in re.findall(r"[A-Za-zÀ-ÿ]{4,}", stripped)]
    shouting = [w for w in words if w.isupper()]
    return len(shouting) <= 1 and "!" not in stripped


def _calm_tone(text: str, _context: Dict[str, Any]) -> bool:
    return _no_tells(text, _URGENCY) and "!" not in text


# criterion text (lower-cased) -> deterministic check
CHECKS: Dict[str, Callable[[str, Dict[str, Any]], bool]] = {
    "no link": lambda text, _c: not _URL.search(text),
    "no link in the opener": lambda text, _c: not _URL.search(
        _first_sentence(text)),
    "no urgency": lambda text, _c: _no_tells(text, _URGENCY),
    "no generic greeting": lambda text, _c: _no_tells(text, _GENERIC),
    "no credential request": lambda text, _c: _no_tells(text, _CREDENTIAL),
    "asks one question": _asks_one_question,
    "one clear question": _asks_one_question,
    "one action": _asks_one_question,
    "mentions the shared interest": lambda text, c: _mentions(
        text, _context_value(c, "interest")),
    "specific event context": lambda text, c: any(
        _mentions(text, _context_value(c, key))
        for key in ("city", "event", "venue")),
    "uses the order number": lambda text, c: _mentions(
        text, _context_value(c, "order")),
    "natural tone": _natural_tone,
    "calm tone": _calm_tone,
}


def check(criterion: str, text: str, context: Dict[str, Any] = None) -> bool:
    """One criterion against one draft; an unknown criterion is NOT met."""
    fn = CHECKS.get(_low(criterion))
    return bool(fn(str(text or ""), dict(context or {}))) if fn else False


def unmet(expected: Any, prediction: Any,
          context: Dict[str, Any] = None) -> List[str]:
    """The criteria the draft does not satisfy (for an auditable receipt)."""
    criteria = [str(c) for c in ((expected or {}).get("criteria") or [])]
    text = _text(prediction)
    if not text.strip():
        return list(criteria)
    return [c for c in criteria if not check(c, text, context)]


def social_rubric(expected: Any, prediction: Any,
                  context: Dict[str, Any] = None) -> float:
    """Fraction of the golden criteria the draft satisfies (0..1).

    An empty draft, or a golden row with no criteria, scores 0: nothing was
    demonstrated.
    """
    criteria = [str(c) for c in ((expected or {}).get("criteria") or [])]
    if not criteria or not _text(prediction).strip():
        return 0.0
    met = len(criteria) - len(unmet(expected, prediction, context))
    return round(met / len(criteria), 6)


__all__ = ["CHECKS", "check", "social_rubric", "unmet"]
