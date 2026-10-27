"""social.py — draft a message, then let the deterministic scorer judge it.

The model writes text; it does not get to decide whether the text is any
good. Every draft is passed through ``pretext_score`` and ``ready`` is the
SCORER's verdict. A critical tell (asking for a password/OTP, brand/sender
mismatch) leaves a draft unusable even if it reads well.

A URL the model invents is stripped before scoring and marks the draft
not-ready: the only link allowed in a lure is the one the caller's tracker
issued, and a fabricated host is how a campaign ends up pointing at a
domain nobody controls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

from phantom.automation.social.pretext_score import score_pretext

from ..router import ask

_URL = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)


@dataclass
class SocialDraft:
    ok: bool = False
    text: str = ""
    subject: str = ""
    score: int = 0
    ready: bool = False
    model: str = ""
    error: str = ""
    issues: List[str] = field(default_factory=list)

    def marker(self) -> str:
        return (f"AI_SOCIAL: model={self.model or '-'} ready={int(self.ready)} "
                f"score={self.score} issues={','.join(self.issues) or 'none'}")


def _strip_invented_urls(text: str, allowed: str) -> tuple[str, bool]:
    """Remove any URL that is not the caller's link. Returns (text, stripped)."""
    allowed = str(allowed or "").strip()
    removed = False

    def replace(match: re.Match) -> str:
        nonlocal removed
        url = match.group(0)
        if allowed and (url == allowed or url.startswith(allowed)):
            return url
        removed = True
        return ""

    cleaned = _URL.sub(replace, str(text or ""))
    if removed:
        cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
        cleaned = re.sub(r"[ \t]+([.,;:])", r"\1", cleaned).strip()
    return cleaned, removed


def draft(context: Dict[str, Any], *, channel: str = "dm",
          subject: str = "") -> SocialDraft:
    """One drafting call, scored. ``ok`` only says the model answered."""
    payload = {
        "context": {str(k): str(v)[:1200] for k, v in (context or {}).items()},
        "channel": str(channel or "dm"),
        "subject": str(subject or "")[:200],
    }
    result = ask("social", payload, schema="social")
    if not result.ok:
        return SocialDraft(False, "", subject, 0, False, result.model,
                           result.error)
    text = str(result.data.get("text") or "").strip()
    if not text:
        return SocialDraft(False, "", subject, 0, False, result.model,
                           "empty draft")
    subj = str(result.data.get("subject") or subject or "")[:200]

    allowed = str(context.get("link") or "")
    text, stripped = _strip_invented_urls(text, allowed)
    if stripped and allowed:
        text = f"{text} {allowed}".strip()
    if not text:
        return SocialDraft(False, "", subj, 0, False, result.model,
                           "draft was only an invented URL")

    score = score_pretext(
        subj, text, channel=channel,
        brand=str(context.get("brand") or ""),
        target_name=str(context.get("target_name") or ""),
        link=allowed,
        sender=str(context.get("sender") or ""))
    issues = list(score.codes())
    if stripped:
        issues.append("invented_url_stripped")
    ready = bool(score.ready and not stripped)
    return SocialDraft(True, text, subj, score.value, ready, result.model, "",
                       issues)


def apply_to_body(original: str, proposal: SocialDraft) -> tuple[str, str]:
    """The engine hook: (final body, marker). Off/fallback keeps the body."""
    if proposal.ok and proposal.ready and proposal.text.strip():
        return proposal.text, (f"AI_SOCIAL: model={proposal.model or '-'} "
                               f"ready=1 score={proposal.score}")
    reason = proposal.error or "not_ready"
    return original, (f"AI_SOCIAL: fallback reason={reason[:80]} "
                      f"score={proposal.score}")
