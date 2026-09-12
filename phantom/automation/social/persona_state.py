"""persona_state.py — persistent social-state ledger (warmup + follow).

The warmup problem the operator flagged: a multi-day engagement spans
several phantom sessions. An in-memory wait state dies with the process —
the operator closes phantom on day 1, reopens on day 3, and the chain
either re-waits forever or, worse, forgets the follow was already sent.

The fix: every time-sensitive social fact lives in a small JSON ledger
under data/social_state.json (0600) and is re-evaluated against WALL-CLOCK
time on every load:

    * persona warmup  — created_at + warmup_deadline; a fresh persona
                        must age N hours before its first cold contact
                        (cold DMs on day 0 are the #1 ban signal);
    * follow requests — sent_at + accepted; a request sent yesterday is
                        still pending today, one accepted last week is
                        already actionable;
    * conversations   — the two-stage contact: which handles got the OPENER
                        (stage 1, no link), which one replied, and which
                        already received the link (stage 2). Without this a
                        restart either re-sends the opener to someone who
                        already answered, or worse, never sends the link at
                        all because the process that held it died.

The file is the single source of truth: the SocialEngine reads it at
construction and re-writes it on every state mutation, so ANY new process
resumes exactly where the last one stopped. Bounded, atomic writes,
never raises — a corrupt/missing file just means empty state.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any, Dict, List, Optional

# default warmup: 72h between persona creation and first cold contact.
# Aggressive runs shorten it; speed keeps the countdown but never blocks.
WARMUP_HOURS_DEFAULT = 72.0
WARMUP_HOURS_AGGRESSIVE = 6.0

_STATE_VERSION = 2


class PersonaState:
    """Durable persona + follow-request state with wall-clock semantics."""

    def __init__(self, path: Optional[str] = None,
                 now: Optional[float] = None) -> None:
        self.path = path or _default_path()
        self._now = now if now is not None else time.time
        self._data: Dict[str, Any] = self._load()

    # ── persistence ───────────────────────────────────────────────────
    # a v1 file predates conversations: it still loads, it simply has none.
    # The upgrade is silent and lossless, so an engagement started before
    # this feature resumes instead of being thrown away.
    _KNOWN_VERSIONS = (1, 2)

    def _blank(self) -> Dict[str, Any]:
        return {"version": _STATE_VERSION, "personas": {}, "follows": {},
                "conversations": {}}

    def _load(self) -> Dict[str, Any]:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if (isinstance(raw, dict)
                    and raw.get("version") in self._KNOWN_VERSIONS):
                return {"version": _STATE_VERSION,
                        "personas": raw.get("personas") or {},
                        "follows": raw.get("follows") or {},
                        "conversations": raw.get("conversations") or {}}
        except (OSError, ValueError):
            pass
        return self._blank()

    def _save(self) -> None:
        try:
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=d or ".", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(self._data, f, indent=2)
                os.replace(tmp, self.path)
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass
            finally:
                if os.path.exists(tmp):
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
        except OSError:
            pass  # persistence is best-effort; the chain never dies for it

    def reload(self) -> None:
        """Re-read from disk (wall-clock re-evaluation on session start)."""
        self._data = self._load()

    # ── persona warmup ────────────────────────────────────────────────
    def persona_created(self, persona_id: str, name: str = "",
                        aggressive: bool = False) -> float:
        """Register a persona (idempotent): first call wins — re-running
        a session never RESETS the warmup clock."""
        personas = self._data["personas"]
        if persona_id in personas and personas[persona_id].get("created_at"):
            return personas[persona_id]["created_at"]
        hours = (WARMUP_HOURS_AGGRESSIVE if aggressive
                 else WARMUP_HOURS_DEFAULT)
        rec = personas.setdefault(persona_id, {"name": name or persona_id})
        rec.setdefault("created_at", self._now())
        rec["warmup_deadline"] = rec["created_at"] + hours * 3600.0
        self._save()
        return rec["created_at"]

    def warmup_remaining(self, persona_id: str) -> float:
        """Seconds of warmup left for this persona (<=0 = ready)."""
        rec = self._data["personas"].get(persona_id) or {}
        deadline = rec.get("warmup_deadline")
        if deadline is None:
            return 0.0  # unknown persona is never blocked
        return deadline - self._now()

    def warmup_ok(self, persona_id: str, aggressive: bool = False) -> bool:
        if aggressive:
            return True  # explicit override: burn the persona if asked
        return self.warmup_remaining(persona_id) <= 0.0

    def warmup_note(self, persona_id: str) -> str:
        """Human sentence for markers/logs."""
        left = self.warmup_remaining(persona_id)
        if left <= 0:
            return "warmup complete"
        h = left / 3600.0
        if h >= 1.0:
            return f"warmup: {h:.1f}h remaining (persona too fresh to DM)"
        return f"warmup: {int(left / 60.0)}m remaining (persona too fresh to DM)"

    # ── follow requests ───────────────────────────────────────────────
    def follow_sent(self, handle: str, platform: str = "") -> None:
        self._data["follows"][handle] = {
            "platform": platform, "sent_at": self._now(),
            "accepted": False, "accepted_at": None,
        }
        self._save()

    def follow_accepted(self, handle: str) -> bool:
        rec = self._data["follows"].get(handle)
        if rec is None:
            return False
        if not rec.get("accepted"):
            rec["accepted"] = True
            rec["accepted_at"] = self._now()
            self._save()
        return True

    def follow_status(self, handle: str) -> Dict[str, Any]:
        return dict(self._data["follows"].get(handle) or {})

    def pending_follows(self) -> List[str]:
        return [h for h, r in self._data["follows"].items()
                if not r.get("accepted")]

    def accepted_follows(self) -> List[str]:
        return [h for h, r in self._data["follows"].items()
                if r.get("accepted")]


    # ── conversations (two-stage contact) ─────────────────────────────
    def conversation_start(self, handle: str, platform: str = "",
                           pretext: str = "", strategy: str = "",
                           link: str = "") -> Dict[str, Any]:
        """Record that the OPENER (stage 1, no link) went out to `handle`.

        Idempotent: a resumed run that re-sends the opener does not reset
        the clock, so the stage-2 wait measures from the FIRST contact.
        """
        c = self._data["conversations"].setdefault(handle, {})
        c.setdefault("platform", platform)
        c.setdefault("pretext", pretext)
        c.setdefault("strategy", strategy)
        if link:
            c.setdefault("link", link)
        c.setdefault("sent_at", self._now())
        c.setdefault("reply_at", None)
        c.setdefault("stage2_at", None)
        self._save()
        return dict(c)

    def mark_reply(self, handle: str) -> bool:
        """The target ANSWERED the opener. This is the gate stage 2 waits
        on: a link sent before the reply is a cold link again, which is the
        whole thing the two-stage strategy exists to avoid."""
        c = self._data["conversations"].get(handle)
        if c is None:
            return False
        if not c.get("reply_at"):
            c["reply_at"] = self._now()
            self._save()
        return True

    def reply_seen(self, handle: str) -> bool:
        return bool((self._data["conversations"].get(handle) or {})
                    .get("reply_at"))

    def stage2_ready(self, handle: str, aggressive: bool = False) -> bool:
        """True when the link may be sent: stage 1 landed, the link has not
        been sent yet, and the target replied (or the operator explicitly
        accepted the cold re-contact)."""
        c = self._data["conversations"].get(handle)
        if not c or not c.get("sent_at") or c.get("stage2_at"):
            return False
        return bool(c.get("reply_at")) or aggressive

    def stage2_sent(self, handle: str) -> bool:
        """Mark the link as delivered (idempotent)."""
        c = self._data["conversations"].get(handle)
        if c is None:
            return False
        if not c.get("stage2_at"):
            c["stage2_at"] = self._now()
            self._save()
        return True

    def conversation_status(self, handle: str) -> Dict[str, Any]:
        return dict(self._data["conversations"].get(handle) or {})

    def awaiting_stage2(self, aggressive: bool = False) -> List[str]:
        """Handles whose opener landed and whose link is still owed — the
        work a NEW session picks up after a restart (this is the multi-day
        case: the opener went out yesterday, the reply arrived today)."""
        return [h for h in self._data["conversations"]
                if self.stage2_ready(h, aggressive=aggressive)]

    def conversations(self) -> Dict[str, Dict[str, Any]]:
        return {h: dict(c) for h, c in self._data["conversations"].items()}


def _default_path() -> str:
    try:
        from phantom.utils.paths import data_dir
        return os.path.join(data_dir(), "social_state.json")
    except Exception:
        return os.path.join("data", "social_state.json")


# module-level singleton (per-process) — one file, one truth
_SHARED: Optional[PersonaState] = None


def shared_state() -> PersonaState:
    global _SHARED
    if _SHARED is None:
        _SHARED = PersonaState()
    return _SHARED
