"""confirm.py — operator identity checks (the "is this him?" gate).

Two moments need a human eye, everywhere else the chain runs alone:

1. START-GATE: precise username + platform in hand -> show avatar, bio,
   follower/following counts -> operator confirms it is the right
   starting profile (beats 2 hours of OSINT on the wrong person);
2. MID-RUN ambiguity: 2+ close candidates below CONFIRMED -> show both
   with images + direct links -> same:<handle> | stop | widen.

Contract (mirrors the LLM-approval gate on purpose):

* unattended runs NEVER block: ask() waits `timeout` for an answer,
  then falls back to the safe default (widen-once-halt, never contact
  on a guess);
* every check carries everything needed to decide (rendered profile
  cards + profile URLs), so CLI, API and Electron share one queue;
* answers are explicit and auditable; stale checks prune by TTL.
"""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

DEFAULT_TIMEOUT = 120.0
TTL = 3600.0
_MAX_CHECKS = 50


class IdentityCheck:
    def __init__(self, kind: str, target: str,
                 candidates: List[Dict[str, Any]],
                 description: str = "") -> None:
        self.id = uuid.uuid4().hex[:8]
        self.kind = kind            # "start" | "ambiguous"
        self.target = target
        self.candidates = candidates  # [{handle, platform, avatar_url,
                                      #   bio, followers, following, link,
                                      #   tier, score, evidence}]
        self.description = description
        self.created_at = time.time()
        self.answer: Optional[str] = None
        self.answered_at: Optional[float] = None
        self._event = threading.Event()

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "target": self.target,
                "candidates": self.candidates,
                "description": self.description,
                "created_at": self.created_at,
                "answer": self.answer, "answered_at": self.answered_at}

    def decide(self, answer: str) -> bool:
        answer = (answer or "").strip()
        if not answer:
            return False
        self.answer = answer
        self.answered_at = time.time()
        self._event.set()
        return True


class IdentityChecks:
    """Process-wide pending-check queue (one per operator session)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._checks: Dict[str, IdentityCheck] = {}

    def create(self, kind: str, target: str,
               candidates: List[Dict[str, Any]],
               description: str = "") -> IdentityCheck:
        with self._lock:
            check = IdentityCheck(kind, target, candidates, description)
            self._checks[check.id] = check
            while len(self._checks) > _MAX_CHECKS:
                oldest = min(self._checks.values(),
                             key=lambda c: c.created_at)
                del self._checks[oldest.id]
            return check

    def pending(self) -> List[Dict[str, Any]]:
        now = time.time()
        with self._lock:
            out = []
            for check in list(self._checks.values()):
                if check.answer is not None:
                    continue
                if now - check.created_at > TTL:
                    continue
                out.append(check.to_dict())
            return out

    def answer(self, check_id: str, decision: str) -> bool:
        with self._lock:
            check = self._checks.get(check_id)
        if check is None:
            return False
        return check.decide(decision)

    def ask(self, description: str, candidates: List[Dict[str, Any]],
            target: str = "", timeout: float = DEFAULT_TIMEOUT,
            kind: str = "ambiguous") -> str:
        """ask-hook signature for the recon engine: register a pending
        check, wait up to timeout for the operator, fall back to "".
        "" means safe default downstream (widen once, halt, no contact).
        """
        check = self.create(kind, target, candidates, description)
        check._event.wait(timeout=max(0.0, float(timeout or 0.0)))
        return check.answer or ""


_checks = IdentityChecks()


def get_checks() -> IdentityChecks:
    """Process-wide singleton (API server + CLI share it in-process)."""
    return _checks


def make_ask(target: str = "", timeout: float = DEFAULT_TIMEOUT,
             checks: Optional[IdentityChecks] = None):
    """Build an ask hook bound to a manager (default: the singleton)."""
    mgr = checks if checks is not None else _checks

    def _ask(description: str, candidates) -> str:
        serial = []
        for c in candidates or []:
            if isinstance(c, (list, tuple)) and len(c) >= 3:
                handle, platform, result = c[0], c[1], c[2]
                serial.append({
                    "handle": str(handle), "platform": str(platform),
                    "avatar_url": getattr(result, "avatar_url", ""),
                    "bio": getattr(result, "bio", ""),
                    "followers": getattr(result, "followers", ""),
                    "following": getattr(result, "following", ""),
                    "link": f"https://{platform}.com/{handle}"
                    if platform and str(platform) not in ("", "unknown")
                    else "",
                })
            elif isinstance(c, dict):
                serial.append(c)
        return mgr.ask(description, serial, target=target, timeout=timeout)

    return _ask
