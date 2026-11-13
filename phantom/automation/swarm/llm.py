"""LLM on-demand with operator approval (Fase 6).

The rule the operator set: the LLM may run from the start IF the
operator wants it, or mid-session IF the orchestrator decides it is
needed — but ONLY with operator approval, flippable live (Electron
checkbox / API) or pre-approved (CLI --llm).

Why mid-run is better than from-zero: an advisor consulted AFTER the
deterministic engines ran reasons over committed facts (services,
failures, stalls) instead of hallucinating a plan from a bare target.

Safety contract (unchanged from the advisor itself):

* default DENIED — no approval, no transport, no exception;
* consult output is validated capability ids (whitelist + registry),
  surfaced as suggestions/hypotheses — NEVER committed as facts and
  never executed directly;
* approval "once" is consumed by a single consult.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

DENIED = "denied"
ONCE = "once"
SESSION = "session"

_MAX_PENDING = 20


class LLMApproval:
    """Thread-safe operator approval gate for LLM use in one operation."""

    def __init__(self, state: str = DENIED) -> None:
        self._lock = threading.Lock()
        self._state = state if state in (DENIED, ONCE, SESSION) else DENIED
        self._pending: List[Dict[str, Any]] = []
        self._seq = 0

    # ------------------------------------------------------------ control

    def approve_once(self) -> str:
        with self._lock:
            self._state = ONCE
            return self._state

    def approve_session(self) -> str:
        with self._lock:
            self._state = SESSION
            return self._state

    def deny(self) -> str:
        with self._lock:
            self._state = DENIED
            return self._state

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def allows(self) -> bool:
        with self._lock:
            return self._state in (ONCE, SESSION)

    def consume(self) -> bool:
        """Approve one consult: SESSION stays, ONCE degrades to DENIED."""
        with self._lock:
            if self._state == SESSION:
                return True
            if self._state == ONCE:
                self._state = DENIED
                return True
            return False

    # ------------------------------------------------------------ requests

    def request(self, reason: str, context: str = "") -> int:
        """The orchestrator asks: record a pending request for the
        operator (Electron checkbox / API). Returns the request id."""
        with self._lock:
            self._seq += 1
            self._pending.append({
                "id": self._seq, "reason": reason[:200],
                "context": context[:300],
                "time": time.strftime("%H:%M:%S"),
                "state_at_request": self._state,
            })
            del self._pending[:-_MAX_PENDING]
            return self._seq

    def pending_requests(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(p) for p in self._pending]


def consult(task, wm, approval: Optional["LLMApproval"],
            advisor_factory: Optional[Callable[[], Any]] = None,
            registry=None) -> Tuple[List[str], str]:
    """One approved consult: validated capability ids, or ([], reason).

    Reasons: "denied" (no approval — transport never touched),
    "unavailable" (approved but no model reachable), "consulted".
    Never raises.
    """
    if approval is None or not approval.allows():
        return [], "denied"
    try:
        if advisor_factory is not None:
            advisor = advisor_factory()
        else:
            from phantom.automation.llm_advisor import LLMAdvisor
            advisor = LLMAdvisor(enabled=True)
        if not advisor.available():
            return [], "unavailable"
        suggestions = advisor.suggest(wm, registry) or []
    except Exception:
        return [], "unavailable"
    # consume the one-shot only after a real consult (an unreachable
    # model must not burn the operator's approval)
    try:
        approval.consume()
    except Exception:
        pass
    return [str(s) for s in suggestions], "consulted"
