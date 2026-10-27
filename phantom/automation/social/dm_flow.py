"""dm_flow.py — a DM conversation, not a spray.

The DM path already renders plausible openers and can mask a link. What it
lacked is the thing that makes social engineering work: SEQUENCE. A link in
the first message from a stranger is the single most-reported pattern; a
short rapport, a pretext that fits the thread, and only then a link is the
same operator behaviour a human would use.

This module is the deterministic policy for that sequence:

    opener ──engaged──> rapport ──2 exchanges──> pretext ──> link
       │                    │                        │
       └──suspicious────────┴──hostile──> closed    └──request──> handoff

Rules, all testable offline:

* **No link before the minimum number of exchanges** (default 2).
* **Suspicion accumulates**; past the limit the flow stops rather than
  pushing (a burned channel is worse than an unused one).
* **A direct request** ("who are you", "prove it", "send it here") is handed
  to the operator: a script that improvises authority gets caught.
* **Pacing is per platform** and is advice to the caller, not a sleep here,
  so the module stays pure and the runtime keeps the scheduling.

Nothing here sends anything: it returns a Decision the engine executes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

OPENER = "opener"
RAPPORT = "rapport"
PRETEXT = "pretext"
LINK = "link"
WAIT = "waiting"
CLOSED = "closed"
HANDOFF = "handoff"

STATES = (OPENER, RAPPORT, PRETEXT, LINK, WAIT, CLOSED, HANDOFF)

ENGAGED = "engaged"
NEUTRAL = "neutral"
REQUEST = "request"
SUSPICIOUS = "suspicious"
HOSTILE = "hostile"
REPLY_KINDS = (ENGAGED, NEUTRAL, REQUEST, SUSPICIOUS, HOSTILE)

# Seconds a human would plausibly leave between messages. The caller sleeps;
# this module only says how long.
PACING: Dict[str, int] = {
    "telegram": 90,
    "discord": 120,
    "instagram": 240,
    "whatsapp": 180,
    "default": 150,
}

_SUSPICION_LIMIT = 0.6
_SUSPICION_STEP = 0.4
_MIN_EXCHANGES_FOR_LINK = 2

_HOSTILE = (
    "fuck off", "scam", "spam", "report you", "blocked", "creep",
    "leave me alone", "not interested", "stop messaging", "vaffanculo",
    "truffa", "segnalo", "bloccato",
)
_REQUEST = (
    "who are you", "who is this", "do i know you", "prove", "send it here",
    "what do you want", "chi sei", "chi è", "come mi conosci",
    "mandalo qui", "dimostra",
)
_SUSPICIOUS = (
    "how did you get", "how did you find", "where did you find",
    "suspicious", "strange",
    "why me", "come mi hai trovato", "strano", "sospetto",
)
_ENGAGED = (
    "thanks", "thank you", "sure", "ok", "okay", "yes", "please",
    "interessante", "interessato", "certo", "va bene", "grazie", "sì",
    "dimmi", "tell me", "go on", "continue",
)


@dataclass
class Flow:
    target: str = ""
    platform: str = "default"
    state: str = OPENER
    exchanges: int = 0
    suspicion: float = 0.0
    link_sent: bool = False
    history: List[Tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {"target": self.target, "platform": self.platform,
                "state": self.state, "exchanges": self.exchanges,
                "suspicion": round(self.suspicion, 2),
                "link_sent": self.link_sent,
                "history": list(self.history)}


@dataclass
class Decision:
    action: str            # send | wait | stop | handoff
    stage: str             # opener | rapport | pretext | link
    state: str             # the flow's NEXT state
    reason: str = ""
    delay_s: int = 0
    link_allowed: bool = False

    def marker(self, handle: str = "") -> str:
        who = f" handle={handle}" if handle else ""
        return (f"DM_DECISION:{who} action={self.action} stage={self.stage} "
                f"state={self.state} link_allowed={int(self.link_allowed)} "
                f"delay_s={self.delay_s} reason={_slug(self.reason)}")


def _slug(text: str) -> str:
    """Marker-safe reason: one token, no spaces (the parser splits on them)."""
    return "_".join(str(text or "").split())[:160]


def classify_reply(text: str) -> str:
    """Map one reply to a coarse kind. Deliberately simple and inspectable.

    Hostile first (a threat of reporting ends the thread), then a direct
    request (authority is the operator's to establish), then suspicion,
    then engagement. Anything else is neutral: silence is not consent.
    """
    low = " ".join(str(text or "").lower().split())
    if not low:
        return NEUTRAL
    if any(p in low for p in _HOSTILE):
        return HOSTILE
    if any(p in low for p in _REQUEST):
        return REQUEST
    if any(p in low for p in _SUSPICIOUS) or low.endswith("?"):
        return SUSPICIOUS
    if any(p in low for p in _ENGAGED) or re.search(r"\b(ok|yes|sure)\b", low):
        return ENGAGED
    return NEUTRAL


def delay_for(platform: str) -> int:
    return int(PACING.get(str(platform or "default").lower(),
                          PACING["default"]))


def advance(flow: Flow, reply: Optional[str] = None,
            *, min_exchanges_for_link: int = _MIN_EXCHANGES_FOR_LINK,
            suspicion_limit: float = _SUSPICION_LIMIT) -> Decision:
    """One step of the conversation. Mutates the flow, sends nothing."""
    kind = classify_reply(reply) if reply is not None else NEUTRAL
    if reply is not None:
        flow.history.append((reply, kind))
        flow.exchanges += 1
    base_delay = delay_for(flow.platform)

    if flow.state == CLOSED:
        return Decision("stop", "none", CLOSED, "conversation already closed")
    if kind == HOSTILE:
        flow.state = CLOSED
        return Decision("stop", "none", CLOSED,
                        "target was hostile — do not push a burned channel")
    if kind == REQUEST:
        flow.state = HANDOFF
        return Decision("handoff", "none", HANDOFF,
                        "target asked who you are / for proof: the operator "
                        "takes over, a script must not improvise authority")
    if kind == SUSPICIOUS:
        flow.suspicion = min(1.0, flow.suspicion + _SUSPICION_STEP)
        if flow.suspicion >= suspicion_limit:
            flow.state = CLOSED
            return Decision("stop", "none", CLOSED,
                            "suspicion above the limit — stop instead of "
                            "trying harder")
        return Decision("wait", flow.state, flow.state,
                        "target is suspicious: do not advance or link now",
                        delay_s=base_delay * 2)

    if kind == ENGAGED and flow.state == OPENER:
        flow.state = RAPPORT
        return Decision("send", "rapport", RAPPORT,
                        "first reply engaged — build rapport before any ask",
                        delay_s=base_delay)
    if kind == ENGAGED and flow.state == RAPPORT:
        if flow.exchanges >= min_exchanges_for_link:
            flow.state = PRETEXT
            return Decision("send", "pretext", PRETEXT,
                            "enough exchanges — deliver the pretext, still no "
                            "link", delay_s=base_delay)
        return Decision("send", "rapport", RAPPORT,
                        "keep the rapport going to the minimum exchange "
                        "count", delay_s=base_delay)
    if kind == ENGAGED and flow.state == PRETEXT and not flow.link_sent:
        flow.state = LINK
        flow.link_sent = True
        return Decision("send", "link", LINK,
                        "pretext accepted and rapport established — the link "
                        "is now defensible", delay_s=base_delay,
                        link_allowed=True)
    if kind == ENGAGED and flow.state == LINK:
        flow.state = WAIT
        return Decision("wait", "link", WAIT,
                        "link delivered: wait for the action, do not nag",
                        delay_s=base_delay)
    if kind == NEUTRAL:
        if flow.state == OPENER:
            return Decision("wait", OPENER, OPENER,
                            "no engagement yet: wait, do not double-text")
        return Decision("wait", flow.state, flow.state,
                        "reply carried no signal: stay, do not escalate",
                        delay_s=base_delay)
    # engaged in an unexpected state: hold
    return Decision("wait", flow.state, flow.state,
                    f"no transition from {flow.state} for {kind}",
                    delay_s=base_delay)


def opening_decision(flow: Flow) -> Decision:
    """The first message of a cold thread: opener, no link, paced."""
    flow.state = OPENER
    return Decision("send", "opener", OPENER,
                    "cold opener: no link, no ask, no urgency",
                    delay_s=delay_for(flow.platform), link_allowed=False)
