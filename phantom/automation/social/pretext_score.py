"""pretext_score.py — would a human click this, or report it?

Deliverability answers "will the filter drop it". This answers the other
half: "will the RECIPIENT believe it". A message can pass SPF/DKIM and still
be obviously fake — generic greeting, urgency, a link that does not match
the story, a request for a code. Those are the tells that get a campaign
reported on the first message, and they are checkable BEFORE sending.

The scorer is a pure function: no I/O, no model, no template mutation. It
returns a 0-100 value, a letter grade, and the exact issues with the fix,
so an operator can iterate on a pretext instead of guessing why it failed.

Calibration is deliberately conservative: a critical tell (asking for a
password/OTP, a brand/sender mismatch) blocks the send regardless of how
polished the rest is. Everything else accumulates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit

_SEV = ("critical", "high", "medium", "low")
_PENALTY = {"critical": 35, "high": 18, "medium": 8, "low": 3}

_CREDENTIAL = (
    "password", "passcode", "one-time code", "one time code", "otp",
    "verification code", "security code", "codice di verifica",
    "password dimenticata", "conferma la tua identità", "verify your identity",
    "confirm your identity", "inserisci la password", "enter your password",
)
_URGENCY = (
    "urgent", "immediately", "right away", "within 24 hours", "last warning",
    "final notice", "account will be closed", "account will be suspended",
    "act now", "expires today", "subito", "urgente", "entro 24 ore",
    "ultimo avviso", "account verrà chiuso", "account sospeso",
)
_GENERIC = (
    "dear customer", "dear user", "dear sir/madam", "valued customer",
    "gentile cliente", "caro utente", "gentile utente", "spettabile cliente",
)
_TOO_GOOD = (
    "you have won", "congratulations, you", "claim your prize", "refund of",
    "inheritance", "unclaimed funds", "hai vinto", "premio", "rimborso",
    "eredità", "fondi non reclamati",
)
_VAGUE_CTA = (
    "click here", "clicca qui", "follow this link", "segui questo link",
    "login to continue", "accedi per continuare",
)
_CAPS = re.compile(r"\b[A-Z]{4,}\b")
_URL = re.compile(r"https?://([^\s/]+)", re.IGNORECASE)
# A host mentioned WITHOUT a scheme ("accedi da banca.example") is exactly
# what a mismatched link hides behind, so it has to be seen too. Limited to
# common TLDs to avoid flagging "dott.rossi".
_BARE_HOST = re.compile(
    r"\b((?:[a-z0-9-]+\.)+(?:com|net|org|it|io|ai|app|dev|co|uk|de|fr|es|"
    r"nl|ru|cn|info|biz|example|local|cloud|site|online))\b",
    re.IGNORECASE)


@dataclass
class Issue:
    severity: str
    code: str
    detail: str
    fix: str = ""

    def line(self) -> str:
        return f"[{self.severity}] {self.code}: {self.detail}"


@dataclass
class PretextScore:
    value: int = 100
    issues: List[Issue] = field(default_factory=list)

    @property
    def grade(self) -> str:
        v = self.value
        if v >= 90:
            return "A"
        if v >= 75:
            return "B"
        if v >= 60:
            return "C"
        if v >= 40:
            return "D"
        return "F"

    @property
    def blocking(self) -> bool:
        return any(i.severity == "critical" for i in self.issues)

    @property
    def ready(self) -> bool:
        """A send is defensible only when nothing critical fires and the
        message reads at least 'C'."""
        return not self.blocking and self.value >= 60

    def codes(self, severity: Optional[str] = None) -> List[str]:
        return [i.code for i in self.issues
                if severity is None or i.severity == severity]

    def top_fix(self) -> str:
        for sev in _SEV:
            for i in self.issues:
                if i.severity == sev and i.fix:
                    return f"{i.code}: {i.fix}"
        return ""

    def marker(self) -> str:
        return (f"PRETEXT_SCORE: score={self.value} grade={self.grade} "
                f"ready={int(self.ready)} "
                f"issues={','.join(self.codes()) or 'none'}")

    def report(self) -> List[str]:
        out = [self.marker()]
        for i in sorted(self.issues, key=lambda x: _SEV.index(x.severity)):
            out.append("  " + i.line() + (f" -> {i.fix}" if i.fix else ""))
        return out


def _host(url: str) -> str:
    try:
        return (urlsplit(url or "").hostname or "").lower()
    except Exception:
        return ""


def _domain_of(address: str) -> str:
    m = re.search(r"<([^>]+)>", address or "")
    addr = (m.group(1) if m else (address or "")).strip()
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def _brand_token(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(text or "").lower())


def score_pretext(subject: str, body: str, *, channel: str = "email",
                  brand: str = "", target_name: str = "", link: str = "",
                  sender: str = "") -> PretextScore:
    """Score one rendered message for HUMAN plausibility. Pure function."""
    rep = PretextScore()
    issues = rep.issues
    text = str(body or "")
    low = " ".join(text.lower().split())
    subject = str(subject or "")
    channel = str(channel or "email").lower()

    def add(severity: str, code: str, detail: str, fix: str = "") -> None:
        issues.append(Issue(severity, code, detail, fix))

    if any(p in low for p in _CREDENTIAL):
        add("critical", "credential_request",
            "asks for a password/OTP/identity confirmation — the single "
            "most-reported pattern; no legitimate flow asks in a message",
            "send the target to the real service and ask for nothing")
    if any(p in low for p in _GENERIC):
        add("high", "generic_greeting",
            "generic greeting — a stranger addressing a person by role is a "
            "tell",
            "use the name the platform shows, or no salutation at all")
    urgency_hits = [p for p in _URGENCY if p in low]
    if urgency_hits:
        add("high" if len(urgency_hits) > 1 else "medium", "urgency",
            f"manufactured urgency: {', '.join(urgency_hits[:3])}",
            "state the consequence once, calmly, or drop it")
    if any(p in low for p in _TOO_GOOD):
        add("high", "too_good_to_be_true",
            "prize/refund/inheritance framing — the classic bait pattern",
            "use a pretext with a plausible, boring reason")
    if any(p in low for p in _VAGUE_CTA):
        add("medium", "vague_cta",
            "'click here' as the action — no reason given for the click",
            "name the thing the link opens")
    if "kindly" in low:
        add("medium", "kindly",
            "'kindly' is over-represented in scam corpora",
            "drop it")

    # personalisation: only judged when the caller knows the name
    if target_name:
        first = str(target_name).split()[0].lower()
        if first and first not in low and first not in subject.lower():
            add("medium", "no_personalisation",
                f"the message never uses the target's name ({first})",
                "open with the name the profile shows")

    # brand vs actual sender/link
    brand_token = _brand_token(brand)
    sender_dom = _domain_of(sender)
    link_host = _host(link)
    if brand_token and sender_dom and brand_token not in \
            sender_dom.replace(".", ""):
        add("high", "brand_sender_mismatch",
            f"claims to be {brand} but sends from {sender_dom}",
            "send from a domain whose name matches the story")
    if link and link_host and brand_token and brand_token not in \
            link_host.replace(".", ""):
        add("high", "brand_link_mismatch",
            f"claims to be {brand} but the link goes to {link_host}",
            "serve the lure from the brand-consistent domain")
    mentioned = {h.lower() for h in _URL.findall(text)}
    mentioned |= {m.group(1).lower() for m in _BARE_HOST.finditer(text)}
    mentioned = {h for h in mentioned if h and h != link_host
                 and not link_host.endswith("." + h)
                 and not h.endswith("." + link_host)}
    if link_host and mentioned:
        add("high", "link_host_mismatch",
            f"body mentions {', '.join(sorted(mentioned))} but the link is "
            f"{link_host}", "show the same host you link to")
    if link and not link.startswith("https://"):
        add("medium", "insecure_link", "the link is not HTTPS",
            "TLS on every hop: an http link is an instant warning")

    if len(_CAPS.findall(text)) >= 2:
        add("medium", "shouting",
            "multiple ALL-CAPS words", "normal sentence case")
    if text.count("!") >= 3:
        add("low", "exclamations", "three or more exclamation marks",
            "one at most")
    if len(" ".join(text.split())) < 40:
        add("medium", "too_short",
            "the message is a one-liner with no context",
            "give a reason a stranger would actually have to write")
    if channel in ("dm", "telegram", "discord", "instagram",
                   "whatsapp") and len(text) > 1200:
        add("medium", "dm_too_long",
            "a DM this long reads like an email pasted into a chat",
            "cut it to two or three sentences")
    if channel == "email":
        if not subject.strip():
            add("high", "no_subject", "email with no subject",
                "write the subject a human would write")
        if "dear" in low and "unsubscribe" in low:
            add("low", "bulk_language",
                "consumer email reads like a newsletter",
                "write it as a person, not a mailing list")

    rep.value = max(0, min(100, 100 - sum(_PENALTY[i.severity]
                                          for i in issues)))
    return rep
