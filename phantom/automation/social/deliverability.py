"""deliverability.py — pre-send anti-blocking preflight for the email hop.

The email hop is the one stage that fails **silently**: a message that lands
in Spam, or is dropped by the gateway, looks exactly like "nobody clicked".
When the whole engagement hangs on one email, that email is scored before it
is relayed — the same way an operator does not fire an exploit without a
preflight.

The checks are the vectors that actually get mail blocked at Gmail and
Microsoft 365 (the two filters that matter), grouped by what the filter sees:

    IDENTITY   From-domain vs the service named in the display name; a
               free-mail box whose real address the recipient will read;
               mixed-script (Cyrillic homoglyph) subjects/display names —
               modern filters score those heavily;
    DOMAIN     link host vs sender domain, bare IP, loopback, one-shot
               tunnel / edge host, dynamic DNS, public shortener. Link
               reputation is scored separately from content, and a
               sender/link domain mismatch is an immediate tell;
    CONTENT    hidden images (``display:none`` — classic spam marker, and
               Gmail strips them, silently killing open tracking),
               image-only mail, poor text-to-image ratio, spam phrases,
               shouty subjects;
    CHANNEL    HTML with no plaintext alternative, bulk mail with no
               unsubscribe line, free-mail volume caps.

Nothing here substitutes for SPF/DKIM/DMARC: a domain with correct
authentication is the single highest-value fix, and this module says so
rather than pretending a template tweak is enough.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit

_SEV = ("critical", "high", "medium", "low")

# hosts that are, by construction, one-shot / obviously operator infra
_EPHEMERAL_HOST_SUFFIXES = (
    "trycloudflare.com", "ngrok.io", "ngrok-free.app", "ngrok.app",
    "lhr.life", "localhost.run", "serveo.net", "localtunnel.me",
    "workers.dev", "pages.dev", "vercel.app", "netlify.app",
    "duckdns.org", "no-ip.org", "noip.com", "ddns.net", "zapto.org",
    "hopto.org", "myftp.org", "serveftp.com", "bore.pub", "pinggy.io",
)

# public shorteners: Safe Browsing expands them, the preview card is lost,
# and the hop carries someone else's reputation instead of yours
_SHORTENER_HOSTS = (
    "is.gd", "v.gd", "tinyurl.com", "bit.ly", "rb.gy", "t.co", "ow.ly",
    "cutt.ly", "shorturl.at", "rebrand.ly", "short.io", "urlz.fr",
    "surl.li", "clck.ru", "u.to", "tiny.cc",
)

_FREE_MAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "proton.me", "protonmail.com", "icloud.com", "aol.com",
    "msn.com", "yandex.com", "mail.com", "gmx.com", "gmx.de", "web.de",
    "zoho.com", "libero.it", "virgilio.it", "tiscali.it",
}

_SPAM_PHRASES = (
    "verify your account", "click here", "act now", "urgent action",
    "your account will be closed", "your account will be suspended",
    "confirm your identity", "click the link below", "limited time",
    "final notice", "wire transfer", "gift card", "password expired",
    "unusual sign-in", "unusual activity", "dear customer", "dear user",
    "kindly", "bank account", "social security", "tax refund",
    "invoice attached", "you have won", "100% free",
)

_CYRILLIC = re.compile(r"[\u0400-\u04FF]")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass
class Issue:
    """One thing the filter will not like, with the fix that removes it."""
    severity: str          # critical | high | medium | low
    code: str
    detail: str
    fix: str = ""

    def line(self) -> str:
        return f"[{self.severity}] {self.code}: {self.detail}"


@dataclass
class DeliverabilityReport:
    score: int = 100
    issues: List[Issue] = field(default_factory=list)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90:
            return "A"
        if s >= 75:
            return "B"
        if s >= 60:
            return "C"
        if s >= 40:
            return "D"
        return "F"

    @property
    def blocking(self) -> bool:
        """A critical issue means the message is likely DROPPED, not merely
        filtered — there is no 'it still might work'."""
        return any(i.severity == "critical" for i in self.issues)

    def codes(self, severity: Optional[str] = None) -> List[str]:
        return [i.code for i in self.issues
                if severity is None or i.severity == severity]

    def top_fix(self) -> str:
        """The single most valuable change, worst severity first."""
        for sev in _SEV:
            for i in self.issues:
                if i.severity == sev and i.fix:
                    return f"{i.code}: {i.fix}"
        return ""

    def marker(self) -> str:
        return (f"DELIVERABILITY: score={self.score} grade={self.grade} "
                f"issues={','.join(self.codes()) or 'none'}")

    def report(self) -> List[str]:
        out = [self.marker()]
        for i in sorted(self.issues, key=lambda x: _SEV.index(x.severity)):
            out.append(f"  {i.line()}" + (f" -> {i.fix}" if i.fix else ""))
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


def _display_name(address: str) -> str:
    m = re.match(r"\s*([^<]+)<", address or "")
    return m.group(1).strip().strip('"') if m else ""


def deliverability_report(subject: str, body_text: str, html: str,
                          link: str, sender: str = "",
                          tracking_pixel: str = "",
                          is_bulk: bool = False) -> DeliverabilityReport:
    """Score one outgoing message and return the report.

    Pure function: no I/O, no config, no message mutation — it can be called
    on a rendered message before relay, or offline on a template.
    """
    rep = DeliverabilityReport()
    issues: List[Issue] = rep.issues

    def add(severity: str, code: str, detail: str, fix: str = "") -> None:
        issues.append(Issue(severity, code, detail, fix))

    link_host = _host(link)
    sender_dom = _domain_of(sender)
    display = _display_name(sender)
    html = html or ""
    body_text = body_text or ""

    # ── identity ────────────────────────────────────────────────────────
    if not sender_dom:
        add("critical", "no_sender", "no sender domain in the From header",
            "set transports.phish_from to a domain with SPF/DKIM")
    elif sender_dom in _FREE_MAIL:
        add("medium", "free_mail_sender",
            f"sending from a free-mail box ({sender_dom}) — the real address "
            f"is what the recipient reads, and daily volume is capped",
            "use a domain you control with SPF/DKIM/DMARC")
    if _CYRILLIC.search(subject or "") or (display and _CYRILLIC.search(display)):
        add("high", "mixed_script",
            "Cyrillic homoglyphs in the subject/display name — modern "
            "filters score mixed-script strings heavily",
            "drop the homoglyphs: a word-order change is human-visible and "
            "filter-neutral")

    # ── domain / link ───────────────────────────────────────────────────
    if link_host:
        if link_host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            add("critical", "loopback_link",
                f"link points at {link_host} — nobody outside this host can "
                f"open it",
                "set tracker.public_url to the public hostname")
        elif _IPV4.match(link_host):
            add("critical", "ip_link",
                f"link points at a bare IP ({link_host})",
                "put a domain in front of the tracker")
        else:
            if any(link_host == s or link_host.endswith("." + s)
                   for s in _EPHEMERAL_HOST_SUFFIXES):
                add("high", "ephemeral_host",
                    f"link host {link_host} is a one-shot tunnel / edge host",
                    "a real domain is required for reputation")
            if any(link_host == s or link_host.endswith("." + s)
                   for s in _SHORTENER_HOSTS):
                add("medium", "shortener",
                    f"link host is a public shortener ({link_host}) — the hop "
                    f"carries someone else's reputation and the preview card "
                    f"is lost",
                    "park the redirect on a domain you control")
            if sender_dom and link_host != sender_dom \
                    and not link_host.endswith("." + sender_dom):
                add("high", "link_domain_mismatch",
                    f"link host ({link_host}) does not match the sender "
                    f"domain ({sender_dom})",
                    "serve the lure from the same domain that sends the mail")
    if link and not link.startswith("https://"):
        add("high", "insecure_link", "the link is not HTTPS",
            "TLS on the tracker: Gmail warns on plain-http links")

    # ── content ─────────────────────────────────────────────────────────
    low = html.lower()
    if "display:none" in low or "display: none" in low:
        add("high", "hidden_pixel",
            "hidden image (display:none) — a classic spam marker that Gmail "
            "strips, which also silently kills open tracking",
            "emit the pixel as a normal inline 1x1 image instead")
    imgs = low.count("<img")
    text_len = len(re.sub(r"\s+", " ", body_text).strip())
    if imgs and text_len < 50:
        add("critical", "image_only",
            f"image-only message ({imgs} image(s), {text_len} chars of text)",
            "write real body text: image-only mail is almost always filtered")
    elif imgs >= 2 and text_len < 200:
        add("high", "low_text_ratio",
            f"{imgs} images against {text_len} chars of text",
            "keep a healthy text-to-image ratio")

    blob = f"{subject or ''} {body_text}".lower()
    hits = [p for p in _SPAM_PHRASES if p in blob]
    if hits:
        add("high" if len(hits) >= 2 else "medium", "spam_phrases",
            f"spam-trigger phrases: {', '.join(hits[:5])}",
            "rewrite the sentence, keep the meaning")

    subject = subject or ""
    if not subject.strip():
        add("high", "no_subject", "empty subject",
            "a real message always has one")
    else:
        letters = [c for c in subject if c.isalpha()]
        if letters and sum(c.isupper() for c in letters) / len(letters) > 0.6:
            add("medium", "shouty_subject",
                "the subject is mostly capitalised", "use normal sentence case")
        if len(subject) > 78:
            add("low", "long_subject",
                f"subject is {len(subject)} chars (clients truncate ~78)",
                "shorten it")
        if subject.count("!") >= 2:
            add("low", "exclamation",
                "multiple exclamation marks in the subject", "one at most")

    if html and not body_text.strip():
        add("medium", "no_plaintext", "HTML with no plaintext alternative",
            "always send a text/plain part")
    if is_bulk and "unsubscribe" not in low:
        add("medium", "no_unsubscribe", "bulk mail with no unsubscribe line",
            "add a List-Unsubscribe footer (RFC 8058)")

    # ── score ───────────────────────────────────────────────────────────
    penalty = {"critical": 45, "high": 18, "medium": 8, "low": 3}
    rep.score = max(0, min(100, 100 - sum(penalty[i.severity] for i in issues)))
    return rep
