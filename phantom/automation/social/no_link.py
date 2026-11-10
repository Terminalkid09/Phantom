"""no_link.py — lures that do not ask the target to click a suspicious URL.

The link is the weakest part of a campaign: a domain that does not match the
story, a shortener, a preview card from a stranger. Three mechanisms move
the ask somewhere a filter and a careful human do not look:

  * DEVICE CODE / OAuth consent: the target opens the provider's REAL page
    (a domain they already trust), types a short code, and approves an app.
    What comes back is a token for the scopes the app asked for. This module
    produces the PLAN and the exact steps — it never registers an app, never
    requests a code, and never polls a token endpoint.
  * CALENDAR INVITE: an .ics attachment is opened by the calendar app, not
    the browser; the URL sits in a field the mail filter rarely rewrites and
    the invite arrives from a name the target recognises.
  * QR CODE: the destination is not visible as text at all. The module only
    builds the payload and an image URL/command; nothing is generated over
    the network.

Every helper is pure and consent-aware: the returned dict says what the
mechanism captures, what it needs, and where the operator's authorization
must exist. `choose_channel` is the DM-first decision, with a marker and an
explicit-email override that never reroutes silently.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, Optional, Sequence
from urllib.parse import quote

# ── device code / OAuth consent ─────────────────────────────────────────────

DEVICE_PROVIDERS: Dict[str, Dict[str, str]] = {
    "microsoft": {
        "device_login": "https://microsoft.com/devicelogin",
        "app_hint": "an Entra ID app registration in a tenant you control",
        "scopes_hint": "offline_access openid profile plus the mail/files "
                       "scopes the app is consented for",
    },
    "google": {
        "device_login": "https://www.google.com/device",
        "app_hint": "an OAuth client of type 'TV and Limited Input'",
        "scopes_hint": "openid email profile plus the scopes the app requests",
    },
    "github": {
        "device_login": "https://github.com/login/device",
        "app_hint": "a GitHub OAuth App with device flow enabled",
        "scopes_hint": "repo read:user (only what the app is granted)",
    },
}

_DEVICE_LIMITS = (
    "requires an app registered by the operator (real client id)",
    "the target must open the real provider page and type the code",
    "conditional access / passkeys / admin consent can block the grant",
    "the token only reaches the scopes the app was consented for",
)


def device_code_plan(provider: str = "microsoft", *, app_name: str = "",
                     scopes: Sequence[str] = (), tenant: str = "",
                     pretext: str = "") -> Dict[str, object]:
    """The device-code lure as a plan. No request, no code, no polling."""
    key = (provider or "microsoft").strip().lower()
    spec = DEVICE_PROVIDERS.get(key)
    if spec is None:
        return {"error": f"unknown provider {provider!r}",
                "valid": sorted(DEVICE_PROVIDERS)}
    steps = [
        f"Register the app: {spec['app_hint']}.",
        "Enable the device authorization grant for that app.",
        f"Ask the target to open {spec['device_login']} "
        f"(a real provider domain) and enter the code your app shows.",
        "The target signs in and approves the app's request.",
        "The app receives tokens for the consented scopes.",
    ]
    return {
        "kind": "device_code",
        "provider": key,
        "device_login_url": spec["device_login"],
        "app_name": app_name or "an app name that matches the pretext",
        "tenant": tenant,
        "scopes": list(scopes) or [spec["scopes_hint"]],
        "pretext": pretext or "security check / app access",
        "steps": steps,
        "captures": ("an OAuth access/refresh token for the consented "
                     "scopes (mail, files, profile) — no password, no MFA "
                     "code, and it survives a password change until revoked"),
        "consent": ("needs a registered app, an authorization to test the "
                    "provider, and the target's own approval. Nothing is "
                    "requested by this helper."),
        "limits": list(_DEVICE_LIMITS),
        "network": False,
    }


# ── calendar invite (.ics) ──────────────────────────────────────────────────

def _escape_ics(text: str) -> str:
    return (str(text or "").replace("\\", "\\\\").replace(";", "\\;")
            .replace(",", "\\,").replace("\r\n", "\\n")
            .replace("\n", "\\n"))


def _ics_time(value: str) -> str:
    """Accept `YYYYMMDDTHHMMSSZ`, `YYYY-MM-DD HH:MM` or a date."""
    raw = str(value or "").strip()
    if re.match(r"^\d{8}T\d{6}Z?$", raw):
        return raw
    digits = re.sub(r"[^0-9]", "", raw)
    if len(digits) >= 12:
        clock = digits[8:14].ljust(6, "0")
        return f"{digits[:8]}T{clock}Z"
    if len(digits) == 8:
        return f"{digits}T090000Z"
    return raw


def _fold_ics(line: str, limit: int = 74) -> str:
    """RFC 5545 folds long content lines with CRLF + a leading space."""
    if len(line) <= limit:
        return line
    out = [line[:limit]]
    rest = line[limit:]
    while rest:
        out.append(" " + rest[:limit - 1])
        rest = rest[limit - 1:]
    return "\r\n".join(out)


def calendar_invite(subject: str, start: str, end: str, *,
                    organizer: str = "", attendee: str = "",
                    url: str = "", description: str = "",
                    location: str = "", uid: str = "") -> Dict[str, object]:
    """A valid .ics invite carrying the lure URL. Pure string builder."""
    if not (subject or "").strip():
        return {"error": "calendar invite needs a subject"}
    if not (start or "").strip() or not (end or "").strip():
        return {"error": "calendar invite needs start and end"}
    stamp = hashlib.sha1(
        f"{subject}|{start}|{url}|{attendee}".encode("utf-8"),
        usedforsecurity=False).hexdigest()
    uid_value = uid or f"{stamp}@phantom.invalid"
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Phantom//Calendar Lure//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:REQUEST",
        "BEGIN:VEVENT",
        f"UID:{uid_value}",
        f"DTSTAMP:{_ics_time(start) or '19700101T000000Z'}",
        f"DTSTART:{_ics_time(start)}",
        f"DTEND:{_ics_time(end)}",
        f"SUMMARY:{_escape_ics(subject)}",
    ]
    if description:
        lines.append(f"DESCRIPTION:{_escape_ics(description)}")
    if location:
        lines.append(f"LOCATION:{_escape_ics(location)}")
    if organizer:
        lines.append(f"ORGANIZER:mailto:{_escape_ics(organizer)}")
    if attendee:
        lines.append(f"ATTENDEE;RSVP=TRUE:mailto:{_escape_ics(attendee)}")
    if url:
        lines.append(f"URL:{_escape_ics(url)}")
    lines += ["STATUS:CONFIRMED", "SEQUENCE:0", "END:VEVENT", "END:VCALENDAR"]
    ics = "\r\n".join(_fold_ics(line) for line in lines) + "\r\n"
    return {
        "kind": "calendar_invite",
        "ics": ics,
        "filename": "invite.ics",
        "subject": subject,
        "url": url,
        "captures": ("a calendar-app open of the URL (IP/device), and the "
                     "invite itself reaches the target from the organizer's "
                     "real mail flow"),
        "consent": ("only against a target you are authorized to contact; "
                    "the invite is a real calendar object and will be shown "
                    "as such"),
        "network": False,
    }


# ── QR ──────────────────────────────────────────────────────────────────────

def qr_payload(url: str, *, size: int = 300,
               error_correction: str = "M") -> Dict[str, object]:
    """Build the QR payload and a render URL — no request is made here."""
    target = str(url or "").strip()
    if not target.lower().startswith(("http://", "https://")):
        return {"error": "QR needs an absolute http(s) URL"}
    ecc = (error_correction or "M").upper()
    if ecc not in ("L", "M", "Q", "H"):
        ecc = "M"
    encoded = quote(target, safe="")
    return {
        "kind": "qr",
        "data": target,
        "encoded": encoded,
        "size": int(size),
        "error_correction": ecc,
        "image_url": (f"https://api.qrserver.com/v1/create-qr-code/"
                      f"?size={int(size)}x{int(size)}&ecc={ecc}"
                      f"&data={encoded}"),
        "offline_command": f"qrencode -o qr.png {quote(target)}",
        "captures": ("a scan of the QR (IP/device on the landing page); the "
                     "destination is not readable as text"),
        "consent": ("the public QR renderer sees the destination URL; use "
                    "qrencode locally to keep it off a third party"),
        "network": False,
    }


# ── DM-first decision ───────────────────────────────────────────────────────

@dataclass
class ChannelDecision:
    channel: str
    target: str
    person: bool
    dm_available: bool
    explicit_email: bool
    rerouted: bool
    reason: str

    def marker(self) -> str:
        return (f"CHANNEL: channel={self.channel} person={int(self.person)} "
                f"dm_available={int(self.dm_available)} "
                f"explicit_email={int(self.explicit_email)} "
                f"rerouted={int(self.rerouted)} reason={self.reason}")

    def to_dict(self) -> Dict[str, object]:
        return {"channel": self.channel, "target": self.target,
                "person": self.person, "dm_available": self.dm_available,
                "explicit_email": self.explicit_email,
                "rerouted": self.rerouted, "reason": self.reason,
                "marker": self.marker()}


_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


def looks_like_person(target: str) -> bool:
    """A handle/username is a person; an IP, URL or address is not."""
    text = str(target or "").strip()
    if not text:
        return False
    if text.startswith("@"):
        return True
    if _EMAIL.match(text):
        return False
    if text.lower().startswith(("http://", "https://")):
        return False
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", text):
        return False
    return " " not in text and "/" not in text


def choose_channel(target: str, *, explicit_email: bool = False,
                   dm_transport: bool = False,
                   is_person: Optional[bool] = None) -> ChannelDecision:
    """DM-first for a person WITH a configured transport; never silent.

    An explicit email campaign is never rerouted: the decision says
    `rerouted=False` and the email path stays exactly as the caller asked.
    """
    person = looks_like_person(target) if is_person is None else bool(is_person)
    if explicit_email:
        return ChannelDecision("email", target, person, dm_transport, True,
                               False, "explicit_email")
    if person and dm_transport:
        return ChannelDecision("dm", target, True, True, False, True,
                               "person_with_dm_transport")
    if person:
        return ChannelDecision("email", target, True, False, False, False,
                               "no_dm_transport_configured")
    return ChannelDecision("email", target, False, dm_transport, False, False,
                           "target_is_not_a_person")
