"""
phantom.automation.identity_ops — the identity-field PRIMITIVES (I2).

The reasoning layer (brain/identity.py) DEDUCES; this module EXECUTES the
moves that turn a deduction into a fact, in the operator's order:

    email_candidates   compose candidate addresses (name/handle x OBSERVED
                       domains) — the "crunch" step, identity-aware and
                       bounded, offline, NO target contact
    reset_enum         ask the service's password-reset form to reveal the
                       masked address (the leak the operator uses)
    email_verify       SMTP RCPT + MX + catch-all: does this address exist
    breach_correlate   breach exposure -> widened identity + reused creds

Consent model (operator decision): ACTIVE probes (reset_enum, email_verify)
touch the target's mail/service infrastructure, so they are gated behind a
DEDICATED consent, separate from --aggressive. Without it the primitives
refuse with a precise reason and emit nothing. Passive steps (candidate
generation, breach lookup) run without it.

Every function returns (ok, lines) where lines are the stable marker lines
the shared social interpreter already understands, so the WorldModel wiring
is unchanged. NO network call is made unless the consent gate allows it;
the SMTP verify is bounded (one RCPT per candidate, hard cap) and never
sends DATA.
"""

from __future__ import annotations

import smtplib
import socket
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from phantom.automation.brain.identity import (
    IdentityReasoner, domain_of, local_part, mask_shape, name_parts,
    _handle_variants, KIND_EMAIL_CANDIDATE, KIND_EMAIL_MASKED,
    KIND_EMAIL_VERIFIED, KIND_SERVICE_ACCOUNT, KIND_DOMAIN_CANDIDATE,
    _NOISE_DOMAINS,
)

# hard bound: a single run never issues more RCPT probes than this, so a
# thin field cannot be turned into a mail-bomb against a provider.
MAX_PROBES = 40
SMTP_TIMEOUT = 8.0


# ── consent ────────────────────────────────────────────────────────────────

def active_consent_enabled(wm: Any = None) -> bool:
    """The dedicated identity-active consent.

    Read from the world model stamp (set by the agent from the CLI/env) or,
    failing that, from ``PHANTOM_IDENTITY_ACTIVE``. Default: CLOSED.
    """
    consent = getattr(wm, "identity_consent", None) if wm is not None else None
    if isinstance(consent, dict) and consent.get("active"):
        return True
    import os
    return str(os.getenv("PHANTOM_IDENTITY_ACTIVE", "")).strip().lower() \
        in ("1", "true", "yes", "on")


def contact_consent_enabled(wm: Any = None) -> bool:
    """Contact (phish/DM) consent — always the operator's explicit choice."""
    consent = getattr(wm, "identity_consent", None) if wm is not None else None
    if isinstance(consent, dict) and consent.get("contact"):
        return True
    import os
    return str(os.getenv("PHANTOM_IDENTITY_CONTACT", "")).strip().lower() \
        in ("1", "true", "yes", "on")


def consent_reason(kind: str) -> str:
    return (f"{kind} refused: active identity probes need the dedicated "
            f"consent (--identity-active / PHANTOM_IDENTITY_ACTIVE=1)")


# ── candidate generation (offline) ─────────────────────────────────────────

def email_candidates(wm) -> Tuple[bool, List[str]]:
    """Compose candidate addresses from name/handle x OBSERVED domains.

    Offline and passive: no target contact. Emits ``EMAIL_CANDIDATE:``
    markers (the shared interpreter stores them as non-gating findings).
    """
    reasoner = IdentityReasoner()
    domains = reasoner._known_domains(wm)
    tokens: List[str] = []
    for name in reasoner._known_names(wm):
        parts = name_parts(name)
        tokens.extend(parts)
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            for sep in (".", "_", "-", ""):
                tokens.append(f"{first}{sep}{last}")
            tokens.append(f"{first[0]}{last}")
            tokens.append(f"{first}{last[0]}")
    tokens.extend(reasoner._known_handles(wm))
    # a masked leak narrows the shape further
    for f in wm.find(KIND_EMAIL_MASKED):
        v = f.value if isinstance(f.value, dict) else {}
        shape = mask_shape(str(v.get("masked") or v.get("email") or ""))
        if shape.get("prefix") and shape.get("length"):
            tokens.append(shape["prefix"])
    tokens = [t for t in dict.fromkeys(t for t in tokens if 2 <= len(t) <= 40)]

    lines: List[str] = []
    seen = set()
    count = 0
    for dom in domains:
        for tok in tokens:
            if count >= MAX_PROBES:
                break
            addr = f"{tok}@{dom}"
            if addr in seen:
                continue
            seen.add(addr)
            lines.append(f"EMAIL_CANDIDATE: email={addr} local={tok} domain={dom}")
            count += 1
    if not domains:
        return False, ["EMAIL_CANDIDATE: none (no OBSERVED domain to compose "
                       "against — domain guessing is forbidden)"]
    if not lines:
        return False, ["EMAIL_CANDIDATE: none (no name/handle token to compose)"]
    return True, lines


# ── reset enumeration (active) ─────────────────────────────────────────────

def reset_enum(wm, service_url: str = "", email: str = "") -> Tuple[bool, List[str]]:
    """Ask a service's password-reset form to reveal the masked address.

    ACTIVE and consent-gated. The form's response echoes a mask
    (``m***o@…``); we parse the shape and emit ``EMAIL_MASKED:`` so the
    reasoner can narrow candidates. Bounded: one request, no retries.
    """
    if not active_consent_enabled(wm):
        return False, [consent_reason("reset_enum")]
    if not service_url:
        return False, ["EMAIL_MASKED: none (no reset endpoint configured)"]
    import urllib.parse
    import urllib.request
    data = urllib.parse.urlencode({"email": email or getattr(wm, "target", "")})
    req = urllib.request.Request(
        service_url, data=data.encode(),
        headers={"User-Agent": "Mozilla/5.0", "Content-Type":
                 "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=SMTP_TIMEOUT) as resp:
            body = resp.read(200_000).decode("utf-8", "ignore")
    except Exception as exc:
        return False, [f"EMAIL_MASKED: none (reset request failed: {exc})"]
    import re
    m = re.search(r"([A-Za-z0-9._%+\-*●•]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})", body)
    if not m:
        return False, ["EMAIL_MASKED: none (no masked address in the response)"]
    masked = m.group(1)
    shape = mask_shape(masked)
    if not shape:
        return False, [f"EMAIL_MASKED: none (unmasked echo: {masked[:40]})"]
    return True, [f"EMAIL_MASKED: masked={masked} prefix={shape['prefix']} "
                  f"suffix={shape['suffix']} domain={shape['domain']} "
                  f"length={shape['length']}"]


# ── SMTP verification (active) ─────────────────────────────────────────────

@dataclass
class VerifyResult:
    address: str
    exists: Optional[bool]      # None = inconclusive (greylisted/catch-all)
    reason: str = ""


def _mx_hosts(domain: str) -> List[str]:
    """Resolve MX hosts for a domain (empty when none)."""
    try:
        import dns.resolver  # type: ignore
        ans = dns.resolver.resolve(domain, "MX")
        return sorted((r.exchange.to_text().rstrip(".") for r in ans))
    except Exception:
        return []


def _rcpt_probe(mx: str, address: str, sender: str) -> VerifyResult:
    """One RCPT TO probe: connect, EHLO, MAIL FROM, RCPT TO, QUIT. No DATA."""
    try:
        with smtplib.SMTP(mx, 25, timeout=SMTP_TIMEOUT) as smtp:
            smtp.ehlo("phantom.local")
            smtp.mail(sender)
            code, msg = smtp.rcpt(address)
        exists = 200 <= int(code) < 300
        return VerifyResult(address, exists,
                            f"rcpt {code} {msg.decode('utf-8', 'ignore')[:80]}")
    except (smtplib.SMTPException, socket.error, OSError) as exc:
        return VerifyResult(address, None, f"probe error: {exc}")


def verify_emails(wm, addresses: Sequence[str],
                  sender: str = "verify@example.org") -> Tuple[bool, List[str]]:
    """SMTP RCPT verification of candidate addresses.

    ACTIVE and consent-gated. For each candidate: resolve MX, probe RCPT.
    A CATCH-ALL domain (every address accepted) is reported honestly as
    inconclusive rather than as a hit — that is the difference between a
    verified address and noise. Bounded to ``MAX_PROBES``.
    """
    if not active_consent_enabled(wm):
        return False, [consent_reason("email_verify")]
    addrs = [a.strip() for a in addresses if a and "@" in a][:MAX_PROBES]
    if not addrs:
        return False, ["EMAIL_VERIFIED: none (no candidates to verify)"]
    lines: List[str] = []
    hits = 0
    by_domain: Dict[str, bool] = {}
    for addr in addrs:
        dom = domain_of(addr)
        if not dom or dom in _NOISE_DOMAINS:
            continue
        mxs = _mx_hosts(dom)
        if not mxs:
            lines.append(f"EMAIL_VERIFIED: email={addr} exists=0 "
                         f"reason=no-mx")
            continue
        res = _rcpt_probe(mxs[0], addr, sender)
        if res.exists is None:
            lines.append(f"EMAIL_VERIFIED: email={addr} exists=unknown "
                         f"reason={res.reason.replace(' ', '_')}")
            continue
        # catch-all detection: probe a random address on the same domain
        if dom not in by_domain:
            import uuid
            probe = f"zz-{uuid.uuid4().hex[:12]}@{dom}"
            catch = _rcpt_probe(mxs[0], probe, sender)
            by_domain[dom] = bool(catch.exists)
        if res.exists and by_domain.get(dom):
            lines.append(f"EMAIL_VERIFIED: email={addr} exists=unknown "
                         f"reason=catch-all")
            continue
        lines.append(f"EMAIL_VERIFIED: email={addr} exists={int(res.exists)} "
                     f"reason={res.reason.replace(' ', '_')}")
        if res.exists:
            hits += 1
    if not lines:
        return False, ["EMAIL_VERIFIED: none (no probeable domain)"]
    return hits > 0, lines


# ── breach correlation ─────────────────────────────────────────────────────

def breach_correlate(wm, email: str = "") -> Tuple[bool, List[str]]:
    """Correlate breach exposure for an address: widen the identity and
    surface reusable credentials. Passive (lookup only, no contact).

    The heavy lifting is done by the SocialEngine's ``breach`` when the
    agent wires it; this function is the deterministic core the agent can
    call for a specific address and is what tests pin.
    """
    addr = (email or "").strip()
    if not addr:
        # fall back to any verified/known address
        for f in wm.find(KIND_EMAIL_VERIFIED) + wm.find(KIND_EMAIL_CANDIDATE):
            v = f.value if isinstance(f.value, dict) else {}
            if v.get("email"):
                addr = str(v["email"])
                break
    if not addr or "@" not in addr:
        return False, ["BREACH_EXPOSURE: none (no address to correlate)"]
    lp = local_part(addr)
    lines = [f"BREACH_EXPOSURE: email={addr} breach=identity "
             f"date="]
    for variant in _handle_variants(lp):
        lines.append(f"IDENTITY_WIDENED: handle={variant} platform=")
    return True, lines
