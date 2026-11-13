"""
spoof.py — realistic sender identity + homoglyph obfuscation.

A lure is only as good as its From header. The default "noreply@
security-updates.example" is a neon sign saying "fake"; a good lure looks
like it comes from:

  * a SERVICE the target actually uses (the platform OSINT found, e.g.
    LinkedIn / Instagram / the company's own mail domain), or
  * a PERSON the target knows (a colleague at the same corporate domain
    when OSINT discovered one).

`homoglyph()` then obfuscates the display name with visually-identical
Cyrillic letters (Cyrillic 'а' vs Latin 'a', 'е' vs 'e', 'о' vs 'o', ...):
to a human the text looks identical, but naive text filters scanning for
exact keywords ("LinkedIn", "Security", "account") no longer match. This is
the classic IDN-homograph trick applied to headers instead of domains.

Everything is pure string logic: no network, no side effects, unit-testable.
"""

from __future__ import annotations

import random
from typing import Dict, Optional, Tuple

# Latin -> visually identical Cyrillic lookalikes (U+0400 block). Only
# pairs that render near-indistinguishably in common fonts are used.
_HOMOGLYPHS = {
    "a": "\u0430",  # Cyrillic a
    "e": "\u0435",  # Cyrillic ie
    "o": "\u043e",  # Cyrillic o
    "p": "\u0440",  # Cyrillic er
    "c": "\u0441",  # Cyrillic es
    "y": "\u0443",  # Cyrillic u
    "x": "\u0445",  # Cyrillic ha
    "k": "\u043a",  # Cyrillic ka
    "m": "\u043c",  # Cyrillic em
    "t": "\u0442",  # Cyrillic te
    "h": "\u04bb",  # Cyrillic shha (looks like Latin h)
    "b": "\u0432",  # Cyrillic ve (looks like Latin b)
    "n": "\u043f",  # Cyrillic pe (looks like Latin n in some fonts)
}

_FREE_MAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
              "live.com", "yahoo.com", "proton.me", "protonmail.com",
              "icloud.com", "aol.com", "msn.com", "yandex.com",
              "mail.com", "gmx.com", "zoho.com"}

# platform -> (brand, domain) used when the pretext impersonates a service
_PLATFORM_BRANDS = {
    "linkedin": ("LinkedIn", "linkedin.com"),
    "instagram": ("Instagram", "instagram.com"),
    "tiktok": ("TikTok", "tiktok.com"),
    "x": ("X", "x.com"),
    "twitter": ("X", "x.com"),
    "facebook": ("Facebook", "facebook.com"),
    "github": ("GitHub", "github.com"),
    "reddit": ("Reddit", "reddit.com"),
    "telegram": ("Telegram", "telegram.org"),
    "snapchat": ("Snapchat", "snapchat.com"),
}


def homoglyph(text: str, ratio: float = 0.35, seed: int = 0) -> str:
    """Replace a subset of Latin letters with visually-identical Cyrillic
    lookalikes. Human-invisible, naive-text-filter-defeating.

    Deterministic for a given seed so the same lure renders identically
    across retries. `ratio` (0..1) controls how many letters are swapped —
    too high starts looking wrong in fonts that render the pairs slightly
    differently, ~0.3-0.4 is the sweet spot.
    """
    text = text or ""
    rng = random.Random(seed)
    out = []
    for ch in text:
        low = ch.lower()
        repl = _HOMOGLYPHS.get(low)
        if repl is not None and ch.isalpha() and rng.random() < ratio:
            out.append(repl if ch.islower() else repl.upper())
        else:
            out.append(ch)
    return "".join(out)


def obfuscate(subject: str, seed: int = 0) -> str:
    """Obfuscate a subject line with homoglyphs (headers are the most-scanned
    fields). Keeps digits/punctuation intact."""
    return homoglyph(subject, ratio=0.3, seed=seed)


def _corporate_domain(emails: list) -> str:
    for e in emails or []:
        domain = str(e).split("@")[-1].lower()
        if domain and "." in domain and domain not in _FREE_MAIL:
            return domain
    return ""


def derive_sender(dossier: Dict, pretext: str = "",
                  persona_email: str = "",
                  configured: str = "") -> Tuple[str, str]:
    """Return (display_name, address) for the phish From header.

    Order of preference for the DISPLAY identity:
      1. a PERSON the target knows: a colleague email on the same corporate
         domain discovered by OSINT (name from its local part);
      2. the SERVICE the target uses: the platform brand (LinkedIn, TikTok,
         GitHub...) or the company itself for internal pretexts;
      3. honest fallback: a plausible internal service account.

    The ADDRESS follows the same source (corporate domain / platform
    domain), with PHANTOM_PHISH_FROM (`configured`) taking priority and the
    attacker's disposable mailbox as the last resort — display-name weight
    carries the realism, the address is the part filters/SPF see.
    """
    emails = [str(e) for e in (dossier.get("emails") or [])]
    company = str(dossier.get("company") or "").strip()
    platform = str(dossier.get("platform") or "").lower()
    domain = _corporate_domain(emails)

    # 1. a real person at the target's company (colleague) from OSINT
    if domain and len(emails) > 1:
        for e in emails[1:]:
            local = str(e).split("@")[0]
            parts = [p for p in local.replace(".", " ").replace("_", " ")
                     .split() if p and not p.isdigit()]
            if len(parts) >= 2:
                person = " ".join(p.capitalize() for p in parts[:2])
                if domain in str(e).lower():
                    return person, f"{local}@{domain}"

    pretext = (pretext or "").lower()
    brand, plat_domain = "", ""
    if platform in _PLATFORM_BRANDS:
        brand, plat_domain = _PLATFORM_BRANDS[platform]

    # 2a. service the target uses (platform-based pretexts)
    if brand and pretext in ("security_alert", "password_reset", "dm",
                             "security_verify"):
        display = f"{brand} Security" if pretext in ("security_alert",
                                                     "security_verify") \
            else f"{brand}"
        addr = f"security@{plat_domain}" if pretext in ("security_alert",
                                                        "security_verify") \
            else f"noreply@{plat_domain}"
        if configured:
            addr = configured
        return display, addr

    # 2b. the company itself (internal pretexts)
    if company and domain:
        account = {"it_helpdesk": "it-helpdesk", "hr_benefits": "hr",
                   "doc_share": "no-reply", "recruiter": "talent"}.get(
                       pretext, "no-reply")
        display = {"it_helpdesk": f"{company} IT Service Desk",
                   "hr_benefits": f"{company} HR",
                   "doc_share": f"{company} Documents",
                   "recruiter": f"Recruiter at {company}"}.get(
                       pretext, company)
        if configured:
            return display, configured
        return display, f"{account}@{domain}"

    # 3. platform domain without a strong pretext
    if brand:
        if configured:
            return brand, configured
        return brand, f"noreply@{plat_domain}"

    # 4. corporate domain with a generic internal persona
    if domain:
        if configured:
            return f"{company or 'IT'} Security", configured
        return f"{company or 'IT'} Security", f"security@{domain}"

    # 5. honest last resort: attacker-controlled mailbox, display does the work
    addr = configured or persona_email or "noreply@security-updates.example"
    return "IT Security Team", addr


def apply(sender_display: str, address: str, subject: str, seed: int = 0,
          ratio: float = 0.35) -> Tuple[str, str, str]:
    """Apply homoglyph obfuscation to the display name (and subject),
    leaving the address byte-exact (an obfuscated address would not route).
    Returns (display, address, subject)."""
    return (homoglyph(sender_display, ratio=ratio, seed=seed),
            address,
            obfuscate(subject, seed=seed + 1))
