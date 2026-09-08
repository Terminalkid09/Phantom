"""
targets.py — target classification for the autonomous agent.

A target can be an IP, a domain, a URL, an email address, a username or a
phone number. The agent must understand WHAT it is dealing with and adapt
the enumeration phase (network recon vs OSINT/social engineering) while the
rest of the kill chain always converges on beacon injection + persistence.

    ip / domain / url   -> network chain (scan -> services -> creds -> beacon)
    email / username    -> identity chain (osint -> breach -> phish -> victim_ip
                           -> creds -> beacon)
    phone               -> identity chain (osint -> sms phish -> victim_ip
                           -> creds -> beacon)
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

from urllib.parse import urlparse

# E.164-ish: optional +, 7..15 digits, spaces/dashes tolerated
_PHONE_RE = re.compile(r"^\+?[\d\s\-]{7,18}$")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")

# classic-looking usernames (may contain underscores), not matching other types
_USERNAME_HINT_RE = re.compile(r"^[a-zA-Z0-9_\.\-]{2,64}$")

# Common gTLD/generic suffixes + internal pseudo-TLDs. A dotted string is a
# DOMAIN only when its last label looks like a real suffix — otherwise it is a
# USERNAME (usernames very often contain dots: "mario.rossi", "giulia.b").
_TLD_SET = {
    # generic TLDs
    "com", "net", "org", "io", "co", "info", "biz", "dev", "app", "xyz",
    "online", "site", "tech", "store", "ai", "me", "tv", "cc", "cloud",
    "digital", "gg", "pro", "blog", "life", "world", "today", "click",
    "link", "page", "team", "social", "media", "design", "agency", "io",
    # internal / pseudo TLDs (intranet, lab, corp networks)
    "local", "internal", "corp", "lan", "home", "intranet", "office",
}


def _looks_like_tld(label: str) -> bool:
    """True when `label` is a plausible domain suffix: every 2-letter suffix
    is a country-code TLD, otherwise it must be in the known set."""
    lab = label.lower()
    return bool(lab) and lab.isalpha() and (len(lab) == 2 or lab in _TLD_SET)

IDENTITY_TYPES = ("email", "username", "phone")
NETWORK_TYPES = ("ip", "domain", "url")


def classify_target(target: str) -> str:
    """Classify a target string into its red-team entity type.

    Order matters: URL -> IP -> email -> phone -> domain -> username.
    """
    t = (target or "").strip()
    if not t:
        return "username"

    if t.startswith(("http://", "https://")):
        return "url"

    # bare IPv4 / IPv6
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass

    # email: user@domain.tld
    if _EMAIL_RE.match(t):
        return "email"

    # phone: all-digits (with optional +, spaces) and not an IP
    stripped = re.sub(r"[\s\-\+]", "", t)
    if _PHONE_RE.match(t) and stripped.isdigit() and 7 <= len(stripped) <= 15:
        return "phone"

    # dotted string: a DOMAIN only when the last label looks like a real TLD
    # (or an internal pseudo-TLD like .corp/.local) — "mario.rossi" is a
    # username, "testfire.net" is a domain
    if "." in t and not t.startswith(".") and not t.endswith(".") \
            and " " not in t and ":" not in t:
        last = t.rsplit(".", 1)[-1]
        if _looks_like_tld(last):
            return "domain"
        return "username"

    # @-prefixed or otherwise name-like: username
    return "username"


def target_host(target: str, target_type: str = "") -> str:
    """The hostname/IP the network tooling should aim at.

    For URLs the hostname is extracted; everything else is passed through.
    """
    tt = target_type or classify_target(target)
    if tt == "url":
        parsed = urlparse(target if "://" in target else f"http://{target}")
        return parsed.hostname or target
    return target


def is_identity_target(target_type: str) -> bool:
    return target_type in IDENTITY_TYPES


def is_network_target(target_type: str) -> bool:
    return target_type in NETWORK_TYPES
