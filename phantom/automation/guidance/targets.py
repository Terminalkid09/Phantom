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


def split_host_port(target: str) -> tuple:
    """("host", port_or_None) for a bare ``host:port``, else the input.

    A service target — ``127.0.0.1:8081``, ``example.com:8443`` — is the form
    an operator actually has in front of them, and it used to fall through
    every branch of `classify_target` (the ``:`` excluded it from the domain
    branch, the port excluded it from the IP branch) and came out a
    USERNAME: the whole network chain was replaced by an identity chain
    against a string that was never a person. Splitting the port here keeps
    the two facts separate instead of guessing.
    """
    t = (target or "").strip()
    if not t or "://" in t:
        return t, None
    if t.startswith("["):                      # [::1]:8080
        host, _, rest = t[1:].partition("]")
        if host and rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
            if 0 < port < 65536:
                return host, port
        return t, None
    if t.count(":") == 1:
        host, _, tail = t.partition(":")
        if host and tail.isdigit() and 0 < int(tail) < 65536:
            return host.strip(), int(tail)
    return t, None


def classify_target(target: str) -> str:
    """Classify a target string into its red-team entity type.

    Order matters: URL -> IP -> email -> phone -> (host:port) domain ->
    username.
    """
    t = (target or "").strip()
    if not t:
        return "username"

    if t.startswith(("http://", "https://")):
        return "url"

    # a bare service endpoint (`host:port`): classify the HOST, not the pair
    _host, _port = split_host_port(t)
    if _port is not None and _host != t:
        kind = classify_target(_host)
        if kind in ("ip", "domain"):
            return kind

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

    For URLs the hostname is extracted; a bare ``host:port`` loses its port
    (nmap/osint tools take a host, and a port appended to one makes the
    command malformed rather than more specific); everything else is passed
    through unchanged.
    """
    tt = target_type or classify_target(target)
    if tt == "url":
        parsed = urlparse(target if "://" in target else f"http://{target}")
        return parsed.hostname or target
    if tt in ("ip", "domain"):
        host, port = split_host_port(target)
        if port is not None:
            return host
    return target


def is_identity_target(target_type: str) -> bool:
    return target_type in IDENTITY_TYPES


def is_network_target(target_type: str) -> bool:
    return target_type in NETWORK_TYPES
