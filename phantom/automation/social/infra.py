"""infra.py — readiness preflight for the lure infrastructure.

The lure hop fails the same silent way the email hop does (see
``deliverability.py``): the page loads, the target types nothing, and it looks
exactly like "nobody was interested". What actually went wrong is
infrastructure — a lure link pointing at a LAN address, a port nobody listens
on, or a relay whose session cookie is dropped because the page is plain HTTP.
None of those produce an error at the moment they happen.

So the infrastructure is checked BEFORE a lure is handed to the operator,
against the four things that decide whether the link can work at all:

    REACHABILITY   a public URL that actually resolves — a link that does not
                   resolve is dead for the target and indistinguishable from
                   a target who ignored it;
    TRANSPORT      HTTPS in front. For the AiTM relay this is not cosmetic: a
                   ``Secure`` / ``SameSite=None`` cookie is dropped on plain
                   HTTP and the relay breaks *after* the credentials are
                   typed, which is the worst possible moment;
    PRESENTATION   a bare IP in the address bar (readable through the whole
                   visit), a redirect still pointing at the built-in
                   placeholder, a brand left at its default;
    LIABILITY      the AiTM relay switched on at all, and what it requires.

HONEST LIMIT — read before trusting a green report: none of this substitutes
for a domain you control, for SPF/DKIM/DMARC on the mail hop, or for an
authorization to test the service you are about to impersonate. The checks are
ADVISORY by design: an operator can run with a blocker in front of them (it is
their engagement), and a check that cannot be evaluated says nothing rather
than inventing a verdict — a failed DNS lookup is reported only when the
resolver positively answered that the name does not exist.
"""

from __future__ import annotations

import re
import socket
import threading
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from phantom.automation.social import kits

BLOCKER = "blocker"
WARNING = "warning"
INFO = "info"

#: what the framework ships as a placeholder, and therefore what a target
#: reads if nobody changed it
_DEFAULT_REDIRECT = "https://example.com"
_DEFAULT_BRAND = "Account verification"

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

#: the config key -> env var pairs this module reads when it is not given a
#: value. Same pairs `tracker.py` uses, so the preflight and the tracker can
#: never read two different settings.
_CONFIG_KEYS = {
    "public_url": ("tracker.public_url", "PHANTOM_TRACK_URL"),
    "redirect": ("tracker.redirect", "PHANTOM_TRACK_REDIRECT"),
    "brand": ("tracker.brand", "PHANTOM_TRACK_BRAND"),
    "skin": ("tracker.skin", "PHANTOM_TRACK_SKIN"),
}


@dataclass(frozen=True)
class InfraCheck:
    """One thing that decides whether the lure can work, and its fix."""

    code: str
    severity: str          # blocker | warning | info
    detail: str
    remedy: str = ""


@dataclass
class InfraReport:
    checks: List[InfraCheck] = field(default_factory=list)

    @property
    def blockers(self) -> List[InfraCheck]:
        return [c for c in self.checks if c.severity == BLOCKER]

    @property
    def warnings(self) -> List[InfraCheck]:
        return [c for c in self.checks if c.severity == WARNING]

    @property
    def ok(self) -> bool:
        """No BLOCKER. Warnings and info never make a report not-ok: they are
        things the operator should know, not things that stop the hop."""
        return not self.blockers

    def codes(self, severity: Optional[str] = None) -> List[str]:
        return [c.code for c in self.checks
                if severity is None or c.severity == severity]

    def render(self) -> str:
        """One line, shaped like deliverability's marker."""
        return (f"INFRA: ok={self.ok} blockers={len(self.blockers)} "
                f"warnings={len(self.warnings)} "
                f"codes={','.join(self.codes()) or 'none'}")

    def lines(self) -> List[str]:
        order = (BLOCKER, WARNING, INFO)
        out = [self.render()]
        for chk in sorted(self.checks,
                          key=lambda c: order.index(c.severity)
                          if c.severity in order else len(order)):
            out.append(f"  [{chk.severity}] {chk.code}: {chk.detail}"
                       + (f" -> {chk.remedy}" if chk.remedy else ""))
        return out

    def top_remedy(self) -> str:
        """The single most valuable fix, worst severity first."""
        for sev in (BLOCKER, WARNING):
            for chk in self.checks:
                if chk.severity == sev and chk.remedy:
                    return f"{chk.code}: {chk.remedy}"
        return ""


def _split_url(url: str) -> Tuple[str, str]:
    """(scheme, host) of a configured public URL. Tolerates a bare host."""
    text = (url or "").strip()
    if not text:
        return "", ""
    scheme, sep, rest = text.partition("://")
    if not sep:                    # configured without a scheme
        scheme, rest = "", scheme
    host = rest.split("/", 1)[0].split("?", 1)[0]
    host = host.rsplit("@", 1)[-1]           # drop any userinfo
    if host.startswith("["):                 # IPv6 literal
        host = host[1:].split("]", 1)[0]
    else:
        host = host.split(":", 1)[0]
    return scheme.lower(), host.lower()


def _resolves(host: str, timeout: float = 2.0) -> Optional[bool]:
    """Best-effort DNS check: True / False / None ("could not tell").

    The lookup runs in a daemon thread with a short join, so a slow resolver
    can never stall a lure build, and ANY failure returns None. None is not
    False: a resolver we could not reach says nothing about the name, and
    reporting "does not resolve" for a DNS hiccup would be a fabricated
    verdict on the operator's own infrastructure.
    """
    if not host:
        return None
    answer: List[bool] = []

    def _lookup() -> None:
        try:
            socket.getaddrinfo(host, None)
            answer.append(True)
        except Exception:
            answer.append(False)

    try:
        thread = threading.Thread(target=_lookup, daemon=True)
        thread.start()
        thread.join(timeout)
    except Exception:
        return None
    return answer[0] if answer else None


def _config_value(config_key: str, env_var: str, default: str = "") -> str:
    try:
        from phantom.utils import config as cfg
        return str(cfg.get(config_key, default, env=env_var) or "")
    except Exception:
        return default


def _config_flag() -> bool:
    try:
        from phantom.utils import config as cfg
        return bool(cfg.get_bool("phishing.aitm", False, env="PHANTOM_AITM"))
    except Exception:
        return False


def infra_preflight(public_url: str = "", redirect: str = "", skin: str = "",
                    host: str = "", port: int = 0,
                    aitm: Optional[bool] = None, brand: str = "",
                    resolve: bool = True) -> InfraReport:
    """Check the lure infrastructure and return the report.

    Every argument is optional: an empty one is read from the same
    ``tracker.*`` config key (and legacy env var) the tracker itself reads, so
    the preflight never judges settings the run will not use.

    ``resolve=False`` skips the DNS lookup entirely (tests, and callers that
    know the host is internal).
    """
    if not public_url:
        public_url = _config_value(*_CONFIG_KEYS["public_url"])
    if not redirect:
        redirect = _config_value(*_CONFIG_KEYS["redirect"], _DEFAULT_REDIRECT)
    if not brand:
        brand = _config_value(*_CONFIG_KEYS["brand"], _DEFAULT_BRAND)
    if not skin:
        skin = _config_value(*_CONFIG_KEYS["skin"])
    if aitm is None:
        aitm = _config_flag()

    checks: List[InfraCheck] = []
    scheme, public_host = _split_url(public_url)
    is_ip = bool(_IPV4.match(public_host))

    # ── reachability ────────────────────────────────────────────────────
    if not public_url:
        checks.append(InfraCheck(
            "public_url_missing", BLOCKER,
            "no tracker.public_url is set: lure links fall back to the local "
            "bind address, so the target is handed a LAN address that is not "
            "reachable from outside",
            "set tracker.public_url to the public hostname of the tracker "
            "(a domain in front of the listener)"))
    else:
        if scheme != "https":
            if aitm:
                checks.append(InfraCheck(
                    "public_url_not_https", BLOCKER,
                    f"the public URL is not HTTPS ({scheme or 'no scheme'}): a "
                    f"Secure/SameSite=None cookie is DROPPED on plain HTTP, so "
                    f"the relay breaks silently — after the credentials are "
                    f"typed",
                    "terminate TLS in front of the tracker (reverse proxy or "
                    "tunnel) and point tracker.public_url at the https URL"))
            else:
                checks.append(InfraCheck(
                    "public_url_not_https", WARNING,
                    f"the public URL is not HTTPS ({scheme or 'no scheme'}): "
                    f"browsers flag a plain HTTP lure and mail gateways score "
                    f"the link up",
                    "serve the lure over TLS"))
        if is_ip:
            checks.append(InfraCheck(
                "public_url_is_ip", WARNING,
                f"the public host is a bare IP ({public_host}): the address "
                f"bar shows it for the whole visit, which a target can read",
                "put a domain in front of the tracker — a throwaway "
                "lookalike domain is cheap"))
        elif resolve:
            try:
                verdict = _resolves(public_host)
            except Exception:
                # a preflight must never be able to break a lure build
                verdict = None
            if verdict is False:
                checks.append(InfraCheck(
                    "public_url_unresolvable", WARNING,
                    f"{public_host} does not resolve: the link is dead for the "
                    f"target, and a dead link is indistinguishable from a "
                    f"target who ignored it",
                    "fix DNS for the lure domain, or use the host that "
                    "actually resolves"))

    # ── presentation ────────────────────────────────────────────────────
    if (redirect or "").strip().rstrip("/") == _DEFAULT_REDIRECT:
        checks.append(InfraCheck(
            "redirect_default", WARNING,
            f"tracker.redirect is still the built-in {_DEFAULT_REDIRECT}: a "
            f"target who looks at where they landed reads a placeholder",
            "point tracker.redirect at the page the pretext promises"))

    if (brand or "").strip() == _DEFAULT_BRAND:
        checks.append(InfraCheck(
            "brand_default", INFO,
            f"tracker.brand is still the placeholder '{_DEFAULT_BRAND}': the "
            f"login page shows that string as the brand",
            "set tracker.brand to what the pretext claims to be"))

    resolved_skin, known = kits.resolve_kit(skin)
    if (skin or "").strip() and not known:
        checks.append(InfraCheck(
            "kit_unknown", WARNING,
            f"tracker.skin '{skin.strip()}' is not a known kit: "
            f"'{resolved_skin}' is what actually renders",
            f"valid kits: {', '.join(kits.kit_ids())}"))

    # ── liability ───────────────────────────────────────────────────────
    if aitm:
        if not public_host or is_ip:
            checks.append(InfraCheck(
                "aitm_without_domain", BLOCKER,
                "phishing.aitm is ON but the public host is an IP (or unset): "
                "the relay serves a real login on a bare address, which is the "
                "ceiling of the technique and reads as hostile",
                "a domain with TLS in front of the tracker is required for "
                "the relay"))
        checks.append(InfraCheck(
            "aitm_enabled", INFO,
            "the AiTM relay is ON: it is credential theft against a live "
            "service, and it is deliberately NOT wired into auto-mode",
            "run it only on an engagement you are contracted for"))

    # ── transport availability ──────────────────────────────────────────
    if port:
        try:
            from phantom.automation.social.tracker import _port_available
            if not _port_available(host or "0.0.0.0", int(port)):
                checks.append(InfraCheck(
                    "port_unavailable", BLOCKER,
                    f"port {int(port)} cannot be bound: another service holds "
                    f"it, so every lure link points at a server nobody is "
                    f"listening on",
                    "free the port, or let the tracker shift to the next free "
                    "one and use the URL it reports"))
        except Exception:
            # the probe is best-effort: an unavailable probe says nothing
            pass

    return InfraReport(checks)
