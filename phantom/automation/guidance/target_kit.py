"""target_kit.py — one resolution from the world model to host and URL.

Extracted from ``guidance/kit.py`` (2026-11-05): kit is ~5.2k lines and the
functions below are a single cohesive cluster — every network adapter ends up
asking "what bare host / what URL am I aiming at". They were the only place
that answer lived, in the middle of a 5.2k-line file, which is why the split
was deferred until now.

Nothing here changed behaviour: the bodies are the ones that shipped. The one
back-reference (``best_origin``, still in kit) is imported INSIDE the function
that uses it, so importing this module never triggers a circular import.
"""

from __future__ import annotations

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.targets import split_host_port


def _resolve_target_address(wm: WorldModel) -> str:
    """The raw address to aim at (victim IP > edge origin > target).

    Extracted so host/URL normalization share one resolution instead of
    drifting apart across 30+ adapters.
    """
    ips = wm.find("victim_ip")
    if ips:
        return str(ips[0].value.get("ip", wm.target))
    # Lazy on purpose: `best_origin` lives in kit (it reads the edge module)
    # and kit imports THIS module at module level.
    from phantom.automation.guidance.kit import best_origin

    origin = best_origin(wm)
    if origin:
        return origin
    return wm.target


def _bare_host(raw: str) -> str:
    """Bare machine name from anything the operator may type: full URLs
    (scheme/userinfo/port/path/query), bare hosts, trailing dots/slashes.
    Unparseable input comes back stripped but untouched (never invent)."""
    s = (raw or "").strip().rstrip("/")
    if not s:
        return ""
    if "://" in s:
        try:
            from urllib.parse import urlsplit
            parts = urlsplit(s)
            host = parts.hostname or ""
            if host:
                return host.lower()
        except ValueError:
            pass
    # bare host, maybe with a stray path
    host = s.split("/")[0].split("?")[0].split("#")[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    host = host.strip().rstrip(".").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    # A service target (`host:port`) is still a machine plus a port: network
    # tooling needs the bare host, and the adapter asks for the port
    # separately. Leaving it attached produced `nc 127.0.0.1:8443 21 22 ...`,
    # which nc reads as one unresolvable host and the scan reports as dead.
    host, _ = split_host_port(host)
    return host


def _hport(host: str, port) -> str:
    """``host:port`` netloc with the port appearing exactly ONCE.

    A service target (``127.0.0.1:8081``) already carries its port, and every
    adapter that appends a discovered one produced ``http://127.0.0.1:8081:8081/
    upload`` — a URL curl rejects, which the engine reports as "no output"
    (i.e. the target looks unreachable while curl was never asked a valid
    question). When the candidate port differs from the one in the target,
    the CANDIDATE wins: it is the port a fact was recorded for.
    """
    raw = str(host or "").strip()
    port = str(port or "").strip()
    if not port:
        return raw
    bare, own = split_host_port(raw)
    if own is None:
        return f"{raw}:{port}"
    if str(own) == port:
        return raw
    return f"{bare}:{port}"


def _effective_target(wm: WorldModel) -> str:
    """The machine to aim network tooling at: ALWAYS a bare host.

    For identity targets (username/email/phone) the harvested victim IP
    becomes the real machine target; for network targets it is the target
    itself. This is how the identity chain converges on beacon injection.

    EDGE-AWARE: when the address in scope is a provider's reverse proxy, the
    machine to aim at is the ORIGIN discovered behind it. Every network
    adapter in this kit goes through this one function, so "do not scan the
    CDN, scan the box behind it" is one rule in one place instead of a rule
    every adapter has to remember.

    URL targets (http://host/app) resolve to the host: 31 adapters from
    nmap to ssh pass this straight to the tool, and a scheme/path in a
    tool argument is a broken command, never an intention.
    """
    return _bare_host(_resolve_target_address(wm))


def _external_intel_applicable(wm: WorldModel) -> bool:
    """Public sources cannot know a private/reserved address.

    Querying Shodan/bgpview/crt.sh about an RFC1918 host can only return
    "not found", and the query itself leaks the operator's LAN address to
    third parties (observed 2026-10-17: 192.168.1.18 was sent to Shodan and
    bgpview for nothing). Keep `external_recon` plannable only for public
    IPs and for names; the engine keeps its own guard for direct callers.
    """
    host = _effective_target(wm)
    try:
        import ipaddress
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return bool(host)


def _effective_url(wm: WorldModel) -> str:
    """Full normalized URL for HTTP tooling (scheme://host[:port][/path]).

    URL targets keep their scheme/port/path; bare hosts default to plain
    http://host. The one place URL construction lives, so adapters stop
    concatenating "http://" in front of whatever the target string is.
    """
    raw = (_resolve_target_address(wm) or "").strip()
    if "://" not in raw:
        host = _bare_host(raw)
        return f"http://{host}" if host else ""
    try:
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(raw)
        if not parts.hostname:
            return ""
        netloc = parts.hostname.lower()
        if parts.port:
            netloc += f":{parts.port}"
        path = parts.path or ""
        return urlunsplit((parts.scheme.lower() or "http", netloc, path,
                           parts.query, ""))
    except ValueError:
        host = _bare_host(raw)
        return f"http://{host}" if host else ""
