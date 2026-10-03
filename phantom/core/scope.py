"""Engagement scope gate.

Authorization must be decided on FACTS, not on a single convenience lookup:

* A hostname can legitimately resolve to several addresses (CDN, round-robin),
  on both IPv4 and IPv6. Checking ONE address — or only A records — lets the
  others through.
* A hostname can resolve DIFFERENTLY at check time and at use time (DNS
  rebinding): an address that passed the check is not the address the tool
  later dials. The approved resolution is therefore FROZEN for a short window,
  so every check inside one operation sees the same answer, and a name that
  resolves to a MIX of in-scope and out-of-scope addresses is REFUSED
  outright rather than half-authorized.

Failing closed is the rule everywhere: an unresolvable hostname is refused
unless the operator declared that exact hostname in scope (an explicit,
deliberate authorization).
"""
import ipaddress
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

# How long an approved resolution is trusted. Long enough to cover one
# operation's check-then-use window, short enough that a rotated CDN does not
# pin a stale address for the whole engagement.
_RESOLUTION_TTL_SECONDS = 300

_LOCK = threading.Lock()
# target(lower) -> (expires_at_monotonic, tuple(addresses))
_FROZEN: Dict[str, Tuple[float, Tuple[str, ...]]] = {}


def resolve_addresses(target: str) -> List[str]:
    """Every A and AAAA address for *target* (deduplicated, string form).

    Uses ``getaddrinfo(AF_UNSPEC)`` so IPv6 is not silently dropped, and
    strips any IPv6 zone id (``fe80::1%eth0`` -> ``fe80::1``) so the value can
    be parsed and compared. Returns [] when the name does not resolve.
    """
    out: List[str] = []
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_UNSPEC,
                                   socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return []
    for info in infos:
        addr = info[4][0]
        if not addr:
            continue
        addr = addr.split("%", 1)[0]
        try:
            parsed = str(ipaddress.ip_address(addr))
        except ValueError:
            continue
        if parsed not in out:
            out.append(parsed)
    return out


def _frozen(target: str) -> Optional[Tuple[str, ...]]:
    with _LOCK:
        hit = _FROZEN.get(target.lower())
        if hit and hit[0] > time.monotonic():
            return hit[1]
        if hit:
            del _FROZEN[target.lower()]
    return None


def freeze_resolution(target: str, addresses: Optional[List[str]] = None,
                      ttl: int = _RESOLUTION_TTL_SECONDS) -> Tuple[str, ...]:
    """Pin *target*'s resolution for ``ttl`` seconds and return it.

    Called with no ``addresses`` it resolves now and caches the result. The
    point is that every scope check in the window sees the SAME addresses, so
    a rebind between the check and the action cannot swap them.
    """
    if addresses is None:
        addresses = resolve_addresses(target)
    frozen = tuple(addresses)
    with _LOCK:
        _FROZEN[target.lower()] = (time.monotonic() + ttl, frozen)
    return frozen


def clear_scope_cache() -> None:
    """Drop every frozen resolution (tests, and after a scope change)."""
    with _LOCK:
        _FROZEN.clear()


def _scope_hostnames(scope_list: List[str]) -> set:
    """Case-insensitive hostname entries declared in the scope list."""
    out = set()
    for entry in scope_list:
        entry = (entry or "").strip()
        if entry and "/" not in entry:
            try:
                ipaddress.ip_address(entry)
            except ValueError:
                out.add(entry.lower())
    return out


def _authorized(ip, scope_list: List[str]) -> bool:
    for entry in scope_list:
        entry = (entry or "").strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            elif ip == ipaddress.ip_address(entry):
                return True
        except ValueError:
            # a hostname entry is not an address and is handled elsewhere
            continue
    return False


def is_in_scope(target: str, scope_list: List[str]) -> bool:
    """Checks if a target (IP or hostname) is within the allowed scope.

    * IP target       -> checked against every network/host entry.
    * Hostname target -> ALL resolved A/AAAA records must be authorized. A name
      that resolves to a mix of in-scope and out-of-scope addresses (the DNS
      rebinding shape) is REFUSED: one of them would be reachable without an
      authorization. The resolution is frozen for the TTL so a rebind between
      this check and the action cannot change the answer.
    * Unresolvable hostname -> FAIL CLOSED unless the exact hostname is
      declared as a scope entry. An authorization gate must never guess.
    """
    if not scope_list:
        # no scope declared: the CALLER decides what unscoped means
        # (the API gate refuses targeted commands; the CLI warns loudly)
        return True

    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError:
        # An explicitly scoped NAME authorizes the name itself, deliberately
        # (this is the operator saying "I know this name").
        if target.lower() in _scope_hostnames(scope_list):
            return True
        addresses = _frozen(target)
        if addresses is None:
            addresses = freeze_resolution(target)
        ips: List[object] = []
        for addr in addresses:
            try:
                ips.append(ipaddress.ip_address(addr))
            except ValueError:
                continue
        if not ips:
            # cannot verify authorization -> refuse
            return False
        # EVERY resolved address must be authorized (rebinding defense).
        return all(_authorized(ip, scope_list) for ip in ips)

    return _authorized(ip_obj, scope_list)


def unscoped_allowed() -> bool:
    """Explicit opt-out for running against targets with NO engagement scope.

    Default OFF: an authorization gate must fail closed. The documented
    escape hatch for lab/CTF work is ``engagement.allow_unscoped`` in the
    config file or ``PHANTOM_ALLOW_UNSCOPED=1``. This is the SAME switch the
    desktop API already honours, so auto-mode and the API can never disagree
    about what unscoped means (A-6).
    """
    try:
        from phantom.utils import config as cfg
        return cfg.get_bool("engagement.allow_unscoped", False,
                            env="PHANTOM_ALLOW_UNSCOPED")
    except Exception:
        return False


def scope_status(target: str, scope_list: List[str]) -> str:
    """Tri-state for policy gates: 'ok' | 'unscoped' | 'out_of_scope'.

    'unscoped' means the target is fine but NO engagement scope is declared
    — the caller decides whether that is acceptable (API: refuse unless an
    explicit opt-out; CLI: warn loudly).
    """
    if not scope_list:
        return "unscoped"
    return "ok" if is_in_scope(target, scope_list) else "out_of_scope"


def scope_reason(target: str, scope_list: List[str]) -> Optional[str]:
    """Why a target is out of scope, or None when it is authorized.

    Distinguishes the rebinding case ("resolves to N addresses, only some
    authorized") from a plain out-of-scope address, so the operator gets an
    actionable message instead of a bare refusal.
    """
    if not scope_list or is_in_scope(target, scope_list):
        return None
    try:
        ipaddress.ip_address(target)
        return f"{target} is not in the engagement scope"
    except ValueError:
        pass
    addresses = _frozen(target) or resolve_addresses(target)
    if not addresses:
        return (f"{target} does not resolve and is not declared as a scope "
                f"entry (fail closed)")
    parsed = []
    for addr in addresses:
        try:
            parsed.append(ipaddress.ip_address(addr))
        except ValueError:
            continue
    good = [str(ip) for ip in parsed if _authorized(ip, scope_list)]
    bad = [str(ip) for ip in parsed if not _authorized(ip, scope_list)]
    if good and bad:
        return (f"{target} resolves MIXED: {len(good)} address(es) in scope, "
                f"{len(bad)} out ({', '.join(bad[:3])}) — refused as a DNS "
                f"rebinding risk")
    return (f"{target} resolves only to addresses outside the scope "
            f"({', '.join(bad[:3])})")
