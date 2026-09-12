import ipaddress
import socket
from typing import List


def _resolve_all(target: str) -> List[str]:
    """ALL A records for a hostname.

    `gethostbyname` resolves a SINGLE address; a CDN / round-robin host
    can legitimately answer different IPs on the same FQDN, and a scope
    check that only verifies one of them is bypassable by the others.
    Returns [] when the hostname does not resolve.
    """
    try:
        _, _, addrs = socket.gethostbyname_ex(target)
        return [a for a in (addrs or []) if a]
    except (socket.gaierror, OSError):
        return []


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


def is_in_scope(target: str, scope_list: List[str]) -> bool:
    """Checks if a target (IP or hostname) is within the allowed scope.

    * IP target       -> checked against every network/host entry.
    * Hostname target -> ALL resolved A records are checked (a single
      resolution is not enough: CDN/round-robin hosts resolve to several).
    * Unresolvable hostname -> FAIL CLOSED unless the exact hostname is
      declared as a scope entry. An authorization gate must never guess.
    """
    if not scope_list:
        # no scope declared: the CALLER decides what unscoped means
        # (the API gate refuses targeted commands; the CLI warns loudly)
        return True

    try:
        ip_obj = ipaddress.ip_address(target)
        ips: List[object] = [ip_obj]
    except ValueError:
        ips = []
        for addr in _resolve_all(target):
            try:
                ips.append(ipaddress.ip_address(addr))
            except ValueError:
                continue
        if not ips:
            # cannot verify authorization -> refuse unless explicitly listed
            return target.lower() in _scope_hostnames(scope_list)

    for entry in scope_list:
        entry = (entry or "").strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
                if any(ip in network for ip in ips):
                    return True
            else:
                if any(ip == ipaddress.ip_address(entry) for ip in ips):
                    return True
        except ValueError:
            # a hostname entry: authorize the exact host (case-insensitive)
            if target.lower() == entry.lower():
                return True
            continue
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