"""
internal_recon.py — post-exploitation internal network discovery.

Before lateral movement, an operator learns WHAT ELSE is around the
foothold: interfaces, routes, ARP neighbors, then probes the live
neighbors for the services the pivot chain speaks (SSH/SMB/WinRM).
This module turns that craft into a capability:

    beacon task  ->  internal snapshot (interfaces/routes/ARP)
    interpreter  ->  internal_host findings (candidate peers)
    scope check  ->  only in-scope candidates become pivot peers
    planner      ->  lateral/smb/winrm pivots now have a host slot source

The probe is deliberately BOUNDED: a fixed TCP-connect sweep over the
ARP table (typically < 20 hosts on a real LAN segment) for at most 4
pivot ports, 300ms timeout each. This is recon a helpdesk ticket could
explain, not a scan that lights up the SOC.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from phantom.automation.belief import Finding, WorldModel

# ports the pivot chain actually speaks (ssh=22, smb=445, winrm=5985)
_PIVOT_PORTS = (22, 445, 5985)
# bounded connect timeout (seconds) per host:port
_PROBE_TIMEOUT = 0.3
# never probe more neighbors than this in one snapshot (noise cap)
_MAX_NEIGHBORS = 32


def internal_snapshot_command(os_name: str) -> str:
    """Beacon shell one-liner: interfaces + routes + ARP neighbors.

    Windows: Get-NetRoute/Get-NetNeighbor equivalents via netsh/arp;
    Linux: ip route/ neigh (falling back to /proc/net/arp for stripped
    boxes without iproute2). Marker-delimited for the interpreter.
    """
    if "windows" in os_name.lower():
        return (
            "echo __NET_BEGIN__ & "
            "route print -4 | findstr /R /C:\"^ *0\\.0\\.0\\.0\" & "
            "ipconfig | findstr /C:\"IPv4\" /C:\"Subnet\" & "
            "arp -a | findstr /C:\"dynamic\" & "
            "echo __NET_END__"
        )
    return (
        "echo __NET_BEGIN__; "
        "ip -4 addr show 2>/dev/null | grep -E 'inet ' ; "
        "ip route 2>/dev/null || cat /proc/net/route 2>/dev/null | head -8 ; "
        "(ip neigh 2>/dev/null || arp -a 2>/dev/null || "
        "cat /proc/net/arp 2>/dev/null) ; "
        "echo __NET_END__"
    )


def internal_probe_command(hosts: List[str], ports=(_PIVOT_PORTS)) -> str:
    """Bounded TCP-connect probe over the candidate hosts (runs on the
    beacon via shell). One line per open service:
        __SVC__ <host> <port>
    """
    uniq = [h for h in dict.fromkeys(hs for hs in hosts if hs)][:_MAX_NEIGHBORS]
    lines = ["echo __PROBE_BEGIN__"]
    if "windows" in _probe_os_hint():
        for h in uniq:
            for p in ports:
                lines.append(
                    f"powershell -NoP -W Hidden -C "
                    f"(New-Object Net.Sockets.TcpClient)"
                    f".ConnectAsync('{h}',{p}).Wait(300) -ErrorAction SilentlyContinue"
                    f"; if ($?) {{ echo __SVC__ {h} {p} }}")
    else:
        for h in uniq:
            for p in ports:
                lines.append(
                    f"timeout 1 bash -c \"echo >/dev/tcp/{h}/{p}\" 2>/dev/null "
                    f"&& echo __SVC__ {h} {p}")
    lines.append("echo __PROBE_END__")
    return " ; ".join(lines)


def _probe_os_hint() -> str:
    """The adapter decides the shell dialect; the beacon's OS finding
    flows through the slot, so this reads the live world model."""
    try:
        from phantom.core.knowledge import session_wm
        from phantom.automation.guidance.kit import _target_os
        return (_target_os(session_wm()) or "").lower()
    except Exception:
        return ""


def _extract_ip(text: str) -> str:
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", text or "")
    return m.group(1) if m else ""


def internal_recon_interpreter(output: str, wm: WorldModel,
                               slots: Dict[str, Any]) -> List[Finding]:
    """Parse the __NET_BEGIN__ snapshot into findings.

    * gateway          kind=internal_gateway  (the default route's next hop)
    * local subnet     recorded on the finding value (cidr when derivable)
    * ARP neighbors    kind=internal_host, one finding per distinct IP
                       (loopback/multicast/0.0.0.0 excluded)
    """
    if "__NET_BEGIN__" not in output:
        return []
    body = output.split("__NET_BEGIN__", 1)[1]
    body = body.split("__NET_END__", 1)[0]
    lines = [l.strip() for l in body.splitlines() if l.strip()]

    gateway = ""
    iface_ips: List[str] = []
    neighbors: List[str] = []
    for ln in lines:
        low = ln.lower()
        # skip our own markers
        if "__NET" in low:
            continue
        # default routes (windows route print / linux 'default via')
        if ("0.0.0.0" in ln and "gateway" not in low) or low.startswith("default"):
            gw = _extract_ip(ln.split("0.0.0.0")[-1]) if "0.0.0.0" in ln \
                else _extract_ip(ln.split("via")[-1] if "via" in low else ln)
            if gw and not gateway:
                gateway = gw
                continue
        # our own interface addresses (windows ipconfig / linux ip -4 addr)
        if "ipv4" in low or "inet " in low or "inet\b" in low:
            ip = _extract_ip(ln)
            if ip:
                iface_ips.append(ip)
                continue
        # ARP neighbors
        if "dynamic" in low or "REACHABLE" in ln or "ether" in low \
                or (" incomplete" not in low and _extract_ip(ln)
                    and ("arp" in low or re.search(
                        r"\d{1,3}(?:\.\d{1,3}){3}\s", ln))):
            ip = _extract_ip(ln)
            if ip:
                neighbors.append(ip)

    findings: List[Finding] = []
    if gateway:
        findings.append(Finding(
            kind="internal_gateway", key=gateway,
            value={"gateway": gateway},
            confidence=0.9, source="internal_recon",
            evidence=f"default gateway {gateway}"))

    own = set(iface_ips) | {gateway}
    seen = set()
    for ip in neighbors:
        if ip in own or ip in seen:
            continue
        if ip.startswith(("0.", "224.", "239.", "255.")) or ip.endswith(".1.1") \
                and ip.count(".") != 3:
            continue
        seen.add(ip)
        findings.append(Finding(
            kind="internal_host", key=ip,
            value={"ip": ip, "gateway": gateway,
                   "os": slots.get("os", ""), "via": "arp_neighbor"},
            confidence=0.7, source="internal_recon",
            evidence=f"ARP neighbor {ip}"))
    return findings


def internal_probe_interpreter(output: str, wm: WorldModel,
                               slots: Dict[str, Any]) -> List[Finding]:
    """Parse __SVC__ host port lines into internal_service findings —
    these directly feed the pivot capabilities' host/service selection.
    Markers may share one physical line (the probe is one joined shell
    command), so the output is split on the MARKER, not on newlines."""
    if "__SVC__" not in output:
        return []
    svc_names = {22: "ssh", 445: "smb", 5985: "winrm"}
    out: List[Finding] = []
    seen = set()
    for chunk in output.split("__SVC__")[1:]:  # skip the pre-marker prefix
        toks = chunk.split()
        if len(toks) >= 2:
            host, port = toks[0], _int_or_0(toks[1])
            if host and port and (host, port) not in seen:
                seen.add((host, port))
                out.append(Finding(
                    kind="internal_service", key=f"{host}:{port}",
                    value={"host": host, "port": port,
                           "service": svc_names.get(port, str(port))},
                    confidence=0.85, source="internal_recon_probe",
                    evidence=f"__SVC__ {host} {port}"))
    return out


def _int_or_0(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return 0


def internal_peers_in_scope(wm: WorldModel, scope_list: List[str]) -> List[str]:
    """Candidate peers from internal_host/internal_service findings,
    filtered through the engagement scope. The scope gate is the same
    `is_in_scope` the rest of the auto-mode honors — an ARP neighbor is
    NOT authorization; only in-scope hosts become pivot targets."""
    if not (wm.find("internal_host") or wm.find("internal_service")):
        return []
    from phantom.core.scope import is_in_scope
    peers: List[str] = []
    for kind in ("internal_host", "internal_service"):
        for f in wm.find(kind):
            v = f.value if isinstance(f.value, dict) else {}
            host = str(v.get("host") or v.get("ip") or f.key or "").strip()
            if host and host not in peers and is_in_scope(host, scope_list):
                peers.append(host)
    return peers
