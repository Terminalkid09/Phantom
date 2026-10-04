"""
external_intel.py — passive external-intel recon engine.

Phantom already wrapped several public services (Shodan InternetDB, crt.sh
CT logs, BGP) but they only ran from the manual modules: the automatic
planner never used them, so a profile that could not (or must not) run a
loud port scan had no way to learn the target's surface from the wider
internet's view.

This is the in-process engine behind the ``external_recon`` capability. It
is PASSIVE (no packet is ever sent at the target): for an IP it asks
Shodan for the host's known open ports and hostnames; for a domain it mines
crt.sh CT-log subdomains; it also records the host's BGP netblock. The
markers it prints are turned into ordinary `service` / `hostname` facts by
``external_intel_interp``, so the rest of the chain reasons about them
exactly as it does about a scan result — and, being a low-rank source for
`service`, it only runs when the real scanner is unavailable or dead.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List
from urllib.parse import urlsplit

from phantom.automation.belief import Finding


# Well-known TCP ports -> service name. Shodan returns PORT NUMBERS, but the
# chain's gates are service-KIND gates (`_has_service_kind("service", "ssh")`),
# so a bare "tcp/22" finding would satisfy nothing. Mapping the port to its
# service name is what makes an external finding usable by the planner.
_PORT_SERVICES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "smtp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker",
    2376: "docker", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 5985: "winrm", 5986: "winrm", 6379: "redis", 8080: "http",
    8443: "https", 9200: "elasticsearch", 27017: "mongodb",
    11211: "memcached", 6443: "kubernetes",
}


def _host_of(raw: str) -> str:
    """Bare hostname/IP from a target string (URL, host:port, host)."""
    value = str(raw or "").strip()
    if not value:
        return ""
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]
    # strip userinfo and port; keep IPv6 literals intact
    if value.startswith("["):
        return value[1:value.index("]")] if "]" in value else value
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _service_for(port: int) -> str:
    return _PORT_SERVICES.get(port, "")


def external_intel_engine(wm, slots: Dict[str, Any]) -> str:
    """Query the public services already wrapped in utils/api.py and emit
    markers. Never raises: a failing service contributes nothing."""
    try:
        from phantom.utils import api as ext
    except Exception:
        return "# external intel: api wrappers unavailable"

    host = _host_of(getattr(wm, "target", ""))
    if not host:
        return "# external intel: no host"

    lines: List[str] = []
    if _is_ip(host):
        try:
            data = ext.shodan_lookup(host) or {}
        except Exception:
            data = {}
        if isinstance(data, dict):
            # full API returns "ports"; InternetDB also returns "hostnames"
            for port in (data.get("ports") or [])[:200]:
                try:
                    p = int(port)
                except (TypeError, ValueError):
                    continue
                lines.append(f"SHODAN: host={host} port={p}")
            for name in (data.get("hostnames") or [])[:100]:
                if name:
                    lines.append(f"HOSTNAME: host={name} source=shodan")
        try:
            bgp = ext.bgp_lookup(host) or {}
        except Exception:
            bgp = {}
        prefix = ""
        if isinstance(bgp, dict):
            prefixes = bgp.get("prefixes") or []
            if prefixes:
                prefix = str(prefixes[0].get("prefix") or "")
            elif bgp.get("prefix"):
                prefix = str(bgp.get("prefix") or "")
        if prefix:
            lines.append(f"BGP: host={host} prefix={prefix}")
    else:
        try:
            subs = ext.crtsh_lookup(host) or []
        except Exception:
            subs = []
        for name in subs[:300]:
            if name:
                lines.append(f"HOSTNAME: host={name} source=crtsh")

    return "\n".join(lines) or f"# external intel: no public data for {host}"


def _parse_marker(line: str) -> Dict[str, str]:
    kv: Dict[str, str] = {}
    for chunk in (line or "").split():
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


def external_intel_interp(output: str, wm, slots: Dict[str, Any]) -> List[Finding]:
    """Marker lines -> `service` / `hostname` facts.

    Confidence is deliberately below a real scan: an external view is a
    lead, and a later nmap finding for the same port overwrites it.
    """
    findings: List[Finding] = []
    for line in (output or "").splitlines():
        if line.startswith("SHODAN:"):
            kv = _parse_marker(line[len("SHODAN:"):])
            host = kv.get("host", "")
            try:
                port = int(kv.get("port", ""))
            except (TypeError, ValueError):
                continue
            if not (0 < port < 65536):
                continue
            svc = _service_for(port)
            findings.append(Finding(
                kind="service", key=f"tcp/{port}",
                value={"port": str(port), "service": svc, "host": host,
                       "derived": "external_intel"},
                confidence=0.5, source="external_recon", target=wm.target))
        elif line.startswith("HOSTNAME:"):
            kv = _parse_marker(line[len("HOSTNAME:"):])
            name = kv.get("host", "").strip().strip(".")
            if not name:
                continue
            findings.append(Finding(
                kind="hostname", key=f"hostname:{name}",
                value={"hostname": name, "source": kv.get("source", "")},
                confidence=0.5, source="external_recon", target=wm.target))
        elif line.startswith("BGP:"):
            kv = _parse_marker(line[len("BGP:"):])
            prefix = kv.get("prefix", "")
            if prefix:
                findings.append(Finding(
                    kind="netblock", key=f"netblock:{prefix}",
                    value={"prefix": prefix},
                    confidence=0.5, source="external_recon", target=wm.target))
    return findings
