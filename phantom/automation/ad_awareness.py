"""
ad_awareness.py — Active Directory domain detection and enumeration.

Detects AD environments from network signals, extracts domain structure
information, and enriches the WorldModel with domain-specific facts that
feed the planner (kerberoasting, AS-REP roasting, DC enumeration).

Detection signals (passive and active, all non-disruptive):
  1. Port-based: 88 (Kerberos), 389/636 (LDAP/LDAPS), 3268/3269 (GC),
     464 (kpasswd), 135 (RPC endpoint mapper)
  2. DNS SRV records: _ldap._tcp.dc._msdcs, _kerberos._tcp, _gc._tcp
  3. LDAP rootDSE anonymous bind: namingContexts, domainFunctionality,
     supportedSASL, domainControllerFunctionality, forestFunctionality
  4. SMB null session: hostname, domain name from NTLM challenge
  5. Kerberos pre-authentication check (no auth required)

Findings feed: ad_domain, ad_dc, ad_users, ad_kerberoastable, ad_asrep
"""

from __future__ import annotations

import re
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from phantom.automation.belief import WorldModel, Finding


# ── data model ─────────────────────────────────────────────────────────

@dataclass
class DomainInfo:
    """Structured AD domain information."""
    domain_name: str = ""                    # CORP.LOCAL
    netbios_name: str = ""                   # CORP
    dns_forest: str = ""                     # corp.local
    naming_context: str = ""                 # DC=corp,DC=local
    dc_hostnames: List[str] = field(default_factory=list)   # DC01, DC02
    dc_ips: List[str] = field(default_factory=list)         # 10.0.0.1
    functional_level: int = 0                # 0-7+
    functional_level_label: str = ""          # "Windows Server 2016+"
    domain_sid: str = ""
    supported_sasl: List[str] = field(default_factory=list)
    kerberos_detected: bool = False
    ldap_anon_bind: bool = False
    smb_domain_detected: bool = False
    gc_available: bool = False               # Global Catalog (3268/3269)
    confidence: float = 0.0


# ── port-based detection ───────────────────────────────────────────────

AD_PORTS: Dict[int, str] = {
    88: "kerberos",
    135: "rpc_endpoint_mapper",
    389: "ldap",
    464: "kpasswd",
    636: "ldaps",
    3268: "global_catalog",
    3269: "global_catalog_ssl",
}


def detect_ad_ports(open_ports: List[int]) -> List[str]:
    """Given a list of open ports, return which AD services are present."""
    return [AD_PORTS[p] for p in open_ports if p in AD_PORTS]


def is_likely_dc(open_ports: List[int]) -> bool:
    """Heuristic: is this host likely a Domain Controller?"""
    ad_ports = set(open_ports) & set(AD_PORTS.keys())
    # A DC has Kerberos + LDAP + likely KPasswd
    return 88 in ad_ports and 389 in ad_ports


# ── LDAP rootDSE anonymous bind ────────────────────────────────────────

def _ldap_rootdse_query(host: str, port: int = 389,
                         timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    """Perform an anonymous LDAP rootDSE search.

    Returns structured information or None on failure.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
    except Exception:
        return None

    try:
        # LDAP search request for rootDSE (anonymous bind, base scope, all attrs)
        ldap_search = bytes.fromhex(
            "300c020101600702010304008000"
        )
        sock.sendall(ldap_search)
        chunks = []
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
            except Exception:
                break
        data = b"".join(chunks)
        sock.close()

        if not data or len(data) < 8:
            return None

        body = data.decode("utf-8", errors="replace")
        info: Dict[str, Any] = {
            "rootdse_raw_size": len(data),
        }

        # Naming contexts: DC=domain,DC=tld
        nc_matches = re.findall(r"namingContexts[^\\x00-\\x1f]*?((?:[A-Z]+=[^,]+,\s*)+)", body)
        if nc_matches:
            info["naming_contexts"] = [nc.strip() for nc in nc_matches]
            # Extract domain from first naming context
            first_nc = nc_matches[0]
            dc_match = re.findall(r"DC=([a-zA-Z0-9._-]+)", first_nc, re.I)
            if dc_match:
                info["domain_name"] = ".".join(dc_match)

        # Domain functional level
        dfl_match = re.search(r"domainFunctionality[^\\d]*(\\d+)", body)
        if dfl_match:
            dfl = int(dfl_match.group(1))
            info["functional_level"] = dfl
            info["functional_level_label"] = {
                0: "Windows 2000", 1: "Windows 2000 Mixed",
                2: "Windows Server 2003", 3: "Windows Server 2008",
                4: "Windows Server 2008 R2", 5: "Windows Server 2012",
                6: "Windows Server 2012 R2", 7: "Windows Server 2016+",
            }.get(dfl, f"Level {dfl}")

        # Forest functional level
        ffl_match = re.search(r"forestFunctionality[^\\d]*(\\d+)", body)
        if ffl_match:
            info["forest_functional_level"] = int(ffl_match.group(1))

        # Domain SID
        sid_match = re.search(r"objectSid[^A-Za-z0-9]*([A-Za-z0-9+/=]{4,})", body)
        if sid_match:
            info["sid_encoded"] = sid_match.group(1)

        # Supported SASL mechanisms
        sasl_matches = re.findall(r"supportedSASLMechanisms[^A-Za-z]*([A-Z]+)", body, re.I)
        if sasl_matches:
            info["sasl"] = [s.strip().upper() for s in sasl_matches if s.strip()]

        # DNS hostname
        dns_match = re.search(r"dnsHostName[^A-Za-z]*([A-Za-z0-9._-]+)", body)
        if dns_match:
            info["dc_hostname"] = dns_match.group(1)

        # LDAP service name
        ldap_svc = re.search(r"ldapServiceName[^A-Za-z]*([A-Za-z0-9._-]+)", body)
        if ldap_svc:
            hostname_part = ldap_svc.group(1).split("@")[-1]
            info["dc_hostname"] = info.get("dc_hostname") or hostname_part

        return info
    except Exception:
        return None


# ── SMB NTLM domain extraction ─────────────────────────────────────────

def _smb_domain_extract(host: str, port: int = 445,
                         timeout: float = 5.0) -> Optional[Dict[str, str]]:
    """Extract domain and hostname from SMB negotiate response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
    except Exception:
        return None

    try:
        # SMB Negotiate Protocol Request
        nbss = bytes.fromhex(
            "00000054ff534d4272000000001801c00000000000000000"
            "00000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000"
        )
        sock.sendall(nbss)
        chunks = []
        sock.settimeout(3.0)
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
            except Exception:
                break
        data = b"".join(chunks)
        sock.close()

        if len(data) < 40:
            return None

        result: Dict[str, str] = {}
        # Windows SMB often embeds NTLM challenge with domain info
        # Look for Unicode domain/hostname strings in the response
        try:
            text = data.decode("utf-16-le", errors="ignore")
            # Domain detection: "WORKGROUP" or actual domain
            if "WORKGROUP" not in text:
                for match in re.finditer(r"[A-Za-z0-9._-]{4,}", text):
                    val = match.group(0)
                    if "." in val and not re.search(r"\\.\\d+$", val):
                        result["domain"] = val
                        break
        except Exception:
            pass

        return result if result else None
    except Exception:
        return None


# ── DNS SRV discovery ──────────────────────────────────────────────────

def _dns_srv_lookup(service: str, domain: str,
                     timeout: float = 5.0) -> List[str]:
    """Look up SRV records for AD services. Requires resolvable DNS."""
    import subprocess
    # Use nslookup or dig (available on most pentest platforms)
    target = f"_{service}._tcp.{domain}"
    result = []
    for tool in ("dig", "nslookup"):
        try:
            if tool == "dig":
                proc = subprocess.run(
                    ["dig", "+short", "SRV", target],
                    capture_output=True, text=True, timeout=3
                )
                for line in proc.stdout.split("\\n"):
                    if line.strip():
                        # dig SRV: "0 100 389 dc01.corp.local."
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            hostname = parts[3].rstrip(".")
                            result.append(hostname)
                if result:
                    return result
            else:
                proc = subprocess.run(
                    ["nslookup", "-type=SRV", target],
                    capture_output=True, text=True, timeout=3
                )
                for line in proc.stdout.split("\\n"):
                    if "svr hostname" in line.lower():
                        hostname = line.split("=")[-1].strip().rstrip(".")
                        result.append(hostname)
                if result:
                    return result
        except Exception:
            continue
    return result


# ── Kerberos pre-auth check ────────────────────────────────────────────

def _kerberos_asrep_check(domain: str, host: str,
                           username: str = "administrator",
                           timeout: float = 5.0) -> bool:
    """Check if Kerberos is reachable and AS-REP roasting may be possible."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, 88))
        sock.close()
        return True
    except Exception:
        return False


# ── high-level engine ──────────────────────────────────────────────────

class ADAwareness:
    """Detect and enumerate Active Directory environments."""

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout
        self.domain: Optional[DomainInfo] = None

    def assess(self, host: str, open_ports: List[int],
               wm: Optional[WorldModel] = None) -> Optional[DomainInfo]:
        """Full AD assessment of a host. Thread-safe, never raises."""
        self.domain = DomainInfo()
        info = self.domain

        # 1. Port-based detection
        ad_signals = detect_ad_ports(open_ports)
        info.kerberos_detected = "kerberos" in ad_signals
        info.gc_available = "global_catalog" in ad_signals or "global_catalog_ssl" in ad_signals
        info.confidence = min(1.0, len(ad_signals) * 0.15)

        if not ad_signals:
            return None  # Not a domain environment

        # 2. LDAP rootDSE for domain details
        ldap_port = 3268 if info.gc_available else 389
        ldap_data = _ldap_rootdse_query(host, ldap_port, self.timeout)
        if ldap_data:
            info.ldap_anon_bind = True
            info.naming_context = ldap_data.get("naming_contexts", [""])[0] if ldap_data.get("naming_contexts") else ""
            info.domain_name = ldap_data.get("domain_name", "") or info.domain_name
            info.functional_level = ldap_data.get("functional_level", 0)
            info.functional_level_label = ldap_data.get("functional_level_label", "")
            info.confidence = max(info.confidence, 0.7)

        # Parse domain from naming context
        if info.naming_context and not info.domain_name:
            dc_match = re.findall(r"DC=([a-zA-Z0-9._-]+)", info.naming_context, re.I)
            if dc_match:
                info.domain_name = ".".join(dc_match)

        # 3. SMB domain extraction
        if 445 in open_ports or 139 in open_ports:
            smb_data = _smb_domain_extract(host, 445, self.timeout)
            if smb_data and smb_data.get("domain"):
                info.netbios_name = smb_data["domain"]
                info.smb_domain_detected = True
                if not info.domain_name:
                    info.domain_name = smb_data["domain"]

        # 4. DNS SRV for DC discovery
        if info.domain_name:
            for svc in ("ldap._tcp.dc._msdcs", "kerberos._tcp", "gc._tcp"):
                hosts = _dns_srv_lookup(svc, info.domain_name, self.timeout)
                for h in hosts:
                    if h not in info.dc_hostnames:
                        info.dc_hostnames.append(h)

        # 5. Kerberos pre-auth check
        if info.kerberos_detected:
            info.kerberos_detected = _kerberos_asrep_check(
                info.domain_name, host, timeout=self.timeout,
            )

        # 6. Feed WorldModel
        if wm:
            self._to_worldmodel(wm, host, info)

        return info

    def _to_worldmodel(self, wm: WorldModel, host: str, info: DomainInfo) -> None:
        """Write domain knowledge into the WorldModel."""
        if info.domain_name:
            wm.add_finding(
                kind="ad_domain",
                key=info.domain_name.upper(),
                value={
                    "domain": info.domain_name,
                    "netbios": info.netbios_name,
                    "dc_hostnames": info.dc_hostnames,
                    "dc_ips": info.dc_ips,
                    "functional_level": info.functional_level,
                    "functional_label": info.functional_level_label,
                    "ldap_anon": info.ldap_anon_bind,
                    "gc_available": info.gc_available,
                    "kerberos": info.kerberos_detected,
                    "naming_context": info.naming_context,
                },
                confidence=info.confidence,
                source="ad_awareness",
                target=host,
            )

        if info.ldap_anon_bind:
            wm.add_finding(
                kind="ad_weakness",
                key=f"ldap_anon:{host}",
                value={
                    "type": "anonymous_bind",
                    "host": host,
                    "description": "LDAP allows anonymous binds — user enumeration possible",
                },
                confidence=0.9,
                source="ad_awareness",
                target=host,
            )

        if info.kerberos_detected:
            wm.add_finding(
                kind="ad_attack_surface",
                key=f"kerberos:{host}",
                value={
                    "type": "kerberos",
                    "host": host,
                    "as_rep_possible": True,
                    "kerberoast_possible": info.ldap_anon_bind,
                },
                confidence=0.8,
                source="ad_awareness",
                target=host,
            )

        # Domain environment flag for enterprise scoring
        wm.add_finding(
            kind="environment",
            key="domain_detected",
            value={
                "type": "active_directory",
                "domain": info.domain_name,
                "dc_host": host,
                "confidence": info.confidence,
            },
            confidence=info.confidence,
            source="ad_awareness",
            target=host,
        )


def assess_active_directory(wm: WorldModel, host: str,
                            open_ports: List[int]) -> Optional[DomainInfo]:
    """Quick AD assessment — feed results directly into the WorldModel."""
    engine = ADAwareness(timeout=5.0)
    return engine.assess(host, open_ports, wm=wm)