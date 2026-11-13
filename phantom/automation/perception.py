"""
perception.py — turn raw tool output into typed Findings.

Each interpreter is pure (output -> list of dicts with
{kind, key, value, confidence, evidence}) so it is trivially testable
and reusable by any capability's interpreter slot.
"""

from __future__ import annotations

import json
import re
from typing import List, Dict, Any, Optional


def _p(**kw) -> Dict[str, Any]:
    kw.setdefault("confidence", 0.5)
    kw.setdefault("evidence", "")
    kw.setdefault("source", "perception")
    return kw


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------

# nmap labels a TLS-wrapped service with the WRAPPED protocol after a
# slash (`ssl/http` on 443, `ssl/ldap` on 636, `ssl/smtp` on 465). Keep the
# full token: truncating it to `ssl` erases the distinction between an
# HTTPS server and an LDAPS/IMAPS/SMTPS service, which made the web gates
# (`web_creds`/`web_rce`) fire against a non-web surface.
_NMAP_PORT_RE = re.compile(
    r"(\d+)/(tcp|udp)[ \t]+open[ \t]+([\w\-\./]+)(?:[ \t]+([^\n]*))?"
)

# Ports whose conventional service nmap's /etc/services database gets wrong.
# The Docker lab exposes SSH on 2222 and HTTP on 8081; nmap labels them
# `EtherNetIP-1` and `blackice-icecap`, so the planner never saw an SSH or web
# surface and refused the credentials the app had just leaked. Only replace
# labels that are known placeholders: a real banner/fingerprint still wins.
_ALT_PORT_SERVICES = {
    "2222": "ssh",
    "22222": "ssh",
    "2121": "ftp",
    "8081": "http",
    "8080": "http",
    "8443": "https",
}
_AMBIGUOUS_SERVICES = {
    "", "unknown", "ethernetip-1", "blackice-icecap", "http-alt",
    "https-alt", "tcpwrapped",
}


def normalize_service(port: object, service: str) -> str:
    """Correct an nmap placeholder label on a conventional alternate port.

    The port number is the only evidence available in a port-only scan; this
    deliberately does not override an explicit non-placeholder banner.
    """
    raw = str(service or "").strip().lower()
    if raw in _AMBIGUOUS_SERVICES:
        return _ALT_PORT_SERVICES.get(str(port), service)
    return service
# nc -zv floor sweep: "Connection to 10.0.0.9 22 port [tcp/ssh] succeeded!"
# (BSD netcat) or "connect to 10.0.0.9 22 port 22 tcp: Connection refused"-style
# open report (traditional / OpenBSD variants). Only SUCCEEDED connects
# count as open ports.
_NC_PORT_RE = re.compile(
    r"(?:Connection to|connect to)[ \t]+[\d\.]+[ \t]+(\d+)[ \t]+port[ \t]+"
    r"(?:\[tcp/([\w\-\*]+)\][ \t]+)?succeeded",
    re.IGNORECASE,
)
# masscan: "Discovered open port 80/tcp on 10.0.0.9"
_MASSCAN_PORT_RE = re.compile(
    r"Discovered open port (\d+)/(tcp|udp) on ([\d\.]+)", re.IGNORECASE
)
_OS_DETAILS_RE = re.compile(r"OS details: (.*)", re.IGNORECASE)
_OS_MATCH_RE = re.compile(r"OS:\s*([^\n]+)", re.IGNORECASE)
_SCRIPT_RE = re.compile(r"\|\s*([\w\-\.]+):\s*\n?((?:\|.*\n?)+)")


def parse_nmap_ports(output: str, source: str = "nmap") -> List[Dict[str, Any]]:
    """Extract open ports/services/versions from TEXT output.

    Accepts nmap's classic table, the toolbelt's `nc -zv` floor sweep and
    masscan 'Discovered open port' lines — so every scan implementer feeds
    the same `service` facts downstream. nc/masscan lines carry no service
    label; the well-known-port table fills the gap (weak labels are fine:
    version_detect and the fingerprint engine re-probe and correct).

    A scan REPORT is an advertisement, not a handshake. Measured 2026-11-02:
    the ``decoy_scan`` benchmark plants ``3306/tcp open mysql`` on a host
    with no MySQL, and the run stored it as a service fact (false positive
    ``service:tcp/3306``) then planned around it. So a port that only a
    report claims is marked ``advertised: True`` and stays non-actionable
    until ``WorldModel.confirm_service`` sees the port answer.

    The ``nc -zv`` branch is the exception on purpose: its line is logged
    only after the TCP connect SUCCEEDED ("Connection to ... succeeded"),
    which is the handshake the other two formats only promise. It is marked
    confirmed here rather than advertised, otherwise the one genuinely
    probed path would need a second probe to trust itself."""
    if not output:
        return []
    findings = []
    seen = set()
    for m in _NMAP_PORT_RE.finditer(output):
        port, proto, svc, ver = m.group(1), m.group(2), m.group(3), (m.group(4) or "").strip()
        if (port, proto) in seen:
            continue
        seen.add((port, proto))
        svc = normalize_service(port, svc)
        value = {"port": port, "protocol": proto, "service": svc,
                 "version": ver, "product": "", "advertised": True}
        if ver:
            value["product"] = ver.split()[0] if ver else ""
        findings.append(_p(kind="service", key=f"{proto}/{port}", value=value,
                           confidence=0.9, evidence=m.group(0), source=source))
    if findings:
        return findings
    # toolbelt floor sweep (nc -zv)
    from phantom.automation.fingerprint.probes import PORT_SERVICE_MAP
    for m in _NC_PORT_RE.finditer(output):
        port = m.group(1)
        if port in seen:
            continue
        seen.add(port)
        svc = m.group(2) or PORT_SERVICE_MAP.get(int(port), "unknown")
        if svc == "*":       # nc prints [tcp/*] for an unassigned port
            svc = PORT_SERVICE_MAP.get(int(port), "unknown")
        findings.append(_p(kind="service", key=f"tcp/{port}",
                           value={"port": port, "protocol": "tcp",
                                  "service": svc, "version": "", "product": "",
                                  # a logged SUCCEEDED connect: confirmed, not
                                  # merely advertised (see the docstring)
                                  "advertised": False},
                           confidence=0.7, evidence=m.group(0), source=source or "nc"))
    if findings:
        return findings
    # masscan full-range sweep
    for m in _MASSCAN_PORT_RE.finditer(output):
        port, proto, host = m.group(1), m.group(2), m.group(3)
        if port in seen:
            continue
        seen.add(port)
        svc = PORT_SERVICE_MAP.get(int(port), "unknown")
        findings.append(_p(kind="service", key=f"{proto}/{port}",
                           value={"port": port, "protocol": proto,
                                  "service": svc, "version": "", "product": "",
                                  "advertised": True},
                           confidence=0.7, evidence=m.group(0),
                           source=source or "masscan"))
    return findings


def parse_nmap_os(output: str, source: str = "nmap") -> List[Dict[str, Any]]:
    if not output:
        return []
    m = _OS_DETAILS_RE.search(output) or _OS_MATCH_RE.search(output)
    if not m:
        return []
    name = m.group(1).strip()
    return [_p(kind="os", key="detected", value={"name": name, "accuracy": 90},
               confidence=0.8, evidence=m.group(0), source=source)]


def parse_nmap_script_creds(output: str, source: str = "nmap_scripts") -> List[Dict[str, Any]]:
    """Extract credentials from Nmap script output blocks."""
    if not output:
        return []
    creds = []
    for script_id, block in _SCRIPT_RE.findall(output):
        clean = re.sub(r"^\s*\|_?\s*", "", block, flags=re.MULTILINE)
        users = re.findall(r"(?:username|user|account)\s*[:\-=]\s*([^\s,;]+)", clean, re.I)
        passes = re.findall(r"(?:password|pass)\s*[:\-=]\s*([^\s,;]+)", clean, re.I)
        for i, u in enumerate(users):
            p = passes[i] if i < len(passes) else ""
            if u and p:
                creds.append(_p(kind="creds", key=f"{script_id}:{u}", value={
                    "username": u, "password": p, "service": "", "method": f"nmap_{script_id}"
                }, confidence=0.6, evidence=script_id, source=source))
    return creds


# ---------------------------------------------------------------------------
# banners / fingerprint
# ---------------------------------------------------------------------------

def parse_ssh_banner(line: str) -> Optional[Dict[str, Any]]:
    if not line:
        return None
    m = re.search(r"SSH-2\.0-([^\s]+)", line)
    if not m:
        return None
    return _p(kind="banner", key="ssh", value={"product": m.group(1)},
              confidence=0.9, evidence=line, source="banner")


def parse_http_banner(headers: str) -> List[Dict[str, Any]]:
    if not headers:
        return []
    findings = []
    for name in ("Server", "X-Powered-By", "X-Generator"):
        m = re.search(rf"^{name}:\s*(.+)$", headers, re.I | re.MULTILINE)
        if m:
            findings.append(_p(kind="web_header", key=name.lower(),
                               value={name.lower(): m.group(1).strip()},
                               confidence=0.8, evidence=m.group(0), source="http"))
    title = re.search(r"<title[^>]*>(.*?)</title>", headers, re.I | re.S)
    if title:
        findings.append(_p(kind="web_title", key="title",
                           value={"title": title.group(1).strip()},
                           confidence=0.7, evidence=title.group(0)[:120], source="http"))
    return findings


_CMS_HINTS = [
    ("wordpress", r"wp-content|wp-includes|wordpress"),
    ("joomla", r"joomla|com_content"),
    ("drupal", r"drupal|/sites/default/"),
    ("shopify", r"cdn\.shopify|myshopify"),
    ("prestashop", r"prestashop|presta"),
]


def detect_cms(html_or_headers: str) -> Optional[Dict[str, Any]]:
    if not html_or_headers:
        return None
    low = html_or_headers.lower()
    for cms, pattern in _CMS_HINTS:
        if re.search(pattern, low):
            return _p(kind="web_app", key=cms, value={"name": cms, "version": ""},
                      confidence=0.8, evidence=pattern, source="http")
    return None


# ---------------------------------------------------------------------------
# service-specific
# ---------------------------------------------------------------------------

def parse_smb_shares(output: str, source: str = "smbmap") -> List[Dict[str, Any]]:
    """smbmap -H output: column-aligned shares with permission markers."""
    if not output:
        return []
    shares = []
    for line in output.splitlines():
        if not line.strip() or line.startswith("----"):
            continue
        cols = [c.strip() for c in line.split("  ") if c.strip()]
        if len(cols) < 3 or cols[0] in ("Sharename", "----------"):
            continue
        name, typ, perm = cols[0], cols[1], cols[2]
        comment = cols[3] if len(cols) > 3 else ""
        if "IPC$" in name:
            perm = "READ ONLY"
        if not any(p in perm.upper() for p in ("READ", "WRITE", "EXEC")):
            continue
        shares.append(_p(kind="smb_share", key=name, value={
            "name": name, "type": typ, "permissions": perm, "comment": comment,
            "writable": "WRITE" in perm.upper(),
        }, confidence=0.7, evidence=line.strip(), source=source))
    return shares


def parse_redis_info(output: str) -> List[Dict[str, Any]]:
    """Redis INFO output → version + role + save-persistence facts."""
    if not output:
        return []
    findings = []
    m = re.search(r"redis_version:([\d\.]+)", output)
    if m:
        findings.append(_p(kind="redis", key="version", value={"version": m.group(1)},
                           confidence=0.9, evidence=m.group(0), source="redis"))
    m = re.search(r"role:(\w+)", output)
    if m:
        findings.append(_p(kind="redis", key="role", value={"role": m.group(1)},
                           confidence=0.9, evidence=m.group(0), source="redis"))
    if "protected mode: no" in output.lower() or "protected-mode no" in output.lower():
        findings.append(_p(kind="redis", key="no_auth", value={"no_auth": True},
                           confidence=0.9, evidence="protected mode disabled", source="redis"))
    return findings


def parse_mysql_dump(output: str) -> List[Dict[str, Any]]:
    """Extract version/credentials-ish facts from mysql client errors/info."""
    if not output:
        return []
    findings = []
    m = re.search(r"Welcome to the MySQL monitor.*?Server version:\s*([\d\.]+)", output, re.S)
    if m:
        findings.append(_p(kind="mysql", key="version", value={"version": m.group(1)},
                           confidence=0.8, evidence=m.group(0)[:80], source="mysql"))
    return findings


# ---------------------------------------------------------------------------
# generic
# ---------------------------------------------------------------------------

def parse_key_value_list(output: str, kind: str, key_field: str) -> List[Dict[str, Any]]:
    """Generic 'k = v' / 'k: v' lines → findings of one kind."""
    if not output:
        return []
    findings = []
    for line in output.splitlines():
        m = re.match(r"^\s*([\w\-\.]+)\s*[=:]\s*(.+)$", line.strip())
        if m:
            findings.append(_p(kind=kind, key=m.group(1),
                               value={key_field: m.group(2).strip()},
                               confidence=0.6, evidence=line.strip()))
    return findings


def parse_json_output(output: str, kind: str, value_key: str = "data") -> List[Dict[str, Any]]:
    if not output:
        return []
    try:
        data = json.loads(output)
    except (json.JSONDecodeError, ValueError, TypeError):
        return []
    if isinstance(data, list):
        return [_p(kind=kind, key=str(i), value={value_key: item},
                   confidence=0.9, evidence=str(item)[:200]) for i, item in enumerate(data)]
    return [_p(kind=kind, key="root", value=data, confidence=0.9, evidence=output[:200])]
