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

_NMAP_PORT_RE = re.compile(
    r"(\d+)/(tcp|udp)[ \t]+open[ \t]+([\w\-\.]+)(?:[ \t]+([^\n]*))?"
)
_OS_DETAILS_RE = re.compile(r"OS details: (.*)", re.IGNORECASE)
_OS_MATCH_RE = re.compile(r"OS:\s*([^\n]+)", re.IGNORECASE)
_SCRIPT_RE = re.compile(r"\|\s*([\w\-\.]+):\s*\n?((?:\|.*\n?)+)")


def parse_nmap_ports(output: str, source: str = "nmap") -> List[Dict[str, Any]]:
    """Extract open ports/services/versions from text output."""
    if not output:
        return []
    findings = []
    seen = set()
    for m in _NMAP_PORT_RE.finditer(output):
        port, proto, svc, ver = m.group(1), m.group(2), m.group(3), (m.group(4) or "").strip()
        if (port, proto) in seen:
            continue
        seen.add((port, proto))
        value = {"port": port, "protocol": proto, "service": svc,
                 "version": ver, "product": ""}
        if ver:
            value["product"] = ver.split()[0] if ver else ""
        findings.append(_p(kind="service", key=f"{proto}/{port}", value=value,
                           confidence=0.9, evidence=m.group(0), source=source))
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
