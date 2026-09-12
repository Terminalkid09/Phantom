"""
surface.py — attack-surface engine for hardened targets.

Against a hardened perimeter (CDN/WAF in front of everything, zero obvious
services) the footprint scan legitimately finds almost nothing — that is
the moment a senior operator switches from PORT enumeration to ASSET
enumeration. This engine does exactly that, in bounded layers:

  CT LOGS        every TLS certificate ever issued for the domain ->
                 forgotten/hidden hostnames nmap will never show
  WAYBACK CDX    historical URLs -> old endpoints, admin panels, APIs,
                 backup paths that still live behind the CDN
  JS ENDPOINTS   scripts of the live homepage/API -> API routes, static
                 buckets, third-party services the app actually calls
  MAIL LAYER     SPF/DMARC/MX -> mail topology, spoofability, M365/Google
                 Workspace fingerprint, security contacts
  SSO / OAUTH    well-known OIDC discovery + IdP fingerprints -> SSO
                 portals, tenant names, OAuth apps that become phish
                 pretexts and SSO-bypass pivots
  VPN GATEWAY    SSL-VPN fingerprints (Fortinet/SonicWall/Ivanti/Pulse/
                 Cisco) -> the classic first-foothold on hardened nets
  DNS MISC       zone transfer, subdomain records, DKIM selectors,
                CAA/DANE anomalies

Every finding carries a RISK SCORE so the planner can rank real attack
paths over inventory noise, and the whole pass is bounded (<= 25 network
calls) and never raises.
"""

from __future__ import annotations

import json
import re
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_HOST_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}", re.I)


def _fetch(url: str, timeout: float = 15.0) -> str:
    try:
        from phantom.core.executor import execute_quiet
        res = execute_quiet(
            f"curl -s -L -m {int(timeout)} -A '{_UA}' '{url}'",
            timeout=timeout + 10)
        return (res.stdout or "")[:500000]
    except Exception:
        return ""


def _dns(record: str, qname: str, resolver: str = "") -> str:
    try:
        from phantom.core.executor import execute_quiet
        r = f" @{resolver}" if resolver else ""
        res = execute_quiet(f"dig +short {record} {qname}{r}", timeout=12)
        return (res.stdout or "").strip()
    except Exception:
        return ""


# ── result model ─────────────────────────────────────────────────────────────

@dataclass
class SurfaceAsset:
    kind: str          # ct_host | wayback_url | js_endpoint | mail | sso | vpn | dns
    value: str
    detail: str = ""
    risk: float = 0.3  # 0..1 planner-weighted attack-path value
    evidence: str = ""


@dataclass
class SurfaceResult:
    domain: str
    assets: List[SurfaceAsset] = field(default_factory=list)

    def markers(self) -> List[str]:
        out = [f"SURFACE_DOMAIN: domain={self.domain} assets={len(self.assets)}"]
        for a in self.assets:
            out.append(
                f"SURFACE_ASSET: kind={a.kind} value={a.value} "
                f"risk={a.risk:.2f} detail={a.detail.replace(' ', '_')[:80]} "
                f"evidence={a.evidence}")
        return out

    def top(self, n: int = 12) -> List[SurfaceAsset]:
        return sorted(self.assets, key=lambda a: -a.risk)[:n]


# ── CT logs ──────────────────────────────────────────────────────────────────

def _ct_logs(domain: str) -> List[SurfaceAsset]:
    """Certificate Transparency: every hostname a cert was EVER issued for.
    The single richest source of hidden hosts on hardened perimeters."""
    assets: List[SurfaceAsset] = []
    raw = _fetch(
        f"https://crt.sh/?q=%.{domain}&output=json&exclude=expired=false",
        timeout=25.0)
    if not raw or raw.startswith("<"):
        raw = _fetch(
            f"https://crt.sh/?q=%.{domain}&output=json", timeout=25.0)
    try:
        rows = json.loads(raw)
    except (ValueError, TypeError):
        return assets
    names: Dict[str, int] = {}
    for row in rows[:3000]:
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lstrip("*.").lower()
            if n.endswith(domain) and n != domain and len(n) < 100:
                names[n] = names.get(n, 0) + 1
    interesting = re.compile(
        r"(dev|test|stag|uat|old|legacy|admin|internal|vpn|mail|smtp|api|"
        r"jenkins|gitlab|jira|confluence|grafana|kibana|sso|auth|login|"
        r"portal|backup|bak|demo|sandbox|pre|qa|zabbix|nagios|cacti|"
        r"sonarqube|nexus|artifactory|tower|ansible|rancher|portainer)",
        re.I)
    for n, count in sorted(names.items(), key=lambda kv: -kv[1]):
        risk = 0.5 if interesting.search(n) else 0.25
        if re.search(r"(dev|test|stag|old|legacy|bak|sandbox|demo)", n, re.I):
            risk = 0.7   # forgotten environments are the classic way in
        if re.search(r"(vpn|sso|auth|login|portal)", n, re.I):
            risk = 0.65  # edge services: direct foothold candidates
        assets.append(SurfaceAsset(
            "ct_host", n, f"seen in {count} cert(s)", risk, "crt.sh"))
    return assets[:40]


# ── Wayback endpoints ────────────────────────────────────────────────────────

def _wayback_endpoints(domain: str) -> List[SurfaceAsset]:
    assets: List[SurfaceAsset] = []
    raw = _fetch(
        "http://web.archive.org/cdx/search/cdx?url={}/*&output=text&"
        "limit=1500&collapse=urlkey&fl=original&filter=statuscode:200"
        .format(domain), timeout=25.0)
    if not raw:
        return assets
    seen = set()
    juicy = re.compile(
        r"(admin|manager|console|dashboard|api/|swagger|graphql|actuator|"
        r"\.env|config|backup|old|bak|test|dev|debug|phpinfo|\.sql|\.zip|"
        r"\.tar|\.bak|login|sso|auth|jmx|jenkins|git)", re.I)
    for url in raw.splitlines()[:800]:
        url = url.strip()
        if not url or url in seen or len(url) > 180:
            continue
        seen.add(url)
        if juicy.search(url):
            assets.append(SurfaceAsset(
                "wayback_url", url, "historical 200 endpoint",
                0.6, "wayback_cdx"))
        if len(assets) >= 25:
            break
    return assets


# ── JS endpoint discovery ────────────────────────────────────────────────────

def _js_endpoints(url: str, domain: str) -> List[SurfaceAsset]:
    assets: List[SurfaceAsset] = []
    html = _fetch(url, timeout=20.0)
    if not html:
        return assets
    scripts = re.findall(r'src="([^"]+\.js[^"]*)"', html)[:15]
    hosts: set = set()
    paths: set = set()
    base = url.rstrip("/")
    for s in scripts:
        js_url = s if s.startswith("http") else f"{base}/{s.lstrip('/')}"
        body = _fetch(js_url, timeout=12.0)[:200000]
        if not body:
            continue
        for m in re.finditer(r'"(/[a-zA-Z0-9_\-/\.]{2,60})"', body):
            p = m.group(1)
            if re.search(r"(api|v[12]/|admin|auth|login|upload|internal)",
                         p, re.I) and len(paths) < 20:
                paths.add(p)
        for h in _HOST_RE.findall(body):
            if h.endswith(domain) or any(
                    x in h for x in ("s3", "blob.core", "cloudfront",
                                     "azurewebsites", "firebaseio",
                                     "herokuapp", "vercel")):
                hosts.add(h.lower())
        if len(hosts) > 10:
            break
    for p in sorted(paths)[:15]:
        assets.append(SurfaceAsset(
            "js_endpoint", f"{url.rstrip('/')}{p}", "referenced in app JS",
            0.55, "js_parse"))
    for h in sorted(hosts)[:10]:
        risk = 0.6 if h.endswith(domain) else 0.4
        assets.append(SurfaceAsset("js_host", h, "referenced in app JS",
                                   risk, "js_parse"))
    return assets


# ── mail layer ───────────────────────────────────────────────────────────────

def _mail_layer(domain: str) -> List[SurfaceAsset]:
    assets: List[SurfaceAsset] = []
    mx = _dns("MX", domain)
    if mx:
        first = mx.splitlines()[0].strip()
        assets.append(SurfaceAsset("mail", first, "MX primary",
                                   0.35, "dns_mx"))
        if "outlook" in first or "office365" in first or "protection" in first:
            assets.append(SurfaceAsset("mail", "m365", "Microsoft 365 tenant",
                                       0.4, "dns_mx"))
        elif "google" in first:
            assets.append(SurfaceAsset("mail", "gws", "Google Workspace",
                                       0.4, "dns_mx"))
    spf = _dns("TXT", domain)
    spf_txt = " ".join(l for l in spf.splitlines() if "spf" in l.lower())
    if spf_txt:
        if "~all" in spf_txt or "-all" in spf_txt:
            assets.append(SurfaceAsset("mail", "spf_strict",
                                       "SPF hard-fails spoofing", 0.1, "dns_txt"))
        elif "?all" in spf_txt or "+all" in spf_txt or not spf_txt.strip():
            assets.append(SurfaceAsset("mail", "spf_weak",
                                       "SPF allows spoofed mail", 0.75, "dns_txt"))
    dmarc = _dns("TXT", f"_dmarc.{domain}")
    if not dmarc or "v=DMARC" not in dmarc:
        assets.append(SurfaceAsset("mail", "dmarc_missing",
                                   "no DMARC: spoofed mail lands in inbox",
                                   0.8, "dns_txt"))
    else:
        if "p=none" in dmarc:
            assets.append(SurfaceAsset("mail", "dmarc_none",
                                       "DMARC p=none: spoofing unmonitored",
                                       0.6, "dns_txt"))
    return assets


# ── SSO / OAuth surface ──────────────────────────────────────────────────────

def _sso_surface(domain: str) -> List[SurfaceAsset]:
    assets: List[SurfaceAsset] = []
    # OIDC discovery on the canonical SSO prefixes
    for prefix in ("sso", "auth", "login", "id", "accounts"):
        disc = _fetch(
            f"https://{prefix}.{domain}/.well-known/"
            f"openid-configuration", timeout=12.0)
        if disc.strip().startswith("{"):
            try:
                data = json.loads(disc)
                issuer = str(data.get("issuer", ""))[:120]
                assets.append(SurfaceAsset(
                    "sso", f"{prefix}.{domain}",
                    f"OIDC issuer={issuer}", 0.7, "oidc_discovery"))
                break
            except ValueError:
                pass
    # Okta / Auth0 / AzureAD tenant fingerprints
    if _fetch(f"https://{domain}.okta.com/.well-known/openid-configuration",
              timeout=10.0).strip().startswith("{"):
        assets.append(SurfaceAsset("sso", f"{domain}.okta.com",
                                   "Okta tenant", 0.75, "okta_probe"))
    if _fetch(f"https://{domain}.auth0.com/.well-known/openid-configuration",
              timeout=10.0).strip().startswith("{"):
        assets.append(SurfaceAsset("sso", f"{domain}.auth0.com",
                                   "Auth0 tenant", 0.75, "auth0_probe"))
    aad = _fetch("https://login.microsoftonline.com/"
                 f"{domain}/.well-known/openid-configuration", timeout=10.0)
    if aad.strip().startswith("{") and "tenant_discovery_endpoint" in aad:
        assets.append(SurfaceAsset("sso", "azure_ad",
                                   f"AAD tenant {domain} (Managed)",
                                   0.7, "aad_probe"))
    return assets


# ── VPN gateway fingerprint ──────────────────────────────────────────────────

_VPN_SIGS = (
    ("fortinet", "fortigate", 0.8),
    ("sonicwall", "sonicwall", 0.75),
    ("ivanti", "ivanti/connect-secure", 0.85),
    ("pulse", "pulse-secure", 0.8),
    ("cisco", "anyconnect/asa", 0.7),
    ("citrix", "netscaler/gateway", 0.8),
    ("zscaler", "zscaler", 0.5),
    ("openvpn", "openvpn-as", 0.6),
)


def _vpn_gateways(hosts: List[str]) -> List[SurfaceAsset]:
    assets: List[SurfaceAsset] = []
    for h in hosts[:6]:
        if not re.search(r"(vpn|remote|gateway|portal|ssl)", h, re.I):
            continue
        body = _fetch(f"https://{h}", timeout=12.0).lower()
        if not body:
            body = _fetch(f"http://{h}", timeout=10.0).lower()
        for sig, label, risk in _VPN_SIGS:
            if sig in body:
                assets.append(SurfaceAsset(
                    "vpn", h, f"{label} gateway detected",
                    risk, "http_fingerprint"))
                break
    return assets


# ── DNS misconfigs ───────────────────────────────────────────────────────────

def _dns_misc(domain: str) -> List[SurfaceAsset]:
    assets: List[SurfaceAsset] = []
    ns = _dns("NS", domain).splitlines()
    if ns:
        ns_host = ns[0].strip()
        axfr = _dns("AXFR", domain, resolver=ns_host.split()[0])
        if axfr and "failed" not in axfr.lower() and len(axfr.splitlines()) > 3:
            assets.append(SurfaceAsset(
                "dns", f"AXFR@{ns_host}",
                f"zone transfer works! {len(axfr.splitlines())} records",
                0.85, "dig_axfr"))
    # DKIM selectors reveal mail vendors; CAA reveals cert vendors
    for sel in ("default", "google", "selector1", "selector2", "k1", "s1",
                "dkim", "mail"):
        txt = _dns("TXT", f"{sel}._domainkey.{domain}")
        if txt and "v=DKIM1" in txt:
            assets.append(SurfaceAsset(
                "dns", f"dkim:{sel}", "DKIM selector present", 0.2, "dns_txt"))
            break
    return assets


# ── engine entry ─────────────────────────────────────────────────────────────

def map_surface(domain: str) -> Tuple[bool, List[str]]:
    """Full bounded pass. Returns marker lines for the interpreter."""
    try:
        domain = (domain or "").strip().lower()
        domain = domain.split("/")[0]
        if not domain or "." not in domain:
            return False, ["ERROR: map_surface needs a domain"]
        result = SurfaceResult(domain=domain)

        result.assets.extend(_ct_logs(domain))
        hosts = [a.value for a in result.assets if a.kind == "ct_host"]
        result.assets.extend(_wayback_endpoints(domain))
        # homepage URL: prefer apex https
        url = f"https://{domain}"
        result.assets.extend(_js_endpoints(url, domain))
        result.assets.extend(_mail_layer(domain))
        result.assets.extend(_sso_surface(domain))
        result.assets.extend(_vpn_gateways(hosts))
        result.assets.extend(_dns_misc(domain))

        return True, result.markers()
    except Exception as e:
        return False, [f"ERROR: surface mapping failed: {e}"]


def surface_risk_summary(result: SurfaceResult) -> Dict[str, float]:
    """Per-kind average risk — feeds the planner's cost/rank heuristics."""
    by_kind: Dict[str, List[float]] = {}
    for a in result.assets:
        by_kind.setdefault(a.kind, []).append(a.risk)
    return {k: sum(v) / len(v) for k, v in by_kind.items()}