"""
reasoning.py — deterministic red-team inference engine.

Sits between perception (findings) and the planner. Applies explicit,
traceable rules that combine OS signals, open services, software versions,
Active Directory markers, credentials and identity context into NEW
hypotheses + deduced findings. No CVE database, no LLM: it reasons over
bug *classes* and attack-path logic the way a senior operator would.

Outputs (all source="reasoning", confidence <= 0.7 so they are never
mistaken for confirmed facts):

  * deduced findings in dedicated kinds — `os_inferred`, `service_role`,
    `ad_hint`, `vuln_class`, `attack_path` — none of which gate any
    capability, so an inference can guide but never *authorize* a move.
  * hypotheses (capability_id + reason + cost + priority) the planner can
    verify cheaply; the agent exposes them as planner preferences.

The engine is idempotent: re-running it on the same WorldModel adds no
duplicate findings (keyed) and no duplicate hypotheses (capability+reason).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from phantom.automation.belief import Finding, Hypothesis, WorldModel


@dataclass
class ReasoningResult:
    """What one reasoning pass produced (and registered on the WorldModel)."""
    findings: List[Finding] = field(default_factory=list)
    hypotheses: List[Hypothesis] = field(default_factory=list)
    preferences: List[str] = field(default_factory=list)  # capability ids


# ---------------------------------------------------------------------------
# port → role / OS signal tables (single source of truth)
# ---------------------------------------------------------------------------

_WEB_PORTS = {"80", "443", "8080", "8443", "8000", "8888", "3000", "5000"}
_DB_PORTS = {"3306", "5432", "1433", "6379", "27017", "27018", "9200",
             "11211", "1521", "5984"}
_MAIL_PORTS = {"25", "110", "143", "465", "587", "993", "995"}
_AD_PORTS = {"88", "389", "636", "3268", "3269", "464"}
_WINDOWS_PORTS = {"135", "139", "445", "3389", "5985", "5986"}
_LINUX_PORTS = {"22", "111", "2049"}
_ANDROID_PORTS = {"5555"}
_DNS_PORTS = {"53"}
_FTP_PORTS = {"21"}
_SNMP_PORTS = {"161", "162"}
_DOCKER_PORTS = {"2375", "2376"}
_VNC_PORTS = {"5900", "5901", "5902"}
_TELNET_PORTS = {"23"}
_K8S_PORTS = {"6443", "10250", "10255"}

_ROLE_BY_PORT = {}
for _p in _WEB_PORTS:
    _ROLE_BY_PORT[_p] = "web"
for _p in _DB_PORTS:
    _ROLE_BY_PORT[_p] = "database"
for _p in _MAIL_PORTS:
    _ROLE_BY_PORT[_p] = "mail"
for _p in _AD_PORTS:
    _ROLE_BY_PORT[_p] = "active-directory"
for _p in _WINDOWS_PORTS:
    _ROLE_BY_PORT[_p] = "windows-remote"
for _p in _LINUX_PORTS:
    _ROLE_BY_PORT[_p] = "unix-remote"
for _p in _ANDROID_PORTS:
    _ROLE_BY_PORT[_p] = "android"
for _p in _DNS_PORTS:
    _ROLE_BY_PORT[_p] = "dns"
for _p in _FTP_PORTS:
    _ROLE_BY_PORT[_p] = "file-transfer"
for _p in _SNMP_PORTS:
    _ROLE_BY_PORT[_p] = "snmp"
for _p in _DOCKER_PORTS:
    _ROLE_BY_PORT[_p] = "container-orchestration"
for _p in _VNC_PORTS:
    _ROLE_BY_PORT[_p] = "remote-desktop"
for _p in _TELNET_PORTS:
    _ROLE_BY_PORT[_p] = "remote-terminal"
for _p in _K8S_PORTS:
    _ROLE_BY_PORT[_p] = "kubernetes"


class ReasoningEngine:
    """Deterministic inference: findings -> deduced findings + hypotheses."""

    def __init__(self, registry=None, paranoid: bool = False) -> None:
        # registry is optional so the engine stays unit-testable without a
        # full capability library; when present, hypotheses are validated
        # against real capability ids and paranoid mode drops loud caps.
        self.registry = registry
        self.paranoid = paranoid
        self._peers: List[str] = []

    # ------------------------------------------------------------- helpers

    def _cap_stealth(self, cap_id: str) -> Optional[str]:
        if self.registry is None:
            return None
        cap = getattr(self.registry, "get", lambda _id: None)(cap_id)
        return getattr(cap, "stealth_level", None)

    def _loud(self, cap_id: str) -> bool:
        # forceful = loud by nature (mass brute / auto-exploit / AD attacks /
        # lateral movement) — paranoid refuses THESE, not every capability
        # that happens to be tagged stealth_level="aggressive" (a single
        # ssh_login or beacon deploy must stay available in paranoid mode).
        if self.registry is None:
            return False
        cap = self.registry.get(cap_id)
        if cap is None:
            return False
        if getattr(cap, "forceful", False):
            return True
        return getattr(cap, "stealth_level", "") == "aggressive" and not cap_id in (
            "ssh_login", "beacon_deploy", "beacon_via_rce", "persistence_install",
            "privesc_system", "privesc_service_perms", "inject_beacon", "os_detect")

    def _skip_loud(self, cap_id: str) -> bool:
        """In paranoid mode, never propose an aggressive (forceful/loud)
        capability: the planner would refuse it anyway, so don't prefer it."""
        return self.paranoid and self._loud(cap_id)

    @staticmethod
    def _services(wm: WorldModel) -> List[Dict[str, Any]]:
        """Normalized service findings (port stringified, product/version)."""
        out: List[Dict[str, Any]] = []
        for f in wm.find("service"):
            v = f.value if isinstance(f.value, dict) else {}
            port = str(v.get("port") or "")
            if not port:
                # fall back to parsing the key "tcp/22"
                port = str(f.key).split("/")[-1]
            item = dict(v)
            item["_key"] = f.key
            item["port"] = port
            out.append(item)
        return out

    @staticmethod
    def _ports(wm: WorldModel) -> Set[str]:
        return {s["port"] for s in ReasoningEngine._services(wm)}

    def _hyp(self, capability_id: str, reason: str, cost: float = 0.0,
             priority: float = 0.5) -> Optional[Dict[str, Any]]:
        if self._skip_loud(capability_id):
            return None
        return {"capability_id": capability_id, "reason": reason,
                "cost": cost, "priority": priority}

    # -------------------------------------------------------- rule plumbing

    def _rules(self):
        return [
            self._rule_os_inference,
            self._rule_service_roles,
            self._rule_ad_domain,
            self._rule_credential_reuse,
            self._rule_vuln_class,
            self._rule_web_tech,
            self._rule_attack_path,
            self._rule_rce_bridge,
            self._rule_environment,
            self._rule_cloud_operations,
            self._rule_mobile_surface,
        ]

    @staticmethod
    def _register_finding(wm: WorldModel, kind: str, key: str, value: Any,
                          confidence: float, evidence: str) -> Finding:
        return wm.add_finding(kind, key, value, confidence=confidence,
                              source="reasoning", evidence=evidence)

    @staticmethod
    def _register_hypothesis(wm: WorldModel, hyp: Dict[str, Any]) -> Optional[Hypothesis]:
        """Add a hypothesis unless an identical one already exists (in ANY
        state: pending, confirmed, refuted, abandoned) — a hypothesis is a
        one-time record whose status evolves, never re-added."""
        for h in wm.hypotheses:
            if h.capability_id == hyp["capability_id"] and h.reason == hyp["reason"]:
                return None
        return wm.add_hypothesis(
            capability_id=hyp["capability_id"], reason=hyp["reason"],
            cost=hyp.get("cost", 0.0), priority=hyp.get("priority", 0.5))

    def resolve(self, wm: WorldModel,
                failed_cap_ids=None) -> List[Dict[str, str]]:
        """Close pending hypotheses against the world state.

        Fact-based (not timing-based) so ordering never matters:
          * confirmed  — one of the capability's effect facts is present.
          * refuted    — the capability actually ran (recorded action) but
                         its effect fact is still absent.
          * abandoned  — marked failed but never actually attempted (missing
                         tool / out of scope / blocked), effect absent.
        Returns the list of {capability, status} transitions.
        """
        from phantom.automation.planner import _fact_satisfied
        failed = set(failed_cap_ids or ())
        attempted = {a.get("capability") for a in wm.actions_taken}
        resolved: List[Dict[str, str]] = []
        for h in wm.hypotheses:
            if h.status != "pending":
                continue
            cap = self.registry.get(h.capability_id) if self.registry else None
            if cap is None:
                continue
            if any(_fact_satisfied(wm, e) for e in cap.effects):
                h.status = "confirmed"
                h.evidence = "effect fact present in world model"
            elif h.capability_id in attempted:
                h.status = "refuted"
                h.evidence = "ran without producing its effect"
            elif h.capability_id in failed:
                h.status = "abandoned"
                h.evidence = "not runnable in this engagement"
            else:
                continue
            resolved.append({"capability": h.capability_id, "status": h.status})
        return resolved

    def run(self, wm: WorldModel, peers: Optional[List[str]] = None) -> ReasoningResult:
        """Apply every rule; register deductions; return planner preferences.

        `peers` is the set of in-scope peer targets (campaign/lateral) known
        to the agent; the attack-path rule uses it to propose lateral moves.
        """
        self._peers = [p for p in (peers or []) if p != wm.target]
        result = ReasoningResult()
        for rule in self._rules():
            for finding, hyp in rule(wm):
                if finding is not None:
                    result.findings.append(finding)
                if hyp is not None:
                    h = self._register_hypothesis(wm, hyp)
                    if h is not None:
                        result.hypotheses.append(h)
        # preferences: capability ids of new hypotheses, stable order
        seen: Set[str] = set()
        for h in result.hypotheses:
            if h.capability_id not in seen:
                seen.add(h.capability_id)
                result.preferences.append(h.capability_id)
        return result

    # ------------------------------------------------------------------ rules

    def _rule_os_inference(self, wm: WorldModel):
        """Infer the OS family from service/banner fingerprints when the
        confirmed `os` finding is absent (os_detect is a loud, often-skipped
        capability). The deduced `os_inferred` finding drives platform
        selection without ever satisfying the confirmed `os` gate."""
        if wm.find("os"):
            return []
        ports = self._ports(wm)
        services = self._services(wm)

        os_name = ""
        evidence: List[str] = []
        if ports & _WINDOWS_PORTS:
            os_name = "windows"
            evidence.append("windows ports: " + ",".join(sorted(ports & _WINDOWS_PORTS)))
        elif ports & _ANDROID_PORTS:
            os_name = "android"
            evidence.append("adb port 5555 open")
        elif ports & _LINUX_PORTS:
            os_name = "linux"
            evidence.append("unix ports: " + ",".join(sorted(ports & _LINUX_PORTS)))
        # refine linux via banner text
        for s in services:
            blob = " ".join(str(s.get(k, "")) for k in ("version", "product", "service")).lower()
            if "openssh" in blob or "debian" in blob or "ubuntu" in blob or "linux" in blob:
                if not os_name or os_name == "linux":
                    os_name = "linux"
                    evidence.append("banner hints linux")
        for f in wm.find("banner"):
            if "openssh" in str(f.value).lower():
                os_name = os_name or "linux"
                evidence.append("ssh banner")

        if not os_name:
            return []

        finding = self._register_finding(
            wm, "os_inferred", "detected",
            {"os": os_name, "evidence": evidence, "inferred": True},
            confidence=0.6, evidence="; ".join(evidence))
        hyps = []
        if os_name == "windows":
            hyps.append(self._hyp(
                "privesc_service_perms",
                "Windows host inferred: service-permission escalation path",
                cost=4.0, priority=0.6))
            hyps.append(self._hyp(
                "smb_enum", "Windows host inferred: enumerate SMB shares",
                cost=1.5, priority=0.7))
        elif os_name == "linux":
            hyps.append(self._hyp(
                "privesc_sudo",
                "Linux host inferred: sudo escalation path",
                cost=3.5, priority=0.6))
        return [(finding, h) for h in hyps]

    def _rule_service_roles(self, wm: WorldModel):
        """Classify each open service into a role and emit role-specific
        hypotheses (exposed admin panels, anonymous FTP, default creds,
        unauthenticated databases, ...)."""
        out = []
        for s in self._services(wm):
            port = s["port"]
            role = _ROLE_BY_PORT.get(port)
            if not role:
                continue
            self._register_finding(
                wm, "service_role", f"{port}",
                {"port": port, "role": role,
                 "service": s.get("service", ""),
                 "product": s.get("product", ""),
                 "version": s.get("version", "")},
                confidence=0.7, evidence=f"port {port} -> {role}")
            if role == "web":
                out.append((None, self._hyp(
                    "http_probe",
                    f"web service on {port}: fingerprint server + app stack",
                    cost=0.5, priority=0.8)))
            elif role == "database":
                out.append((None, self._hyp(
                    "redis_info" if port == "6379" else "version_detect",
                    f"database on {port}: check auth state and version",
                    cost=0.8, priority=0.7)))
            elif role == "active-directory":
                out.append((None, self._hyp(
                    "version_detect",
                    f"AD service on {port}: fingerprint domain services",
                    cost=2.5, priority=0.7)))
            elif role == "windows-remote":
                if port == "445":
                    out.append((None, self._hyp(
                        "smb_enum", "SMB open: enumerate shares and null session",
                        cost=1.5, priority=0.7)))
            elif role == "file-transfer":
                out.append((None, self._hyp(
                    "version_detect",
                    f"FTP on {port}: check for anonymous access",
                    cost=2.5, priority=0.6)))
            elif role == "snmp":
                out.append((None, self._hyp(
                    "version_detect",
                    f"SNMP on {port}: probe community strings",
                    cost=2.0, priority=0.6)))
            elif role == "container-orchestration":
                out.append((None, self._hyp(
                    "http_probe",
                    f"docker API on {port}: check for unauthenticated control",
                    cost=0.5, priority=0.7)))
            elif role == "remote-terminal":
                out.append((None, self._hyp(
                    "version_detect",
                    f"telnet on {port}: weak-auth / cleartext channel",
                    cost=2.0, priority=0.6)))
        return out

    def _rule_ad_domain(self, wm: WorldModel):
        """Active Directory inference: Kerberos (88) + LDAP (389/636) or GC
        (3268/3269) strongly implies a domain controller. Emit `ad_hint`
        (NOT the gating `ad_domain`) and prioritize the AD kill chain once a
        beacon foothold exists."""
        if wm.find("ad_domain"):
            return []  # already confirmed — nothing to infer
        ports = self._ports(wm)
        kerberos = "88" in ports
        ldap = bool(ports & {"389", "636", "3268", "3269"})
        smb = "445" in ports
        if not (kerberos and (ldap or smb)) and not (ldap and smb):
            return []
        confidence = 0.75 if (kerberos and ldap) else 0.6
        evidence = "DC ports: " + ",".join(sorted(
            ports & (_AD_PORTS | {"445"})))
        self._register_finding(
            wm, "ad_hint", "domain",
            {"domain": "", "dc_ports": sorted(ports & _AD_PORTS),
             "has_smb": smb, "inferred": True},
            confidence=confidence, evidence=evidence)
        hyps = [
            self._hyp("ad_enum", "AD domain inferred from DC ports: enumerate "
                     "the domain once a beacon foothold exists",
                     cost=2.0, priority=0.8),
            self._hyp("kerberoast", "AD domain inferred: SPN TGS tickets are "
                     "the primary credential path",
                     cost=3.5, priority=0.75),
            self._hyp("as_rep_roast", "AD domain inferred: probe accounts "
                     "without pre-authentication",
                     cost=3.5, priority=0.7),
            self._hyp("dc_sync", "AD domain inferred: replicate hashes once "
                     "SYSTEM on the DC is reachable",
                     cost=5.5, priority=0.6),
        ]
        return [(None, h) for h in hyps]

    def _rule_credential_reuse(self, wm: WorldModel):
        """Credentials found for one service are reusable elsewhere: propose
        cheap cross-service checks against every open remote-access port."""
        creds = wm.find("creds")
        if not creds:
            return []
        ports = self._ports(wm)
        hyps = []
        # valid creds carry more weight than breach-dump guesses
        valid = any(
            isinstance(f.value, dict) and f.value.get("valid") for f in creds)
        base_priority = 0.85 if valid else 0.6
        if "22" in ports:
            hyps.append(self._hyp(
                "ssh_login", "credentials available: test reuse over SSH",
                cost=1.2, priority=base_priority))
        if "445" in ports:
            hyps.append(self._hyp(
                "smb_enum", "credentials available: test SMB access",
                cost=1.5, priority=base_priority))
        if ports & {"5985", "5986"}:
            hyps.append(self._hyp(
                "winrm_pivot", "credentials available: WinRM lateral path",
                cost=4.6, priority=base_priority - 0.15))
        if "21" in ports:
            hyps.append(self._hyp(
                "version_detect", "credentials available: test FTP login",
                cost=2.5, priority=base_priority - 0.2))
        if ports & _WEB_PORTS:
            hyps.append(self._hyp(
                "http_probe", "credentials available: test web admin surfaces",
                cost=0.5, priority=base_priority - 0.1))
        return [(None, h) for h in hyps]

    def _rule_vuln_class(self, wm: WorldModel):
        """Bug-class inference from software@version + open ports — NOT a CVE
        list. Flags classes a senior operator would chase: path-traversal/RCE
        in known-bad Apache builds, EternalBlue-class SMB, unauthenticated
        Redis/Mongo/Elasticsearch, default-cred Tomcat, etc."""
        out: List[tuple] = []
        software: Dict[str, str] = {}
        for s in self._services(wm):
            product = (s.get("product") or "").lower()
            version = str(s.get("version") or "").lower()
            if product:
                software[product] = version

        def _flag(product: str, cls: str, detail: str, priority: float,
                  cap_id: str = "service_exploit", cost: float = 4.0):
            self._register_finding(
                wm, "vuln_class", f"{product}:{cls}",
                {"software": product, "class": cls, "detail": detail,
                 "priority": priority},
                confidence=0.55, evidence=detail)
            out.append((None, self._hyp(
                cap_id, f"{cls}: {detail}", cost=cost, priority=priority)))

        def _numeric(version: str):
            m = re.search(r"(\d+)\.(\d+)", version)
            if not m:
                return None
            return int(m.group(1)), int(m.group(2))

        for product, version in software.items():
            if product.startswith("apache"):
                if "2.4.49" in version:
                    _flag("apache", "path-traversal-rce",
                          "Apache 2.4.49 is vulnerable to path traversal/RCE",
                          0.95)
                elif "2.4.50" in version:
                    _flag("apache", "path-traversal-rce",
                          "Apache 2.4.50 path traversal (incomplete fix)",
                          0.9)
            elif product.startswith("openssh"):
                nv = _numeric(version)
                if nv and nv[0] < 8:
                    _flag("openssh", "user-enum",
                          "old OpenSSH (<8.x): username enumeration / weak kex",
                          0.6, cap_id="ssh_banner", cost=0.3)
            elif "tomcat" in product:
                _flag("tomcat", "manager-default-creds",
                      "Tomcat manager default creds / PUT upload class",
                      0.7, cap_id="http_probe", cost=0.5)
            elif "elasticsearch" in product or "elastic" in product:
                _flag("elasticsearch", "unauth-rce",
                      "Elasticsearch unauthenticated RCE class (old builds)",
                      0.7, cap_id="http_probe", cost=0.5)
            elif "redis" in product:
                _flag("redis", "unauth-rce",
                      "Redis may be unauthenticated: RCE / persistence writes",
                      0.8, cap_id="redis_info", cost=0.8)

        # SMB open -> EternalBlue-class RCE candidate (no patch evidence yet)
        if "445" in self._ports(wm):
            _flag("smb", "eternalblue-class",
                  "SMB (445) open without patch evidence: MS17-010 class RCE possible",
                  0.7)
        # Redis reported auth-disabled -> unauth RCE / write primitive
        for f in wm.find("redis"):
            if isinstance(f.value, dict) and f.value.get("no_auth"):
                _flag("redis", "unauth-rce",
                      "Redis reports auth disabled: RCE / persistence write class",
                      0.9, cap_id="redis_info", cost=0.8)
                break
        return out

    def _rule_web_tech(self, wm: WorldModel):
        """Web-app/CMS/stack fingerprint -> bug-class probe hypotheses."""
        out = []
        apps = wm.find("web_app")
        for f in apps:
            name = (f.value.get("name") or "") if isinstance(f.value, dict) else ""
            name = str(name).lower()
            if not name:
                continue
            if name in ("wordpress", "joomla", "drupal", "prestashop"):
                self._register_finding(
                    wm, "vuln_class", f"cms:{name}",
                    {"software": name, "class": "cms-plugin-vuln",
                     "detail": f"{name} plugin/theme attack surface",
                     "priority": 0.7},
                    confidence=0.55, evidence=f"cms detected: {name}")
                out.append((None, self._hyp(
                    "hunt_web", f"{name} detected: hunt plugin/authz bug classes",
                    cost=1.0, priority=0.75)))
                out.append((None, self._hyp(
                    "service_exploit",
                    f"{name} detected: match known CVEs for the platform",
                    cost=4.0, priority=0.6)))
        for f in wm.find("web_header"):
            v = f.value if isinstance(f.value, dict) else {}
            powered = str(v.get("x-powered-by", "")).lower()
            server = str(v.get("server", "")).lower()
            if "php" in powered:
                out.append((None, self._hyp(
                    "hunt_web", "PHP backend detected: LFI/RFI/SSTI classes",
                    cost=1.0, priority=0.7)))
            if "nginx" in server or "apache" in server or "iis" in server:
                out.append((None, self._hyp(
                    "service_exploit",
                    f"{server.split('/')[0]} server detected: version-class check",
                    cost=4.0, priority=0.55)))
        return out

    def _rule_attack_path(self, wm: WorldModel):
        """Build the BloodHound-style graph (hosts/accounts/domain + typed
        edges) and derive concrete lateral moves: the next peer on the
        shortest path to a privileged account, or the peers reachable with
        the held credentials."""
        from phantom.automation.attack_path import pivot_plan

        plan = pivot_plan(wm, peers=self._peers)
        graph = plan["graph"]
        self._register_finding(
            wm, "attack_path", "graph", graph, confidence=0.6,
            evidence=(f"{len(graph['nodes'])} nodes, "
                      f"{len(graph['edges'])} edges"))
        if plan["foothold_accounts"] or plan["privileged_accounts"]:
            self._register_finding(
                wm, "pivot_plan", "plan",
                {"foothold_accounts": plan["foothold_accounts"],
                 "next_peers": plan["next_peers"],
                 "privileged_accounts": plan["privileged_accounts"],
                 "reached_privileged": plan["reached_privileged"],
                 "path_to_privileged": plan["path_to_privileged"]},
                confidence=0.5, evidence="lateral-movement plan")

        hyps = []
        if wm.find("beacon") and wm.find("creds"):
            if plan["reached_privileged"]:
                hyps.append(self._hyp(
                    "dc_sync",
                    "foothold holds a privileged account: DCSync the domain",
                    cost=5.5, priority=0.9))
            for peer in plan["next_peers"]:
                hyps.append(self._hyp(
                    "lateral_pivot",
                    f"pivot to peer {peer} with held credentials",
                    cost=4.5, priority=0.75))
            if "445" in self._ports(wm):
                hyps.append(self._hyp(
                    "smb_pivot", "SMB open + creds: PsExec-style lateral path",
                    cost=4.8, priority=0.65))
        if wm.find("ad_hint") and not wm.find("ad_domain"):
            hyps.append(self._hyp(
                "ad_enum", "AD inferred: confirm the domain from the beacon",
                cost=2.0, priority=0.8))
        return [(None, h) for h in hyps]

    def _rule_rce_bridge(self, wm: WorldModel):
        """The senior foothold chain WITHOUT credentials: confirmed
        code-execution candidates become verified footholds, and a verified
        foothold becomes a beacon injection through the same channel.

        The anomaly engine reports 13 bug classes; the ones that are
        code-execution primitives (SSTI, command injection, JNDI, template
        headers) bridge into rce_foothold directly, while data/redirect
        classes chain to their own next moves."""
        out = []
        rce_classes = {"ssti", "cmdi", "jndi", "header_ssti"}
        for f in wm.find("hunt_anomaly"):
            v = f.value if isinstance(f.value, dict) else {}
            cls = v.get("cls", "")
            if cls in rce_classes and v.get("confirmed"):
                self._register_finding(
                    wm, "vuln_class", f"{cls}:rce",
                    {"software": cls, "class": f"{cls}-rce",
                     "detail": f"confirmed {cls.upper()} — attempt command execution",
                     "priority": 0.95},
                    confidence=0.75, evidence=str(v.get("evidence", ""))[:200])
                out.append((None, self._hyp(
                    "rce_foothold",
                    f"confirmed {cls.upper()} — verify command execution "
                    f"(no creds needed)", cost=1.5, priority=0.95)))
                break
        # NoSQL injection is a credential/data primitive: operator payloads
        # that bypass auth dump records or log in — harvest creds from it.
        for f in wm.find("hunt_anomaly"):
            v = f.value if isinstance(f.value, dict) else {}
            if v.get("cls") == "nosqli" and v.get("confirmed"):
                out.append((None, self._hyp(
                    "web_creds",
                    "confirmed NoSQL injection — harvest records/creds from "
                    "the store", cost=2.0, priority=0.85)))
                break
        # Sensitive-file exposure is a direct intelligence primitive
        for f in wm.find("hunt_anomaly"):
            v = f.value if isinstance(f.value, dict) else {}
            if v.get("cls") == "exposure" and v.get("confirmed"):
                self._register_finding(
                    wm, "vuln_class", "exposure:secrets",
                    {"software": "web-root", "class": "source-secrets",
                     "detail": "sensitive file disclosed (.git/.env/backup)",
                     "priority": 0.9},
                    confidence=0.7, evidence=str(v.get("evidence", ""))[:200])
                out.append((None, self._hyp(
                    "web_creds",
                    "sensitive file disclosed — mine it for credentials/secrets",
                    cost=1.5, priority=0.9)))
                break
        for f in wm.find("exploit_plan"):
            v = f.value if isinstance(f.value, dict) else {}
            if str(v.get("kind", "")).lower() != "rce":
                continue
            out.append((None, self._hyp(
                "rce_foothold",
                f"RCE-class CVE {v.get('cve', '?')} — verify execution",
                cost=2.0, priority=0.8)))
        if wm.find("rce_foothold"):
            out.append((None, self._hyp(
                "beacon_via_rce",
                "RCE foothold confirmed — inject the beacon through the same "
                "channel (no credentials required)",
                cost=5.0, priority=0.95)))
        return out

    def _rule_cloud_operations(self, wm: WorldModel):
        """When the world model indicates a container/cloud box (from the
        environment probe or the cloud-metadata path), chain into the new
        cloud/IAM operations: harvest instance credentials from INSIDE the
        box, then enumerate object storage with them. Also recognize a
        Kubernetes pod and propose an escape probe."""
        out = []
        is_container = is_k8s = False
        for f in wm.find("environment"):
            v = f.value if isinstance(f.value, dict) else {}
            kinds = v.get("kinds") or []
            labels = [str(k.get("kind", "")) for k in kinds] if kinds else []
            if any(x in labels for x in ("container", "kubernetes", "cloud")):
                is_container = True
            if "kubernetes" in labels:
                is_k8s = True

        # beacon up + container/cloud box -> harvest IAM from metadata
        if wm.find("beacon") and is_container:
            out.append((None, self._hyp(
                "cloud_creds_harvest",
                "beacon on a container/cloud box — harvest instance IAM via "
                "the metadata service", cost=0.5, priority=0.8)))
        # container is kubernetes -> escape surface probe
        if wm.find("beacon") and is_k8s:
            out.append((None, self._hyp(
                "k8s_escape",
                "beacon in a Kubernetes pod — probe container-escape "
                "primitives (sa-token / privileged / kubelet)",
                cost=0.8, priority=0.85)))
        # cloud creds held -> enumerate storage / account
        if wm.find("cloud_creds"):
            out.append((None, self._hyp(
                "cloud_s3_enum",
                "cloud IAM credentials held — enumerate object storage and "
                "account access", cost=1.2, priority=0.8)))
        return out

    def _rule_mobile_surface(self, wm: WorldModel):
        """The mobile surface probe flagged device-management / push or
        mobile-web endpoints: prioritize the mobile attack branch and, when
        a session exists, look for the mobile-homing services a real phone
        would contact. Complementary (planes-of-observation), never a gate."""
        out = []
        if wm.find("mobile"):
            out.append((None, self._hyp(
                "service_exploit",
                "mobile/device-management surface detected — probe the "
                "mobile-facing services for bug classes",
                cost=2.0, priority=0.65)))
            out.append((None, self._hyp(
                "http_probe",
                "mobile surface detected — fingerprint the mobile endpoints",
                cost=0.5, priority=0.6)))
        return out

    def _rule_environment(self, wm: WorldModel):
        """Recognize the environment: exposed management APIs (Docker/K8s),
        SCADA/ICS ports, and cloud metadata reached through SSRF. The senior
        operator picks weapons by battlefield — environment is a strategic
        signal, never a gate."""
        out = []
        ports = self._ports(wm)
        if ports & {"2375", "2376"} or ports & {"6443", "10250", "10255"}:
            out.append((None, self._hyp(
                "env_probe",
                "management APIs exposed (Docker/K8s) — recognize the "
                "environment", cost=0.6, priority=0.6)))
        if ports & {"502", "102", "20000", "47808", "4840"}:
            out.append((None, self._hyp(
                "env_probe",
                "SCADA/ICS ports exposed — classify the environment",
                cost=0.6, priority=0.65)))
        # beacon is up and the environment is still unknown: recognize it
        # from INSIDE the box (container markers, AWS metadata via IMDSv2)
        if wm.find("beacon") and not wm.find("environment"):
            out.append((None, self._hyp(
                "env_probe_internal",
                "beacon up — recognize the environment from inside the box",
                cost=0.4, priority=0.55)))
        for f in wm.find("hunt_anomaly"):
            v = f.value if isinstance(f.value, dict) else {}
            if v.get("cls") != "ssrf" or not v.get("confirmed"):
                continue
            endpoint = str(v.get("endpoint", ""))
            if "meta-data" in endpoint or "ami-id" in str(v.get("signals", "")):
                self._register_finding(
                    wm, "environment", "cloud",
                    {"kinds": [{"kind": "cloud", "provider": "aws",
                                "detail": "cloud metadata reachable via SSRF"}],
                     "raw": str(v.get("evidence", ""))[:200]},
                    confidence=0.75,
                    evidence=str(v.get("evidence", ""))[:200])
                out.append((None, self._hyp(
                    "rce_foothold",
                    "SSRF reaches cloud metadata — harvest IAM credentials",
                    cost=1.5, priority=0.9)))
        return out
