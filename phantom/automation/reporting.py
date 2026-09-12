"""
reporting.py — the dual reporting engine.

Every autonomous run produces TWO artifacts:
  * RawReport  — complete audit trail for the operator: every decision,
                 every command, every finding, every failure, timestamps.
  * ClientReport — sanitized, formatted for the client: executive summary,
                 findings grouped by severity, and remediation steps
                 (sourced from the blue-team model + risk engine).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.threatmodel import BlueTeamModel


@dataclass
class FindingEntry:
    kind: str
    key: str
    value: Any
    confidence: float
    source: str
    target: str = ""
    evidence: str = ""
    ts: float = 0.0

    @classmethod
    def from_finding(cls, f) -> "FindingEntry":
        return cls(kind=f.kind, key=f.key, value=f.value,
                   confidence=f.confidence, source=f.source, target=f.target,
                   evidence=getattr(f, "evidence", ""),
                   ts=getattr(f, "ts", 0.0))


@dataclass
class RawReport:
    """Complete operator-facing audit trail."""

    target: str
    goal: str
    started: str
    ended: str = ""
    actions: List[Dict[str, Any]] = field(default_factory=list)
    failures: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[FindingEntry] = field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    campaign_trail: List[Dict[str, Any]] = field(default_factory=list)
    opsec_spent: float = 0.0
    c2_evidence: List[Dict[str, Any]] = field(default_factory=list)
    # chronological narrative: findings + actions + failures + noise + C2
    timeline: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_agent(cls, agent) -> "RawReport":
        wm: WorldModel = agent.wm
        return cls(
            target=agent.target,
            goal=agent.goal or "",
            started=datetime.now().isoformat(timespec="seconds"),
            actions=list(wm.actions_taken),
            failures=list(wm.failures),
            findings=[FindingEntry.from_finding(f) for f in wm.all_findings()],
            hypotheses=[h.to_dict() for h in wm.hypotheses],
            campaign_trail=list(agent.sink.events),
            opsec_spent=wm.opsec_spent,
            c2_evidence=cls._c2_evidence(agent),
            timeline=cls._timeline(agent),
        )

    @staticmethod
    def _timeline(agent) -> List[Dict[str, Any]]:
        """Chronological narrative merged from every recorded event."""
        try:
            from phantom.automation.timeline import build_timeline, to_dicts
            return to_dicts(build_timeline(
                agent.wm, c2_evidence=RawReport._c2_evidence(agent)))
        except Exception:
            return []

    @staticmethod
    def _c2_evidence(agent) -> List[Dict[str, Any]]:
        """Beacon-side proof of execution pulled from the live C2 state:
        every task queued to the beacon session and its collected output."""
        evidence = []
        if not getattr(agent, "_session", None):
            return evidence
        try:
            from phantom.core.c2_server import c2_state
        except Exception:
            return evidence
        beacon_id = agent._session.beacon_id
        beacons = c2_state.get_beacons()
        info = beacons.get(beacon_id, {})
        if info:
            evidence.append({
                "beacon_id": beacon_id,
                "registered": True,
                "ip": info.get("ip", ""),
                "os": info.get("os", ""),
                "user": info.get("user", ""),
                "hostname": info.get("hostname", ""),
                "last_seen": info.get("last_seen", ""),
                "tasks_executed": len(c2_state.get_results(beacon_id)),
            })
        for r in c2_state.get_results(beacon_id):
            evidence.append({"beacon_id": beacon_id, "task_id": r.get("task_id"),
                             "output_tail": (r.get("output", "") or "")[:500],
                             "time": r.get("time", "")})
        return evidence

    def _ioc_section(self) -> List[str]:
        """The operator's cleanup list: staging paths, dropper URLs,
        listener ports, phish links, stolen cookies, persistence methods,
        cloud IAM and RCE channels. These are the observable fingerprints
        left on the target and the attacker box — the red-teamer must
        scrub them before closing the engagement."""
        import re
        lines = ["## Cleanup & IOCs", "",
                 "> Scrub these before closing the engagement — they are the "
                 "observable fingerprints left on the target / operator box.",
                 ""]
        staging: set = set()
        urls: set = set()
        ports: set = set()
        for a in self.actions:
            cmd = str(a.get("command", ""))
            for m in re.findall(r"(?:/tmp/|\$TMPDIR|\$env:TEMP|C:\\Users\\)[^ '\"|&;]+", cmd):
                staging.add(m[:80])
            for m in re.findall(r"https?://[^ '\"|&;]+", cmd):
                urls.add(m[:120])
            for m in re.findall(r"\b(?:-p|LPORT|set LPORT)\s+(\d{2,5})\b", cmd):
                ports.add(m)
        items: List[str] = []
        for f in self.findings:
            v = f.value if isinstance(f.value, dict) else {}
            if f.kind == "beacon":
                cb = v.get("callback") or v.get("payload") or ""
                if cb:
                    urls.add(str(cb)[:120])
            elif f.kind == "stolen_cookies":
                items.append(f"Stolen session cookies for {f.target} — rotate/reissue them.")
            elif f.kind == "cdp_cookies":
                items.append(f"CDP-harvested cookies for {f.target} — rotate/reissue them.")
            elif f.kind == "persistence":
                items.append(f"Persistence installed on {f.target}: "
                             f"{v.get('method', '?')} — remove it.")
            elif f.kind == "phish":
                items.append(f"Phish sent ({v.get('channel', '?')}) — delete the lure and burn the tracker.")
            elif f.kind == "victim_ip":
                items.append(f"IP-grabber tracked victim {v.get('ip', '?')} — the tracking link must be taken down.")
            elif f.kind == "cloud_creds":
                items.append(f"Cloud IAM credentials harvested ({v.get('provider', '?')}) — rotate them, they are live.")
            elif f.kind == "rce_foothold":
                items.append(f"RCE channel used on {f.target}: {v.get('channel', '?')} — patch the vulnerability.")
            elif f.kind == "persona":
                items.append(f"Persona used: {v.get('email', '?')} — deactivate the throwaway account.")
        for s in sorted(staging):
            items.append(f"Staging path left on the box: `{s}`")
        for u in sorted(urls):
            items.append(f"Dropper/C2 URL contacted: `{u}`")
        for p in sorted(ports):
            items.append(f"Listener/payload port used: {p}")
        if not items:
            items.append("_No operator-side IOC detected from this run._")
        lines += [f"- {i}" for i in items]
        lines.append("")
        return lines

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_type": "raw",
            "target": self.target,
            "goal": self.goal,
            "started": self.started,
            "ended": self.ended,
            "opsec_spent": round(self.opsec_spent, 2),
            "actions": self.actions,
            "failures": self.failures,
            "findings": [{"kind": f.kind, "key": f.key, "value": f.value,
                          "confidence": f.confidence, "source": f.source,
                          "target": f.target, "evidence": f.evidence}
                         for f in self.findings],
            "hypotheses": self.hypotheses,
            "campaign_trail": self.campaign_trail,
            "c2_evidence": self.c2_evidence,
            "timeline": self.timeline,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_markdown(self) -> str:
        """Human-readable operator report — FULL detail: every command,
        output, credential, hypothesis and piece of evidence. This is the
        red-teamer's working document (the client report is its sanitized,
        editable skeleton)."""
        def kind_count(kind: str) -> int:
            return sum(1 for f in self.findings if f.kind == kind)

        lines = [
            f"# Phantom Raw Report — {self.target}",
            "",
            f"**Goal:** {self.goal}  ",
            f"**Started:** {self.started}  ",
            f"**Ended:** {self.ended or '-'}  ",
            f"**OPSEC spent:** {round(self.opsec_spent, 2)}  ",
            "",
            "## Summary",
            "",
            f"- services: {kind_count('service')}",
            f"- credentials: {kind_count('creds')}",
            f"- beacons: {kind_count('beacon')}",
            f"- persistence: {kind_count('persistence')}",
            f"- system privilege: {kind_count('system_privilege')}",
            f"- injections: {kind_count('injection')}",
            f"- AD domains: {kind_count('ad_domain')}",
            f"- AD creds/hashes: {kind_count('ad_creds')}",
            f"- cracked hashes: {kind_count('cracked')}",
            f"- pivots/lateral: {kind_count('pivot')}",
            f"- hunt anomalies: {kind_count('hunt_anomaly')}",
            f"- RCE footholds: {kind_count('rce_foothold')}",
            f"- cloud IAM creds: {kind_count('cloud_creds')}",
            f"- cloud access: {kind_count('cloud_access')}",
            f"- cloud lateral: {kind_count('cloud_lateral')}",
            f"- environment: {kind_count('environment')}",
            f"- internal hosts: {kind_count('internal_host')}",
            f"- internal services: {kind_count('internal_service')}",
            f"- defensive gaps (EDR/AV): {kind_count('defensive_gap')}",
            f"- mobile surfaces: {kind_count('mobile')}",
            f"- MDM vendors: {kind_count('mdm_vendor')}",
            f"- k8s escapes: {kind_count('k8s_escape')}",
            f"- inferences: {sum(1 for f in self.findings if f.source == 'reasoning')}",
            f"- hypotheses: {len(self.hypotheses)}",
            f"- actions: {len(self.actions)}",
            f"- failures: {len(self.failures)}",
            "",
        ]
        # the timeline goes early: "what happened when" is the first question
        try:
            from phantom.automation.timeline import (
                TimelineEntry, render_markdown, timeline_stats)
            entries = [TimelineEntry(**{k: v for k, v in e.items()
                                        if k != "iso"})
                       for e in self.timeline]
            if entries:
                lines += render_markdown(entries, client=False)
                stats = timeline_stats(entries)
                crit = stats["by_severity"].get("critical", 0)
                high = stats["by_severity"].get("high", 0)
                lines += [f"**Timeline roll-up:** {stats['total']} events, "
                          f"{crit} critical, {high} high severity.", ""]
        except Exception:
            pass
        if self.hypotheses:
            lines += ["## Reasoning & Hypotheses", ""]
            for h in self.hypotheses:
                lines.append(
                    f"- **[{h.get('status', 'pending').upper()}]** "
                    f"`{h.get('capability_id', '')}`: {h.get('reason', '')} "
                    f"(priority {h.get('priority', '')})")
            lines.append("")
        # findings grouped by kind, full value + evidence
        by_kind: Dict[str, List[FindingEntry]] = {}
        for f in self.findings:
            by_kind.setdefault(f.kind, []).append(f)
        lines += ["## Findings", ""]
        for kind in sorted(by_kind):
            fs = by_kind[kind]
            lines.append(f"### {kind} ({len(fs)})")
            lines.append("")
            for f in fs:
                lines.append(f"- `{f.key}` — confidence {f.confidence}, "
                             f"source `{f.source}`")
                if f.evidence:
                    lines.append(f"  - evidence: {str(f.evidence)[:400]}")
                val = (json.dumps(f.value, indent=2, default=str)
                       if isinstance(f.value, (dict, list)) else str(f.value))
                lines.append("  ```json")
                lines.append(str(val))
                lines.append("  ```")
            lines.append("")
        lines += ["## Actions", ""]
        lines.append("| # | Capability | Command | OK | OPSEC |")
        lines.append("|---|-----------|---------|----|-------|")
        for i, a in enumerate(self.actions, 1):
            cmd = str(a.get("command", "")).replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {i} | {a.get('capability', '')} | `{cmd[:220]}` "
                         f"| {a.get('ok')} | {a.get('opsec', '')} |")
        lines.append("")
        lines += ["## Failures", ""]
        if self.failures:
            for f in self.failures:
                lines.append(f"- `{f.get('capability', '')}`: {f.get('reason', '')} "
                             f"(evidence: {str(f.get('evidence', ''))[:240]})")
        else:
            lines.append("_none_")
        lines.append("")
        lines += self._ioc_section()
        if self.c2_evidence:
            lines += ["## C2 Evidence", ""]
            for e in self.c2_evidence:
                if e.get("task_id"):
                    lines.append(f"- task `{e.get('task_id')}` @ {e.get('time', '')}:")
                    lines.append("  ```")
                    lines.append(str(e.get("output_tail", "")))
                    lines.append("  ```")
                else:
                    lines.append(
                        f"- beacon `{e.get('beacon_id')}` — ip {e.get('ip', '')}, "
                        f"os {e.get('os', '')}, user {e.get('user', '')}, "
                        f"hostname {e.get('hostname', '')}, "
                        f"tasks {e.get('tasks_executed', 0)}, "
                        f"last_seen {e.get('last_seen', '')}")
            lines.append("")
        lines.append("_Full decision trail (event stream) is in raw_report.json._")
        return "\n".join(lines)


@dataclass
class ClientFinding:
    severity: str  # critical | high | medium | low | info
    title: str
    detail: str
    remediation: str = ""


# capability category -> kill-chain phase label (methodology skeleton)
_PHASE_BY_CATEGORY = {
    "recon": "Reconnaissance — port scan, service fingerprint, OS detection",
    "osint": "OSINT & Social Engineering — identity/breach/phish to reach the host",
    "social": "OSINT & Social Engineering — identity/breach/phish to reach the host",
    "service": "Service Enumeration — deep checks on exposed services",
    "creds": "Credential Acquisition — offline brute / breach reuse",
    "exploit": "Exploitation — version-matched and bug-class hunting",
    "hunt": "Behavioural Vulnerability Hunting — baseline anomaly probes",
    "beacon": "Initial Access — beacon deployment via C2",
    "persistence": "Persistence — boot/logon mechanisms",
    "lateral": "Lateral Movement — pivot to peer hosts",
    "post": "Post-Exploitation — escalation, injection, harvesting",
    "exfil": "Data Collection",
}


class ClientReport:
    """Sanitized, editable skeleton for the client — the red-teamer refines
    it, but the structure and pre-filled data are already there."""

    def __init__(self, target: str, profile: str = "enterprise") -> None:
        self.target = target
        self.profile = profile
        self.generated = datetime.now().isoformat(timespec="seconds")
        self.findings: List[ClientFinding] = []
        self.reasoning: List[Dict[str, Any]] = []
        self.methodology: List[str] = []
        self.attack_path: Dict[str, int] = {}
        self.mitre: List[Dict[str, Any]] = []
        self.target_risk: Optional[float] = None
        self.executive_summary: str = ""
        self.c2_evidence: List[Dict[str, Any]] = []
        # client-safe chronology: phase + outcome, never a command line
        self.timeline: List[Dict[str, Any]] = []
        self.blue_team = BlueTeamModel.for_profile(profile)

    @classmethod
    def from_agent(cls, agent, profile: str = "enterprise") -> "ClientReport":
        report = cls(agent.target, profile)
        wm = agent.wm
        beacons = wm.find("beacon")
        creds = wm.find("creds", valid=True)
        services = wm.find("service")
        persistence = wm.find("persistence")
        system_priv = wm.find("system_privilege")
        injection = wm.find("injection")
        report.c2_evidence = cls._c2_evidence(agent)
        try:
            from phantom.automation.timeline import build_timeline, to_dicts
            report.timeline = to_dicts(build_timeline(
                wm, c2_evidence=report.c2_evidence))
        except Exception:
            report.timeline = []

        # NOTE: no credentials ever leave this report. Creds live in the raw
        # operator report only; the client sees impact, never secrets.
        if beacons:
            report.findings.append(ClientFinding(
                severity="critical",
                title="Full remote access achieved (beacon)",
                detail=(f"An autonomous agent established a persistent remote "
                        f"session on {agent.target} ({len(beacons)} callback(s))."),
                remediation="Isolate the host immediately and review credentials in use.",
            ))
        if persistence:
            methods = ", ".join(
                (f.value.get("method", "auto") if isinstance(f.value, dict) else "auto")
                for f in persistence)
            report.findings.append(ClientFinding(
                severity="critical",
                title="Persistence installed on compromised host",
                detail=(f"Boot/logon persistence was installed on {agent.target} "
                        f"({methods}): the access survives reboots."),
                remediation="Check startup items, scheduled tasks, services and "
                            "cron/systemd units; clean and reimage if confirmed.",
            ))
        if system_priv:
            identity = system_priv[0].value.get("identity", "") \
                if isinstance(system_priv[0].value, dict) else ""
            report.findings.append(ClientFinding(
                severity="critical",
                title=f"Privilege escalation to {identity} achieved",
                detail=(f"The agent escalated to {identity} on {agent.target}: "
                        f"full control over the host, not just the account."),
                remediation="Audit service creation, scheduled tasks and "
                            "privilege delegation; patch the escalation vector.",
            ))
        if injection:
            procs = ", ".join(
                (f.value.get("target_process", "?") if isinstance(f.value, dict) else "?")
                for f in injection)
            report.findings.append(ClientFinding(
                severity="critical",
                title=f"Beacon injected into privileged process ({procs})",
                detail=(f"The remote session was injected into {procs}: it runs "
                        f"inside a trusted process and survives process-kill "
                        f"attempts on the dropped session."),
                remediation="Hunt for injected code (Get-InjectedThread / Process "
                            "Hacker), kill the process and investigate the parent.",
            ))
        for s in services:
            v = s.value if isinstance(s.value, dict) else {}
            port = v.get("port", "")
            name = v.get("service", "service")
            version = v.get("version", "")
            report.findings.append(ClientFinding(
                severity="info",
                title=f"Exposed service: {name} on port {port}",
                detail=f"Version: {version or 'unknown'}. Assessed for exposure.",
                remediation=("Confirm the service is required, restrict source "
                             "networks, and keep it patched."),
            ))
        # ── post-exploitation / enterprise surfaces (were dropped before:
        # the report only read a fixed kind list, so internal recon, cloud,
        # EDR gaps and mobile never reached the client) ─────────────────
        internal = wm.find("internal_service") or wm.find("internal_host")
        if internal:
            report.findings.append(ClientFinding(
                severity="high",
                title="Internal network reachable from the foothold",
                detail=(f"{len(internal)} internal peer(s) were discovered "
                        "from the compromised host, i.e. the segmentation "
                        "does not contain the breach."),
                remediation=("Enforce east-west segmentation and monitor "
                             "internal service discovery from endpoints."),
            ))
        cloud_acc = wm.find("cloud_access") + wm.find("cloud_lateral")
        if cloud_acc:
            report.findings.append(ClientFinding(
                severity="critical",
                title="Cloud identity plane exposed",
                detail=(f"{len(cloud_acc)} cloud access/lateral fact(s) were "
                        "collected: instance/workload credentials were "
                        "reusable beyond the host."),
                remediation=("Rotate the exposed keys, scope roles to "
                             "least privilege, and require session policies "
                             "for cross-account assumption."),
            ))
        gaps = wm.find("defensive_gap")
        if gaps:
            report.findings.append(ClientFinding(
                severity="high",
                title="Endpoint protection was bypassed/disabled",
                detail=(f"{len(gaps)} defensive gap(s) were recorded on the "
                        "compromised host (AV/EDR control lost)."),
                remediation=("Verify endpoint protection health monitoring, "
                             "enable tamper protection, and alert on "
                             "protection-state changes."),
            ))
        mobile = wm.find("mdm_vendor") + wm.find("mobile")
        if mobile:
            report.findings.append(ClientFinding(
                severity="medium",
                title="Mobile / MDM attack surface exposed",
                detail=(f"{len(mobile)} mobile-management fact(s) were "
                        "identified (enrolment endpoint / managed device)."),
                remediation=("Require device compliance, restrict enrolment "
                             "endpoints, and review BYOD policy."),
            ))
        # reasoning trail: every hypothesis the inference engine formed, with
        # its final status (confirmed/refuted/pending/abandoned) — sanitized,
        # no credentials, no commands.
        report.reasoning = [
            {"capability": h.capability_id, "reason": h.reason,
             "status": h.status, "priority": round(h.priority, 2)}
            for h in wm.hypotheses
        ]
        # methodology skeleton: the kill-chain phases actually executed
        report.methodology = cls._methodology(agent)
        # attack-path summary (counts only — no account names leak); nodes
        # carry either "kind" (new graph) or "type" (legacy graph)
        ap = wm.find("attack_path")
        if ap and isinstance(ap[0].value, dict):
            nodes = ap[0].value.get("nodes", [])

            def _node_kind(n):
                return (n.get("kind") or n.get("type") or "") if isinstance(n, dict) else ""

            report.attack_path = {
                "hosts": sum(1 for n in nodes if _node_kind(n) == "host"),
                "accounts": sum(1 for n in nodes if _node_kind(n) == "account"),
                "domains": sum(1 for n in nodes if _node_kind(n) == "domain"),
            }
        # MITRE ATT&CK mapping + composite target risk (enterprise scoring)
        report.mitre = [
            {"id": f.value.get("id"), "name": f.value.get("name"),
             "tactic": f.value.get("tactic"), "phase": f.value.get("phase")}
            for f in wm.find("attack_technique") if isinstance(f.value, dict)
        ]
        risk_f = wm.find("target_risk")
        if risk_f and isinstance(risk_f[0].value, dict):
            report.target_risk = risk_f[0].value.get("score")
        # inferred context (deterministic reasoning, clearly marked as such)
        for f in wm.find("os_inferred"):
            v = f.value if isinstance(f.value, dict) else {}
            os_name = v.get("os", "unknown")
            report.findings.append(ClientFinding(
                severity="info",
                title=f"Inferred target OS: {os_name}",
                detail="Inferred from open services/banners, not confirmed "
                       "by active OS fingerprinting.",
                remediation="Confirm the OS and apply platform-specific "
                            "hardening.",
            ))
        for f in wm.find("ad_hint"):
            report.findings.append(ClientFinding(
                severity="medium",
                title="Active Directory domain suspected",
                detail="Kerberos/LDAP/SMB ports suggest a domain controller: "
                       "the environment is likely domain-joined with AD "
                       "attack surface.",
                remediation="Review AD hardening: LDAP signing, Kerberos "
                            "policies, service-account hygiene.",
            ))
        for f in wm.find("vuln_class"):
            v = f.value if isinstance(f.value, dict) else {}
            cls = v.get("class", "unknown")
            detail = v.get("detail", "")
            prio = float(v.get("priority", 0.5))
            severity = "high" if prio >= 0.9 else "medium" if prio >= 0.7 else "low"
            report.findings.append(ClientFinding(
                severity=severity,
                title=f"Suspected vulnerability class: {cls}",
                detail=detail or f"Bug class {cls} suspected on the target.",
                remediation="Validate the suspected class manually; patch or "
                            "mitigate if confirmed.",
            ))
        anomalies = wm.find("hunt_anomaly")
        confirmed = [f for f in anomalies
                     if isinstance(f.value, dict) and f.value.get("confirmed")]
        for f in anomalies[:12]:
            v = f.value if isinstance(f.value, dict) else {}
            title = (f"{v.get('severity', 'medium').upper()} behavioural "
                     f"candidate: {v.get('cls', '?')} @ {v.get('endpoint', '?')}")
            if v.get("confirmed"):
                title += " (reproduced)"
            if v.get("confirmed"):
                note = ("Reproduced in the validation pass: treat as a "
                        "likely vulnerability.")
            else:
                note = ("Not yet reproduced: candidate requires manual "
                        "confirmation.")
            detail = (f"Anomaly engine found a {v.get('cls', 'unknown')} "
                      f"candidate on {agent.target}"
                      f"{(':' + str(v.get('port'))) if v.get('port') else ''} "
                      f"at {v.get('endpoint', '?')} — signals: "
                      f"{v.get('signals', '')} (score {v.get('score', '?')}). "
                      f"{note}")
            report.findings.append(ClientFinding(
                severity=v.get("severity", "medium"),
                title=title,
                detail=detail[:600],
                remediation=("Validate the candidate with a manual request "
                             "replay; if real, apply the vendor fix or WAF "
                             "rule for the vector."),
            ))
        # blue-team posture recommendations
        sys_identity = (system_priv[0].value.get("identity", "privileged")
                        if system_priv and isinstance(system_priv[0].value, dict)
                        else "privileged")
        injected_procs = ", ".join(
            (f.value.get("target_process", "?") if isinstance(f.value, dict) else "?")
            for f in injection)
        report.executive_summary = (
            f"Assessment of {agent.target} (profile: {profile}) "
            f"completed with {'success' if beacons else 'partial success'}: "
            f"{len(services)} services exposed, {len(creds)} credential sets "
            f"compromised, {'beacon established' if beacons else 'no beacon'}."
            + (f" Persistence confirmed; escalated to {sys_identity}; injected "
               f"into {injected_procs}." if injection else "")
            + (f" {len(anomalies)} behavioural candidates found on the web "
               f"services ({len(confirmed)} reproduced)." if anomalies else "")
        )
        if wm.hypotheses:
            confirmed_h = sum(1 for h in wm.hypotheses if h.status == "confirmed")
            report.executive_summary += (
                f" The reasoning engine recorded {len(wm.hypotheses)} "
                f"hypotheses ({confirmed_h} confirmed).")
        if report.target_risk is not None:
            report.executive_summary += (
                f" Composite target risk: {report.target_risk}/100.")
        report._remediations = report.blue_team.recommendations()
        return report

    @classmethod
    def _methodology(cls, agent) -> List[str]:
        """Kill-chain phases actually executed, derived from the recorded
        actions — the editable methodology skeleton in the client report."""
        phases: List[str] = []
        seen = set()
        registry = getattr(agent, "registry", None)
        for a in agent.wm.actions_taken:
            cap_id = a.get("capability", "")
            category = ""
            if registry is not None:
                cap = registry.get(cap_id)
                if cap is not None:
                    category = cap.category
            phase = _PHASE_BY_CATEGORY.get(category, category or "Action")
            if phase and phase not in seen:
                seen.add(phase)
                phases.append(phase)
        return phases

    @staticmethod
    def _c2_evidence(agent) -> List[Dict[str, Any]]:
        """Client-safe beacon-side proof of execution: session metadata and
        the sequence of executed tasks, WITHOUT any output that could carry
        credentials. The raw operator report keeps the full outputs."""
        evidence = []
        if not getattr(agent, "_session", None):
            return evidence
        try:
            from phantom.core.c2_server import c2_state
        except Exception:
            return evidence
        beacon_id = agent._session.beacon_id
        beacons = c2_state.get_beacons()
        info = beacons.get(beacon_id, {})
        if info:
            evidence.append({
                "beacon_id": beacon_id,
                "ip": info.get("ip", ""),
                "os": info.get("os", ""),
                "hostname": info.get("hostname", ""),
                "last_seen": info.get("last_seen", ""),
                "session_resumed": bool(info.get("session_resumed_at")),
                "tasks_executed": len(c2_state.get_results(beacon_id)),
            })
        for r in c2_state.get_results(beacon_id):
            # task_id + timestamp only: outputs live in the raw report
            evidence.append({"beacon_id": beacon_id,
                             "task_id": r.get("task_id"),
                             "time": r.get("time", "")})
        return evidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_type": "client",
            "target": self.target,
            "profile": self.profile,
            "generated": self.generated,
            "executive_summary": self.executive_summary,
            "findings": [{"severity": f.severity, "title": f.title,
                          "detail": f.detail, "remediation": f.remediation}
                         for f in self.findings],
            "reasoning": self.reasoning,
            "methodology": self.methodology,
            "attack_path": self.attack_path,
            "mitre": self.mitre,
            "target_risk": self.target_risk,
            "c2_evidence": self.c2_evidence,
            "timeline": self.timeline,
            "recommended_hardening": getattr(self, "_remediations", []),
        }

    def to_markdown(self) -> str:
        lines = [
            f"# Phantom Assessment — {self.target}",
            "",
            f"**Profile:** {self.profile}  ",
            f"**Generated:** {self.generated}  ",
            "",
            "## Executive Summary",
            "",
            self.executive_summary,
            "",
            "## Scope & Methodology",
            "",
            "The target was assessed with the Phantom autonomous red-team "
            "agent. The following phases were executed (refine for the "
            "final client deliverable):",
            "",
        ]
        if self.methodology:
            for i, p in enumerate(self.methodology, 1):
                lines.append(f"{i}. {p}")
        else:
            lines.append("_No phases recorded._")
        lines.append("")
        if self.attack_path:
            lines.append("## Attack Path (summary)")
            lines.append("")
            lines.append(
                f"The agent mapped {self.attack_path.get('hosts', 0)} host(s), "
                f"{self.attack_path.get('accounts', 0)} account(s), and "
                f"{self.attack_path.get('domains', 0)} domain(s).")
            lines.append("")
        # client timeline: the phases in order, no tradecraft detail
        try:
            from phantom.automation.timeline import (
                TimelineEntry, render_markdown)
            entries = [TimelineEntry(**{k: v for k, v in e.items()
                                        if k != "iso"})
                       for e in self.timeline]
            if entries:
                lines += render_markdown(entries, client=True)
        except Exception:
            pass
        lines += [
            "## Findings",
            "",
        ]
        for f in self.findings:
            lines.append(f"### [{f.severity.upper()}] {f.title}")
            lines.append("")
            lines.append(f.detail)
            lines.append("")
            if f.remediation:
                lines.append(f"**Remediation:** {f.remediation}")
                lines.append("")
        if self.c2_evidence:
            lines.append("## C2 Evidence (sanitized)")
            lines.append("")
            lines.append("Beacon-side proof of execution collected from the "
                         "C2 infrastructure. Outputs are intentionally "
                         "omitted here (raw report holds full detail).")
            lines.append("")
            lines.append("| Beacon | IP | OS | Hostname | Tasks | Last seen |")
            lines.append("|--------|----|----|----------|-------|-----------|")
            for e in self.c2_evidence:
                if e.get("task_id"):
                    continue  # task rows go to the execution log below
                lines.append(
                    f"| {e.get('beacon_id', '')} | {e.get('ip', '')} "
                    f"| {e.get('os', '')} | {e.get('hostname', '')} "
                    f"| {e.get('tasks_executed', 0)} | {e.get('last_seen', '')} |")
            lines.append("")
            lines.append("**Executed tasks:**")
            lines.append("")
            for e in self.c2_evidence:
                if e.get("task_id"):
                    lines.append(f"- `{e.get('task_id')}` @ {e.get('time', '')}")
            lines.append("")
        if self.reasoning:
            lines.append("## Reasoning & Hypotheses")
            lines.append("")
            lines.append("The autonomous agent reasoned over the target and "
                         "recorded the following hypotheses (confirmed = "
                         "evidence found; refuted = tested and disproven; "
                         "abandoned = not runnable; pending = not yet tested).")
            lines.append("")
            for h in self.reasoning:
                lines.append(
                    f"- **[{h['status'].upper()}]** `{h['capability']}`: "
                    f"{h['reason']} (priority {h['priority']})")
            lines.append("")
        if self.mitre:
            lines.append("## MITRE ATT&CK Mapping")
            lines.append("")
            lines.append("Techniques mapped from the exposed services:")
            lines.append("")
            for t in self.mitre:
                lines.append(f"- `{t['id']}` — {t['name']} "
                             f"({t['tactic']})")
            lines.append("")
        lines.append("## Recommended Hardening")
        lines.append("")
        for r in getattr(self, "_remediations", []):
            lines.append(f"- {r}")
        return "\n".join(lines)


class CampaignReport:
    """Aggregated, sanitized view of a multi-target campaign.

    Shows impact per target (beacon/persistence/SYSTEM) WITHOUT leaking
    credentials — the raw per-target reports hold the secrets.
    """

    def __init__(self, campaign: Dict[str, Any], profile: str = "enterprise",
                 per_target: Optional[Dict[str, Dict[str, str]]] = None) -> None:
        self.campaign = campaign
        self.profile = profile
        self.per_target = per_target or {}
        self.generated = datetime.now().isoformat(timespec="seconds")

    def to_dict(self) -> Dict[str, Any]:
        results = self.campaign.get("results", {})
        return {
            "report_type": "campaign",
            "goal": self.campaign.get("goal", ""),
            "generated": self.generated,
            "targets": self.campaign.get("targets", []),
            "aggregates": {
                "beacons": self.campaign.get("beacons", 0),
                "persistent_hosts": self.campaign.get("persistent", 0),
                "creds_compromised": self.campaign.get("compromised_creds", 0),
                "services_exposed": self.campaign.get("services", 0),
                "lateral_movements": self.campaign.get("pivots", 0),
                "ad_domains": self.campaign.get("ad_domains", 0),
                "failures": self.campaign.get("failures", 0),
            },
            "per_target": [
                {"target": t, "beacon": bool(r.get("beacon_established")),
                 "persistence": bool(r.get("persistence_installed")),
                 "system_privilege": bool(r.get("system_privilege")),
                 "services": r.get("services_enumerated", 0),
                 "report_dir": self.per_target.get(t, {}).get("dir", "")}
                for t, r in results.items()
            ],
        }

    def to_markdown(self) -> str:
        lines = [
            f"# Phantom Campaign Assessment — {len(self.campaign.get('targets', []))} targets",
            "",
            f"**Profile:** {self.profile}  ",
            f"**Goal:** {self.campaign.get('goal', '')}  ",
            f"**Generated:** {self.generated}  ",
            "",
            "## Executive Summary",
            "",
            (f"{self.campaign.get('beacons', 0)}/{len(self.campaign.get('targets', []))} "
             f"targets compromised, {self.campaign.get('persistent', 0)} persistent "
             f"access, {self.campaign.get('compromised_creds', 0)} credential sets "
             f"recovered, {self.campaign.get('services', 0)} services exposed, "
             f"{self.campaign.get('pivots', 0)} lateral moves, "
             f"{self.campaign.get('ad_domains', 0)} AD domains enumerated."),
            "",
            "## Per-target impact",
            "",
            "| Target | Beacon | Persistence | SYSTEM/root | Services |",
            "|--------|--------|-------------|-------------|----------|",
        ]
        for t, r in self.campaign.get("results", {}).items():
            lines.append(
                f"| {t} | {'yes' if r.get('beacon_established') else 'no'} "
                f"| {'yes' if r.get('persistence_installed') else 'no'} "
                f"| {'yes' if r.get('system_privilege') else 'no'} "
                f"| {r.get('services_enumerated', 0)} |")
        lines.append("")
        lines.append("Details per target (including credentials, for operators "
                     "only) are in each target's raw report.")
        return "\n".join(lines)


class ReportWriter:
    """Writes both reports to disk (one directory per run)."""

    def __init__(self, out_dir: str) -> None:
        self.out_dir = out_dir

    def write(self, raw: RawReport, client: ClientReport) -> Dict[str, str]:
        os.makedirs(self.out_dir, exist_ok=True)
        raw_path = os.path.join(self.out_dir, "raw_report.json")
        raw_md_path = os.path.join(self.out_dir, "raw_report.md")
        client_path = os.path.join(self.out_dir, "client_report.md")
        with open(raw_path, "w", encoding="utf-8") as f:
            f.write(raw.to_json())
        with open(raw_md_path, "w", encoding="utf-8") as f:
            f.write(raw.to_markdown())
        with open(client_path, "w", encoding="utf-8") as f:
            f.write(client.to_markdown())
        return {"raw": raw_path, "raw_md": raw_md_path, "client": client_path}

    def write_campaign(self, campaign: CampaignReport) -> Dict[str, str]:
        os.makedirs(self.out_dir, exist_ok=True)
        json_path = os.path.join(self.out_dir, "campaign_summary.json")
        md_path = os.path.join(self.out_dir, "campaign_report.md")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(campaign.to_dict(), f, indent=2, default=str)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(campaign.to_markdown())
        return {"campaign_json": json_path, "campaign_md": md_path}
