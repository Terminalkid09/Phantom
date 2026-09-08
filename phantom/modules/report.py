"""report.py - Professional engagement reporting.

Produces the same two-report structure as auto-mode:

  * raw     — operator (red teamer) document: EVERYTHING, including
              credentials and full command output, for the operator's
              own audit and as a starting point for the client report.
  * client  — sanitized skeleton: executive summary, scope & methodology,
              findings by severity, hardening recommendations. No
              credentials, no commands — ready to be refined and delivered.

Commands (inside `use report`):

  run                 -> interactive export (default: full set)
  export all          -> full set in data/reports/<timestamp>/
  export json <file>  -> legacy JSON audit dump
  export html <file>  -> client-grade HTML (sanitized)
  export pdf <file>   -> client-grade PDF (sanitized)
  export md <file>    -> operator markdown (everything)
  export client <f>   -> sanitized client markdown
"""

import json
import os
import re
from datetime import datetime

from phantom.modules.base_module import BaseModule
from phantom.core.session import session
from phantom.utils.notifier import notifier
from rich.console import Console

console = Console()

VERSION = "3.0.0"

# Module -> (kill-chain phase, description) for the methodology section.
_PHASE_LABELS = {
    "scan": ("Reconnaissance", "Active network scanning and service enumeration (Nmap)"),
    "osint": ("Reconnaissance", "Passive open-source intelligence gathering"),
    "web": ("Web Application Enumeration", "HTTP/HTTPS endpoint discovery and web testing"),
    "exploit": ("Vulnerability Identification", "CVE correlation and exploitability assessment"),
    "brute": ("Credential Testing", "Authentication service credential auditing"),
    "payload": ("Payload Generation", "Payload synthesis and privilege escalation assessment"),
    "handler": ("Listener Management", "Reverse-connection listener configuration"),
    "pivot": ("Pivoting", "Network pivoting and tunneling"),
    "analyzer": ("Traffic Analysis", "Network traffic capture and anomaly detection"),
    "wordlist": ("Wordlist Generation", "Custom wordlist synthesis"),
}

# Service-keyword -> hardening recommendation (client report appendix).
_HARDENING = {
    "ssh": "Enforce key-based authentication and disable password login; apply rate limiting / fail2ban.",
    "http": "Harden the web server: remove default pages, apply security headers, patch the CMS/stack.",
    "https": "Harden TLS: disable legacy protocols and weak ciphers, patch the web stack, apply security headers.",
    "microsoft-ds": "Disable SMBv1, enforce SMB signing and require authenticated access; restrict exposure.",
    "netbios": "Disable NetBIOS/SMB where not required; enforce SMB signing.",
    "snmp": "Disable SNMP or restrict it to management VLANs with strong community strings.",
    "ftp": "Replace FTP with SFTP; restrict to authenticated users on a management VLAN.",
    "telnet": "Replace Telnet with SSH; disable the service where not required.",
    "mysql": "Restrict MySQL to trusted hosts, enforce strong auth and least-privilege accounts.",
    "mssql": "Disable xp_cmdshell, enforce strong sa password, restrict to trusted hosts.",
    "rdp": "Enforce Network Level Authentication and strong accounts; restrict RDP exposure.",
    "redis": "Disable unprotected Redis instances; bind to loopback or require AUTH.",
    "mongodb": "Require authentication and restrict bind address to trusted networks.",
    "smb": "Disable SMBv1, enforce SMB signing and require authenticated access; restrict exposure.",
    "nfs": "Restrict NFS exports to trusted hosts with root-squash enabled.",
    "vnc": "Disable VNC or enforce strong passwords and restrict exposure.",
    "dns": "Restrict zone transfers to authorized servers; patch the DNS daemon.",
    "smtp": "Disable open relay, enforce STARTTLS and restrict to authorized senders.",
    "pop3": "Enforce TLS and strong accounts; restrict exposure.",
    "imap": "Enforce TLS and strong accounts; restrict exposure.",
}


# ── data access helpers ────────────────────────────────────────────────────

def _services():
    return session.get_result("service_summary") or []


def _ranked():
    exploit_res = session.get_result("exploit") or {}
    return exploit_res.get("ranked", []) or []


def _analyzer_findings():
    analyzer = session.get_result("analyzer") or {}
    return analyzer.get("findings", []) or []


def _kb():
    return session.knowledge_base or {}


def _severity(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _methodology() -> list:
    """Kill-chain phases actually executed, derived from the session results."""
    steps = []
    seen = set()
    for mod in ("scan", "osint", "web", "exploit", "brute", "payload",
                "handler", "pivot", "analyzer", "wordlist"):
        if mod in session.results and mod not in seen:
            phase, desc = _PHASE_LABELS.get(mod, (mod.capitalize(), ""))
            seen.add(mod)
            steps.append({"phase": phase, "module": mod, "description": desc})
    if not steps:
        steps.append({"phase": "Reconnaissance", "module": "scan",
                      "description": "Active network scanning and service enumeration"})
    return steps


def _executive_summary() -> str:
    target = session.target or "Unknown"
    ranked = _ranked()
    services = _services()
    kb = _kb()
    high_risk = sum(1 for r in ranked if r.get("score", 0) >= 70)
    creds = kb.get("creds_found") or []
    os_info = kb.get("os_info") or {}

    parts = [f"The security assessment of target **{target}**"]
    if ranked:
        parts.append(f"identified **{len(ranked)}** potential vulnerabilities"
                     f" (of which **{high_risk}** HIGH risk)")
    else:
        parts.append("identified **no** critical vulnerabilities through automated correlation")
    if services:
        parts.append(f"Reconnaissance found **{len(services)}** exposed services")
    if creds:
        parts.append(f"Credential testing recovered **{len(creds)}** credential set(s)")
    if os_info.get("os"):
        parts.append(f"Operating system identified as **{os_info['os']}**")
    return " ".join(parts) + "."


def _hardening_for(service: str) -> str:
    svc = (service or "").lower()
    for key, rec in _HARDENING.items():
        if key in svc:
            return rec
    return "Patch the affected software to the latest stable version and restrict exposure to trusted networks only."


# ── Markdown builders ──────────────────────────────────────────────────────

def _build_operator_markdown() -> str:
    """Everything the operator needs: creds, commands, full output."""
    target = session.target or "N/A"
    kb = _kb()
    out = []

    def w(line: str = ""):
        out.append(line)

    w(f"# Phantom Operator Report — {target}")
    w()
    w(f"- **Generated**: {datetime.now().isoformat(timespec='seconds')}")
    w(f"- **Target**: {target}")
    w(f"- **Mode**: {session.mode or 'N/A'}")
    if session.scope:
        w(f"- **Scope**: {', '.join(session.scope)}")
    w()
    w("> Internal operator document — contains sensitive material (credentials, commands).")
    w()

    # Summary counts
    ranked = _ranked()
    creds = kb.get("creds_found") or []
    w("## Summary")
    w()
    w(f"- Services found: **{len(_services())}**")
    w(f"- CVEs correlated: **{len(ranked)}**")
    w(f"- Credentials recovered: **{len(creds)}**")
    w(f"- Commands executed: **{len(session.history)}**")
    w(f"- Notes: **{len(session.notes)}**")
    w()

    # OS / KB intelligence
    os_info = kb.get("os_info") or {}
    if os_info:
        w("## OS Intelligence")
        w()
        for k, v in os_info.items():
            if v:
                w(f"- **{k}**: {v}")
        w()

    # Services
    if _services():
        w("## Services")
        w()
        w("| Port | Service | Version |")
        w("|------|---------|---------|")
        for s in _services():
            w(f"| {s.get('port', '?')} | {s.get('service', '?')} | {s.get('version') or '—'} |")
        w()

    # ATT&CK + risk
    techniques = kb.get("attack_techniques") or []
    if techniques:
        w("## MITRE ATT&CK Mapping")
        w()
        w("| Technique | Name | Tactic | Phase | Prevalence |")
        w("|-----------|------|--------|-------|------------|")
        for t in techniques:
            w(f"| {t.get('id', '?')} | {t.get('name', '?')} | {t.get('tactic', '?')} | "
              f"{t.get('phase', '?')} | {t.get('prevalence', 0):.0f} |")
        w()
    if kb.get("target_risk"):
        w(f"## Target Exposure Risk: **{kb['target_risk']:.0f}/100**")
        w()

    # Credentials
    if creds:
        w("## Credentials")
        w()
        w("| Service | Username | Secret | Valid |")
        w("|---------|----------|--------|-------|")
        for c in creds:
            if isinstance(c, dict):
                w(f"| {c.get('service', '?')} | {c.get('username', '?')} | "
                  f"{c.get('password') or c.get('hash') or '?'} | {c.get('valid', '?')} |")
            else:
                w(f"- {c}")
        w()

    # CVEs
    if ranked:
        w("## Vulnerability Correlation")
        w()
        for entry in ranked:
            cve = entry.get("cve", {})
            svc = entry.get("service", {})
            score = entry.get("score", 0)
            badges = []
            if entry.get("has_msf"):
                badges.append("MSF")
            if entry.get("has_poc"):
                badges.append("PoC")
            svc_port = getattr(svc, "port", None) or (svc.get("port") if isinstance(svc, dict) else None)
            svc_name = getattr(svc, "service", None) or (svc.get("service") if isinstance(svc, dict) else None)
            w(f"### {cve.get('id', 'Unknown')} — {svc_name}/{svc_port} [{_severity(score)} {score}/100]"
              + (f" ({', '.join(badges)})" if badges else ""))
            w()
            w(f"{cve.get('description', 'No description')}")
            w()

    # KB vectors / endpoints
    for key, label in (("web_endpoints", "Web Endpoints"), ("subdomains_found", "Subdomains"),
                       ("emails_found", "Emails"), ("breaches_found", "Breaches"),
                       ("social_profiles", "Social Profiles")):
        items = kb.get(key) or []
        if items:
            w(f"## {label}")
            w()
            for item in items:
                if isinstance(item, dict):
                    w(f"- {json.dumps(item, default=str)}")
                else:
                    w(f"- {item}")
            w()

    # Module results (raw outputs)
    w("## Module Results")
    w()
    for mod, res in session.results.items():
        if mod in ("exploit", "service_summary", "_sniffer_active"):
            continue
        w(f"### {mod.upper()}")
        w()
        if isinstance(res, dict):
            for k, v in res.items():
                w(f"**{k}:**")
                w()
                w("```")
                w(str(v)[:4000])
                w("```")
        else:
            w("```")
            w(str(res)[:4000])
            w("```")
        w()

    # Command history
    if session.history:
        w("## Command History")
        w()
        for h in session.history:
            w(f"- `{h}`")
        w()

    # Notes
    if session.notes:
        w("## Field Notes")
        w()
        for n in session.notes:
            w(f"- **[{n.get('timestamp', '')}]** {n.get('text', '')}")
        w()

    w("---")
    w(f"*Phantom Framework v{VERSION} — internal operator report*")
    return "\n".join(out)


def _build_client_markdown() -> str:
    """Sanitized client skeleton: methodology, findings by severity, hardening."""
    target = session.target or "N/A"
    kb = _kb()
    ranked = _ranked()
    findings = _analyzer_findings()
    out = []

    def w(line: str = ""):
        out.append(line)

    w(f"# Penetration Test Report — {target}")
    w()
    w(f"- **Date**: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    w(f"- **Target**: {target}")
    w(f"- **Scope**: {', '.join(session.scope) if session.scope else 'As authorized'}")
    w(f"- **Classification**: Confidential")
    w()

    # Executive summary
    w("## Executive Summary")
    w()
    w(_executive_summary())
    w()

    # Scope & Methodology
    w("## Scope & Methodology")
    w()
    w("The assessment followed a structured kill-chain methodology. "
      "The following phases were executed:")
    w()
    for i, step in enumerate(_methodology(), 1):
        w(f"{i}. **{step['phase']}** — {step['description']}")
    w()
    w("All testing was performed against the authorized scope above. "
      "Findings are classified by severity and ordered by business impact.")
    w()

    # Findings by severity
    if ranked:
        w("## Findings")
        w()
        by_sev = {"HIGH": [], "MEDIUM": [], "LOW": []}
        for entry in ranked:
            by_sev[_severity(entry.get("score", 0))].append(entry)
        for sev in ("HIGH", "MEDIUM", "LOW"):
            group = by_sev[sev]
            if not group:
                continue
            w(f"### {sev}")
            w()
            for entry in group:
                cve = entry.get("cve", {})
                svc = entry.get("service", {})
                svc_port = getattr(svc, "port", None) or (svc.get("port") if isinstance(svc, dict) else None)
                svc_name = getattr(svc, "service", None) or (svc.get("service") if isinstance(svc, dict) else None)
                w(f"#### {cve.get('id', 'Unknown CVE')} — {svc_name}/{svc_port} "
                  f"(score {entry.get('score', 0)}/100)")
                w()
                w(f"{cve.get('description', 'No description available')}")
                w()
            w()

    # Anomalies from analyzer
    if findings:
        w("## Captured Information & Anomalies")
        w()
        for sev, typ, detail in findings:
            w(f"- **[{sev}]** *{typ}*: {detail}")
        w()

    # Reasoning & hypotheses from the shared WorldModel (client-safe:
    # capability + status only, never commands/credentials)
    try:
        from phantom.core.knowledge import session_wm
        wm = session_wm()
        hyps = [h for h in wm.hypotheses if h.status != "pending"] or \
               wm.hypotheses
        if hyps:
            w("## Reasoning & Hypotheses")
            w()
            w("During the assessment the framework inferred the following "
              "hypotheses about the target (confirmed by evidence, refuted "
              "by execution, or still pending manual verification):")
            w()
            for h in hyps[:12]:
                status = {"confirmed": "CONFIRMED", "refuted": "REFUTED",
                          "abandoned": "ABANDONED", "pending": "PENDING"}
                w(f"- **[{status.get(h.status, h.status)}]** "
                  f"`{h.capability_id}`: {h.reason}")
            w()
    except Exception:
        pass

    # MITRE ATT&CK (client-safe: technique IDs/names only)
    techniques = kb.get("attack_techniques") or []
    if techniques:
        w("## MITRE ATT&CK Coverage")
        w()
        w("The exposed services map to the following adversary techniques "
          "(per MITRE ATT&CK), which the hardening recommendations below "
          "are intended to disrupt:")
        w()
        for t in techniques[:12]:
            w(f"- **{t.get('id', '?')}** — {t.get('name', '?')} "
              f"({t.get('tactic', '?')}, {t.get('phase', '?')})")
        w()
    if kb.get("target_risk"):
        w(f"**Composite target exposure risk: {kb['target_risk']:.0f}/100** "
          "(driven by the most business-critical exposed service).")
        w()

    # Attack surface
    if _services():
        w("## Attack Surface")
        w()
        w("| Port | Service | Version |")
        w("|------|---------|---------|")
        for s in _services():
            w(f"| {s.get('port', '?')} | {s.get('service', '?')} | {s.get('version') or '—'} |")
        w()

    # Recommended hardening
    if _services() or ranked:
        w("## Recommended Hardening")
        w()
        seen = set()
        for s in _services():
            svc = s.get("service", "")
            if svc in seen:
                continue
            seen.add(svc)
            w(f"- **{svc}**: {_hardening_for(svc)}")
        for entry in ranked:
            cve = entry.get("cve", {})
            cve_id = cve.get("id", "Unknown")
            if cve_id not in seen:
                seen.add(cve_id)
                w(f"- **{cve_id}**: Patch to the vendor-recommended fixed version and "
                  "verify the affected service is not exposed beyond the trusted network.")
        w()

    # Field notes (sanitized — no commands/creds)
    if session.notes:
        w("## Field Notes")
        w()
        for n in session.notes:
            w(f"- **[{n.get('timestamp', '')}]** {n.get('text', '')}")
        w()

    w("---")
    w(f"*Report generated with Phantom Framework v{VERSION} — Confidential. "
      "For authorized use only.*")
    return "\n".join(out)


class ReportModule(BaseModule):
    module_name = "report"

    def __init__(self):
        super().__init__()
        self.template_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "templates", "report")

    def suggest_commands(self) -> dict:
        from phantom.modules.suggest import report_suggestion_group
        return report_suggestion_group()

    # ── export entry point ──────────────────────────────────────────────────

    def do_export(self, arg: str):
        """export all|json|html|pdf|md|client [filename]"""
        parts = arg.strip().split()
        fmt = parts[0].lower() if parts else "all"
        filename = parts[1] if len(parts) > 1 else ""

        if fmt == "all":
            self._export_full_set()
            return
        self.export(fmt, filename)

    def export(self, fmt: str = "all", filename: str = ""):
        if fmt == "all":
            self._export_full_set()
            return
        if not filename:
            # Target-derived names are sanitized: URL targets contain slashes
            # that would create missing subdirectories (open() fails) and ".."
            # could escape the reports directory entirely.
            safe_target = re.sub(r"[^A-Za-z0-9._\-]", "_", session.target or "phantom")
            filename = (f"report_{safe_target}_"
                        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}")
        elif not filename.endswith(f".{fmt}"):
            filename += f".{fmt}"

        if fmt == "json":
            self._export_json(filename)
        elif fmt == "html":
            self._export_html(filename)
        elif fmt == "pdf":
            self._export_pdf(filename)
        elif fmt == "md":
            self._export_operator_md(filename)
        elif fmt == "client":
            self._export_client_md(filename)
        else:
            notifier.error(f"Unsupported format: {fmt}")

    def _export_full_set(self):
        """Write the complete double-report set to data/reports/<ts>/."""
        from phantom.utils.paths import reports_dir
        import tempfile
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        rdir = os.path.join(reports_dir(), f"engagement_{ts}")
        os.makedirs(rdir, exist_ok=True)

        raw_json = os.path.join(rdir, "raw_report.json")
        raw_md = os.path.join(rdir, "raw_report.md")
        client_md = os.path.join(rdir, "client_report.md")
        client_html = os.path.join(rdir, "client_report.html")

        self._export_json(raw_json)
        self._export_operator_md(raw_md)
        self._export_client_md(client_md)
        self._export_html(client_html)

        notifier.success(f"Full report set written to {rdir}")
        notifier.info("  raw_report.json   — full structured audit (operator)")
        notifier.info("  raw_report.md     — operator document (creds + commands)")
        notifier.info("  client_report.md  — sanitized client skeleton")
        notifier.info("  client_report.html — sanitized client HTML")

        recorded = self._record_learning()
        if recorded:
            notifier.info(
                f"Engagement learning: {recorded} technique outcome(s) recorded "
                "(Bayesian calibration + history).")

    @staticmethod
    def _record_learning() -> int:
        """Feed the manual engagement's outcomes into the disk-persisted
        learning engines (Bayesian calibration + historical analyzer).

        Called once at report time (never in a hot loop). Only techniques
        with concrete evidence in the session are recorded — no guessing.
        """
        from phantom.core.calibration import calibration_engine
        from phantom.core.history import history_analyzer

        kb = session.knowledge_base or {}
        status = kb.get("status", {}) or {}
        observed = []

        if "scan" in session.results or "service_summary" in session.results:
            observed.append(("network_service_scanning", bool(_services())))
        if "osint" in session.results:
            observed.append(("osint_identity", bool(kb.get("emails_found") or kb.get("subdomains_found"))))
        if "exploit" in session.results:
            observed.append(("exploit_cve_public", bool(_ranked())))
        if "brute" in session.results:
            observed.append(("brute_force_passwords", bool(kb.get("creds_found"))))
        if status.get("beacon_deployed") or kb.get("beacon_deployed"):
            observed.append(("beacon_deploy", True))
        elif status.get("rce_attempted") or "payload" in session.results:
            observed.append(("beacon_deploy", False))
        if kb.get("domain_enumerated") or status.get("post_exploit_done"):
            observed.append(("ad_enumeration", bool(kb.get("ad_domain"))))
        if status.get("hash_crack_done") or kb.get("hash_crack_done"):
            observed.append(("hash_cracking", bool(kb.get("creds_found"))))

        for technique, ok in observed:
            try:
                calibration_engine.observe(technique, ok)
            except Exception:
                pass
            try:
                history_analyzer.record_attempt(technique, "manual", ok)
            except Exception:
                pass
        return len(observed)

    def _export_json(self, filename: str):
        data = {
            "target": session.target,
            "mode": session.mode,
            "scope": session.scope,
            "created_at": session.created_at,
            "exported_at": datetime.now().isoformat(),
            "results": session.results,
            "knowledge_base": session.knowledge_base,
            "notes": session.notes,
            "history": session.history,
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        notifier.success(f"JSON audit saved to {filename}")

    def _export_operator_md(self, filename: str):
        with open(filename, "w", encoding="utf-8") as f:
            f.write(_build_operator_markdown())
        notifier.success(f"Operator report saved to {filename}")

    def _export_client_md(self, filename: str):
        with open(filename, "w", encoding="utf-8") as f:
            f.write(_build_client_markdown())
        notifier.success(f"Client report skeleton saved to {filename}")

    # ── HTML / PDF (client-grade, sanitized) ────────────────────────────────

    def _load_template(self, name: str) -> str:
        path = os.path.join(self.template_dir, name)
        if not os.path.exists(path):
            notifier.error(f"Template not found: {path}")
            return ""
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def _export_html(self, filename: str):
        template = self._load_template("professional.html")
        if not template:
            return

        target = session.target or "Phantom Engagement"
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary = _executive_summary().replace("**", "<strong>").replace(
            "**", "</strong>")

        html = template.replace("{{ target }}", target)
        html = html.replace("{{ date_str }}", date_str)
        html = html.replace("{{ summary }}", summary)
        html = html.replace("{{ vuln_content }}", self._build_vuln_html())
        html = html.replace("{{ service_section }}", self._build_service_section())
        html = html.replace("{{ analyzer_section }}", self._build_analyzer_section())
        html = html.replace("{{ notes_section }}", self._build_notes_section())
        # Client-grade: command history is intentionally NOT included.
        html = html.replace("{{ history_section }}", "")
        html = html.replace("Phantom v2.5", f"Phantom v{VERSION}")

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        notifier.success(f"Client HTML report saved to {filename}")

    def _build_vuln_html(self) -> str:
        ranked = _ranked()
        if not ranked:
            return "<p>No vulnerabilities identified through automated analysis.</p>"
        html = ""
        for entry in ranked:
            cve = entry.get("cve", {})
            svc = entry.get("service", {})
            score = entry.get("score", 0)
            level = "high" if score >= 70 else ("med" if score >= 40 else "low")
            svc_port = getattr(svc, "port", None) or (svc.get("port") if isinstance(svc, dict) else None)
            svc_name = getattr(svc, "service", None) or (svc.get("service") if isinstance(svc, dict) else None)

            badges = ""
            if entry.get("has_msf"):
                badges += "<span class='badge bg-high'>Metasploit Available</span> "
            if entry.get("has_poc"):
                badges += "<span class='badge bg-med'>Public PoC Found</span>"

            html += f"""
        <div class="card vuln-card vuln-{level}">
            <div>
                <strong>{cve.get('id', 'Unknown CVE')}</strong> - {svc_name}/{svc_port}<br>
                <small style="color: #666;">{cve.get('description', 'No description available')[:200]}...</small>
                <div style="margin-top: 10px;">{badges}</div>
            </div>
            <div class="score" style="color: var(--{level});">{score}/100</div>
        </div>"""
        return html

    def _build_service_section(self) -> str:
        services = _services()
        if not services:
            return ""
        rows = ""
        for s in services:
            rows += f"<tr><td>{s.get('port', '?')}</td><td>{s.get('service', '?')}</td><td>{s.get('version') or '—'}</td></tr>"
        return f"""
    <section>
        <h2>Network Reconnaissance</h2>
        <table>
            <thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </section>"""

    def _build_analyzer_section(self) -> str:
        findings = _analyzer_findings()
        if not findings:
            return ""
        items = ""
        for sev, typ, detail in findings:
            color = "high" if sev == "CRITICAL" else ("med" if sev == "HIGH" else "low")
            items += f"<li><span class='badge bg-{color}'>{sev}</span> <strong>{typ}:</strong> {detail}</li>"
        return f"""
    <section>
        <h2>Captured Information & Anomalies</h2>
        <ul>{items}</ul>
    </section>"""

    def _build_notes_section(self) -> str:
        if not session.notes:
            return ""
        items = ""
        for note in session.notes:
            items += f"<li><strong>[{note.get('timestamp', '')}]</strong> {note.get('text', '')}</li>"
        return f"<section><h2>Field Notes</h2><ul>{items}</ul></section>"

    def _export_pdf(self, filename: str):
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        except ImportError:
            notifier.error("reportlab not installed. Install with: pip install reportlab")
            return

        doc = SimpleDocTemplate(filename, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []

        title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=24, spaceAfter=20)
        heading_style = ParagraphStyle('HeadingStyle', parent=styles['Heading2'], fontSize=16, spaceBefore=15, spaceAfter=10)

        elements.append(Paragraph("Security Assessment Report", title_style))
        elements.append(Paragraph(f"<b>Target:</b> {session.target or 'Unknown'}", styles['Normal']))
        elements.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("Executive Summary", heading_style))
        summary_text = _executive_summary().replace("**", "<b>")
        elements.append(Paragraph(summary_text, styles['Normal']))
        elements.append(Spacer(1, 15))

        ranked = _ranked()
        if ranked:
            elements.append(Paragraph("Key Findings", heading_style))
            data = [["CVE ID", "Service", "Score"]]
            for entry in ranked[:10]:
                cve = entry.get("cve", {})
                svc = entry.get("service", {})
                svc_port = getattr(svc, "port", None) or (svc.get("port") if isinstance(svc, dict) else None)
                svc_name = getattr(svc, "service", None) or (svc.get("service") if isinstance(svc, dict) else None)
                data.append([cve.get("id", "—"), f"{svc_name}/{svc_port}", str(entry.get("score", 0))])
            t = Table(data, colWidths=[150, 200, 100])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(t)
            elements.append(Spacer(1, 15))

        services = _services()
        if services:
            elements.append(Paragraph("Exposed Services", heading_style))
            data = [["Port", "Service", "Version"]]
            for s in services:
                data.append([s.get("port", "?"), s.get("service", "?"), s.get("version") or "—"])
            t = Table(data, colWidths=[80, 150, 220])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            elements.append(t)

        if session.notes:
            elements.append(Paragraph("Field Notes", heading_style))
            for note in session.notes:
                elements.append(Paragraph(f"• [{note.get('timestamp', '')}] {note.get('text', '')}", styles['Normal']))

        doc.build(elements)
        notifier.success(f"Client PDF report saved to {filename}")

    def do_run(self, arg):
        if "--quiet" in (arg or "").split():
            self.quiet = True
        if getattr(self, "quiet", False):
            self._export_full_set()
            return
        fmt = input("  Format (all/json/html/pdf/md/client) [all]: ").strip().lower() or "all"
        if fmt == "all":
            self._export_full_set()
            return
        default_name = f"report_{session.target or 'phantom'}.{fmt}"
        fname = input(f"  Filename [{default_name}]: ").strip()
        if not fname:
            fname = default_name
        self.export(fmt, fname)

    def do_preview(self, _):
        self.do_run(_)
