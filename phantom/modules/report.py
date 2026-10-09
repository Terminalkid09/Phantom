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
  export capabilities <file.json> -> machine-readable, per-capability
                         evidence (typed kind, key, confidence, source)
"""

import json
import os
import re
from datetime import datetime
from typing import Optional

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


def _phase_state(modules, count: int) -> str:
    """The THREE honest states of one kill-chain phase.

    "not executed" is not the same as "executed and found nothing". The old
    summary collapsed both into "identified no critical vulnerabilities
    through automated correlation", so a report produced BEFORE the exploit
    module ever ran read exactly like a clean assessment: the client could
    not tell an untested target from a hardened one. The state is read from
    ``session.results`` — never inferred from a missing finding list.
    """
    if isinstance(modules, str):
        modules = (modules,)
    if not any(m in session.results for m in modules):
        return "not-run"
    return "found" if count else "empty"


def _phase_clause(subject: str, modules, count: int, noun: str) -> str:
    """One executive-summary clause for a phase, in its real state."""
    state = _phase_state(modules, count)
    if state == "not-run":
        return f"{subject} was **not executed** in this engagement"
    if state == "empty":
        return f"{subject} ran and found **no** {noun}"
    return f"{subject} found **{count}** {noun}"


def _executive_summary() -> str:
    target = session.target or "Unknown"
    ranked = _ranked()
    services = _services()
    kb = _kb()
    high_risk = sum(1 for r in ranked if r.get("score", 0) >= 70)
    creds = kb.get("creds_found") or []
    os_info = kb.get("os_info") or {}

    parts = [f"The security assessment of target **{target}**"]

    # Reconnaissance — "found nothing" is only claimable if it actually ran.
    parts.append(_phase_clause(
        "Reconnaissance", ("scan", "service_summary"),
        len(services), "exposed services"))

    # Vulnerability identification, with the HIGH-risk breakdown.
    if _phase_state(("exploit",), len(ranked)) == "not-run":
        parts.append("Vulnerability identification was **not executed** "
                     "(no exploitation/correlation phase ran)")
    elif ranked:
        parts.append(f"Vulnerability identification found **{len(ranked)}** "
                     f"potential vulnerabilities (of which **{high_risk}** "
                     "HIGH risk)")
    else:
        parts.append("Vulnerability identification ran and found **no** "
                     "exploitable vulnerabilities")

    # Credential testing.
    parts.append(_phase_clause(
        "Credential testing", ("brute",),
        len(creds), "credential set(s)"))

    if os_info.get("os"):
        parts.append(f"Operating system identified as **{os_info['os']}**")
    return " ".join(parts) + "."


def _hardening_for(service: str) -> str:
    svc = (service or "").lower()
    for key, rec in _HARDENING.items():
        if key in svc:
            return rec
    return "Patch the affected software to the latest stable version and restrict exposure to trusted networks only."


def _unique_dir(root: str, name: str) -> str:
    """Create and return a report directory that cannot silently collide.

    Two reports generated in the same wall-clock second used to land in the
    SAME ``report_<target>_<YYYYmmdd_HHMMSS>`` directory; ``makedirs(...,
    exist_ok=True)`` then let the second run overwrite ``raw_audit`` and
    ``client_report`` — the first engagement's evidence was destroyed with
    no warning. The human-readable timestamp stays; only a real collision
    gets a ``-2``, ``-3`` suffix. ``makedirs`` without ``exist_ok`` is used
    so the check and the create are the same syscall-level step.
    """
    n = 1
    while True:
        candidate = os.path.join(root, name if n == 1 else f"{name}-{n}")
        try:
            os.makedirs(candidate)
        except FileExistsError:
            n += 1
            if n > 1000:
                raise
            continue
        return candidate


def _confidence_text(kind: str, key: str) -> str:
    """Confidence of a finding, looked up in the shared WorldModel.

    The manual modules already compute a confidence for every finding
    (``scan.py`` service = 0.7, ``exploit.py`` privesc = 0.7-0.9) and store
    it in the WorldModel, but the report only read ``session.results`` — so
    the number never reached the client. A finding without a confidence is a
    finding the client cannot weigh. Returns "not recorded" when the
    WorldModel holds no matching evidence (never fabricate a value).
    """
    try:
        from phantom.core.knowledge import session_wm
        for f in session_wm().all_findings():
            if f.kind == kind and f.key == key:
                return f"{float(f.confidence):.2f}"
    except Exception:
        pass
    return "not recorded"


_OUTCOME_LABEL = {
    "ok": "executed — output captured",
    "empty": "executed — no output",
    "error": "blocked / failed",
    "not-run": "not executed",
}


def _module_outcomes() -> list:
    """Every module the session ran, with the REAL outcome of its run.

    "the tool was not installed", "the target was unreachable" and "nothing
    was found" all used to reach the reader as the same empty result. The
    outcome is read from the recorded run status (see ``Session.add_result``)
    — never guessed from the data.
    """
    rows = []
    for mod in session.results:
        if mod.startswith("_"):
            continue
        st = session.result_status.get(mod) or {}
        err = st.get("error") if isinstance(st, dict) else None
        rows.append((mod, session.result_outcome(mod), err))
    return rows


def _capabilities() -> list:
    """Machine-readable evidence, ONE RECORD PER CAPABILITY (G18).

    The report was only readable by a human: the JSON dump carried the raw
    per-module blobs, so nothing downstream (a ticketing system, a coverage
    tracker, a diff between two engagements) could consume a finding without
    re-parsing stdout. Every WorldModel finding is emitted here with its
    typed kind, its key, the confidence the evidence model assigned and the
    source that produced it.
    """
    rows = []
    try:
        from phantom.core.knowledge import session_wm
        for f in session_wm().all_findings():
            rows.append({
                "capability": f.kind,
                "key": f.key,
                "confidence": float(f.confidence),
                "source": f.source,
                "evidence": f.value,
            })
    except Exception:
        pass
    return rows


def _bold_to_html(text: str, open_tag: str, close_tag: str) -> str:
    """Convert markdown ``**bold**`` to markup, alternating open/close.

    ``text.replace("**", "<strong>")`` (the old code) replaced EVERY marker
    with an opening tag; there was no ``**`` left for the closing pass, so
    every client HTML/PDF executive summary shipped with unclosed tags.
    """
    parts = text.split("**")
    out = [parts[0]]
    for i, chunk in enumerate(parts[1:], start=1):
        out.append(open_tag if i % 2 == 1 else close_tag)
        out.append(chunk)
    return "".join(out)


# ── Markdown builders ──────────────────────────────────────────────────────

def _guardrails_markdown() -> list:
    """The protection level THIS engagement ran at, as report lines.

    The manifest is the only record an operator can point at when a client
    asks which controls were active, and it is the reason the API report and
    the CLI report must come from the same generator: when the API built its
    own text, the manifest was silently absent from every UI-produced report.

    Best-effort by design: a reporting problem must never lose the report, so
    a failure degrades to one line saying so instead of raising.
    """
    try:
        from phantom.utils import guardrails as gr
        manifest = gr.build(
            scope=getattr(session, "scope", None),
            targets=[session.target] if session.target else None)
        return ["", gr.report_block(manifest)]
    except Exception as exc:
        return ["", f"_Guardrail manifest unavailable ({type(exc).__name__})._"]


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
    if kb.get("persistence_set") or (kb.get("status") or {}).get("persistence_set"):
        w("- Persistence installed: **yes** — clear it with the beacon's "
          "`unpersist` before demobilizing")
    w()

    # Run outcomes: what actually happened, per module. The raw module
    # output below says nothing about whether a tool was missing.
    outcomes = _module_outcomes()
    if outcomes:
        w("## Module Outcomes")
        w()
        w("| Module | Outcome | Reason |")
        w("|--------|---------|--------|")
        for mod, outcome, err in outcomes:
            w(f"| {mod} | {_OUTCOME_LABEL.get(outcome, outcome)} | {err or '—'} |")
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
            cve_id = cve.get('id', 'Unknown')
            w(f"### {cve_id} — {svc_name}/{svc_port} [{_severity(score)} {score}/100]"
              + (f" ({', '.join(badges)})" if badges else "")
              + f" — confidence {_confidence_text('vuln', cve_id)}")
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

    out.extend(_guardrails_markdown())

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

    # Coverage: an untested or blocked phase must not read as a clean one.
    outcomes = _module_outcomes()
    if outcomes:
        w("## Assessment Coverage")
        w()
        w("Each phase reports what actually happened; a phase that could not "
          "run is listed as such and is not evidence of a clean result:")
        w()
        w("| Phase | Result |")
        w("|-------|--------|")
        for mod, outcome, err in outcomes:
            label = _OUTCOME_LABEL.get(outcome, outcome)
            if outcome == "error" and err:
                label = f"{label} ({err})"
            w(f"| {mod} | {label} |")
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
                client_cve_id = cve.get('id', 'Unknown CVE')
                w(f"#### {client_cve_id} — {svc_name}/{svc_port} "
                  f"(score {entry.get('score', 0)}/100)")
                w()
                w(f"{cve.get('description', 'No description available')}")
                w()
                w(f"_Evidence confidence: "
                  f"{_confidence_text('vuln', client_cve_id)} (assessment "
                  "evidence model)._")
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

    # Persistence & cleanup — only when the engagement installed any. A tool
    # that installs persistence MUST hand the client the way back out: the
    # old report listed the artifacts as IOCs and told the client to remove
    # them, with no supported command to do it. The beacon's `unpersist`
    # deletes exactly what `persist` created (same RunKey value / systemd
    # unit / autostart file / cron line / on-disk copy).
    if kb.get("persistence_set") or (kb.get("status") or {}).get("persistence_set"):
        w("## Persistence & Cleanup")
        w()
        w("During the assessment the beacon installed persistence on the "
          "target. Every artifact below is removed by the beacon's own "
          "`unpersist` command, which reuses the identical paths `persist` "
          "installed:")
        w()
        w("- Windows: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion"
          "\\Run value, plus the beacon copy under `%APPDATA%\\Microsoft"
          "\\Phantom\\`")
        w("- Linux: `~/.config/systemd/user/<name>.service`, "
          "`~/.config/autostart/<name>.desktop`, the `crontab` line, and the "
          "copy in `~/.local/bin/`")
        w("- macOS: `~/Library/LaunchAgents/com.<name>.plist`")
        w()
        w("```")
        w("unpersist              # same default name used by `persist`")
        w("unpersist <name>       # the non-default name you installed with")
        w("```")
        w()

    # Field notes (sanitized — no commands/creds)
    if session.notes:
        w("## Field Notes")
        w()
        for n in session.notes:
            w(f"- **[{n.get('timestamp', '')}]** {n.get('text', '')}")
        w()

    out.extend(_guardrails_markdown())

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
        elif fmt == "capabilities" and not filename.endswith(".json"):
            filename += ".json"
        elif fmt != "capabilities" and not filename.endswith(f".{fmt}"):
            filename += f".{fmt}"

        if fmt == "json":
            self._export_json(filename)
        elif fmt == "capabilities":
            self._export_capabilities(filename)
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

    def generate(self, fmt: str = "html") -> dict:
        """Build the report set for the CURRENT session, non-interactively.

        THE single entry point for callers other than the CLI (the API server):
        the UI used to run a second generator inline that dropped the guardrail
        manifest, so a report delivered to a client from the UI could not show
        which controls were active. One generator, one answer.

        Returns the two artifact paths plus the text previews the UI shows; the
        chosen format decides the file types, and a PDF request without
        reportlab degrades to HTML rather than writing text into a `.pdf`.
        """
        from phantom.utils.paths import reports_dir
        fmt = (fmt or "html").lower()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        safe_target = re.sub(r"[^A-Za-z0-9._-]", "_", session.target or "unknown")
        rdir = _unique_dir(
            reports_dir(),
            f"report_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

        operator_md = _build_operator_markdown()
        client_md = _build_client_markdown()
        note = ""

        if fmt == "json":
            raw_path = os.path.join(rdir, "raw_audit.json")
            self._export_json(raw_path)
            client_path = os.path.join(rdir, "client_report.json")
            with open(client_path, "w", encoding="utf-8") as f:
                json.dump({"generated_at": now, "client_report": client_md},
                          f, indent=2, default=str)
        elif fmt == "capabilities":
            raw_path = os.path.join(rdir, "capabilities.json")
            self._export_capabilities(raw_path)
            client_path = raw_path
        elif fmt == "pdf":
            raw_path = os.path.join(rdir, "raw_audit.md")
            with open(raw_path, "w", encoding="utf-8") as f:
                f.write(operator_md)
            client_path = os.path.join(rdir, "client_report.pdf")
            if not self._export_pdf(client_path):
                client_path = os.path.join(rdir, "client_report.html")
                self._export_html(client_path)
                note = ("reportlab not installed: the client report was written "
                        "as HTML instead of PDF")
        else:
            fmt = "html"
            from html import escape as _e
            raw_path = os.path.join(rdir, "raw_audit.html")
            with open(raw_path, "w", encoding="utf-8") as f:
                f.write("<!DOCTYPE html>\n<html><head><meta charset=\"UTF-8\">"
                        "<title>Phantom Raw Audit</title></head><body><pre>"
                        f"{_e(operator_md)}</pre></body></html>")
            client_path = os.path.join(rdir, "client_report.html")
            self._export_html(client_path)

        out = {
            "raw": operator_md,
            "client": client_md,
            "raw_path": raw_path,
            "client_path": client_path,
            "generated_at": now,
            "format": fmt,
        }
        if note:
            out["note"] = note
        return out

    def _export_full_set(self):
        """Write the complete double-report set to data/reports/<ts>/."""
        from phantom.utils.paths import reports_dir
        import tempfile
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        rdir = _unique_dir(reports_dir(), f"engagement_{ts}")

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
        # Machine-readable, per-capability evidence + per-module outcomes:
        # the parts another tool can consume without re-parsing stdout.
        data["capabilities"] = _capabilities()
        data["module_outcomes"] = [
            {"module": m, "outcome": o, "error": e}
            for m, o, e in _module_outcomes()
        ]
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        notifier.success(f"JSON audit saved to {filename}")

    def _export_capabilities(self, filename: str):
        """Standalone machine-readable export, keyed by capability (G18)."""
        payload = {
            "target": session.target,
            "mode": session.mode,
            "generated_at": datetime.now().isoformat(),
            "capabilities": _capabilities(),
            "module_outcomes": [
                {"module": m, "outcome": o, "error": e}
                for m, o, e in _module_outcomes()
            ],
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        notifier.success(f"Capability export saved to {filename}")

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
        summary = _bold_to_html(_executive_summary(), "<strong>", "</strong>")

        # P1-12: the target string is operator/target-controlled input →
        # escaped before it lands in the client-facing page
        from html import escape as _e
        html = template.replace("{{ target }}", _e(str(target)))
        html = html.replace("{{ date_str }}", date_str)
        html = html.replace("{{ summary }}", summary)
        html = html.replace("{{ vuln_content }}", self._build_vuln_html())
        html = html.replace("{{ service_section }}", self._build_service_section())
        html = html.replace("{{ analyzer_section }}", self._build_analyzer_section())
        html = html.replace("{{ notes_section }}", self._build_notes_section())
        # Client-grade: command history is intentionally NOT included.
        html = html.replace("{{ history_section }}", "")
        # The guardrail manifest is part of the deliverable: the template is
        # set in stone, so when it has no placeholder the section is injected
        # before the footer — never dropped.
        guardrails_html = self._build_guardrails_section()
        if "{{ guardrails_section }}" in html:
            html = html.replace("{{ guardrails_section }}", guardrails_html)
        else:
            html = html.replace("<footer>",
                                guardrails_html + "\n\n    <footer>", 1)
        html = html.replace("Phantom v2.5", f"Phantom v{VERSION}")

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        notifier.success(f"Client HTML report saved to {filename}")

    def _build_vuln_html(self) -> str:
        from html import escape as _e
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

            # P1-12: every target-derived field is escaped at serialization —
            # a service banner like `<script>x</script>` must render as text
            html += f"""
        <div class="card vuln-card vuln-{level}">
            <div>
                <strong>{_e(str(cve.get('id', 'Unknown CVE')))}</strong> - {_e(str(svc_name))}/{_e(str(svc_port))}<br>
                <small style="color: #666;">{_e(str(cve.get('description', 'No description available'))[:200])}...</small>
                <div style="margin-top: 10px;">{badges}</div>
                <small style="color: #888;">Evidence confidence: {_e(_confidence_text('vuln', str(cve.get('id', 'Unknown'))))}</small>
            </div>
            <div class="score" style="color: var(--{level});">{score}/100</div>
        </div>"""
        return html

    def _build_service_section(self) -> str:
        from html import escape as _e
        services = _services()
        if not services:
            return ""
        rows = ""
        for s in services:
            # P1-12: banner/version strings are target-derived → escaped
            rows += (f"<tr><td>{s.get('port', '?')}</td>"
                     f"<td>{_e(str(s.get('service', '?')))}</td>"
                     f"<td>{_e(str(s.get('version') or '—'))}</td></tr>")
        return f"""
    <section>
        <h2>Network Reconnaissance</h2>
        <table>
            <thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </section>"""

    def _build_analyzer_section(self) -> str:
        from html import escape as _e
        findings = _analyzer_findings()
        if not findings:
            return ""
        items = ""
        for sev, typ, detail in findings:
            color = "high" if sev == "CRITICAL" else ("med" if sev == "HIGH" else "low")
            items += (f"<li><span class='badge bg-{color}'>{sev}</span> "
                      f"<strong>{_e(str(typ))}:</strong> {_e(str(detail))}</li>")
        return f"""
    <section>
        <h2>Captured Information & Anomalies</h2>
        <ul>{items}</ul>
    </section>"""

    def _build_notes_section(self) -> str:
        from html import escape as _e
        if not session.notes:
            return ""
        items = ""
        for note in session.notes:
            items += (f"<li><strong>[{_e(str(note.get('timestamp', '')))}]</strong> "
                      f"{_e(str(note.get('text', '')))}</li>")
        return f"<section><h2>Field Notes</h2><ul>{items}</ul></section>"

    def _build_guardrails_section(self) -> str:
        """The guardrail manifest, escaped, as a valid HTML section."""
        from html import escape as _e
        body = _e("\n".join(_guardrails_markdown()).strip())
        return ("<section>\n        <h2>Guardrails</h2>\n"
                f"        <pre>{body}</pre>\n    </section>")

    def _export_pdf(self, filename: str):
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        except ImportError:
            notifier.error("reportlab not installed. Install with: pip install reportlab")
            return False

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
        summary_text = _bold_to_html(_executive_summary(), "<b>", "</b>")
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
        return True

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
