import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from rich.console import Console

console = Console()

KB_STATUS_DEFAULT = {
    "classified": False,
    "scan_done": False,
    "os_detected": False,
    "scan_stealth_done": False,
    "osint_done": False,
    "dns_recon_done": False,
    "social_recon_done": False,
    "web_recon_done": False,
    "breach_check_done": False,
    "cve_correlate_done": False,
    "default_creds_tested": False,
    "rce_attempted": False,
    "beacon_deployed": False,
    "persistence_set": False,
    "post_exploit_done": False,
    "hash_crack_done": False,
}


@dataclass
class Session:
    target: str = ""
    lhost: str = ""
    lport: int = 0
    mode: str = ""
    scope: List[str] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    notes: List[Dict[str, str]] = field(default_factory=list)
    history: List[str] = field(default_factory=list)
    active_wordlist: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    knowledge_base: Dict[str, Any] = field(default_factory=lambda: {
        "target": "",
        "target_type": None,
        "stealth": True,
        "aggressive": False,
        "started_at": None,
        "status": dict(KB_STATUS_DEFAULT),
        "services": [],
        "os_info": {},
        "creds_found": [],
        "rce_vectors": [],
        "cves": [],
        "web_endpoints": [],
        "social_profiles": [],
        "emails_found": [],
        "subdomains_found": [],
        "breaches_found": [],
        "beacon_deployed": False,
        "persistence_set": False,
        "current_step": None,
        "errors": [],
        "next_targets": [],
        "last_output": {},
        # Enterprise context fields
        "critical_infrastructure": False,
        "domain_environment": False,
        "network_segmentation": {},
        "critical_assets": [],
        "password_policy": {},
        "waf_detected": False,
        "domain_enumerated": False,
        "known_defaults": False,
    })

    def add_result(self, module: str, data: Any) -> None:
        self.results[module] = data

    def get_result(self, module: str) -> Any:
        return self.results.get(module)

    def add_note(self, text: str) -> None:
        self.notes.append({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "text": text
        })

    def add_history(self, cmd: str) -> None:
        # Never persist an inline credential (`SSHPASS='pw'`, `-p secret`,
        # `password=x`): history is serialized into the saved session JSON,
        # so a raw command would put the target's password at rest in
        # data/sessions/. Redaction keeps the command readable for the
        # operator and inert on disk.
        try:
            from phantom.utils.redact import redact_text
            cmd = redact_text(cmd)
        except Exception:
            pass
        self.history.append(f"[{datetime.now().strftime('%H:%M:%S')}] {cmd}")

    def save(self, name: str) -> None:
        """Save the current session to data/sessions/{name}.json atomically
        (the shared WorldModel is embedded so the reasoning state survives)."""
        from phantom.utils.paths import sessions_dir
        sdir = sessions_dir()
        os.makedirs(sdir, exist_ok=True)
        path = os.path.join(sdir, f"{_check_session_name(name)}.json")
        data = json.loads(json.dumps(self.__dict__, indent=2, default=str))
        try:
            from phantom.core.knowledge import session_wm
            data["_wm"] = json.loads(session_wm().to_json())
        except Exception:
            pass
        with tempfile.NamedTemporaryFile(mode='w', dir=sdir, delete=False, suffix='.json', encoding='utf-8') as tmp:
            json.dump(data, tmp, indent=2, default=str)
            tmp_path = tmp.name
        os.replace(tmp_path, path)
        console.print(f"[green][+] Session saved: {path}[/]")

    def export_markdown(self, filename: str) -> None:
        """Export session to a professional Markdown report."""
        from phantom.utils.paths import sessions_dir
        sdir = sessions_dir()
        os.makedirs(sdir, exist_ok=True)
        path = os.path.join(sdir, _check_session_name(filename))
        with open(path, "w", encoding="utf-8") as f:

            def w(line: str = ""):
                f.write(line + "\n")

            # ── Header ──────────────────────────────────────────────────────
            w("# Phantom Security Assessment Report")
            w()
            w("| Field | Value |")
            w("|-------|-------|")
            w(f"| **Target** | {self.target or 'N/A'} |")
            w(f"| **Date** | {self.created_at} |")
            w(f"| **Mode** | {self.mode or 'N/A'} |")
            if self.scope:
                w(f"| **Scope** | {', '.join(self.scope)} |")
            w()

            # ── Executive Summary ───────────────────────────────────────────
            w("## Executive Summary")
            exploit_res = self.get_result("exploit") or {}
            ranked = exploit_res.get("ranked", [])
            services = self.get_result("service_summary") or []
            high_risk = len([r for r in ranked if r.get('score', 0) >= 70])

            summary_parts = []
            summary_parts.append(f"Security assessment of **{self.target or 'target'}**")
            if ranked:
                summary_parts.append(f"identified **{len(ranked)}** potential vulnerabilities")
                if high_risk:
                    summary_parts.append(f"(**{high_risk}** classified as HIGH risk)")
            else:
                summary_parts.append("identified **no** critical vulnerabilities through automated correlation")
            summary_parts.append(f"Reconnaissance found **{len(services)}** active services exposed on the network")
            w(" ".join(summary_parts) + ".")
            w()

            # ── Network Reconnaissance ──────────────────────────────────────
            if services:
                w("## Network Reconnaissance")
                w("| Port | Service | Version |")
                w("|------|---------|---------|")
                for s in services:
                    ver = s.get('version') or '—'
                    w(f"| {s.get('port', '?')} | {s.get('service', '?')} | {ver} |")
                w()

            # ── Vulnerability Analysis ──────────────────────────────────────
            if ranked:
                w("## Vulnerability Analysis")
                w("### Key Findings")
                w()
                w("| Severity | CVE ID | Service | Score | Exploit Availability |")
                w("|----------|--------|---------|-------|---------------------|")
                for entry in ranked:
                    cve = entry.get('cve', {})
                    svc = entry.get('service', {})
                    svc_get = getattr(svc, "get", lambda k, d="": d)
                    score = entry.get('score', 0)
                    if score >= 70:
                        sev = ":red_circle: **HIGH**"
                    elif score >= 40:
                        sev = ":large_orange_diamond: **MED**"
                    else:
                        sev = ":large_green_circle: **LOW**"
                    badges = []
                    if entry.get('has_msf'):
                        badges.append("Metasploit")
                    if entry.get('has_poc'):
                        badges.append("PoC")
                    exploit_str = ", ".join(badges) if badges else "—"
                    w(f"| {sev} | {cve.get('id', 'N/A')} | {svc_get('port', '?')}/{svc_get('service', '?')} | {score}/100 | {exploit_str} |")
                w()

                # Detailed descriptions
                w("### Vulnerability Details")
                for entry in ranked:
                    cve = entry.get('cve', {})
                    w(f"- **{cve.get('id', 'Unknown CVE')}**: {cve.get('description', 'No description')[:300]}")
                w()

            # ── Scan Results ────────────────────────────────────────────────
            scan_res = self.get_result("scan")
            if scan_res:
                w("## Scan Results")
                if isinstance(scan_res, dict):
                    for key, val in scan_res.items():
                        w(f"- **{key}**: {val}")
                elif isinstance(scan_res, list):
                    for item in scan_res:
                        w(f"- {item}")
                else:
                    w(str(scan_res))
                w()

            # ── OSINT Results ───────────────────────────────────────────────
            osint_res = self.get_result("osint")
            if osint_res:
                w("## OSINT Results")
                if isinstance(osint_res, dict):
                    for key, val in osint_res.items():
                        if isinstance(val, list):
                            w(f"- **{key}**:")
                            for v in val:
                                w(f"  - {v}")
                        else:
                            w(f"- **{key}**: {val}")
                elif isinstance(osint_res, list):
                    for item in osint_res:
                        if isinstance(item, dict):
                            for k, v in item.items():
                                w(f"- **{k}**: {v}")
                        else:
                            w(f"- {item}")
                else:
                    w(str(osint_res))
                w()

            # ── Analyzer Findings ──────────────────────────────────────────
            analyzer_res = self.get_result("analyzer")
            if analyzer_res:
                findings = analyzer_res.get("findings", [])
                if findings:
                    w("## Captured Information & Anomalies")
                    for sev, typ, detail in findings:
                        w(f"- **[{sev}]** *{typ}*: {detail}")
                    w()

            # ── Command History ─────────────────────────────────────────────
            if self.history:
                w("## Command History")
                for h in self.history:
                    w(f"- {h}")
                w()

            # ── Notes ───────────────────────────────────────────────────────
            if self.notes:
                w("## Field Notes")
                for n in self.notes:
                    w(f"- **[{n['timestamp']}]** {n['text']}")
                w()

            # ── Raw Results Summary ─────────────────────────────────────────
            w("## Raw Results Summary")
            for mod, res in self.results.items():
                if mod in ("exploit", "service_summary", "analyzer"):
                    continue
                w(f"### {mod.upper()}")
                w(f"```")
                w(str(res)[:2000])
                w(f"```")
                w()

            w("---")
            w(f"*Report generated by Phantom Framework v3.0.0 — Confidential*")

        console.print(f"[green][+] Report exported: {path}[/]")

    def load(self, name: str) -> None:
        from phantom.utils.paths import sessions_dir
        path = os.path.join(sessions_dir(), f"{_check_session_name(name)}.json")
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            wm_data = data.pop("_wm", None)
            for k, v in data.items():
                setattr(self, k, v)
            if wm_data:
                try:
                    from phantom.automation.belief import WorldModel
                    from phantom.core.knowledge import set_wm
                    set_wm(WorldModel.from_dict(wm_data))
                    console.print(f"[green][+] Shared knowledge restored "
                                  f"({len(wm_data.get('findings', []))} findings).[/]")
                except Exception:
                    pass
            console.print(f"[green][+] Session loaded: {path}[/]")
            return
        console.print(f"[red]Session '{name}' not found.[/]")

    @staticmethod
    def list_saved() -> List[str]:
        from phantom.utils.paths import sessions_dir
        sdir = sessions_dir()
        os.makedirs(sdir, exist_ok=True)
        d = [f.replace(".json", "") for f in os.listdir(sdir) if f.endswith(".json")]
        return sorted(list(set(d)))

    @staticmethod
    def load_raw(name: str) -> dict:
        """Load a session file as a raw dictionary without affecting the current session."""
        from phantom.utils.paths import sessions_dir
        path = os.path.join(sessions_dir(), f"{_check_session_name(name)}.json")
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

session = Session()


_SESSION_NAME_RE = None


def _check_session_name(name: str) -> str:
    """Validate a session/report file stem: refuse path traversal instead
    of sanitizing it silently (a silently rewritten name writes somewhere
    the operator did not ask for). Spaces are allowed (UX: "my run"),
    separators/.. /leading dots/absolute paths are not."""
    global _SESSION_NAME_RE
    if _SESSION_NAME_RE is None:
        import re as _re
        _SESSION_NAME_RE = _re.compile(r"^[A-Za-z0-9._\- ]+$")
    clean = (name or "").strip()
    if not clean or not _SESSION_NAME_RE.match(clean):
        raise ValueError(f"invalid session name: {name!r}")
    if clean.startswith(".") or ".." in clean:
        raise ValueError(f"invalid session name: {name!r}")
    return clean
