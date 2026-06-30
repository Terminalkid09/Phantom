import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List
from rich.console import Console

console = Console()

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
    ai_connector: Any = None

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
        self.history.append(f"[{datetime.now().strftime('%H:%M:%S')}] {cmd}")

    def save(self, name: str) -> None:
        """Save the current session to data/sessions/{name}.json atomically."""
        from phantom.utils.paths import sessions_dir
        sdir = sessions_dir()
        os.makedirs(sdir, exist_ok=True)
        path = os.path.join(sdir, f"{name}.json")
        with tempfile.NamedTemporaryFile(mode='w', dir=sdir, delete=False, suffix='.json', encoding='utf-8') as tmp:
            json.dump(self.__dict__, tmp, indent=2, default=str)
            tmp_path = tmp.name
        os.replace(tmp_path, path)
        console.print(f"[green][+] Session saved: {path}[/]")

    def export_markdown(self, filename: str) -> None:
        """Export session to a professional Markdown report."""
        from phantom.utils.paths import sessions_dir
        sdir = sessions_dir()
        os.makedirs(sdir, exist_ok=True)
        path = os.path.join(sdir, filename)
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
                    w(f"| {sev} | {cve.get('id', 'N/A')} | {svc.get('port', '?')}/{svc.get('service', '?')} | {score}/100 | {exploit_str} |")
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
            w(f"*Report generated by Phantom Framework v2.0.0 — Confidential*")

        console.print(f"[green][+] Report exported: {path}[/]")

    def load(self, name: str) -> None:
        from phantom.utils.paths import sessions_dir
        path = os.path.join(sessions_dir(), f"{name}.json")
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for k, v in data.items():
                setattr(self, k, v)
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
        path = os.path.join(sessions_dir(), f"{name}.json")
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

session = Session()
