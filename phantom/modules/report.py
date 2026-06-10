import json
import os
from datetime import datetime
from phantom.modules.base_module import BaseModule
from phantom.core.session import session
from phantom.utils.notifier import notifier
from rich.console import Console

console = Console()

class ReportModule(BaseModule):
    module_name = "report"

    def __init__(self):
        super().__init__()
        # Professional path for templates
        self.template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "templates", "report")

    def export(self, fmt: str = "json", filename: str = ""):
        if not filename:
            filename = f"report_{session.target or 'phantom'}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
        else:
            if not filename.endswith(f".{fmt}"):
                filename += f".{fmt}"

        if fmt == "json":
            self._export_json(filename)
        elif fmt == "html":
            self._export_html(filename)
        elif fmt == "pdf":
            self._export_pdf(filename)
        else:
            notifier.error(f"Unsupported format: {fmt}")

    def _export_json(self, filename: str):
        data = {
            "target": session.target,
            "mode": session.mode,
            "scope": session.scope,
            "created_at": session.created_at,
            "exported_at": datetime.now().isoformat(),
            "results": session.results,
            "notes": session.notes,
            "history": session.history,
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        notifier.success(f"JSON report saved to {filename}")

    def _get_executive_summary(self):
        target = session.target or "Unknown"
        vulns = session.get_result("exploit") or {}
        ranked = vulns.get("ranked", [])
        
        high_risk = len([r for r in ranked if r['score'] >= 70])
        services = session.get_result("service_summary") or []
        
        summary = f"The security assessment of target <strong>{target}</strong> "
        if not ranked:
            summary += "identified no critical vulnerabilities through automated correlation. "
        else:
            summary += f"uncovered <strong>{len(ranked)}</strong> potential vulnerabilities. "
            if high_risk > 0:
                summary += f"Of these, <strong>{high_risk}</strong> are classified as HIGH risk, requiring immediate attention. "
        
        summary += f"Reconnaissance efforts identified <strong>{len(services)}</strong> active services exposed on the network."
        return summary

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
        date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        summary = self._get_executive_summary()

        # Build sections
        vuln_content = self._build_vuln_html()
        service_section = self._build_service_section()
        analyzer_section = self._build_analyzer_section()
        notes_section = self._build_notes_section()
        history_section = self._build_history_section()

        # Replace placeholders
        html = template.replace("{{ target }}", target)
        html = html.replace("{{ date_str }}", date_str)
        html = html.replace("{{ summary }}", summary)
        html = html.replace("{{ vuln_content }}", vuln_content)
        html = html.replace("{{ service_section }}", service_section)
        html = html.replace("{{ analyzer_section }}", analyzer_section)
        html = html.replace("{{ notes_section }}", notes_section)
        html = html.replace("{{ history_section }}", history_section)

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        notifier.success(f"Professional HTML report saved to {filename}")

    def _build_vuln_html(self) -> str:
        exploit_data = session.get_result("exploit") or {}
        ranked = exploit_data.get("ranked", [])
        if not ranked:
            return "<p>No vulnerabilities identified through automated analysis.</p>"
        
        html = ""
        for entry in ranked:
            cve = entry['cve']
            svc = entry['service']
            score = entry['score']
            level = "high" if score >= 70 else ("med" if score >= 40 else "low")
            
            badges = ""
            if entry.get('has_msf'):
                badges += "<span class='badge bg-high'>Metasploit Available</span> "
            if entry.get('has_poc'):
                badges += "<span class='badge bg-med'>Public PoC Found</span>"

            html += f"""
        <div class="card vuln-card vuln-{level}">
            <div>
                <strong>{cve.get('id', 'Unknown CVE')}</strong> - {svc.port}/{svc.service}<br>
                <small style="color: #666;">{cve.get('description', 'No description available')[:200]}...</small>
                <div style="margin-top: 10px;">{badges}</div>
            </div>
            <div class="score" style="color: var(--{level});">{score}/100</div>
        </div>"""
        return html

    def _build_service_section(self) -> str:
        services = session.get_result("service_summary") or []
        if not services:
            return ""
        
        rows = ""
        for s in services:
            rows += f"<tr><td>{s['port']}</td><td>{s['service']}</td><td>{s['version'] or '—'}</td></tr>"
            
        return f"""
    <section>
        <h2>Network Reconnaissance</h2>
        <table>
            <thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </section>"""

    def _build_analyzer_section(self) -> str:
        analyzer = session.get_result("analyzer") or {}
        findings = analyzer.get("findings", [])
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
            items += f"<li><strong>[{note['timestamp']}]</strong> {note['text']}</li>"
        return f"<section><h2>Field Notes</h2><ul>{items}</ul></section>"

    def _build_history_section(self) -> str:
        if not session.history:
            return ""
        content = "\n".join(session.history)
        return f"<section><h2>Audit Log (Command History)</h2><pre>{content}</pre></section>"

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
        
        elements.append(Paragraph(f"Security Assessment Report", title_style))
        elements.append(Paragraph(f"<b>Target:</b> {session.target or 'Unknown'}", styles['Normal']))
        elements.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("Executive Summary", heading_style))
        summary_text = self._get_executive_summary().replace("<strong>", "<b>").replace("</strong>", "</b>")
        elements.append(Paragraph(summary_text, styles['Normal']))
        elements.append(Spacer(1, 15))

        exploit_data = session.get_result("exploit") or {}
        ranked = exploit_data.get("ranked", [])
        if ranked:
            elements.append(Paragraph("Key Findings", heading_style))
            data = [["CVE ID", "Service", "Score"]]
            for entry in ranked[:10]:
                data.append([entry['cve'].get('id', '—'), f"{entry['service'].port}/{entry['service'].service}", str(entry['score'])])
            
            t = Table(data, colWidths=[150, 200, 100])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(t)
            elements.append(Spacer(1, 15))

        services = session.get_result("service_summary") or []
        if services:
            elements.append(Paragraph("Exposed Services", heading_style))
            data = [["Port", "Service", "Version"]]
            for s in services:
                data.append([s['port'], s['service'], s['version'] or "—"])
            t = Table(data, colWidths=[80, 150, 220])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            elements.append(t)

        if session.notes:
            elements.append(Paragraph("Field Notes", heading_style))
            for note in session.notes:
                elements.append(Paragraph(f"• [{note['timestamp']}] {note['text']}", styles['Normal']))

        doc.build(elements)
        notifier.success(f"PDF report saved to {filename}")

    def do_run(self, _):
        fmt = input("  Format (json/html/pdf) [json]: ").strip().lower() or "json"
        default_name = f"report_{session.target or 'phantom'}.{fmt}"
        fname = input(f"  Filename [{default_name}]: ").strip()
        if not fname:
            fname = default_name
        self.export(fmt, fname)

    def do_preview(self, _):
        self.do_run(_)
