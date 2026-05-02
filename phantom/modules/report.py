import json
import os
from datetime import datetime
from phantom.modules.base_module import BaseModule
from phantom.core.session import session
from rich.console import Console

console = Console()

class ReportModule(BaseModule):
    module_name = "report"

    def export(self, fmt: str = "json", filename: str = ""):
        # Assicura che il filename abbia l'estensione corretta
        if not filename:
            filename = f"report_{session.target or 'phantom'}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
        else:
            # Aggiunge l'estensione se non presente
            if not filename.endswith(f".{fmt}"):
                filename += f".{fmt}"

        if fmt == "json":
            self._export_json(filename)
        elif fmt == "html":
            self._export_html(filename)
        elif fmt == "pdf":
            self._export_pdf(filename)
        else:
            console.print(f"[red]Unsupported format: {fmt}[/]")

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
        console.print(f"[green][+] JSON report saved to {filename}[/]")

    def _export_html(self, filename: str):
        # Basic HTML template with a little style
        html = f"""<!DOCTYPE html>
<html>
<head><title>Phantom Report - {session.target}</title>
<style>
body {{ font-family: monospace; margin: 2em; background: #fff; }}
.section {{ margin: 2em 0; }}
pre {{ background: #f4f4f4; padding: 1em; overflow: auto; }}
h1 {{ color: #2c3e50; }}
</style>
</head>
<body>
<h1>Phantom Penetration Test Report</h1>
<p><strong>Target:</strong> {session.target}<br>
<strong>Mode:</strong> {session.mode}<br>
<strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<div class='section'>
<h2>Notes</h2>
<ul>
"""
        for note in session.notes:
            html += f"<li><strong>{note['timestamp']}</strong> {note['text']}</li>"
        html += "</ul></div><div class='section'><h2>Command History</h2><pre>"
        for cmd in session.history:
            html += cmd + "\n"
        html += "</pre></div><div class='section'><h2>Module Results</h2><pre>"
        html += json.dumps(session.results, indent=2, default=str)
        html += "</pre></div></body></html>"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        console.print(f"[green][+] HTML report saved to {filename}[/]")

    def _export_pdf(self, filename: str):
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas
        except ImportError:
            console.print("[red]reportlab not installed. Install with: pip install reportlab[/]")
            return
        c = canvas.Canvas(filename, pagesize=A4)
        width, height = A4
        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, height - 60, "Phantom Pentest Report")
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 90, f"Target: {session.target}")
        c.drawString(50, height - 110, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        y = height - 150
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "Notes")
        y -= 20
        c.setFont("Helvetica", 10)
        for note in session.notes:
            c.drawString(60, y, f"[{note['timestamp']}] {note['text'][:80]}")
            y -= 15
            if y < 50:
                c.showPage()
                y = height - 50
        c.save()
        console.print(f"[green][+] PDF report saved to {filename}[/]")

    def do_run(self, _):
        fmt = input("  Format (json/html/pdf) [json]: ").strip().lower() or "json"
        default_name = f"report_{session.target or 'phantom'}.{fmt}"
        fname = input(f"  Filename [{default_name}]: ").strip()
        if not fname:
            fname = default_name
        self.export(fmt, fname)

    def do_preview(self, _):
        self.do_run(_)