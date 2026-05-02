import cmd
from rich.console import Console
from rich.table import Table
from phantom.core.session import session
from phantom.core.scope import is_in_scope
from phantom.core.notes import show_notes

console = Console()

BANNER = """
  ██████╗ ██╗  ██╗ █████╗ ███╗  ██╗████████╗ ██████╗ ███╗  ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗ ██║╚══██╔══╝██╔═══██╗████╗████║
  ██████╔╝███████║███████║██╔██╗██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚████║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚███║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
  v1.0.0 — Offensive Security Framework
"""

class PhantomShell(cmd.Cmd):
    intro = ""
    prompt = "[phantom] > "

    def preloop(self):
        console.print(BANNER)

    def do_set(self, arg: str):
        """set target <ip/domain> | set mode <recon|osint|full|exploit> | set scope <cidr,ip,...>"""
        parts = arg.strip().split(maxsplit=1)
        if len(parts) < 2:
            console.print("[red]Usage: set <target|mode|scope> <value>[/]")
            return
        key, value = parts[0].lower(), parts[1]

        if key == "target":
            if session.scope and not is_in_scope(value, session.scope):
                console.print(f"[yellow][!] Warning: {value} is out of current scope.[/]")
                confirm = input("    Proceed anyway? [y/N] ").strip().lower()
                if confirm != "y":
                    return
            session.target = value
            console.print(f"[green][+] Target set to {value}[/]")

        elif key == "mode":
            if value in ("recon", "osint", "full", "exploit"):
                session.mode = value
                console.print(f"[green][+] Mode set to {value}[/]")
            else:
                console.print("[red]Invalid mode. Use: recon, osint, full, exploit[/]")

        elif key == "scope":
            session.scope = [s.strip() for s in value.split(",")]
            console.print(f"[green][+] Scope set to {', '.join(session.scope)}[/]")

        else:
            console.print(f"[red]Unknown key: {key}[/]")

    def do_show(self, arg: str):
        """show session | show scope | show presets"""
        arg = arg.strip().lower()
        if arg == "session":
            table = Table(title="Current session")
            table.add_column("Field", style="cyan")
            table.add_column("Value")
            table.add_row("Target", session.target or "—")
            table.add_row("Mode", session.mode)
            table.add_row("Scope", ", ".join(session.scope) if session.scope else "—")
            table.add_row("Active wordlist", session.active_wordlist or "—")
            table.add_row("Completed modules", ", ".join(session.results.keys()) or "—")
            table.add_row("Notes", str(len(session.notes)))
            console.print(table)
        elif arg == "scope":
            if session.scope:
                console.print(f"[cyan]Scope: {', '.join(session.scope)}[/]")
            else:
                console.print("[yellow]No scope defined.[/]")
        elif arg == "presets":
            console.print("[yellow]Presets not yet implemented.[/]")
        else:
            console.print("[red]Usage: show session | show scope | show presets[/]")

    def do_note(self, arg: str):
        """note \"<text>\" — add an inline note to the session"""
        text = arg.strip().strip('"').strip("'")
        if not text:
            console.print("[red]Usage: note \"your note here\"[/]")
            return
        session.add_note(text)
        console.print("[green][+] Note added.[/]")

    def do_notes(self, arg: str):
        """Display all notes in the current session"""
        show_notes()

    def do_save_session(self, name: str):
        """save-session <name> — save current session to disk"""
        name = name.strip()
        if not name:
            console.print("[red]Usage: save-session <name>[/]")
            return
        session.save(name)
        console.print(f"[green][+] Session saved as {name}.json[/]")

    def do_load_session(self, name: str):
        """load-session <name> — load a previously saved session"""
        name = name.strip()
        if not name:
            console.print("[red]Usage: load-session <name>[/]")
            return
        try:
            session.load(name)
            console.print(f"[green][+] Session loaded: {name}[/]")
        except FileNotFoundError:
            console.print(f"[red]Session '{name}' not found.[/]")

    def do_list_sessions(self, arg: str):
        """List all saved sessions"""
        saved = session.list_saved()
        if not saved:
            console.print("[yellow]No saved sessions.[/]")
            return
        for s in saved:
            console.print(f"  [cyan]{s}[/]")

    def do_wordlists(self, arg: str):
        """wordlists list | wordlists use <name> | wordlists search <keyword> | wordlists info <name>"""
        from phantom.utils.wordlists import WordlistManager
        WordlistManager().handle(arg)

    def do_history(self, arg: str):
        """Show command history for this session"""
        if not session.history:
            console.print("[yellow]No commands in history.[/]")
            return
        for entry in session.history:
            console.print(f"  [dim]{entry}[/]")

    def do_capture(self, arg: str):
        """Save snapshot of current output (to be implemented)"""
        console.print("[yellow]Capture command not yet implemented.[/]")

    def do_export(self, arg: str):
        """export <json|pdf|html> [filename] — export session results"""
        from phantom.modules.report import ReportModule
        parts = arg.strip().split()
        if not parts:
            console.print("[red]Usage: export <json|pdf|html> [filename][/]")
            return
        fmt = parts[0].lower()
        if fmt not in ("json", "pdf", "html"):
            console.print("[red]Invalid format. Use json, pdf, or html.[/]")
            return
        default_name = f"report_{session.target or 'phantom'}.{fmt}"
        filename = parts[1] if len(parts) > 1 else default_name
        rm = ReportModule()
        rm.export(fmt, filename)

    def do_use(self, arg: str):
        """use <module> — enter a module (scan, osint, web, brute, exploit, payload, handler, pivot, analyzer, report)"""
        module_name = arg.strip().lower()
        modules = {
            "scan": "phantom.modules.scan.ScanModule",
            "osint": "phantom.modules.osint.OsintModule",
            "web": "phantom.modules.web.WebModule",
            "brute": "phantom.modules.brute.BruteModule",
            "exploit": "phantom.modules.exploit.ExploitModule",
            "payload": "phantom.modules.payload.PayloadModule",
            "handler": "phantom.modules.handler.HandlerModule",
            "pivot": "phantom.modules.pivot.PivotModule",
            "analyzer": "phantom.modules.analyzer.AnalyzerModule",
            "report": "phantom.modules.report.ReportModule",
        }
        if module_name not in modules:
            console.print(f"[red]Unknown module: {module_name}[/]")
            console.print(f"  Available: {', '.join(modules.keys())}")
            return
        import importlib
        path, cls_name = modules[module_name].rsplit(".", 1)
        mod = importlib.import_module(path)
        cls = getattr(mod, cls_name)
        instance = cls()
        instance.cmdloop()

    def do_back(self, arg: str):
        """Return to main shell (already here)"""
        console.print("[yellow]Already at main shell.[/]")

    def do_exit(self, arg: str):
        """Exit Phantom, optionally save current session"""
        if session.target:
            confirm = input("Save current session before exiting? [y/N] ").strip().lower()
            if confirm == "y":
                name = input("Session name: ").strip()
                if name:
                    session.save(name)
                    console.print(f"[green][+] Session saved: {name}[/]")
        console.print("\n[dim]Phantom closed.[/]\n")
        return True

    def do_quit(self, arg: str):
        return self.do_exit(arg)

    def default(self, line: str):
        console.print(f"[red]Unknown command: {line}[/] (type 'help' for available commands)")