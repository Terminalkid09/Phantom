import cmd
import sys
import os
import platform
import importlib.util
import argparse
import json                 
from datetime import datetime
from rich.console import Console
from rich.table import Table
from phantom.core.session import session
from phantom.core.scope import is_in_scope
from phantom.core.notes import show_notes

console = Console()


def build_banner() -> str:
    import sys
    import platform
    from datetime import datetime

    python_ver = sys.version.split()[0]
    os_info = platform.system() + " " + platform.release()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    return f"""
[bold red] ________  ___  ___  ________  ________   _________  ________  _____ ______   [/]
[bold red]|\\   __  \\|\\  \\|\\  \\|\\   __  \\|\\   ___  \\|\\___   ___\\\\   __  \\|\\   _ \\  _   \\  [/]
[bold red]\\ \\  |\\  \\ \\  \\\\  \\ \\  |\\  \\ \\  \\ \\  \\|___ \\  \\_\\ \\  |\\  \\ \\  \\\\__\\ \\  \\ [/]
[bold red] \\ \\   ____\\ \\   __  \\ \\   __  \\ \\  \\ \\  \\   \\ \\  \\ \\ \\  \\\\  \\ \\  \\|__| \\  \\[/]
[bold red]  \\ \\  \\___|\\ \\  \\ \\  \\ \\  \\ \\  \\ \\  \\ \\  \\   \\ \\  \\ \\ \\  \\\\  \\ \\  \\    \\ \\  \\[/]
[bold red]   \\ \\__\\    \\ \\__\\ \\__\\ \\__\\ \\__\\ \\__\\ \\__\\   \\ \\__\\ \\ \\_______\\ \\__\\    \\ \\__\\[/]
[bold red]    \\|__|     \\|__|\\|__|\\|__|\\|__|\\|__| \\|__|    \\|__|  \\|_______|\\|__|     \\|__|[/]
  [dim]──────────────────────────────────────────────────────────────────────────────────[/]
  [bold white]Offensive Security Framework[/]  [dim]v1.1.0[/]
  [cyan]Python[/] [dim]{python_ver}[/]   [cyan]OS[/] [dim]{os_info}[/]   [cyan]Time[/] [dim]{now}[/]
  [dim]──────────────────────────────────────────────────────────────────────────────────[/]
  [dim]Use 'help' for commands. Use responsibly and legally.[/]
"""


# Mode → modules sequence mapping
MODE_SEQUENCES = {
    "recon":   ["scan", "osint"],
    "osint":   ["osint"],
    "full":    ["scan", "osint", "web", "exploit"],
    "exploit": ["exploit", "payload"],
}


class PhantomShell(cmd.Cmd):
    intro = ""
    prompt = "[phantom] > "

    def precmd(self, line: str) -> str:
        """Allow hyphens in commands by translating them to underscores."""
        if not line.strip():
            return line
        # Only translate the command part, not the arguments
        parts = line.split(maxsplit=1)
        cmd_part = parts[0].replace("-", "_")
        if len(parts) > 1:
            return f"{cmd_part} {parts[1]}"
        return cmd_part

    def preloop(self):
        console.print(build_banner())
        self.plugins = self._load_plugins()
        if self.plugins:
            console.print(f"[dim][+] Loaded {len(self.plugins)} plugin(s)[/]")

    def _load_plugins(self):
        """Load external plugins from ~/.phantom/plugins/*.py"""
        plugin_dir = os.path.expanduser("~/.phantom/plugins")
        if not os.path.exists(plugin_dir):
            os.makedirs(plugin_dir, exist_ok=True)
            return {}

        plugins = {}
        for file in os.listdir(plugin_dir):
            if file.endswith(".py") and not file.startswith("__"):
                name = file[:-3]
                spec = importlib.util.spec_from_file_location(name, os.path.join(plugin_dir, file))
                module = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(module)
                    # Cerca una classe che eredita da BaseModule
                    for attr in dir(module):
                        obj = getattr(module, attr)
                        if isinstance(obj, type) and hasattr(obj, "module_name") and obj.__name__ != "BaseModule":
                            plugins[obj.module_name] = obj
                except Exception as e:
                    console.print(f"[red]Failed to load plugin {file}: {e}[/]")
        return plugins

    # Profile management
    def save_profile(self, name: str):
        """Save current session settings as a profile."""
        profile_dir = os.path.expanduser("~/.phantom/profiles")
        os.makedirs(profile_dir, exist_ok=True)
        profile_path = os.path.join(profile_dir, f"{name}.json")
        data = {
            "target": session.target,
            "mode": session.mode,
            "scope": session.scope,
            "active_wordlist": session.active_wordlist,
            "timeout_seconds": 300, 
            "aggressive_confirm": True,
        }
        with open(profile_path, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[green][+] Profile saved: {name}[/]")

    def load_profile(self, name: str):
        """Load a profile and apply settings to current session."""
        profile_path = os.path.expanduser(f"~/.phantom/profiles/{name}.json")
        if not os.path.exists(profile_path):
            console.print(f"[red]Profile '{name}' not found.[/]")
            return
        with open(profile_path, "r") as f:
            data = json.load(f)
        if data.get("target"):
            session.target = data["target"]
        if data.get("mode"):
            session.mode = data["mode"]
        if data.get("scope"):
            session.scope = data["scope"]
        if data.get("active_wordlist"):
            session.active_wordlist = data["active_wordlist"]
        console.print(f"[green][+] Profile '{name}' loaded.[/]")
        self.do_show("session")

    def do_save_profile(self, name: str):
        """save-profile <name> — save current settings as a profile."""
        if not name.strip():
            console.print("[red]Usage: save-profile <name>[/]")
            return
        self.save_profile(name.strip())

    def do_load_profile(self, name: str):
        """load-profile <name> — load a profile."""
        if not name.strip():
            console.print("[red]Usage: load-profile <name>[/]")
            return
        self.load_profile(name.strip())

    def do_list_profiles(self, arg: str):
        """List all saved profiles."""
        profile_dir = os.path.expanduser("~/.phantom/profiles")
        if not os.path.exists(profile_dir):
            console.print("[yellow]No profiles found.[/]")
            return
        profiles = [f.replace(".json", "") for f in os.listdir(profile_dir) if f.endswith(".json")]
        if not profiles:
            console.print("[yellow]No profiles found.[/]")
            return
        console.print("[cyan]Available Profiles:[/]")
        for p in profiles:
            console.print(f"  [white]- {p}[/]")

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
            valid_modes = list(MODE_SEQUENCES.keys())
            if value in valid_modes:
                session.mode = value
                steps = " → ".join(MODE_SEQUENCES[value])
                console.print(f"[green][+] Mode set to {value}[/]  [dim]({steps})[/]")
                console.print(f"[dim]    Type 'run' to launch the sequence automatically.[/]")
            else:
                console.print(f"[red]Invalid mode. Use: {', '.join(valid_modes)}[/]")

        elif key == "scope":
            session.scope = [s.strip() for s in value.split(",")]
            console.print(f"[green][+] Scope set to {', '.join(session.scope)}[/]")

        else:
            console.print(f"[red]Unknown key: {key}[/]")

    def do_run(self, _):
        """run — launch all modules for the current mode in sequence"""
        if not session.target:
            console.print("[red][!] No target set. Use 'set target <ip>' first.[/]")
            return

        mode = session.mode
        steps = MODE_SEQUENCES.get(mode, ["scan"])
        total = len(steps)

        console.print(f"\n[bold cyan][*] Mode: {mode.upper()} — {' → '.join(s.upper() for s in steps)}[/]\n")

        for i, module_name in enumerate(steps, 1):
            console.print(f"[bold cyan]── STEP {i}/{total}: {module_name.upper()} {'─' * (50 - len(module_name))}[/]")
            self.do_use(module_name)
            console.print(f"\n[green][+] {module_name.upper()} complete.[/]\n")

        console.print(f"[bold green][+] {mode.upper()} sequence complete. Results saved to session.[/]")
        console.print(f"[dim]    Use 'export json report.json' to generate a report.[/]")

    def do_show(self, arg: str):
        """show session | show scope | show presets | show mode"""
        arg = arg.strip().lower()
        if arg == "session":
            table = Table(title="Current session")
            table.add_column("Field", style="cyan")
            table.add_column("Value")
            table.add_row("Target", session.target or "—")
            table.add_row("Mode", session.mode)
            table.add_row("Mode sequence", " → ".join(MODE_SEQUENCES.get(session.mode, [])))
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
        elif arg == "mode":
            console.print(f"[cyan]Mode: {session.mode}[/]")
            console.print(f"  Sequence: {' → '.join(MODE_SEQUENCES.get(session.mode, []))}")
            console.print(f"  Type 'run' to launch.")
        elif arg == "presets":
            console.print("[yellow]Presets not yet implemented.[/]")
        else:
            console.print("[red]Usage: show session | show scope | show mode | show presets[/]")

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

    def do_scan_diff(self, arg: str):
        """scan-diff <target> [--since YYYY-MM-DD | --old TS --new TS]"""
        from phantom.utils.scan_history import load_history, diff_scans
        parser = argparse.ArgumentParser(prog="scan-diff", add_help=False)
        parser.add_argument("target", help="Target to diff")
        parser.add_argument("--since", help="Compare last scan with the one after this date (YYYY-MM-DD)")
        parser.add_argument("--old", help="Old timestamp (format: YYYYMMDD_HHMMSS)")
        parser.add_argument("--new", help="New timestamp (format: YYYYMMDD_HHMMSS)")
        try:
            args = parser.parse_args(arg.split())
        except SystemExit:
            return

        history = load_history(args.target)
        if len(history) < 2:
            console.print("[yellow]Need at least two scans for diff.[/]")
            return

        if args.old and args.new:
            old = next((h for h in history if args.old in h["timestamp"]), None)
            new = next((h for h in history if args.new in h["timestamp"]), None)
        elif args.since:
            since_dt = datetime.strptime(args.since, "%Y-%m-%d")
            new = history[0]  # latest
            candidates = [h for h in history if datetime.fromisoformat(h["timestamp"]) > since_dt]
            old = candidates[-1] if candidates else None
        else:
            new = history[0]
            old = history[1]

        if not old or not new:
            console.print("[red]Could not find matching scans.[/]")
            return

        added, removed, changed = diff_scans(old["services"], new["services"])

        console.print(f"\n[bold cyan]Diff: {old['timestamp']} → {new['timestamp']}[/]\n")
        if added:
            console.print("[green][+] Added ports:[/]")
            for s in added:
                console.print(f"    {s['port']}/{s['protocol']}  {s['service']}  {s['version']}")
        if removed:
            console.print("[red][-] Removed ports:[/]")
            for s in removed:
                console.print(f"    {s['port']}/{s['protocol']}  {s['service']}  {s['version']}")
        if changed:
            console.print("[yellow][*] Changed services:[/]")
            for old_s, new_s in changed:
                console.print(f"    {old_s['port']}/{old_s['protocol']}: {old_s['service']} {old_s['version']} → {new_s['service']} {new_s['version']}")
        if not (added or removed or changed):
            console.print("[dim]No changes detected.[/]")

    def do_use(self, arg: str):
        """use <module> — enter a module"""
        module_name = arg.strip().lower()
        modules = {
            "scan":     "phantom.modules.scan.ScanModule",
            "osint":    "phantom.modules.osint.OsintModule",
            "web":      "phantom.modules.web.WebModule",
            "brute":    "phantom.modules.brute.BruteModule",
            "exploit":  "phantom.modules.exploit.ExploitModule",
            "payload":  "phantom.modules.payload.PayloadModule",
            "handler":  "phantom.modules.handler.HandlerModule",
            "pivot":    "phantom.modules.pivot.PivotModule",
            "analyzer": "phantom.modules.analyzer.AnalyzerModule",
            "report":   "phantom.modules.report.ReportModule",
        }
        modules.update(self.plugins) # Add loaded plugins to the available modules
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