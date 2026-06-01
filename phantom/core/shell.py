import cmd
import sys
import os
import importlib.util
import json                 
from datetime import datetime
from dotenv import load_dotenv
from rich.console import Console
from phantom.core.session import session
from phantom.core.scope import is_in_scope
from phantom.core.notes import show_notes
from phantom.utils.notifier import notifier

# Load environment variables
load_dotenv()

console = Console()


def build_dashboard():
    """Build a structured dashboard header without taking up full terminal height."""
    from rich.panel import Panel
    from rich.console import Group

    # Header Panel
    target = session.target or "None"
    mode = session.mode.upper()
    header_panel = Panel(
        f"[bold cyan]Target:[/] {target}  |  [bold magenta]Mode:[/] {mode}  |  [bold yellow]Time:[/] {datetime.now().strftime('%H:%M:%S')}",
        title="[bold white]Phantom Framework Status[/]",
        border_style="blue"
    )

    # Info Panel
    scope = ", ".join(session.scope) if session.scope else "None"
    sniffer_status = "[green]ACTIVE[/]" if session.results.get("_sniffer_active") else "[red]INACTIVE[/]"
    info_panel = Panel(
        f"[bold green]Scope:[/] {scope}  |  [bold cyan]Sniffer:[/] {sniffer_status}  |  [bold white]Notes:[/] {len(session.notes)}",
        border_style="dim"
    )
    
    return Group(header_panel, info_panel)


def build_banner() -> str:
    import sys
    import platform
    from datetime import datetime

    python_ver = sys.version.split()[0]
    os_info = platform.system() + " " + platform.release()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    return fr"""
[bold red]
  ██████╗ ██╗  ██╗ █████╗ ███╗  ██╗████████╗ ██████╗ ███╗  ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗ ██║╚══██╔══╝██╔═══██╗████╗████║
  ██████╔╝███████║███████║██╔██╗██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚████║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚███║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
[/bold red]
  [dim]──────────────────────────────────────────────────────────────────────────────────[/dim]
  [bold white]Offensive Security Framework[/bold white]  [dim]v2.0.0[/dim]
  [cyan]Python[/cyan] [dim]{python_ver}[/dim]   [cyan]OS[/cyan] [dim]{os_info}[/dim]   [cyan]Time[/cyan] [dim]{now}[/dim]
  [dim]──────────────────────────────────────────────────────────────────────────────────[/dim]
  [dim]Use 'help' for commands. Use responsibly and legally.[/dim]
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
    # Default prompt (colored). Tests expect the ANSI-colored prompt string
    prompt = "\033[1;36m[phantom]\033[0m > "

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
        console.print(build_dashboard())
        # Use colored prompt for interactive sessions; class attribute remains plain for tests
        self.prompt = "\033[1;36m[phantom]\033[0m > "
        self.plugins = self._load_plugins()
        if self.plugins:
            notifier.info(f"Loaded {len(self.plugins)} plugin(s)")

    def postcmd(self, stop, line):
        """Update prompt with context."""
        t = f"(\033[1;31m{session.target}\033[0m)" if session.target else ""
        m = f"[\033[1;35m{session.mode.upper()}\033[0m]" if session.mode else ""
        self.prompt = f"\033[1;36mphantom\033[0m{t}{m} > "
        return stop

    def _load_plugins(self):
        """
        Load external plugins from ~/.phantom/plugins/*.py and phantom/plugins/*.py
        Security: Verifies class inheritance and warns user.
        """
        plugin_dirs = [
            os.path.expanduser("~/.phantom/plugins"),
            os.path.join(os.path.dirname(__file__), "..", "plugins")
        ]
        
        plugins = {}
        self._plugin_modules = {} 
        
        for plugin_dir in plugin_dirs:
            if not os.path.exists(plugin_dir):
                continue
                
            plugin_files = [f for f in os.listdir(plugin_dir) if f.endswith(".py") and not f.startswith("__")]
            
            for file in plugin_files:
                # Conditional Loading for AI Connector
                if file == "ai_connector.py":
                    provider = os.getenv("AI_PROVIDER", "").lower()
                    if provider not in ["openai", "ollama"]:
                        continue # Skip loading

                name = file[:-3]
                plugin_path = os.path.join(plugin_dir, file)
                
                # Basic permission check on Linux/Unix
                if os.name == "posix":
                    import stat
                    mode = os.stat(plugin_path).st_mode
                    if mode & stat.S_IWOTH:
                        notifier.error(f"Security Error: Plugin {file} is world-writable! Skipping.")
                        continue
                elif os.name == "nt":
                    notifier.info(f"Plugin {file} loaded (no permission check on Windows)")

                spec = importlib.util.spec_from_file_location(name, plugin_path)
                module = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(module)
                    from phantom.modules.base_module import BaseModule
                    for attr in dir(module):
                        obj = getattr(module, attr)
                        if (isinstance(obj, type) and 
                            issubclass(obj, BaseModule) and 
                            obj is not BaseModule and
                            hasattr(obj, "module_name")):
                            
                            self._plugin_modules[obj.module_name] = obj
                            plugins[obj.module_name] = obj
                            
                            # Register AI plugin singleton in session
                            if obj.module_name == "ai_connector":
                                session.ai_connector = obj()
                                
                except Exception as e:
                    notifier.error(f"Failed to load plugin {file}: {e}")
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
        notifier.success(f"Profile saved: {name}")

    def load_profile(self, name: str):
        """Load a profile and apply settings to current session."""
        profile_path = os.path.expanduser(f"~/.phantom/profiles/{name}.json")
        if not os.path.exists(profile_path):
            notifier.error(f"Profile '{name}' not found.")
            return
        try:
            with open(profile_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            notifier.error(f"Cannot load profile: {e}")
            return

        # Validate and apply with type checking
        if isinstance(data.get("target"), str):
            session.target = data["target"]
        if data.get("mode") in ("recon", "osint", "full", "exploit"):
            session.mode = data["mode"]
        if isinstance(data.get("scope"), list):
            session.scope = [str(s) for s in data["scope"]]
        if isinstance(data.get("active_wordlist"), str):
            session.active_wordlist = data["active_wordlist"]
        
        # Apply timeout and aggressive confirm
        if isinstance(data.get("timeout_seconds"), (int, float)):
            from phantom.core import executor
            executor.TIMEOUT_SECONDS = max(10, min(int(data["timeout_seconds"]), 3600))
        if isinstance(data.get("aggressive_confirm"), bool):
            session.aggressive_confirm = data["aggressive_confirm"]

        notifier.success(f"Profile '{name}' loaded.")
        self.do_show("session")

    def do_save_profile(self, name: str):
        """save-profile <name> — save current settings as a profile."""
        if not name.strip():
            notifier.error("Usage: save-profile <name>")
            return
        self.save_profile(name.strip())

    def do_load_profile(self, name: str):
        """load-profile <name> — load a profile."""
        if not name.strip():
            notifier.error("Usage: load-profile <name>")
            return
        self.load_profile(name.strip())

    def do_list_profiles(self, arg: str):
        """List all saved profiles."""
        profile_dir = os.path.expanduser("~/.phantom/profiles")
        if not os.path.exists(profile_dir):
            notifier.warn("No profiles found.")
            return
        profiles = [f.replace(".json", "") for f in os.listdir(profile_dir) if f.endswith(".json")]
        if not profiles:
            notifier.warn("No profiles found.")
            return
        console.print("[cyan]Available Profiles:[/]")
        for p in profiles:
            console.print(f"  [white]- {p}[/]")

    def do_set(self, arg: str):
        """set target <ip/domain> | set mode <recon|osint|full|exploit> | set scope <cidr,ip,...>"""
        parts = arg.strip().split(maxsplit=1)
        if len(parts) < 2:
            notifier.error("Usage: set <target|mode|scope> <value>")
            return
        key, value = parts[0].lower(), parts[1]

        if key == "target":
            # Validation estesa: ammette lettere, numeri e i caratteri speciali . _ - : @ 
            # in qualsiasi posizione (inizio/fine inclusi) per supportare gli username social.
            import re
            TARGET_REGEX = re.compile(r'^[@a-zA-Z0-9._\-:]+$')
            URL_TARGET_REGEX = re.compile(r'^https?://[a-zA-Z0-9.\-:/]+$')
            
            is_valid = False
            if value.startswith(("http://", "https://")):
                is_valid = bool(URL_TARGET_REGEX.match(value))
            # Rimosso il divieto di iniziare/finire con punti o trattini per supportare i formati social
            elif TARGET_REGEX.match(value) and '..' not in value:
                is_valid = True
                
            if not is_valid:
                notifier.error(f"Invalid target format: {value}")
                return

            if session.scope and not is_in_scope(value, session.scope):
                notifier.warn(f"{value} is out of current scope.")
                confirm = input("    Proceed anyway? [y/N] ").strip().lower()
                if confirm != "y":
                    return
            session.target = value
            notifier.success(f"Target set to {value}")

        elif key == "mode":
            valid_modes = list(MODE_SEQUENCES.keys())
            if value in valid_modes:
                session.mode = value
                steps = " → ".join(MODE_SEQUENCES[value])
                notifier.success(f"Mode set to {value}  [dim]({steps})[/]")
                notifier.info("Type 'run' to launch the sequence automatically.")
            else:
                notifier.error(f"Invalid mode. Use: {', '.join(valid_modes)}")

        elif key == "scope":
            session.scope = [s.strip() for s in value.split(",")]
            notifier.success(f"Scope set to {', '.join(session.scope)}")

        else:
            notifier.error(f"Unknown key: {key}")

    def do_run(self, _):
        """run — launch all modules for the current mode in sequence"""
        if not session.target:
            notifier.error("No target set. Use 'set target <ip>' first.")
            return
        
        # Fallback to recon if no mode is set
        mode = session.mode if session.mode else "recon"
        steps = MODE_SEQUENCES.get(mode, ["scan"])
        total = len(steps)

        console.print(f"[bold cyan][*] Mode: {mode.upper()} — {' → '.join(s.upper() for s in steps)}[/]")

        for i, module_name in enumerate(steps, 1):
            console.print(f"[bold cyan]── STEP {i}/{total}: {module_name.upper()} {'─' * (50 - len(module_name))}[/]")
            self.do_use(module_name)
            notifier.success(f"{module_name.upper()} complete.")
            console.print()

        notifier.success(f"{mode.upper()} sequence complete. Results saved to session.")
        notifier.info("Use 'export json report.json' to generate a report.")

    def do_show(self, arg: str):
        """show session | show scope | show mode"""
        arg = arg.strip().lower()
        if arg == "session":
            from phantom.core import executor
            from rich.table import Table
            table = Table(title="Current session")
            table.add_column("Field", style="cyan")
            table.add_column("Value")
            table.add_row("Target", session.target or "—")
            table.add_row("Mode", session.mode)
            table.add_row("Mode sequence", " → ".join(MODE_SEQUENCES.get(session.mode, [])))
            table.add_row("Scope", ", ".join(session.scope) if session.scope else "—")
            table.add_row("Timeout", f"{executor.TIMEOUT_SECONDS}s")
            table.add_row("Active wordlist", session.active_wordlist or "—")
            table.add_row("Completed modules", ", ".join(session.results.keys()) or "—")
            table.add_row("Notes", str(len(session.notes)))
            console.print(table)
        elif arg == "scope":
            if session.scope:
                console.print(f"[cyan]Scope: {', '.join(session.scope)}[/]")
            else:
                notifier.warn("No scope defined.")
        elif arg == "mode":
            console.print(f"[cyan]Mode: {session.mode}[/]")
            console.print(f"  Sequence: {' → '.join(MODE_SEQUENCES.get(session.mode, []))}")
            notifier.info("Type 'run' to launch.")
        else:
            notifier.error("Usage: show session | show scope | show mode")

    def do_note(self, arg: str):
        """note "<text>" — add an inline note to the session"""
        text = arg.strip().strip('"').strip("'")
        if not text:
            notifier.error("Usage: note \"your note here\"")
            return
        session.add_note(text)
        notifier.success("Note added.")

    def do_notes(self, arg: str):
        """Display all notes in the current session"""
        show_notes()

    def do_save_session(self, name: str):
        """save-session <name> — save current session to disk"""
        name = name.strip()
        if not name:
            notifier.error("Usage: save-session <name>")
            return
        session.save(name)
        notifier.success(f"Session saved: {name}.json")

    def do_load_session(self, name: str):
        """load-session <name> — load a previously saved session"""
        name = name.strip()
        if not name:
            notifier.error("Usage: load-session <name>")
            return
        try:
            session.load(name)
            notifier.success(f"Session loaded: {name}")
        except FileNotFoundError:
            notifier.error(f"Session '{name}' not found.")

    def do_list_sessions(self, arg: str):
        """List all saved sessions"""
        saved = session.list_saved()
        if not saved:
            notifier.warn("No saved sessions.")
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
            notifier.warn("No commands in history.")
            return
        for entry in session.history:
            console.print(f"  [dim]{entry}[/]")

    def do_export(self, arg: str):
        """export <json|pdf|html> [filename] — export session results"""
        from phantom.modules.report import ReportModule
        parts = arg.strip().split()
        if not parts:
            notifier.error("Usage: export <json|pdf|html> [filename]")
            return
        fmt = parts[0].lower()
        if fmt not in ("json", "pdf", "html"):
            notifier.error("Invalid format. Use json, pdf, or html.")
            return
        default_name = f"report_{session.target or 'phantom'}.{fmt}"
        filename = parts[1] if len(parts) > 1 else default_name
        rm = ReportModule()
        rm.export(fmt, filename)

    def do_scan_diff(self, arg: str):
        """scan-diff <target> [--since YYYY-MM-DD | --old TS --new TS]"""
        import argparse
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
            notifier.warn("Need at least two scans for diff.")
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
            notifier.error("Could not find matching scans.")
            return

        added, removed, changed = diff_scans(old["services"], new["services"])

        console.print(f"[bold cyan]Diff: {old['timestamp']} → {new['timestamp']}[/]")
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
            notifier.info("No changes detected.")

    def do_use(self, arg: str):
        """use <module> — enter a module"""
        module_name = arg.strip().lower()
        modules = {
            "scan":     "phantom.modules.scan.ScanModule",
            "osint":    "phantom.modules.osint.OsintModule",
            "wifi":     "phantom.modules.wifi.WifiModule",
            "web":      "phantom.modules.web.WebModule",
            "brute":    "phantom.modules.brute.BruteModule",
            "exploit":  "phantom.modules.exploit.ExploitModule",
            "payload":  "phantom.modules.payload.PayloadModule",
            "handler":  "phantom.modules.handler.HandlerModule",
            "pivot":    "phantom.modules.pivot.PivotModule",
            "analyzer": "phantom.modules.analyzer.AnalyzerModule",
            "report":   "phantom.modules.report.ReportModule",
        }
        
        # Standard modules
        if module_name in modules:
            import importlib
            path, cls_name = modules[module_name].rsplit(".", 1)
            mod = importlib.import_module(path)
            cls = getattr(mod, cls_name)
            instance = cls()
            instance.cmdloop()
            return

        # Plugin modules
        plugin_modules = getattr(self, "_plugin_modules", {})
        if module_name in plugin_modules:
            cls = plugin_modules[module_name]
            instance = cls()
            instance.cmdloop()
            return

        notifier.error(f"Unknown module: {module_name}")
        notifier.info(f"Available: {', '.join(list(modules.keys()) + list(plugin_modules.keys()))}")

    def do_help(self, arg: str):
        """help [command] — Show the help panel or details about a specific command."""
        from rich.table import Table
        from rich.panel import Panel
        from rich.columns import Columns

        if arg.strip():
            # Show help for a specific command
            func = getattr(self, f"do_{arg.strip().replace('-', '_')}", None)
            if func and func.__doc__:
                console.print(Panel(func.__doc__, title=f"[bold cyan]Help: {arg}[/]", border_style="cyan"))
            else:
                notifier.error(f"No help available for '{arg}'.")
            return

        # ── Session & Config ────────────────────────────────────────────
        t1 = Table(title="[bold white]Session & Config[/]", border_style="blue", show_lines=False)
        t1.add_column("Command", style="cyan", no_wrap=True)
        t1.add_column("Description", style="white")
        t1.add_row("set target <ip>", "Define the testing target")
        t1.add_row("set mode <mode>", "Select workflow: recon, osint, full, exploit")
        t1.add_row("set scope <cidr,...>", "Define authorized testing boundaries")
        t1.add_row("show session", "Display current session info")
        t1.add_row("note \"text\"", "Add a timestamped note")
        t1.add_row("notes", "Display all session notes")
        t1.add_row("history", "Show command history")

        # ── Execution ───────────────────────────────────────────────────
        t2 = Table(title="[bold white]Execution[/]", border_style="green", show_lines=False)
        t2.add_column("Command", style="cyan", no_wrap=True)
        t2.add_column("Description", style="white")
        t2.add_row("run", "Launch the full mode sequence automatically")
        t2.add_row("use <module>", "Enter a module (scan, osint, wifi, web, ...)")
        t2.add_row("c2", "Enter the C2 Operations Center")

        # ── Persistence ─────────────────────────────────────────────────
        t3 = Table(title="[bold white]Persistence & Reporting[/]", border_style="yellow", show_lines=False)
        t3.add_column("Command", style="cyan", no_wrap=True)
        t3.add_column("Description", style="white")
        t3.add_row("save-session <name>", "Save current session to disk")
        t3.add_row("load-session <name>", "Load a previously saved session")
        t3.add_row("list-sessions", "List all saved sessions")
        t3.add_row("save-profile <name>", "Save settings as a reusable profile")
        t3.add_row("load-profile <name>", "Load a profile")
        t3.add_row("export <json|pdf|html>", "Generate a professional report")
        t3.add_row("scan-diff <target>", "Compare scan results over time")

        # ── Modules ─────────────────────────────────────────────────────
        t4 = Table(title="[bold white]Available Modules[/]", border_style="magenta", show_lines=False)
        t4.add_column("Module", style="bold magenta", no_wrap=True)
        t4.add_column("Purpose", style="white")
        t4.add_row("scan", "Active Reconnaissance (nmap, traceroute)")
        t4.add_row("osint", "Passive Intelligence (crt.sh, Shodan, Whois)")
        t4.add_row("wifi", "Wireless Attacks (aircrack-ng, reaver, PMKID)")
        t4.add_row("web", "Web Application Pentest (gobuster, sqlmap, nikto)")
        t4.add_row("brute", "Credential Auditing (hydra, john, hashcat)")
        t4.add_row("exploit", "CVE Correlation & C2 Beacon Deployment")
        t4.add_row("payload", "Payload Generation (msfvenom)")
        t4.add_row("analyzer", "Traffic Analysis (scapy, tshark)")
        t4.add_row("pivot", "Post-Exploitation (SSH tunneling, chisel)")
        t4.add_row("report", "Report Generation (JSON, PDF, HTML)")
        t4.add_row("c2", "Command & Control Operations Center")

        console.print()
        console.print(t1)
        console.print()
        console.print(t2)
        console.print()
        console.print(t3)
        console.print()
        console.print(t4)
        console.print()
        console.print("[dim]  Type 'help <command>' for details on a specific command.[/]")
        console.print("[dim]  Type 'wordlists list' to manage attack dictionaries.[/]")
        console.print()

    def do_back(self, arg: str):
        """Return to main shell (already here)"""
        notifier.warn("Already at main shell.")

    def do_c2(self, arg: str):
        """c2 - Enter the Phantom C2 Operations Center"""
        notifier.status("Transitioning to C2 Interface...")
        from phantom.core.c2_shell import run_c2
        run_c2()

    def do_exit(self, arg: str):
        """Exit Phantom, optionally save current session and generate report"""
        if session.target:
            # AI Reporting (Optional)
            ai = getattr(session, "ai_connector", None)
            if ai and getattr(ai, "enabled", False):
                confirm_ai = input("Generate AI Executive Summary for this session? [y/N]: ").strip().lower()
                if confirm_ai == "y":
                    notifier.status("Generating AI summary...")
                    summary = session.ai_connector.generate_executive_summary(session.__dict__)
                    if summary:
                        session.add_note(f"AI EXECUTIVE SUMMARY:\n{summary}")
                        notifier.success("AI Summary added to notes.")

            # Auto-Reporting Prompt
            note = input("\nAdd a final manual note for the report? (empty to skip): ").strip()
            if note:
                session.add_note(note)

            confirm = input("Save session and generate Markdown report? [y/N]: ").strip().lower()
            if confirm == "y":
                name = input("Report/Session name (default: auto): ").strip() or "auto"
                session.save(name)
                session.export_markdown(f"{name}.md")

        console.print("\n[dim]Phantom closed.[/]\n")
        return True

    def do_quit(self, arg: str):
        return self.do_exit(arg)

    def default(self, line: str):
        notifier.error(f"Unknown command: {line}")
        notifier.info("Type 'help' for available commands.")
