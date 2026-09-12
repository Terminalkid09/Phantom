import cmd
import sys
import os
import time
import argparse
import importlib.util
import json                 
from datetime import datetime
from dotenv import load_dotenv
from rich.console import Console
from phantom.core.session import session
from phantom.core.scope import is_in_scope
from phantom.core.notes import show_notes
from phantom.utils.notifier import notifier
import traceback


def load_phantom_env() -> None:
    """Load .env from project root, user home, or package dir (in that order)."""
    pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    project_root = os.path.dirname(pkg_dir)
    for path in (
        os.path.join(project_root, ".env"),
        os.path.join(os.path.expanduser("~"), ".phantom", ".env"),
        os.path.join(os.path.expanduser("~"), ".env"),
        os.path.join(pkg_dir, ".env"),
    ):
        if os.path.isfile(path):
            load_dotenv(path)
            return
    load_dotenv()


load_phantom_env()

console = Console()


def _context_hint() -> str:
    """Faded one-line hint: what to do NEXT given the current state.
    Shown after every command so the operator never gets stuck reading
    docs — the shell tells you the obvious next move."""
    hints = []
    if not session.target:
        hints.append("set target <ip|domain|email>")
        hints.append("set scope <cidr,...> (authorized targets)")
        hints.append("help")
    else:
        try:
            from phantom.core.knowledge import knowledge_summary
            counts = knowledge_summary()
        except Exception:
            counts = {}
        if not counts.get("service"):
            hints.append("use scan → run")
            hints.append("auto <target>")
        else:
            if not counts.get("vuln"):
                hints.append("use exploit → run")
            if not counts.get("creds"):
                hints.append("use brute → run")
            hints.append("use web → hunt")
            hints.append("export all (report)")
        hints.append("preflight scan")
        hints.append("run")
    return "[dim]▸ " + "   ".join(hints[:4]) + "[/dim]"


def _engagement_elapsed() -> str:
    """Human-readable elapsed time since the engagement started."""
    started = getattr(session, "engagement_started", None)
    if not started:
        return "0s"
    try:
        from datetime import datetime as _dt
        secs = max(0, int((_dt.now() - _dt.fromisoformat(started)).total_seconds()))
    except Exception:
        return "0s"
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def build_status_bar() -> str:
    """One-line live status: target · type · knowledge counters · beacon · timer.
    Printed after every command so the operator always sees where the
    engagement stands (the "status bar" of the manual shell)."""
    target = session.target or "—"
    ttype = _target_type_tag()
    scope = ", ".join(session.scope) if session.scope else "—"
    elapsed = _engagement_elapsed()

    try:
        from phantom.core.knowledge import knowledge_summary
        counts = knowledge_summary()
        n_serv = counts.get("service", 0)
        n_creds = counts.get("creds", 0)
        n_vuln = counts.get("vuln", 0)
        n_hunt = counts.get("web_app", 0) + counts.get("hunt", 0)
    except Exception:
        n_serv = n_creds = n_vuln = n_hunt = 0

    beacon = "—"
    try:
        from phantom.core.c2_server import c2_state
        n_beacons = len(c2_state.get_beacons())
        if n_beacons:
            beacon = f"[bold green]● {n_beacons} beacon(s)[/]"
        else:
            beacon = "[dim]○ no beacon[/]"
    except Exception:
        beacon = "[dim]○ beacon n/a[/]"

    return (
        f"[bold bright_red]▚ PHANTOM[/] [dim]|[/] "
        f"[bold cyan]{target}[/] [dim]·[/] [bold magenta]{ttype}[/] "
        f"[dim]· scope {scope}[/] "
        f"[dim]·[/] [green]svc {n_serv}[/] "
        f"[dim]·[/] [yellow]creds {n_creds}[/] "
        f"[dim]·[/] [magenta]vuln {n_vuln}[/] "
        f"[dim]·[/] [cyan]hunt {n_hunt}[/] "
        f"[dim]·[/] {beacon} "
        f"[dim]· ⏱ {elapsed}[/]"
    )


def build_dashboard():
    """Compact Rich panel shown on shell entry — one panel, same style as C2."""
    from rich.panel import Panel
    target = session.target or "None"
    ttype = _target_type_tag()
    scope = ", ".join(session.scope) if session.scope else "—"
    elapsed = _engagement_elapsed()
    return Panel(
        f"[bold cyan]Target:[/] {target}   |   "
        f"[bold magenta]Type:[/] {ttype}   |   "
        f"[bold green]Scope:[/] {scope}   |   "
        f"[bold yellow]Notes:[/] {len(session.notes)}   |   "
        f"[bold]⏱ {elapsed}[/]",
        title="[bold]Phantom Framework[/]",
        border_style="blue",
    )


def _target_type_tag() -> str:
    """Cheap target-type tag for the status bar/dashboard."""
    if not session.target:
        return "—"
    try:
        from phantom.automation.guidance.targets import classify_target
        return classify_target(session.target).upper()
    except Exception:
        return "—"


def build_banner() -> str:
    import sys
    import platform
    from datetime import datetime

    python_ver = sys.version.split()[0]
    os_info = platform.system() + " " + platform.release()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Single Rich markup wrapper for the whole wordmark — same pattern as
    # the C2 shell banner. Per-line tags cause Rich to miscalculate widths
    # and corrupt the display on narrower (80-col) terminals.
    return f"""
[bold red]
  ██████╗ ██╗  ██╗ █████╗ ███╗  ██╗████████╗ ██████╗ ███╗  ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗ ██║╚══██╔══╝██╔═══██╗████╗████║
  ██████╔╝███████║███████║██╔██╗██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚████║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚███║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
[/bold red]
  [dim]──────────────────────────────────────────────────────────────────────────────[/dim]
  [bold white]Offensive Security Framework[/bold white]  [dim]v3.0.0[/dim]
  [cyan]Python[/cyan] [dim]{python_ver}[/dim]   [cyan]OS[/cyan] [dim]{os_info}[/dim]   [cyan]Time[/cyan] [dim]{now}[/dim]
  [dim]──────────────────────────────────────────────────────────────────────────────[/dim]
  [dim]Use 'help' for commands. Use responsibly and legally.[/dim]
"""


def build_banner_compact() -> str:
    """Smaller banner for narrow terminals / --quiet startup."""
    import sys
    import platform
    from datetime import datetime

    python_ver = sys.version.split()[0]
    os_info = platform.system() + " " + platform.release()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""
[bold bright_red]█▀█ ██╗ █████╗ ███╗  ██╗████████╗ ██████╗ ███╗  ███╗[/bold bright_red]
[bold cyan]█▀▀ ██║██╔══██╗████╗ ██║╚══██╔══╝██╔═══██╗████╗████║[/bold cyan]
[bold bright_cyan]██║  ██║███████║██╔██╗██║   ██║   ██║   ██║██╔████╔██║[/bold bright_cyan]
[bold bright_white]╚═╝  ╚═╝╚══════╝╚═╝  ╚══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝[/bold bright_white]
  [dim]v3.0.0 · Offensive Security Framework · {now}[/dim]
"""


# Mode → modules sequence mapping
class PhantomShell(cmd.Cmd):
    intro = ""
    # Default prompt (colored). Tests expect the ANSI-colored prompt string
    prompt = "\033[1;36m[phantom]\033[0m > "
    auto_run = False

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
        # First-run bootstrap: auto-generate and persist C2 secrets so the
        # operator never has to hand-edit .env. Show the summary once.
        try:
            from phantom.utils.state import ensure_bootstrap
            created = ensure_bootstrap()
            if any(created.values()):
                fresh = [k.replace("PHANTOM_", "").replace("_", " ").lower()
                         for k, v in created.items() if v]
                notifier.success("First run: C2 secrets auto-generated and saved "
                                 f"to data/phantom_state.json (gitignored): {', '.join(fresh)}.")
                notifier.info("No .env editing needed — 'config' shows the status.")
        except Exception:
            pass
        # Engagement timer: starts when the shell opens (or first target set)
        from datetime import datetime as _dt
        if not getattr(session, "engagement_started", None):
            session.engagement_started = _dt.now().isoformat(timespec="seconds")
        # Use colored prompt for interactive sessions; class attribute remains plain for tests
        self.prompt = "\033[1;36m[phantom]\033[0m > "
        self.plugins = self._load_plugins()
        if self.plugins:
            notifier.info(f"Loaded {len(self.plugins)} plugin(s)")

    def postcmd(self, stop, line):
        """Update prompt with context and refresh the live status bar."""
        if line.strip() and not line.strip().startswith(("set ", "note ")):
            try:
                console.print("[dim]──────────────────────────────────────────[/dim]")
                console.print(build_status_bar())
                console.print(_context_hint())
            except Exception:
                pass
        t = f"(\033[1;31m{session.target}\033[0m)" if session.target else ""
        self.prompt = f"\033[1;36mphantom\033[0m{t} > "
        return stop

    def cmdloop(self, intro=None):
        """First Ctrl+C cancels input + shows hint; second Ctrl+C (within 2s) exits.

        Re-implemented inline so that preloop() runs only once — the stdlib
        cmdloop would re-print the full banner on every KeyboardInterrupt,
        burying the exit hint."""
        import time as _time

        self.preloop()
        if intro is not None:
            self.intro = intro
        if self.intro:
            self.stdout.write(str(self.intro) + "\n")
        self.old_completer = None
        if self.use_rawinput and self.completekey:
            try:
                import readline
                self.old_completer = readline.get_completer()
                readline.set_completer(self.complete)
                readline.parse_and_bind(self.completekey + ": complete")
            except (ImportError, AttributeError):
                pass

        self._intr_count = 0
        self._last_intr = 0.0
        stop = None
        try:
            while not stop:
                try:
                    if self.cmdqueue:
                        line = self.cmdqueue.pop(0)
                    else:
                        if self.use_rawinput:
                            try:
                                line = input(self.prompt)
                            except EOFError:
                                # stdin closed (pipe end, scripted run): exit
                                # the shell cleanly instead of dispatching a
                                # literal "EOF" as a command.
                                console.print()
                                break
                        else:
                            self.stdout.write(self.prompt)
                            self.stdout.flush()
                            line = self.stdin.readline()
                            if not len(line):
                                console.print()
                                break
                            else:
                                line = line.rstrip("\r\n")
                    line = self.precmd(line)
                    stop = self.onecmd(line)
                    stop = self.postcmd(stop, line)
                    # reset double-exit window after a successful command
                    self._intr_count = 0
                except KeyboardInterrupt:
                    now = _time.monotonic()
                    if now - self._last_intr > 2.0:
                        self._intr_count = 0
                    self._intr_count += 1
                    self._last_intr = now
                    if self._intr_count >= 2:
                        console.print("\n[dim]Phantom closed.[/dim]\n")
                        raise SystemExit(0)
                    console.print()
                    console.print(
                        "[bold yellow]^C  —  Ctrl+C again to exit, or keep typing.[/bold yellow]")
                    continue
            self.postloop()
        finally:
            if self.use_rawinput and self.completekey and self.old_completer is not None:
                try:
                    import readline
                    readline.set_completer(self.old_completer)
                except (ImportError, AttributeError):
                    pass



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
                    continue  # ai_connector removed in v3.0 # Skip loading

                name = file[:-3]
                plugin_path = os.path.join(plugin_dir, file)
                
                # Basic permission check on Linux/Unix
                if os.name == "posix":
                    import stat
                    mode = os.stat(plugin_path).st_mode
                    if mode & stat.S_IWOTH:
                        # Mounted from Windows → overly permissive. Fix it silently.
                        os.chmod(plugin_path, mode & ~stat.S_IWOTH)
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

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except SystemExit:
            raise
        except Exception as e:
            notifier.error(f"Command execution failed: {e}")
            import traceback
            console.print(traceback.format_exc())
            return False  # Continue the loop

    def complete_set(self, text: str, line: str, begidx: int, endidx: int) -> list:
        """Tab-completion for `set` (keys + mode values + saved targets)."""
        parts = line.split()
        if len(parts) <= 2:
            keys = ["target", "scope", "lhost", "lport"]
            return [k for k in keys if k.startswith(text)]
        if parts[1] == "target":
            candidates = [session.target] if session.target else []
            try:
                candidates += session.list_saved()
            except Exception:
                pass
            return [c for c in candidates if c.startswith(text)]
        return []

    def do_set(self, arg: str):
        """set target <ip/domain/email> | set scope <cidr,...> | set lhost <ip> | set lport <port>"""
        parts = arg.strip().split(maxsplit=1)
        if len(parts) < 2:
            notifier.error("Usage: set <target|mode|scope|lhost|lport> <value>")
            return
        key, value = parts[0].lower(), parts[1]

        if key == "target":
            import re
            # identity targets are accepted too: emails (@), usernames (dots),
            # phones (+39..., dashes/spaces allowed)
            TARGET_REGEX = re.compile(r'^[@+a-zA-Z0-9._\s\-:]+$')
            URL_TARGET_REGEX = re.compile(r'^https?://[a-zA-Z0-9.\-:/]+$')
            
            is_valid = False
            if value.startswith(("http://", "https://")):
                is_valid = bool(URL_TARGET_REGEX.match(value))
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
            # a new target = a new engagement: fresh shared WorldModel so
            # the manual modules reason over THIS target's findings only
            from phantom.core.knowledge import reset_wm
            reset_wm(target=value)
            notifier.success(f"Target set to {value}")

        elif key == "scope":
            session.scope = [s.strip() for s in value.split(",")]
            notifier.success(f"Scope set to {', '.join(session.scope)}")

        elif key == "mode":
            mode = value.strip().lower()
            valid_modes = ("recon", "osint", "web", "exploit", "full", "deliver")
            if mode not in valid_modes:
                notifier.error(f"Unknown mode '{mode}'. Valid: {', '.join(valid_modes)}")
                return
            session.mode = mode
            notifier.success(f"Mode set to {mode.upper()}")

        elif key == "lhost":
            session.lhost = value
            notifier.success(f"LHOST set to: {value}")
        elif key == "lport":
            try:
                session.lport = int(value)
                notifier.success(f"LPORT set to: {value}")
            except ValueError:
                notifier.error("LPORT must be an integer.")
        else:
            notifier.error(f"Unknown key: {key} (valid: target, mode, scope, lhost, lport)")

    def _instantiate_module(self, module_name: str):
        """Create a module instance by name."""
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
            "wordlist": "phantom.modules.wordlist.WordlistModule",
        }
        if module_name not in modules:
            return None
        import importlib
        path, cls_name = modules[module_name].rsplit(".", 1)
        mod = importlib.import_module(path)
        return getattr(mod, cls_name)()

    def do_run(self, arg: str):
        """run [module] — adaptive next step, or run a specific module.

        With no argument: the shell reads the LIVE engagement (target type,
        findings, reasoning hypotheses) and proposes the single best next
        step with the reason, then asks before executing. With a module
        name it runs that module directly (e.g. `run scan`).
        """
        if not session.target:
            notifier.error("No target set. Use: set target <ip|email|username|domain>")
            return
        module = arg.strip().lower()
        if module:
            instance = self._instantiate_module(module)
            if instance is None:
                notifier.error(f"Unknown module: {module} (use: use <module>)")
                return
            if not self._warn_identity_target(module):
                try:
                    instance.do_run("")
                except NotImplementedError:
                    notifier.warn(f"{module} has no automated run — opening interactive shell.")
                    instance.cmdloop()
            return

        suggestion = self._next_step()
        if not suggestion:
            notifier.info("Nothing actionable right now. Try 'use scan' → 'run', "
                          "or the full chain: auto <target>")
            return
        module, reason = suggestion
        instance = self._instantiate_module(module)
        if instance is None:
            notifier.error(f"Suggested module '{module}' unavailable.")
            return
        console.print(f"[bold cyan]── NEXT STEP: {module.upper()} ──[/]")
        console.print(f"  [dim]reason: {reason}[/]")
        # No extra confirm here: every module flow ends in its own
        # interactive selection (PreviewSession), so nothing executes
        # without an explicit choice — a second prompt was only friction.
        try:
            instance.do_run("")
        except NotImplementedError:
            notifier.warn(f"{module} has no automated run — opening interactive shell.")
            instance.cmdloop()

    _NETWORK_MODULES = {"scan", "web", "exploit", "brute", "pivot", "wifi",
                        "handler", "payload"}

    def _warn_identity_target(self, module_name: str) -> bool:
        """Warn (once) when a NETWORK module is used against an IDENTITY
        target (email/username/phone): the manual entry point for identity
        is osint. Returns True when the warning applies."""
        if module_name not in self._NETWORK_MODULES or not session.target:
            return False
        try:
            from phantom.automation.guidance.targets import classify_target, is_identity_target
            if is_identity_target(classify_target(session.target)):
                notifier.warn(
                    f"Identity target ({classify_target(session.target)}): "
                    f"'{module_name}' is network-oriented. Run 'use osint' first "
                    "to build the dossier (emails/phones/platforms).")
                return True
        except Exception:
            pass
        return False

    # capability id -> manual module (for the reasoning-driven next step)
    _CAPABILITY_MODULE = {
        "osint_identity": "osint", "osint_domain": "osint", "breach_check": "osint",
        "scan_tcp": "scan", "version_detect": "scan", "os_detect": "scan",
        "service_exploit": "exploit", "rce_foothold": "exploit",
        "hunt_web": "web", "http_probe": "web", "web_app": "web",
        "ssh_banner": "scan", "smb_null": "exploit",
        "creds_brute": "brute", "default_creds": "brute",
        "payload_gen": "payload", "pivot": "pivot",
        # deeper capabilities the reasoning engine may suggest: map to the
        # manual module that performs the equivalent step
        "web_rce": "exploit",          # upload-RCE probe / exploit module fire
        "beacon_via_rce": "exploit",   # deploy-agent injects through the RCE
        "hunt_anomaly": "web",
        "environment": "scan",         # env probe is a recon surface check
        "mobile": "web",               # mobile surface is probed over web
        "ad_enum": "exploit", "kerberoast": "exploit", "as_rep_roast": "exploit",
        "dc_sync": "exploit", "hash_crack": "exploit",
        "lateral_pivot": "pivot", "smb_pivot": "pivot", "winrm_pivot": "pivot",
        # post-beacon-only capabilities live in the C2 operations center
        "cloud_creds_harvest": "c2", "cloud_s3_enum": "c2", "k8s_escape": "c2",
    }

    def _next_step(self):
        """Pick the single best next module from the LIVE engagement state:
        target type first (identity -> osint, network -> scan), then the
        senior reasoning hypotheses, then the module with the most
        actionable suggestions."""
        from phantom.automation.guidance.targets import classify_target, is_identity_target
        from phantom.core.knowledge import knowledge_summary

        ttype = classify_target(session.target)
        if is_identity_target(ttype):
            done = set(session.results.keys())
            if "osint" not in done:
                return ("osint", "identity target: build the dossier (emails, phones, "
                                  "platforms) before touching any network")
            return ("scan", "identity chain complete — map the victim's IP/network position")

        # senior reasoning hypotheses carry the WHY (same engine as auto-mode)
        try:
            from phantom.modules.suggest import reasoning_suggestion_group
            groups = reasoning_suggestion_group() or {}
            hyp = (groups.get("SUGGESTED (reasoning)") or [])
            if hyp:
                text = str(hyp[0])
                cap = text[1:text.find("]")] if text.startswith("[") else ""
                reason = text[text.find("]") + 1:].strip() if "]" in text else text
                mod = self._CAPABILITY_MODULE.get(cap)
                if mod:
                    return (mod, reason)
        except Exception:
            pass

        counts = knowledge_summary()
        if counts.get("service", 0) == 0:
            return ("scan", "no services discovered yet — enumerate the target first")

        best, best_n = None, 0
        for mod in ("web", "exploit", "brute", "osint", "payload", "pivot"):
            inst = self._instantiate_module(mod)
            if inst is None:
                continue
            try:
                n = sum(len(v or []) for v in (inst.suggest_commands() or {}).values())
            except Exception:
                n = 0
            if n > best_n:
                best, best_n = mod, n
        if best and best_n > 0:
            return (best, f"{best_n} actionable step(s) ready from current findings")
        return ("scan", "re-enumerate the target (no actionable suggestions yet)")

    MODULE_ALIASES = {
        "s": "scan", "sc": "scan",
        "o": "osint", "os": "osint",
        "w": "web", "we": "web",
        "e": "exploit", "ex": "exploit",
        "b": "brute", "br": "brute",
        "p": "payload", "pay": "payload",
        "h": "handler", "ha": "handler",
        "v": "pivot", "pi": "pivot",
        "a": "analyzer", "an": "analyzer",
        "r": "report", "re": "report",
        "wl": "wordlist",
    }

    def do_suggest(self, arg: str):
        """suggest — evidence-tagged next steps.

        Every suggestion shows WHY (the concrete findings behind it), a
        TRUST score (evidence strength + historical success rate of the
        technique class), and preflight state (missing tools, already-ran,
        out-of-scope). Verify the reasoning in two seconds, then run.
        """
        from phantom.core.suggest_meta import tag_suggestions, render_tagged
        if not session.target:
            notifier.error("No target set. Use: set target <ip|email|username|domain>")
            return
        groups: dict = {}
        for mod in ("scan", "web", "exploit", "brute", "osint", "payload",
                    "pivot", "wifi", "wordlist"):
            inst = self._instantiate_module(mod)
            if inst is None:
                continue
            try:
                for g, cmds in (inst.suggest_commands() or {}).items():
                    groups.setdefault(g, []).extend(cmds or [])
            except Exception:
                continue
        # reasoning hypotheses add the WHY from the shared WorldModel
        try:
            from phantom.modules.suggest import reasoning_suggestion_group
            for g, cmds in (reasoning_suggestion_group() or {}).items():
                groups.setdefault(g, []).extend(cmds or [])
        except Exception:
            pass
        render_tagged(tag_suggestions(groups))

    def do_plan(self, arg: str):
        """plan <goal> — the reasoning engine lays out the chain to a goal.

        Goals: beacon | creds | lateral | ad | identity | deep
        Shows the ordered steps the planner would take with the facts each
        step needs and produces; `suggest` then highlights where you are.
        Nothing is executed.
        """
        from phantom.core.suggest_meta import _wm_evidence
        goal = (arg.strip().lower() or "beacon")
        valid = {"beacon", "creds", "lateral", "ad", "identity", "deep",
                 "footprint", "post_exploit", "crack", "cloud"}
        if goal not in valid:
            notifier.error(f"Unknown goal '{goal}'. Goals: {', '.join(sorted(valid))}")
            return
        if not session.target:
            notifier.error("No target set. Use: set target <ip|email|username|domain>")
            return
        try:
            from phantom.core.knowledge import session_wm
            from phantom.automation.planner import Planner, GOAL_FACTS
            from phantom.automation.guidance.commands import make_registry
            from phantom.automation.guidance.stealth import StealthEngine
            from phantom.automation.stealth.blue_team import BlueTeamModel
            from phantom.automation.guidance.stealth import StealthConfig
            wm = session_wm()
            engine = StealthEngine(
                wm, StealthConfig(), BlueTeamModel.for_profile("enterprise"))
            planner = Planner(make_registry(), engine)
            plan = planner.plan(wm, goal=goal, max_steps=8)
        except Exception as e:
            notifier.error(f"Planner unavailable: {e}")
            return
        console.print(f"[bold cyan]── PLAN → {goal.upper()} "
                      f"({session.target}) ──[/]")
        facts = GOAL_FACTS.get(goal, [])
        done = any(wm.has_any(f) for f in facts)
        if plan.complete and done:
            console.print("  [green]Goal already satisfied by current findings.[/]")
            return
        if not plan.steps:
            console.print(f"  [yellow]No viable path to '{goal}' with current "
                          "findings — scan/enumerate more and re-plan.[/]")
            if plan.blocked_reason:
                console.print(f"  [dim]blocked: {plan.blocked_reason}[/]")
            return
        for i, s in enumerate(plan.steps, 1):
            cap = s.capability
            why = s.reason or ""
            console.print(
                f"  {i:2}. [white]{cap.id}[/] "
                f"[dim]cost={cap.opsec_cost} stealth={cap.stealth_level}"
                f"{' — ' + why if why else ''}[/]")
        console.print("  [dim]Nothing executed. Steps map to modules: "
                      "scan→'use scan', web→'use web', creds→'use brute', "
                      "beacon→'use payload'. 'suggest' shows your next move.[/]")

    def do_preflight(self, arg: str):
        """preflight [module] — check the tools a module needs and show
        install hints for the missing ones. Without arguments checks the
        module you would run next."""
        import shutil as _shutil
        from phantom.core.executor import tool_install_hint

        module_name = arg.strip().lower()
        aliases = self.MODULE_ALIASES
        module_name = aliases.get(module_name, module_name)
        if module_name:
            names = [module_name]
        else:
            names = ["scan"]

        missing = []
        for name in names:
            instance = self._instantiate_module(name)
            if instance is None:
                notifier.error(f"Unknown module: {name}")
                continue
            tools = set()
            try:
                for source in (instance.build_commands(),
                               instance.suggest_commands()):
                    for group in (source or {}).values():
                        for cmd in (group or []):
                            first = cmd.split()[0] if cmd.split() else ""
                            if first:
                                tools.add(first)
            except Exception:
                pass
            for tool in sorted(tools):
                if _shutil.which(tool) is None:
                    missing.append((tool, tool_install_hint(tool)))
            if not tools:
                console.print(f"  [dim]○ {name}: no commands available yet "
                              "(set target first to evaluate its tools).[/]")

        if not missing:
            notifier.success("All required tools are installed.")
            return
        console.print("[bold yellow]Missing tools:[/]")
        for tool, hint in missing:
            console.print(f"  [red]✖ {tool}[/]  [dim]→ {hint}[/]")
        notifier.info("Run 'preflight' again after installing to confirm.")
        notifier.info("Use 'export json report.json' to generate a report.")

    def do_craft(self, arg: str):
        """craft <ipgrab|reel|image|pixel|beacon|hits|wait> — build a
        social lure and get it ready to paste, then watch for the target.

          craft ipgrab [label]            plain click-tracking link
          craft reel <url|search-term>    video lure on a REAL video YOU pick
                                          (IG/TikTok/YT link to mirror, or a
                                          search term; identifier stripped)
          craft image <file|url>          ZERO-CLICK image lure: IP + device +
                                          location captured when it RENDERS
          craft pixel [label]             1x1 tracking pixel (email opens)
          craft beacon [platform]         one-click beacon link disguised as
                                          a reel URL
          craft beacon-player [platform]  upgraded: reel page plays a REAL video,
                                          play click downloads the beacon
                                          (stealth fallback if C2 is down)
          craft real <real-url> [kind]    REAL first hop: a genuine YouTube/
                                          Drive/Notion URL goes in the message,
                                          the capture link goes INSIDE that
                                          content (ipgrab|reel|beacon-player)
          craft channels [url|code]       WHERE the destination can be hidden
                                          (anchor text) and where the raw
                                          domain is all the target reads
          craft idn <domain>              Will a homograph/IDN domain actually
                                          display as the brand? (punycode
                                          verdict, with evidence)
          craft aitm <login-url>          ENTERPRISE (opt-in): AiTM reverse
                                          proxy — serves the REAL login page
                                          and captures credentials AND the
                                          session cookies (beats plain MFA)
          craft hits <code>               every recorded hit/open/cred/session
          craft sessions <code>           sessions taken by an AiTM mount
          craft wait <code> [secs]        live-wait for the target
        """
        from phantom.modules import craft as _craft
        parts = (arg or "").split()
        sub = parts[0].lower() if parts else ""
        if not sub:
            console.print(self.do_craft.__doc__)
            return

        if sub == "ipgrab":
            label = parts[1] if len(parts) > 1 else "phish"
            out = _craft.craft_ipgrab(label=label)
            self._print_lure(out, "IP grabber link (click = IP + device)")
        elif sub == "reel":
            arg = arg.split(maxsplit=1)[1] if len(parts) > 1 else ""
            out = _craft.craft_reel(arg=arg)
            if "error" in out:
                notifier.error(out["error"])
                return
            self._print_lure(out, f"Reel lure ({out.get('video', {}).get('title', '')[:50]})")
            if out.get("hint"):
                notifier.info(out["hint"])
        elif sub == "image":
            src = arg.split(maxsplit=1)[1] if len(parts) > 1 else ""
            out = _craft.craft_image(src)
            if "error" in out:
                notifier.error(out["error"])
                return
            self._print_lure(out, "Image lure (zero-click on render)")
            console.print(f"\n  [cyan]HTML for email/page:[/]\n  {out.get('html', '')}")
            if out.get("hint"):
                notifier.info(out["hint"])
        elif sub == "pixel":
            label = parts[1] if len(parts) > 1 else "px"
            out = _craft.craft_pixel(label=label)
            self._print_lure(out, "Tracking pixel — zero-click: IP when rendered")
            console.print(f"\n  [cyan]HTML for email/page:[/]\n  {out.get('html', '')}")
        elif sub == "beacon":
            platform = parts[1] if len(parts) > 1 else "auto"
            out = _craft.craft_beacon(platform=platform)
            if "error" in out:
                notifier.error(out["error"])
                notifier.info(out.get("hint", ""))
                return
            self._print_lure(out, "Beacon delivery (camouflaged reel link)")
            console.print(f"  [dim]redirects to: {out.get('payload_url', '')}[/]")
            if out.get("hint"):
                notifier.info(out["hint"])
        elif sub == "beacon-player":
            platform = parts[1] if len(parts) > 1 else "auto"
            out = _craft.craft_beacon_player(platform=platform)
            if "error" in out:
                notifier.error(out["error"])
                notifier.info(out.get("hint", ""))
                return
            self._print_lure(out, "Beacon player delivery (reel page, play-click beacon)")
            console.print(f"  [dim]redirects to: {out.get('payload_url', '')}[/]")
            if out.get("hint"):
                notifier.info(out["hint"])
        elif sub == "real":
            args = parts[1:]
            outer = args[0] if args else ""
            inner = args[1] if len(args) > 1 else "ipgrab"
            out = _craft.craft_real(outer_url=outer, inner=inner)
            if "error" in out:
                notifier.error(out["error"])
                if out.get("hint"):
                    notifier.info(out["hint"])
                return
            console.print(f"\n  [bold cyan]► Real first hop "
                          f"({out.get('outer_host')} — {out.get('inner')})[/]")
            console.print(f"  [bold]1) IN THE DM / EMAIL (real URL):[/] "
                          f"{out.get('outer_url')}")
            console.print(f"  [bold]2) INSIDE THE CONTENT:[/] "
                          f"{out.get('inner_paste')}")
            console.print(f"  [dim]tracker url: {out.get('inner_url')}[/]")
            console.print(f"  [dim]where: {out.get('placement')}[/]")
            if out.get("supports_anchor"):
                console.print("  [green]this surface hides the destination: "
                              "the target reads "
                              f"{out.get('inner_display')}[/]")
            else:
                notifier.error(out.get("warning", ""))
                console.print(f"  [dim]anchor-capable middle hops: "
                              f"{', '.join(out.get('recommended_middle_hops', []))}[/]")
            console.print(f"  [dim]code: {out.get('inner_code')} "
                          f"(craft hits / craft wait)[/]")
            console.print(f"\n  [bold]DM text:[/]\n    {out.get('dm_text')}")
            console.print(f"\n  [bold]Email:[/] subject: "
                          f"{out.get('email_subject')}")
            body = str(out.get("email_body", "")).replace("\n", "\n    ")
            console.print(f"    {body}")
            if out.get("note"):
                notifier.info(out["note"])
        elif sub == "idn":
            dom = parts[1] if len(parts) > 1 else ""
            out = _craft.idn_verdict(dom)
            if "error" in out:
                notifier.error(out["error"])
                return
            console.print(f"\n  [bold cyan]► IDN verdict: "
                          f"{out.get('domain')}[/]")
            console.print(f"  scripts:  {', '.join(out.get('scripts') or [])}"
                          f"  [dim](mixed: "
                          f"{out.get('mixed_scripts')})[/]")
            console.print(f"  punycode: {out.get('punycode')}")
            console.print(f"  [bold]address bar shows:[/] "
                          f"{out.get('displayed_in_address_bar')}")
            (notifier.error if out.get("mixed_scripts") else notifier.info)(
                out.get("verdict", ""))
            console.print(f"\n  [dim]{out.get('free_alternative')}[/]")
        elif sub == "channels":
            arg1 = parts[1] if len(parts) > 1 else ""
            if arg1.lower().startswith(("http://", "https://")):
                matrix = _craft.channel_matrix(url=arg1)
            else:
                matrix = _craft.channel_matrix(code=arg1)
            console.print("\n  [bold cyan]► Link rendering matrix[/]")
            for name, row in (matrix.get("channels") or {}).items():
                hides = row.get("hides_destination")
                mark = ("[green]HIDES  [/]" if hides else "[red]VISIBLE[/]")
                console.print(f"  {mark}  [bold]{name}[/] "
                              f"[dim]({row.get('where')})[/]")
                console.print(f"           [dim]paste: "
                              f"{row.get('paste')}[/]")
            mech = matrix.get("mechanisms") or {}
            anchor = mech.get("anchor") or {}
            rdr = mech.get("middle_hop_redirect") or {}
            console.print("\n  [bold cyan]► Mechanism A — anchor (link text)[/]")
            console.print(f"    works on: {', '.join(anchor.get('works_on', []))}")
            console.print(f"    fails on: {', '.join(anchor.get('fails_on', []))}")
            console.print(f"    cost: {anchor.get('cost')}")
            console.print("\n  [bold cyan]► Mechanism B — real third-party "
                          "domain in front[/]")
            console.print(f"    works on: {rdr.get('works_on')}")
            console.print(f"    paste: {rdr.get('paste')}")
            console.print(f"    cost: {rdr.get('cost')}")
            console.print(f"\n  [dim]{matrix.get('truth')}[/]")
        elif sub == "aitm":
            upstream = parts[1] if len(parts) > 1 else ""
            out = _craft.craft_aitm(upstream)
            if "error" in out:
                notifier.error(out["error"])
                if out.get("hint"):
                    notifier.info(out["hint"])
                return
            self._print_lure(out, "AiTM relay (real login page, credentials + "
                                  "session)")
            console.print(f"  [dim]upstream: {out.get('upstream')}[/]")
            if out.get("hint"):
                notifier.info(out["hint"])
        elif sub == "sessions":
            code = parts[1] if len(parts) > 1 else ""
            if not code:
                notifier.error("Usage: craft sessions <code>")
                return
            data = _craft.craft_sessions(code)
            rows = data.get("sessions") or []
            if not rows:
                notifier.info("No sessions captured for this code yet.")
                return
            console.print("\n  [bold cyan]► Captured sessions[/]")
            for s in rows:
                console.print(f"  [bold]{s.get('username') or '(no user)'}[/] "
                              f"[dim]{s.get('ip')} {s.get('time')}[/]")
                console.print(f"    cookies: {s.get('cookies')}")
        elif sub == "hits":
            code = parts[1] if len(parts) > 1 else ""
            if not code:
                notifier.error("Usage: craft hits <code>")
                return
            data = _craft.craft_hits(code)
            self._print_hits(data)
        elif sub == "wait":
            code = parts[1] if len(parts) > 1 else ""
            if not code:
                notifier.error("Usage: craft wait <code> [seconds]")
                return
            timeout = float(parts[2]) if len(parts) > 2 else 300.0
            _craft.craft_wait(code, timeout=timeout)
        else:
            console.print(self.do_craft.__doc__)

    def _print_lure(self, out: dict, what: str):
        console.print(f"\n  [bold cyan]► {what}[/]")
        console.print(f"  [bold]READY TO PASTE:[/] {out.get('url', '')}")
        m = out.get("masked") or {}
        if m:
            # the SAME lure with the visible text swapped for a plausible
            # platform share URL — the destination stays the tracker
            console.print("  [bold]MASKED (link shows a reel URL, goes to the tracker):[/]")
            console.print(f"    telegram/html : {m.get('telegram_html', '')}")
            console.print(f"    discord       : {m.get('discord_markdown', '')}")
            console.print(f"    email anchor  : {m.get('email_anchor', '')}")
            console.print(f"    [dim]{m.get('note', '')}[/]")
        console.print(f"  [dim]code: {out.get('code', '')} | tracker: {out.get('base', '')}[/]")
        console.print("  [dim]watch it with: craft wait <code> | craft hits <code>[/]")

    def _print_hits(self, data: dict):
        hits = data.get("hits") or []
        opens = data.get("opens") or []
        creds = data.get("creds") or []
        sessions = data.get("sessions") or []
        if not (hits or opens or creds or sessions):
            notifier.info("No hits yet — the lure is live and waiting.")
            return
        for h in hits:
            fp = "/".join(x for x in (h.get("os"), h.get("device"),
                                        h.get("browser")) if x) or "device?"
            loc = f"  [{h.get('geo')}]" if h.get("geo") else ""
            console.print(f"  [red]⚡ HIT[/] {h['ip']}  {fp}{loc}  {h['ua'][:30]}")
        for o in opens:
            console.print(f"  [yellow]◉ OPEN[/] {o['ip']}  {o['ua'][:40]}")
        for c in creds:
            console.print(f"  [magenta]◈ CREDS[/] {c['ip']}  "
                          f"{c['username']}:{c['password']}")
        for s in sessions:
            # an AiTM session outlives the credentials: the cookies ARE the
            # logged-in browser, MFA already satisfied
            console.print(f"  [bright_magenta]⛨ SESSION[/] {s['ip']}  "
                          f"{s.get('username') or '(no user)'}")
        notifier.success(
            f"{len(hits)} hit(s) · {len(opens)} open(s) · "
            f"{len(creds)} cred(s) · {len(sessions)} session(s)")

    def do_map(self, arg: str):
        """map [cidr] — discover live hosts on the local network (or the
        given CIDR), feed the network map + WorldModel, then rank every
        device by reachable attack surface and suggest where to start."""
        from phantom.core.netmap import (
            discover_network, seed_worldmodel, recommend_starting_target,
            check_hosts_alive)
        target = arg.strip() or None
        notifier.status("Mapping the network... (arp-scan → nmap -sn → ping)")
        res = discover_network(target=target)
        hosts = res.get("hosts") or []
        # live/dead status: the discovery only answers for hosts that are
        # up NOW, so every freshly found device is alive — the liveness
        # pass matters for hosts kept from earlier scans/ARP cache
        check_hosts_alive(hosts, force=True)
        seed_worldmodel(hosts)
        if not hosts:
            notifier.warn(f"No live hosts found ({res.get('method')}).")
            return
        topo = res.get("topology") or {}
        if topo.get("kind"):
            console.print(f"[bold magenta]Topology: {str(topo.get('kind')).upper()}[/] "
                          f"[dim](gateway {topo.get('gateway') or '?'} · "
                          f"{int(100 * (topo.get('confidence') or 0))}% confidence) "
                          f"— {topo.get('note', '')}[/]")
        console.print(f"[bold cyan]Devices on the network ({res.get('method')}, "
                      f"{res.get('elapsed')}s):[/]")
        console.print(f"  {'':1}{'IP':<16}{'HOSTNAME':<24}{'OS GUESS':<17}SERVICES / PORTS")
        for h in hosts:
            os_g = h.get("os_guess", "") or "—"
            svc = h.get("services") or ("-" if not h.get("ports") else "closed")
            name = (h.get("hostname") or "-")[:23]
            live = h.get("alive", True)
            mark = "[green]●[/]" if live else "[dim]○[/]"
            suffix = "" if live else " [dim](offline)[/]"
            console.print(f"  {mark} {h.get('ip', ''):<15}{name:<24}{os_g:<17}{svc}{suffix}")
        # exposure ranking: quick TCP probe of common ports on every device
        notifier.status("Ranking devices by attack surface (TCP probe, "
                        "bounded)...")
        verdict = recommend_starting_target(hosts)
        ranked = verdict.get("ranked") or []
        if ranked:
            console.print()
            console.print("[bold yellow]── Most exposed devices (live only) ──[/]")
            console.print(f"  {'IP':<18}{'RISK':<9}{'SCORE':<7}OPEN PORTS")
            for r in ranked[:8]:
                ports = ", ".join(f"{p['port']}/{p['service']}"
                                   for p in r["open_ports"][:6])
                console.print(
                    f"  {r.get('ip', ''):<18}{r.get('risk', ''):<9}"
                    f"{r.get('score', 0):<7}{ports}")
            rec = verdict.get("recommended")
            if rec:
                console.print()
                console.print(f"[bold green]▶ Suggested starting target: "
                              f"{rec.get('ip')}[/] "
                              f"[dim]({verdict.get('reason', '')})[/]")
                console.print("  [dim]→ set target and start: "
                              f"set target {rec.get('ip')} → use scan → run[/]")
        else:
            console.print(f"[dim]  {verdict.get('reason', 'No exposed services.')}[/]")
        dead = sum(1 for h in hosts if not h.get("alive", True))
        note = f"{len(hosts)} device(s) found"
        if dead:
            note += f" ({dead} offline, shown faded — powered-off devices are never ranked as targets)"
        notifier.success(note + " — see them on the network map (Electron) "
                         "or in the WorldModel.")

    def do_install(self, arg: str):
        """install <tool> — install a missing tool in the current backend
        environment (apt / brew / choco / pip, auto-selected; WSL on
        Windows). Shows the live output."""
        tool = arg.strip().lower()
        if not tool:
            notifier.error("Usage: install <tool>  (e.g. install hydra)")
            return
        from phantom.core.executor import install_tool
        notifier.status(f"Installing {tool}... (this can take a while)")
        res = install_tool(tool)
        out = (res.get("output") or "").strip()
        if res.get("ok"):
            notifier.success(f"Installed: {tool}")
        else:
            notifier.error(f"Install failed: {tool}")
        if out:
            console.print(out[-1500:])
        else:
            notifier.info(f"Command used: {res.get('command', '')}")

    @staticmethod
    def _required_fact(module_name: str) -> str:
        """The WorldModel fact a module consumes before it can produce
        anything. Empty when the module is a producer (scan/osint)."""
        consumers = {"exploit": "service", "web": "service",
                     "brute": "service", "pivot": "creds",
                     "payload": "service"}
        fact = consumers.get(module_name, "")
        if not fact:
            return ""
        try:
            from phantom.core.knowledge import session_wm
            if session_wm().has_any(fact):
                return ""
        except Exception:
            return ""
        return fact

    def do_auto(self, arg: str):
        """auto | auto <target[,target...|CIDR]> [flags] - Autonomous kill chain.

        `auto` with NO arguments enters the dedicated AUTO-MODE shell
        (multi-target management, flags, plan/launch/resume, .pm export/
        import — mirrors the Electron Auto-Mode panel, like `c2` for the
        C2). With arguments it runs the chain directly.

        Classifies each target (ip/domain/url/email/username/phone) and
        drives the full chain to beacon injection + persistence, then hands
        the beacon to the operator in the C2 terminal. Identity targets
        converge through OSINT -> breach -> persona -> phish -> victim_ip.

        Flags:
          --stealth     paranoid OPSEC: slower, minimal footprint, skips
                        loud tools (mutually exclusive with --aggressive)
          --aggressive  noisy + fast: online brute force, loud tools, broad
                        enumeration (mutually exclusive with --stealth)
          --speed       opportunistic: exploit the first viable opening
                        without raising detection (combines with either)
          --plan        dry-run: print the planned chain, execute nothing
          --verbose     stream the live reasoning trace while running:
                        inferences, hypotheses formed, confirmations and
                        refutations as facts arrive
          -a | -aN      sub-agents: -a = auto-decide, -a2 = 2 agents,
                        --agents N = explicit (multi-target fan-out or
                        same-target phase workers)
          --llm         optional local-LLM advisor: proposes extra
                        hypotheses only (never executes); requires
                        PHANTOM_LLM_MODEL=<path-to-gguf> — try a Qwen2.5
                        Instruct GGUF, swap the file to scale reasoning
          --resume <cp> resume an interrupted run from its auto-mode
                        checkpoint (extract from a .pm with import-session)

        Every run writes a checkpoint each wave under data/sessions/auto_*/
        and can be shared as a single .pm with export-session.

        Examples:
          auto 192.168.1.1
          auto 10.0.0.0/24
          auto bob@corp.com --stealth
          auto +391234567890 --speed
          auto host1,host2 -a3
          auto 192.168.1.1 --verbose
          auto bob@corp.com --resume data/sessions/auto_1700000000/checkpoint.json
        """
        if not arg.strip():
            # `auto` with no arguments: dedicated AUTO-MODE shell (like `c2`)
            notifier.status("Entering AUTO-MODE interface...")
            from phantom.core.auto_shell import run_auto_shell
            run_auto_shell()
            return

        from phantom.core.automode import run_auto_mode

        parser = argparse.ArgumentParser(prog="auto", add_help=False)
        parser.add_argument("targets", nargs="*", default=[],
                            help="Target(s) or CIDR range")
        parser.add_argument("--stealth", action="store_true", default=False,
                            help="paranoid OPSEC (mutually exclusive with --aggressive)")
        parser.add_argument("--aggressive", action="store_true", default=False)
        parser.add_argument("--speed", action="store_true", default=False)
        parser.add_argument("--plan", action="store_true", default=False,
                            help="dry-run: show the planned chain, execute nothing")
        parser.add_argument("--verbose", action="store_true", default=False,
                            help="stream the live reasoning trace (inferences, "
                                 "hypotheses, confirmations/refutations)")
        parser.add_argument("-a", "--agents", nargs="?", const=0, type=int,
                            default=0, metavar="N",
                            help="sub-agent count: -a (auto) or -a2 / --agents 2")
        parser.add_argument("--goal", default="deliver",
                            choices=["deep", "deliver", "complete_kill_chain",
                                     "footprint", "beacon", "creds",
                                     "identity", "post_exploit", "ad",
                                     "crack", "lateral", "cleanup"],
                            help="override the terminal goal "
                                 "(deep = deliver + post_exploit + ad + "
                                 "crack + lateral in one run; default: deliver)")
        parser.add_argument("--profile", default="enterprise",
                            choices=["smb", "enterprise", "cloud", "financial",
                                     "government", "mobile"])
        parser.add_argument("--resume", default="", metavar="CHECKPOINT",
                            help="resume a run from an auto-mode checkpoint "
                                 "(extract it from a .pm with import-session)")
        parser.add_argument("--llm", action="store_true", default=False,
                            help="optional local-LLM advisor (requires "
                                 "PHANTOM_LLM_MODEL=<path-to-gguf>): non-gating "
                                 "hypothesis suggestions, never executes anything")

        try:
            args = parser.parse_args(arg.split())
        except SystemExit:
            return

        if args.stealth and args.aggressive:
            notifier.error("--stealth and --aggressive are mutually exclusive.")
            return
        if args.agents is not None and args.agents < 0:
            notifier.error("Agent count must be >= 1 (use -a for auto).")
            return

        targets = [t.strip() for t in args.targets if t.strip()]

        # Confirm in interactive mode
        if not self.auto_run and sys.stdin.isatty() and targets and not args.plan:
            mode = ("paranoid" if args.stealth else
                    "aggressive" if args.aggressive else "default")
            console.print(f"\n[bold cyan]Auto-Mode Configuration:[/]")
            console.print(f"  Target(s):  [white]{', '.join(targets)}[/]")
            console.print(f"  Mode:       [white]{mode}[/]"
                          f"{' + speed' if args.speed else ''}")
            console.print(f"  Agents:     [white]{args.agents or 'auto'}[/]")
            confirm = input("\nLaunch autonomous kill chain? [Y/n]: ").strip().lower()
            if confirm == "n":
                notifier.warn("Auto-mode cancelled.")
                return

        if targets:
            session.target = targets[0]

        run_auto_mode(
            targets=targets,
            aggressive=args.aggressive,
            stealth=args.stealth,
            speed=args.speed,
            plan=args.plan,
            verbose=args.verbose,
            agents=args.agents or 0,
            goal=args.goal,
            profile=args.profile,
            llm=args.llm,
            resume=args.resume,
        )

    def do_agent(self, arg: str):
        """agent <target[,target...]> [--aggressive] [--goal <goal>] [--max-agents N]
        Autonomous agent campaign (one sub-agent per target).

        The AI-free planner completes the kill chain (scan -> creds -> beacon)
        and, with goal post_exploit, continues through the beacon channel:
        persistence + SYSTEM/root escalation + process injection.
        Targets are auto-classified: ip/domain/url/email/username/phone.
        For identity targets (email/username/phone) the chain runs OSINT ->
        breach lookup -> persona -> phish (email/sms with IP-grabber) ->
        victim_ip -> network chain -> beacon injection + persistence.
        With --deliver the chain stops right after beacon + persistence.
        OPSEC prioritization, sandbox pre-flight, scope enforcement and dual
        reporting (raw audit + sanitized client report). Multi-target targets
        fan out immediately into pooled sub-agents.

        Examples:
          agent 192.168.1.1
          agent 192.168.1.5,192.168.1.6,192.168.1.7
          agent bob@corp.com --aggressive --goal post_exploit
          agent +391234567890 --deliver
        """
        from phantom.automation.agent import run_autonomous, run_campaign
        from phantom.automation.reporting import (
            RawReport, ClientReport, CampaignReport, ReportWriter)
        from phantom.utils.paths import sessions_dir

        parser = argparse.ArgumentParser(prog="agent", add_help=False)
        parser.add_argument("target", nargs="?", default="", help="Target(s), comma-separated")
        parser.add_argument("--aggressive", action="store_true", default=False)
        parser.add_argument("--profile", default="enterprise",
                            choices=["smb", "enterprise", "cloud", "financial",
                                     "government", "mobile"])
        parser.add_argument("--goal", default="complete_kill_chain",
                            choices=["deep", "footprint", "beacon", "creds",
                                     "identity", "complete_kill_chain", "deliver",
                                     "post_exploit",
                                     "ad", "crack", "lateral", "cleanup"])
        parser.add_argument("--deliver", action="store_true", default=False,
                            help="deliver mode: reach beacon injection + "
                                 "persistence, then stop (goal=deliver)")
        parser.add_argument("--cleanup", action="store_true", default=False,
                            help="end the engagement: remove persistence and "
                                 "kill the beacons on every target (goal=cleanup)")
        parser.add_argument("--max-agents", type=int, default=3,
                            help="concurrent sub-agents for multi-target campaigns")
        parser.add_argument("--state", default=None,
                            help="checkpoint file: resumes an interrupted "
                                 "agent run, or writes checkpoints there")
        parser.add_argument("--state-dir", default=None,
                            help="directory for per-target campaign checkpoints "
                                 "(resumes sub-agents that were interrupted)")
        try:
            args = parser.parse_args(arg.split())
        except SystemExit:
            return

        targets = [t.strip() for t in (args.target or "").split(",") if t.strip()]
        if not targets and session.target:
            targets = [session.target]
        if not targets:
            notifier.error("No target set. Provide a target or use 'set target' first.")
            return
        if any(not t for t in targets):
            notifier.error("Empty target in list.")
            return

        # scope enforcement: the session scope is mandatory for the agent
        scope_list = list(session.scope) if session.scope else []
        if not scope_list:
            notifier.warn("No scope defined: the agent will refuse nothing. "
                          "Set scope with 'set scope <cidr,...>' for real engagements.")

        def _stream(kind: str, data: dict) -> None:
            tgt = data.get("target")
            tag = f"[bold blue]{tgt}[/] " if tgt else ""
            if kind == "run":
                console.print(f"{tag} [cyan]>[/] {data.get('banner', data.get('capability'))} "
                              f"(cost {data.get('cost', '?')})")
            elif kind == "found":
                console.print(f"{tag} [green]✓[/] {data.get('capability')}: "
                              f"{', '.join(data.get('findings', []))}")
            elif kind == "tool_missing":
                console.print(f"{tag} [red]⛏[/] {data.get('capability')}: missing tool "
                              f"{', '.join(data.get('tools', []))}")
            elif kind == "failed":
                console.print(f"{tag} [red]✗[/] {data.get('capability')}: {data.get('output', '')[:120]}")
            elif kind == "blocked":
                console.print(f"{tag} [yellow]⛔[/] {data.get('capability')} blocked: "
                              f"{data.get('reason', '')[:120]}")
            elif kind == "beacon_up":
                console.print(f"{tag} [bold magenta]★[/] BEACON UP in C2 "
                              f"({data.get('beacon_id', '')})")
            elif kind == "halt":
                console.print(f"{tag} [yellow]■[/] halt: {data.get('reason', '')}")

        out_root = os.path.join(sessions_dir(), f"agent_{int(time.time())}")
        writer = ReportWriter(out_root)

        goal = "cleanup" if args.cleanup else args.goal
        if args.deliver:
            goal = "deliver"
            notifier.info("Deliver mode: stop after beacon injection + persistence.")
        if args.cleanup:
            notifier.info("Cleanup mode: persistence removal + beacon exit "
                          "on every target.")

        if len(targets) == 1:
            if args.state and os.path.exists(args.state):
                notifier.info(f"Resuming agent run from checkpoint "
                              f"{args.state}...")
            elif args.state:
                notifier.info(f"Checkpoint target: {args.state}")
            result, agent = run_autonomous(
                target=targets[0], profile=args.profile,
                aggressive=args.aggressive, goal=goal,
                scope_list=scope_list,
                on_event=_stream, return_agent=True,
                state_path=args.state)
            paths = writer.write(
                RawReport.from_agent(agent), ClientReport.from_agent(agent, args.profile))
            notifier.success("Agent run finished. Reports:")
            for k, p in paths.items():
                console.print(f"  [cyan]{k}[/]: {p}")
            return

        notifier.info(f"Campaign over {len(targets)} targets "
                      f"(pool: {args.max_agents} sub-agents)...")
        campaign = run_campaign(
            targets=targets, profile=args.profile, aggressive=args.aggressive,
            goal=goal, scope_list=scope_list, max_agents=args.max_agents,
            on_event=_stream, state_dir=args.state_dir)
        per_target = {}
        for t in targets:
            r = campaign["results"].get(t, {})
            a = campaign.get("_agents", {}).get(t)
            if a is not None:
                tdir = os.path.join(out_root, t.replace("/", "_"))
                paths = ReportWriter(tdir).write(
                    RawReport.from_agent(a), ClientReport.from_agent(a, args.profile))
                per_target[t] = {"dir": tdir, **paths}
        cpaths = writer.write_campaign(
            CampaignReport(campaign, args.profile, per_target))
        notifier.success(
            f"Campaign finished: {campaign['beacons']} beacons, "
            f"{campaign['persistent']} persistent, "
            f"{campaign['pivots']} lateral moves, "
            f"{campaign['ad_domains']} AD domains, "
            f"{campaign['compromised_creds']} creds.")
        for k, p in {**per_target, **cpaths}.items():
            console.print(f"  [cyan]{k}[/]: {p}")

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
            table.add_row("Scope", ", ".join(session.scope) if session.scope else "—")
            table.add_row("Timeout", f"{executor.TIMEOUT_SECONDS}s")
            table.add_row("Active wordlist", session.active_wordlist or "—")
            table.add_row("LHOST (Manual)", session.lhost or "Auto-detect")
            table.add_row("LPORT (Manual)", str(session.lport) if session.lport else "Auto-detect")
            table.add_row("Completed modules", ", ".join(session.results.keys()) or "—")
            table.add_row("Notes", str(len(session.notes)))
            console.print(table)
        elif arg == "scope":
            if session.scope:
                console.print(f"[cyan]Scope: {', '.join(session.scope)}[/]")
            else:
                notifier.warn("No scope defined.")
        elif arg == "knowledge":
            from phantom.core.knowledge import knowledge_summary, session_wm
            from rich.table import Table
            counts = knowledge_summary()
            wm = session_wm()
            table = Table(title="Shared knowledge (WorldModel)")
            table.add_column("Kind", style="cyan")
            table.add_column("Count", justify="right")
            if counts:
                for kind in sorted(counts):
                    table.add_row(kind, str(counts[kind]))
            else:
                table.add_row("(empty)", "0")
            console.print(table)
            pending = wm.pending_hypotheses()
            if pending:
                console.print(f"[bold green]▶ {len(pending)} live hypothesis(es) "
                              "— type 'suggest' inside any module to see them.[/]")
            notifier.info("Findings here feed every module's suggestions and the report.")
        else:
            notifier.error("Usage: show session | show scope | show mode | show knowledge")

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
        """List all saved sessions (manual .json + auto .pm bundles)"""
        saved = session.list_saved()
        if saved:
            console.print("[bold]Manual sessions:[/]")
            for s in saved:
                console.print(f"  [cyan]{s}[/]")
        try:
            from phantom.utils.auto_session import list_auto
            auto = list_auto()
        except Exception:
            auto = []
        if auto:
            console.print("[bold]Auto-session bundles (.pm, encrypted):[/]")
            for a in auto:
                console.print(f"  [cyan]{a['name']}[/]  [dim]target {a['target']} · "
                              f"{a['findings']} findings · {a['mtime']} · "
                              f"{a['size']} B[/]")
        if not saved and not auto:
            notifier.warn("No saved sessions.")

    def do_export_session(self, arg: str):
        """export-session [<file.pm>] — bundle this engagement into ONE
        portable .pm file (session + auto-mode checkpoint + report index)
        that another operator can open with import-session, or that resumes
        with `auto <target> --resume <checkpoint>`."""
        from phantom.utils.session_bundle import export_session, summarize
        try:
            path = export_session(out_path=arg.strip() or None)
            notifier.success(f"Session exported: {path}")
            notifier.info("Contiene: stato sessione + checkpoint auto-mode "
                          "+ indice report. Condividi il file .pm con "
                          "l'altro operatore.")
        except Exception as e:
            notifier.error(f"export failed: {e}")

    def do_import_session(self, arg: str):
        """import-session <file.pm> — open a .pm bundle exported by another
        operator (or another machine): restores target/scope/notes/knowledge
        and stages the checkpoint for `auto <target> --resume <file>`."""
        from phantom.utils.session_bundle import import_session, summarize
        path = arg.strip()
        if not path:
            notifier.error("Usage: import-session <file.pm>")
            return
        try:
            data = import_session(path)
            notifier.success(f"Session imported: {path}")
            console.print(f"  [cyan]{summarize(data)}[/]")
            if data.get("resume_path"):
                notifier.info(
                    f"Checkpoint pronto: riprendi con "
                    f"`auto {data.get('target') or '<target>'} "
                    f"--resume {data['resume_path']}`")
        except FileNotFoundError:
            notifier.error(f"File not found: {path}")
        except ValueError as e:
            notifier.error(str(e))
        except Exception as e:
            notifier.error(f"import failed: {e}")

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

    def do_plugins(self, _):
        """plugins — list all loaded plugins."""
        plugin_modules = getattr(self, "_plugin_modules", {})
        if not plugin_modules:
            notifier.warn("No plugins loaded.")
            return

        from rich.table import Table
        table = Table(title="Loaded Plugins", border_style="cyan")
        table.add_column("Plugin Name", style="bold green")
        table.add_column("Source", style="dim")

        for name, cls in plugin_modules.items():
            source = cls.__module__
            table.add_row(name, source)

        console.print(table)
        console.print(f"\n[dim]Use 'use <name>' to enter a plugin module.[/]")

    def complete_use(self, text: str, line: str, begidx: int, endidx: int) -> list:
        """Tab-completion for `use` (modules + aliases)."""
        builtin = ["scan", "osint", "wifi", "web", "brute", "exploit",
                   "payload", "handler", "pivot", "analyzer", "report",
                   "wordlist"]
        plugin_names = list(getattr(self, "_plugin_modules", {}).keys())
        names = builtin + plugin_names + list(self.MODULE_ALIASES.keys())
        return [n for n in names if n.startswith(text)]

    def do_use(self, arg: str):
        """use <module> — enter a module (built-in or plugin; aliases: s, o, w, e, b, p, h, v, a, r, wl)"""
        module_name = arg.strip().lower()
        if not module_name:
            notifier.error("Usage: use <module_name>")
            return

        # short aliases (with collision-safe mapping: sc/ex/pay/ha/pi/an/re)
        aliases = getattr(self, "MODULE_ALIASES", {})
        module_name = aliases.get(module_name, module_name)

        modules = {
            "scan", "osint", "wifi", "web", "brute", "exploit",
            "payload", "handler", "pivot", "analyzer", "report",
            "wordlist", "c2",
        }

        # C2 is an operations center, not a BaseModule — route to do_c2
        if module_name == "c2":
            self.do_c2("")
            return

        if module_name in modules:
            if self._warn_identity_target(module_name):
                # identity target + network module: warn but still enter
                pass
            try:
                instance = self._instantiate_module(module_name)
                if instance:
                    hint = getattr(instance, "show_enter_hint", None)
                    if callable(hint):
                        hint()
                    instance.cmdloop()
            except Exception as e:
                notifier.error(f"Failed to enter module {module_name}: {e}")
            return

        # Plugin modules
        plugin_modules = getattr(self, "_plugin_modules", {})
        if module_name in plugin_modules:
            try:
                cls = plugin_modules[module_name]
                instance = cls()
                instance.cmdloop()
            except Exception as e:
                notifier.error(f"Plugin {module_name} crashed: {e}")
            return

        notifier.error(f"Unknown module: {module_name}")
        notifier.info(f"Available: {', '.join(sorted(modules) + sorted(plugin_modules.keys()))}")

    def do_help(self, arg: str):
        """help [command] — Show the help panel or details about a specific command."""
        from rich.table import Table
        from rich.panel import Panel
        from rich.columns import Columns

        if arg.strip():
            # Show help for a specific command
            func = getattr(self, f"do_{arg.strip().replace('-', '_')}", None)
            if func and func.__doc__:
                from rich.markup import escape
                console.print(Panel(escape(func.__doc__.strip()), title=f"[bold cyan]Help: {arg}[/]", border_style="cyan"))
            else:
                notifier.error(f"No help available for '{arg}'.")
            return

        # ── Session & Config ────────────────────────────────────────────
        t1 = Table(title="[bold white]Session & Config[/]", border_style="blue", show_lines=False)
        t1.add_column("Command", style="cyan", no_wrap=True)
        t1.add_column("Description", style="white")
        t1.add_row("set target <ip>", "Define the testing target")
        t1.add_row("set mode <mode>", "Select workflow: recon, osint, web, exploit, full, deliver")
        t1.add_row("set scope <cidr,...>", "Define authorized testing boundaries")
        t1.add_row("set lhost <ip>", "Set local host IP for callbacks")
        t1.add_row("set lport <port>", "Set local port for callbacks")
        t1.add_row("show session", "Display current session info")
        t1.add_row("config [status|rotate-api-token]", "Auto-generated C2 secrets & mTLS status")
        t1.add_row("setup [status|auto]", "Zero-config wizard: detect transports, write data/config.json")
        t1.add_row("note \"text\"", "Add a timestamped note")
        t1.add_row("notes", "Display all session notes")
        t1.add_row("history", "Show command history")

        # ── Execution ───────────────────────────────────────────────────
        t2 = Table(title="[bold white]Execution[/]", border_style="green", show_lines=False)
        t2.add_column("Command", style="cyan", no_wrap=True)
        t2.add_column("Description", style="white")
        t2.add_row("run", "Adaptive next step (reads target type + findings + reasoning)")
        t2.add_row("run <module>", "Run a specific module directly (e.g. run scan)")
        t2.add_row("suggest", "Evidence-tagged next steps (why + trust + preflight)")
        t2.add_row("plan <goal>", "Lay out the reasoning chain to a goal (beacon/creds/ad/...)")
        t2.add_row("preflight [module]", "Check required tools + install hints")
        t2.add_row("auto <target...>", "Full autonomous kill chain (enumeration -> exploit -> beacon -> persistence)")
        t2.add_row("agent", "Dedicated AUTO-MODE shell (multi-target, flags, plan/resume, .pm)")
        t2.add_row("use <module>", "Enter a module — aliases: s o w e b p h v a r wl (tab-complete)")
        t2.add_row("plugins", "List all loaded external plugins")
        t2.add_row("c2", "Enter the C2 Operations Center")

        # ── Tooling ─────────────────────────────────────────────────
        t2b = Table(title="[bold white]Tooling & Craft[/]", border_style="cyan", show_lines=False)
        t2b.add_column("Command", style="cyan", no_wrap=True)
        t2b.add_column("Description", style="white")
        t2b.add_row("craft ipgrab|reel|image|pixel|beacon|hits|wait", "Build social-engineering lures (IP grabber, zero-click pixel, disguised beacon link)")
        t2b.add_row("map [cidr]", "Discover live hosts on the network and feed the WorldModel")
        t2b.add_row("install <tool>", "Install a missing tool (apt/brew/choco/pip, auto-selected)")
        t2b.add_row("wordlists list|use|search|info", "Manage attack dictionaries (rockyou, seclists, custom)")
        t2b.add_row("ad tree|paths|add-user|add-dc|add-edge|reset", "BloodHound-style AD graph: ingest auto-mode data + manual nodes, shortest paths to Domain Admin")

        # ── Persistence ─────────────────────────────────────────────────
        t3 = Table(title="[bold white]Persistence & Reporting[/]", border_style="yellow", show_lines=False)
        t3.add_column("Command", style="cyan", no_wrap=True)
        t3.add_column("Description", style="white")
        t3.add_row("save-session <name>", "Save current session to disk")
        t3.add_row("load-session <name>", "Load a previously saved session")
        t3.add_row("list-sessions", "List all saved sessions")
        t3.add_row("export-session [<file.pm>]", "Bundle the engagement into one portable .pm file")
        t3.add_row("import-session <file.pm>", "Open a .pm bundle from another operator/machine")
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
        t4.add_row("craft", "Social-Engineering Lures (IP grabber, pixel, disguised links)")
        t4.add_row("handler", "Multi/Handler Bridge (Metasploit payload sessions)")
        t4.add_row("telegram", "Telegram C2 channel (bot control plane)")
        t4.add_row("wordlist", "Wordlist Generator & Manager (see: wordlists list)")
        t4.add_row("report", "Report Generation (JSON, PDF, HTML)")
        t4.add_row("c2", "Command & Control Operations Center")
        console.print()
        console.print(t1)
        console.print()
        console.print(t2)
        console.print()
        console.print(t2b)
        console.print()
        console.print(t3)
        console.print()
        console.print(t4)
        console.print()
        console.print("[dim]  Type 'help <command>' for details on a specific command.[/]")
        console.print("[dim]  Type 'ad paths' for Domain Admin attack paths — 'help ad' for the full AD syntax.[/]")
        console.print("[dim]  Type 'wordlists list' to manage attack dictionaries.[/]")
        console.print()
        try:
            from phantom.core.c2_server import c2_state
            n_beacons = len(c2_state.get_beacons())
            console.print(f"[dim]Phantom v3.0.0 — beacons: {n_beacons} — "
                          f"{_engagement_elapsed()} since session start[/]")
        except Exception:
            console.print("[dim]Phantom v3.0.0[/]")
        console.print()

    def do_config(self, arg: str):
        """config (status|regenerate-api-token) - Show auto-generated secrets status."""
        from rich.table import Table
        from phantom.utils.state import status as state_status, regenerate_secret
        action = arg.strip().lower()
        if action in ("regenerate", "rotate", "rotate-api-token", "regenerate-api-token"):
            try:
                import secrets as _secrets
                from phantom.utils.c2_crypto import regenerate_api_token
                token = regenerate_api_token()
                notifier.success(f"API token rotated. New value: {token}")
                notifier.warn("Update any external client (Telegram bot, scripts) that holds the old token.")
            except Exception as e:
                notifier.error(f"Rotation failed: {e}")
            return
        if action in ("mtls-on", "mtls off", "mtls-on=true"):
            from phantom.utils.state import set_flag
            set_flag("PHANTOM_MTLS_REQUIRED", True)
            notifier.success("mTLS enabled (secure default). Listener will require HTTPS + client certs.")
            return
        if action in ("mtls-off", "mtls off", "mtls-off=true"):
            from phantom.utils.state import set_flag
            set_flag("PHANTOM_MTLS_REQUIRED", False)
            notifier.warn("mTLS disabled — beacon channel no longer requires client certificates.")
            return
        # default: status
        info = state_status()
        table = Table(title="[bold]Phantom Operator State[/]", border_style="magenta")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="white")
        for key, value in info.items():
            table.add_row(str(key), str(value))
        console.print(table)
        notifier.info("Secrets live in data/phantom_state.json (gitignored). "
                      "Env vars override persisted values.")

    def do_setup(self, arg: str):
        """setup [status|auto] - Detect transports, configure optional channels
        interactively and write data/config.json (no .env editing needed).

        'status'  -> just print which channels are usable right now
        'auto'    -> create data/config.json with defaults, no prompts
        (no arg)  -> interactive wizard for the channels that are missing
        """
        from rich.table import Table
        from phantom.automation.social.transports import transport_status
        from phantom.utils import config as cfg

        action = arg.strip().lower()
        if action == "auto":
            cfg.save_config({})
            notifier.success(f"Config defaults written to {cfg.config_path()} "
                             "— zero-config mode ready (local lab + C2).")
            self._print_transport_status(transport_status())
            return
        if action == "status":
            self._print_transport_status(transport_status())
            console.print()
            self._print_sandbox_status()
            console.print()
            self._print_toolbelt_status()
            notifier.info("Run 'setup' to configure the missing channels, "
                          "or 'setup auto' for defaults only.")
            return

        status = transport_status()
        self._print_transport_status(status)
        console.print()
        notifier.info("Configure the optional external channels "
                      "(leave blank to keep current / skip).")

        def _ask(key: str, label: str, env: str, default: str = "") -> str:
            cur = str(cfg.get(key, "", env=env) or "")
            shown = cur or default          # detected suggestion, editable
            try:
                v = input(f"  {label} [{shown}]: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return cur
            if not v:
                if not cur and default:
                    cfg.set(key, default)   # accept the detected value
                    return default
                return cur
            cfg.set(key, v)
            return v

        def _yn(prompt: str) -> bool:
            try:
                v = input(f"  {prompt} [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return False
            return v in ("y", "yes")

        console.print("[bold cyan]-- Email (phishing / email-to-SMS) --[/]")
        _ask("transports.smtp.host", "SMTP host", "PHANTOM_SMTP_HOST")
        _ask("transports.smtp.port", "SMTP port", "PHANTOM_SMTP_PORT")
        _ask("transports.smtp.username", "SMTP username", "PHANTOM_SMTP_USER")
        _ask("transports.smtp.password", "SMTP password", "PHANTOM_SMTP_PASSWORD")
        console.print("[bold cyan]-- SMS (email-to-SMS carrier) --[/]")
        _ask("transports.sms_carrier", "Carrier (verizon|att|tmobile|...)",
             "PHANTOM_SMS_CARRIER")
        console.print("[bold cyan]-- DM (Telegram / Discord / custom) --[/]")
        _ask("transports.telegram_bot_token", "Telegram bot token",
             "PHANTOM_TELEGRAM_BOT_TOKEN")
        _ask("transports.discord_webhook", "Discord webhook URL",
             "PHANTOM_DISCORD_WEBHOOK")
        console.print("[bold cyan]-- C2 callback address --[/]")
        # This is the address embedded in the BEACON and in the dropper's
        # payload URL: it must be reachable BY THE TARGET, never loopback.
        notifier.info("Address the beacon calls back to (public IP or your "
                      "domain). Leave blank to auto-detect; set it whenever "
                      "the target is not on your LAN — with 127.0.0.1 the "
                      "beacon dials itself and the dropper link is dead.")
        _ask("c2.host", "C2 host for the beacon (public IP or domain)",
             "PHANTOM_C2_HOST")
        console.print("[bold cyan]-- Tracker / lure delivery --[/]")
        # OPSEC: this is the URL a VICTIM and any SOC analyst will read in
        # the lure. A raw IP (LAN or public) exposes the operator's box and
        # screams "attack" — a DOMAIN with TLS is the only real answer.
        notifier.info("This URL ends up in the victim's mail headers. Prefer "
                      "a lookalike DOMAIN with TLS (the domain IS the "
                      "camouflage for a reel/short link); a bare IP is "
                      "readable and looks like an attack. Leave blank for "
                      "lab-only (real lure delivery stays blocked).")
        _ask("tracker.public_url",
             "Public tracker URL (e.g. https://ig-video-cdn.net)",
             "PHANTOM_TRACK_URL")
        try:
            from phantom.automation.social.tracker import (
                tracker_opsec_warnings,
            )
            for _w in tracker_opsec_warnings():
                notifier.warn(_w)
        except Exception:
            pass
        console.print("[bold cyan]-- Breach lookup --[/]")
        _ask("breach.hibp_api_key", "HIBP API key (optional)",
             "PHANTOM_HIBP_API_KEY")
        _ask("breach.custom_api", "Custom breach API base URL (optional)",
             "PHANTOM_BREACH_API")
        console.print("[bold cyan]-- Payload sandbox / AV validation --[/]")
        notifier.info("Optional: multi-engine + VM detonation makes the payload "
                      "gate stronger (ClamAV/YARA run when installed).")
        _ask("sandbox.yara_rules", "YARA rules file or directory",
             "PHANTOM_YARA_RULES")
        _ask("sandbox.vm_exec", "VM exec wrapper (e.g. ssh user@vm)",
             "PHANTOM_SANDBOX_VM_EXEC")
        _ask("sandbox.vm_copy", "VM copy command (e.g. scp -i key {local} {remote})",
             "PHANTOM_SANDBOX_VM_COPY")
        _ask("sandbox.vm_edr", "EDR/AV running in the VM (label, e.g. CrowdStrike)",
             "PHANTOM_SANDBOX_VM_EDR")
        console.print("[bold cyan]-- Engagement gates --[/]")
        if _yn("Allow unscoped commands (lab/CTF only)"):
            cfg.set("engagement.allow_unscoped", True)
        if _yn("Allow ransomware simulation (scratch dirs only)"):
            cfg.set("engagement.ransom_sim_allow", True)

        cfg.reload_config()
        console.print()
        notifier.success(f"Config saved to {cfg.config_path()}")
        self._print_transport_status(transport_status())
        console.print()
        self._print_sandbox_status()

    @staticmethod
    def _print_sandbox_status():
        """Which sandbox engines are usable (drives what 'approved' proves)."""
        from rich.table import Table
        from phantom.automation.sandbox.sandbox import sandbox_status
        table = Table(title="[bold]Payload Sandbox Engines[/]", border_style="cyan")
        table.add_column("Engine", style="cyan", no_wrap=True)
        table.add_column("Status", style="white")
        table.add_column("Sample kinds", style="dim")
        for st in sandbox_status():
            mark = "[green]ready[/]" if st["ready"] else "[yellow]missing[/]"
            table.add_row(st["engine"], mark, st["kinds"])
        console.print(table)
        notifier.info("Install clamscan/yara or set PHANTOM_SANDBOX_VM_EXEC to "
                      "raise the gate from one engine to multi-engine + VM.")

    @staticmethod
    def _print_transport_status(status: dict):
        from rich.table import Table
        table = Table(title="[bold]Transport Capability[/]", border_style="cyan")
        table.add_column("Channel", style="cyan", no_wrap=True)
        table.add_column("Status", style="white")
        table.add_column("Detail / how to enable", style="dim")
        for name, st in status.items():
            mark = "[green]ready[/]" if st.get("ready") else "[yellow]missing[/]"
            table.add_row(name, mark, st.get("detail", ""))
        console.print(table)

    def _print_toolbelt_status():
        from rich.table import Table
        from phantom.automation.brain.toolbelt import Toolbelt
        tb = Toolbelt()
        table = Table(title="[bold]Tool Capability (multi-tool per capability)[/]",
                      border_style="cyan")
        table.add_column("Capability", style="cyan", no_wrap=True)
        table.add_column("Selected tool", style="white")
        table.add_column("Missing alternatives", style="dim")
        for cap, ch in tb.status().items():
            tool = ("[green]" + ch.tool + "[/]" if ch.ok
                    else "[yellow]none[/]")
            if ch.tool == "__internal__":
                tool = "[green]built-in engine[/] (no binary needed)"
            table.add_row(cap, tool,
                          (", ".join(ch.alternatives_missing) or "—")
                          + ("" if ch.ok else f" · {ch.reason[:60]}"))
        console.print(table)

    def do_back(self, arg: str):
        """Return to main shell (already here)"""
        notifier.warn("Already at main shell.")

    def do_c2(self, arg: str):
        """c2 - Enter the Phantom C2 Operations Center"""
        notifier.status("Transitioning to C2 Interface...")
        from phantom.core.c2_shell import run_c2
        run_c2()

    def do_malleable(self, arg: str):
        """malleable [show|save|recommend] - Manage malleable C2 profiles for beacon stealth"""
        from phantom.utils.malleable import handle_malleable_command
        handle_malleable_command(arg)

    def do_ad(self, arg: str):
        """ad [tree|paths|add-user <u> [opts]|add-edge <src> <type> <dst>|reset]
            - BloodHound-style AD attack graph from session knowledge.

        subcommands:
          (none) | tree      render the domain graph + attack paths
          paths              only the attack paths to Domain Admin
          add-user <u>       register a user; flags: --kerberoastable
                             --as-rep --cracked --admin-to <host>
                             --session-on <host> --group <g>
          add-edge <s> <t> <d>  raw edge (member_of/admin_to/session/owns)
          add-dc <host>      register the domain controller
          reset              clear the graph (new engagement)"""
        from phantom.core.ad_graph import ADGraph, EDGE_TYPES
        from phantom.core.knowledge import session_wm
        g = ADGraph()
        # ingest whatever the session already knows (idempotent)
        try:
            from phantom.core.ad_graph import ingest_from_wm
            g = ingest_from_wm(session_wm())
        except Exception:
            pass
        parts = arg.strip().split()
        sub = parts[0].lower() if parts else "tree"

        if sub in ("", "tree"):
            for line in g.ascii_tree():
                notifier.info(line)
            return
        if sub == "paths":
            paths = g.paths_to("DA")
            if not paths:
                notifier.warn("No attack paths to DA known yet — collect "
                              "more AD data (add-user --kerberoastable, "
                              "--session-on, --admin-to)")
                return
            for i, p in enumerate(paths, 1):
                chain = " -> ".join(f"{s}[{t}]{d}" for s, t, d in p)
                notifier.info(f"[{i}] {chain}")
            return
        if sub == "add-user":
            if len(parts) < 2:
                notifier.error("Usage: ad add-user <user> [--kerberoastable] "
                               "[--as-rep] [--cracked] [--admin-to H] "
                               "[--session-on H] [--group G]")
                return
            u = parts[1]
            g.add_node(u, "user", label=u)
            opts = parts[2:]
            i = 0
            while i < len(opts):
                o = opts[i].lower()
                if o == "--kerberoastable":
                    g.nodes[u].props["kerberoastable"] = True
                elif o == "--as-rep":
                    g.nodes[u].props["as_rep_roastable"] = True
                elif o == "--cracked":
                    g.nodes[u].props["cracked"] = True
                elif o in ("--admin-to", "--session-on") and i + 1 < len(opts):
                    host = opts[i + 1]
                    et = "admin_to" if o == "--admin-to" else "session"
                    g.add_node(host, "computer")
                    g.add_edge(u, host, et)
                    i += 1
                elif o == "--group" and i + 1 < len(opts):
                    grp = opts[i + 1]
                    g.add_node(grp, "group")
                    g.add_edge(u, grp, "member_of")
                    i += 1
                i += 1
            g._save()
            notifier.success(f"AD user {u} recorded ({sum(len(v.props) for v in g.nodes.values())} graph nodes total)")
            return
        if sub == "add-dc":
            if len(parts) < 2:
                notifier.error("Usage: ad add-dc <host>")
                return
            g.add_node(parts[1], "dc", label="Domain Controller")
            if g.domain:
                g.add_edge(g.domain, parts[1], "owns")
            g._save()
            notifier.success(f"DC {parts[1]} recorded")
            return
        if sub == "add-edge":
            if len(parts) < 4 or parts[2].lower() not in EDGE_TYPES:
                notifier.error(f"Usage: ad add-edge <src> <{'|'.join(EDGE_TYPES)}> <dst>")
                return
            s, t, d = parts[1], parts[2].lower(), parts[3]
            for nid, ntype in ((s, "user"), (d, "computer")):
                if nid not in g.nodes:
                    g.add_node(nid, ntype)
            g.add_edge(s, d, t)
            notifier.success(f"edge {s} -[{t}]-> {d} recorded")
            return
        if sub == "reset":
            from phantom.core import ad_graph as _m
            _m.STATE_PATH.unlink(missing_ok=True)
            from phantom.core.ad_graph import ADGraph as _G
            g2 = _G()
            notifier.success("AD graph cleared")
            return
        notifier.error(f"Unknown ad subcommand: {sub}")

    def do_exit(self, arg: str):
        """exit - Exit Phantom, optionally save current session and generate professional report"""
        if session.target:
            note = input("\n[?] Add a final manual note for the report? (empty to skip): ").strip()
            if note:
                session.add_note(note)

            confirm = input("[?] Save session and generate professional report? [y/N]: ").strip().lower()
            if confirm == "y":
                name = input("[?] Report/Session name (default: auto): ").strip() or "auto"
                session.save(name)
                # Generate professional markdown report with full context
                from phantom.modules.report import ReportModule
                rm = ReportModule()
                rm.export("json", f"{name}.json")
                session.export_markdown(f"{name}.md")
                notifier.success(f"Professional report saved: {name}.md")
        
        notifier.status("Exiting Phantom...")
        sys.exit(0)

    def do_quit(self, arg: str):
        return self.do_exit(arg)

    def default(self, line: str):
        notifier.error(f"Unknown command: {line}")
        notifier.info("Type 'help' for available commands.")
