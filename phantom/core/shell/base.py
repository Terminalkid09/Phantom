"""PhantomShell: the interactive manual shell (loop + infrastructure).

The 36 ``do_*`` commands live in :mod:`phantom.core.shell.commands` as plain
``handler(shell, arg)`` functions and are wired here dynamically, so
``cmd.Cmd`` keeps working (help, completion, precmd) with zero
per-command boilerplate. Everything a command needs from the shell
(module registry, aliases, profiles, plugins) stays on this class.
"""
from __future__ import annotations

import cmd
import importlib.util
import json
import os
import sys
import traceback

from phantom.core.session import session
import phantom.core.shell as _sh  # live console: _sh.console resolves the package attr at call time (test patch point)
from phantom.core.shell.registry import iter_commands
from phantom.core.shell.ui import (
    _context_hint,
    build_banner,
    build_dashboard,
    build_status_bar,
)
from phantom.utils.notifier import notifier

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
        _sh.console.print(build_banner())
        _sh.console.print(build_dashboard())
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
                _sh.console.print("[dim]──────────────────────────────────────────[/dim]")
                _sh.console.print(build_status_bar())
                _sh.console.print(_context_hint())
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
                                _sh.console.print()
                                break
                        else:
                            self.stdout.write(self.prompt)
                            self.stdout.flush()
                            line = self.stdin.readline()
                            if not len(line):
                                _sh.console.print()
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
                        _sh.console.print("\n[dim]Phantom closed.[/dim]\n")
                        raise SystemExit(0)
                    _sh.console.print()
                    _sh.console.print(
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

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except SystemExit:
            raise
        except Exception as e:
            notifier.error(f"Command execution failed: {e}")
            _sh.console.print(traceback.format_exc())
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

    # capability id -> manual module. The map is OWNED by next_moves so the
    # ranked `suggest` list and the adaptive `run` can never disagree on
    # where a capability lives; aliased here because the shell has always
    # exposed this name.
    from phantom.core.next_moves import CAPABILITY_MODULE as _CAPABILITY_MODULE

    def _next_step(self):
        """The single best next module from the LIVE engagement state.

        Delegates to the ranked move engine (next_moves): the adaptive
        `run` proposes exactly what `suggest` ranks first, from ONE decision
        engine instead of a second, parallel heuristic.
        """
        from phantom.core import next_moves as _nm

        base = _nm.base_move()
        if base is not None and base.module:
            return (base.module, base.why)
        try:
            # remember=False: proposing a step must not clobber the numbered
            # list the operator is about to `run <n>`
            ranked = _nm.rank_next_moves(self, limit=1, remember=False)
        except Exception:
            ranked = None
        if ranked is not None and ranked.moves:
            top = ranked.moves[0]
            if top.module:
                return (top.module,
                        top.why or "best next step from current findings")
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

    def complete_use(self, text: str, line: str, begidx: int, endidx: int) -> list:
        """Tab-completion for `use` (modules + aliases)."""
        builtin = ["scan", "osint", "wifi", "web", "brute", "exploit",
                   "payload", "handler", "pivot", "analyzer", "report",
                   "wordlist"]
        plugin_names = list(getattr(self, "_plugin_modules", {}).keys())
        names = builtin + plugin_names + list(self.MODULE_ALIASES.keys())
        return [n for n in names if n.startswith(text)]

    def default(self, line: str):
        from phantom.utils.notifier import notifier as _n
        _n.error(f"Unknown command: {line}")
        _n.info("Type 'help' for available commands.")


def _make_do(name, fn):
    """Build the ``do_<name>`` wrapper cmd.Cmd dispatches to.

    The wrapper keeps the handler's docstring, so ``help <cmd>`` and the
    in-command ``.__doc__`` prints render exactly as before.
    """
    def do_cmd(self, arg):
        return fn(self, arg)
    do_cmd.__name__ = f"do_{name}"
    do_cmd.__doc__ = fn.__doc__
    return do_cmd


for _cmd_name, _cmd_fn in iter_commands():
    setattr(PhantomShell, f"do_{_cmd_name}", _make_do(_cmd_name, _cmd_fn))
del _cmd_name, _cmd_fn
