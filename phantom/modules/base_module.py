import cmd
from rich.console import Console
from phantom.core.session import session
from phantom.core.preview import PreviewSession
from phantom.core.executor import run_commands
from phantom.utils.aggressive import filter_aggressive_commands
from phantom.utils.notifier import notifier

console = Console()

class BaseModule(cmd.Cmd):
    """
    Class for all interactive modules.
    Common commands: back, exit, show, note.
    """
    module_name = "base"

    def __init__(self):
        super().__init__()
        # ONE prompt grammar across every layer (see phantom.core.shell.ui):
        # this used to be a plain `[module:target] > ` that looked nothing
        # like the shell it was entered from and carried no depth cue.
        from phantom.core.shell.ui import build_prompt
        self.prompt = build_prompt(self.module_name)

    def parseline(self, line):
        """Keep hyphenated commands whole (`run-group <name>`).

        `cmd.Cmd` ends a command name at `-`, so `run-group "SERVICE ENUM"`
        arrived as `run` with the argument `-group "SERVICE ENUM"`: the
        module ran its FIRST group and the named-group form of the scripted
        manual core did the wrong thing silently (measured 2026-10-28).
        """
        from phantom.core.shell.registry import normalise_command_line
        return super().parseline(normalise_command_line(line))

    def do_back(self, _):
        """Return to the main shell"""
        return True

    def do_where(self, _):
        """where - Print the current layer, target and scope (same as the shell)"""
        from phantom.core.shell.ui import layer_line
        console.print(layer_line(self.module_name), markup=False)

    def do_exit(self, _):
        """Exit Phantom"""
        raise SystemExit

    def do_show(self, arg):
        """Show session - current session"""
        if arg.strip() == "session":
            console.print(f"  Target: {session.target or 'None'}")
            console.print(f"  Mode: {session.mode}")
            console.print(f"  Scope: {', '.join(session.scope) if session.scope else 'none'}")
            console.print(f"  Active wordlist: {session.active_wordlist or 'default'}")
        else:
            console.print("[red]Usage: show session[/]")

    def do_note(self, arg):
        """note \"<text>\" — add an inline note to the current session."""
        text = arg.strip().strip('"').strip('"')
        if text:
            session.add_note(text)
            console.print("[green][+] Note added.[/]")
        else:
            console.print("[red]Usage: note \"your note here\"[/]")


    # Methods to be implemented by child classes
    def build_commands(self) -> dict:
        """
        return a dictionary of command groups:
        {
        "NMAP": ["nmap -sV target", ...],
        "NETWORK": ["ping target", ...]
        }
        """
        raise NotImplementedError("Each module must implement build_commands()")

    def suggest_commands(self) -> dict:
        """State-aware suggestions computed from the live session.

        Base default: none. Each module overrides this with its own
        suggestion engine (see phantom/modules/suggest.py) so that the
        manual modules generate commands dynamically from the session
        state, mirroring the autonomous agent's adapters.
        """
        return {}

    def do_suggest(self, _):
        """suggest — show state-aware commands for the current session."""
        from phantom.modules.suggest import reasoning_suggestion_group
        groups = dict(self.suggest_commands() or {})
        # merge the LIVE senior reasoning: hypotheses the shared WorldModel
        # inferred from what the operator has found so far.
        for key, cmds in reasoning_suggestion_group().items():
            groups.setdefault(key, []).extend(cmds)
        if not groups:
            console.print(
                "[dim]No state-aware suggestions right now — run the "
                "module's basics first (e.g. 'run' / 'preview').[/]")
            return
        for group, cmds in groups.items():
            console.print(f"  [bold green]-- {group}[/]")
            for command in cmds:
                console.print(f"    [green]▶ {command}[/]")

    def _with_suggestions(self, groups: dict, suggestions: dict) -> dict:
        """Merge suggestions ahead of the static groups (SUGGESTED first)."""
        merged: dict = {}
        for key, cmds in (suggestions or {}).items():
            merged.setdefault(key, []).extend(cmds or [])
        for key, cmds in (groups or {}).items():
            merged.setdefault(key, []).extend(cmds or [])
        return merged

    def show_enter_hint(self) -> None:
        """One-line actionable hint shown when entering the module."""
        suggestions = self.suggest_commands() or {}
        total = sum(len(v) for v in suggestions.values())
        if not total:
            return
        labels = ", ".join(
            g.replace("SUGGESTED", "").strip(" ()")
            for g in suggestions if g
        ) or "context"
        console.print(
            f"[bold green]▶ {total} suggestion(s) ready "
            f"({labels}). Type 'preview' to review.[/]"
        )

    def do_preview(self, _):
        """preview — REVIEW the command plan without executing anything.
        `run` executes (interactive selection), `preview` only shows."""
        if not session.target:
            notifier.error("No target set. Use 'set target <ip>' first.")
            return
        try:
            groups = self.build_commands()
        except Exception:
            groups = {}
        groups = self._with_suggestions(groups or {}, self.suggest_commands() or {})
        if not groups:
            console.print("[dim]No commands to review right now — try `run` or `suggest`.[/]")
            return
        PreviewSession(groups).review()

    def _run_selected(self, chosen) -> None:
        """Execute chosen commands and store the run under this module."""
        chosen = filter_aggressive_commands(chosen)
        from phantom.core.executor import RunStatus
        status = RunStatus()
        results = run_commands(chosen, session.target, status=status)
        session.add_result(getattr(self, "module_name", "module"), results,
                           status=status)

    def do_run_group(self, arg: str):
        """run-group <name> — execute exactly ONE group of this module's plan.

        The group is named, so there is nothing to choose and no menu to
        answer: this is the scriptable form of the `run-group` that only
        exists INSIDE `run`'s interactive menu. `preview` lists the names.
        """
        name = (arg or "").strip()
        if not name:
            notifier.error("Usage: run-group <name> — `preview` lists the "
                           "group names")
            return
        if not session.target:
            notifier.error("No target set. Use 'set target <ip>' first.")
            return
        groups = self.build_commands()
        if not groups:
            return
        preview = PreviewSession(groups)
        chosen = preview.run_group(name)
        if not chosen:
            return          # run_group already named the available groups
        notifier.status(f"Running group '{name.upper()}' on "
                        f"{session.target}...")
        self._run_selected(chosen)

    def _execute_flow(self, arg: str) -> None:
        """Default execution flow (override per module): build commands →
        selection → run. Modules keep their bespoke flows by overriding this
        (they used to be called `do_preview`).

        `choose` answers the menu when a human is attached and falls back to
        the module's own first group when stdin is a pipe, so the flow is
        scriptable instead of dying on `input()`."""
        if not session.target:
            notifier.error("No target set. Use 'set target <ip>' first.")
            return
        groups = self.build_commands()
        if not groups:
            return
        preview = PreviewSession(groups)
        chosen = preview.choose(self._group_from_arg(arg))
        if chosen is None:
            notifier.warn("Cancelled.")
            return
        self._run_selected(chosen)

    @staticmethod
    def _group_from_arg(arg: str) -> str:
        """`run --group <name>` picks a group without a menu."""
        tokens = (arg or "").split()
        for index, token in enumerate(tokens):
            if token in ("--group", "-g") and index + 1 < len(tokens):
                return tokens[index + 1]
            if token.startswith("--group="):
                return token.split("=", 1)[1]
        return ""

    def _run_quiet(self, suggestions: dict) -> bool:
        """--quiet path: run the top suggested command directly, print only
        its raw output (pipe-able). Returns True if something ran."""
        from phantom.core.executor import execute_quiet
        cmds = []
        for group in (suggestions or {}).values():
            cmds.extend(group or [])
        if not cmds:
            console.print(
                "[red]No suggestions available to run in --quiet mode. "
                "Run 'preview' interactively first.[/]")
            return False
        cmd = cmds[0]
        console.print(f"[dim]# {cmd}[/]")
        budget = self.quiet_timeout_seconds(cmd)
        if budget > 300:
            # silence reads as a hang: say up front how long this may take
            print(f"[quiet] long-running command: killed after "
                  f"{budget // 60} min if it has not finished (a full-port "
                  f"sweep of a firewalled host measured >46 min on this LAN). "
                  f"Ctrl-C stops it; `run` without --quiet lets it continue.")
        res = execute_quiet(cmd, session.target, timeout=budget)
        if res.stdout:
            print(res.stdout.rstrip())
        if res.stderr:
            print(res.stderr.rstrip())
        # A killed command is not a finished one. Without this line the
        # operator — or the script reading the pipe — sees a partial sweep and
        # reads it as the whole answer ("0 services" on a host that has some).
        if getattr(res, "timed_out", False):
            print(f"[quiet] TIMED OUT after {budget}s: the output above is "
                  f"PARTIAL, not a result. Re-run interactively (`run`, "
                  f"without --quiet) to extend or background it.")
        return True

    # A --quiet run is a one-shot: it may not sit on a command forever.
    # Modules whose top suggestion is inherently slow override the hook — a
    # full-port nmap sweep is minutes, not seconds, and the flat 120 s that
    # used to be hardcoded killed that sweep mid-flight.
    quiet_timeout_default = 120

    def quiet_timeout_seconds(self, cmd: str) -> int:
        """Seconds a --quiet command may run before it is killed."""
        return self.quiet_timeout_default

    def do_run(self, arg: str):
        """run [--quiet] — EXECUTE the module flow (interactive selection).
        `preview` only shows the plan; `run` executes it. With --quiet:
        execute the top suggested command directly (pipe-able)."""
        if "--quiet" in (arg or "").split():
            self.quiet = True
        # TOOL GATE: the same check `preflight` runs, applied here — a
        # missing binary used to surface as a confusing mid-flow failure
        # ('run scan' with python-nmap installed but no nmap binary).
        # Interactive: warn with the exact install hints and keep going (a
        # module may only need the tool conditionally). Quiet/scripted:
        # refuse, because there is nobody to read the warning — but only
        # for the TOP suggestion, which is the one quiet mode will run.
        try:
            from phantom.core.executor import module_missing_tools
            if getattr(self, "quiet", False):
                top = []
                for group in (self.suggest_commands() or {}).values():
                    top.extend(group or [])
                missing = module_missing_tools(self, commands=top[:1])
            else:
                missing = module_missing_tools(self)
        except Exception:
            missing = []
        if missing:
            from phantom.utils.notifier import notifier
            tools = ", ".join(t for t, _ in missing)
            if getattr(self, "quiet", False):
                notifier.error(
                    f"Missing tool(s) for this module: {tools}. Install them "
                    "or run interactively to see the hints.",
                    hint="; ".join(h for _, h in missing[:3]))
                return False
            notifier.warn(f"Missing tool(s) for this module: {tools} — the "
                          "run may fail partway; `preflight` lists the "
                          "install hints.")
        if getattr(self, "quiet", False):
            if self._run_quiet(self.suggest_commands()):
                return
            self.quiet = False  # fall back to interactive
        return self._execute_flow(arg)

    def do_quiet(self, _):
        """quiet — toggle non-interactive mode (top suggestion, raw output)."""
        self.quiet = not getattr(self, "quiet", False)
        console.print(
            f"[green]quiet mode {'ON' if self.quiet else 'OFF'}[/] — "
            "'run' will execute the top suggestion directly.")