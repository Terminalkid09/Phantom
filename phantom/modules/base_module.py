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
        target = session.target if session.target else "no-target"
        self.prompt = f"[{self.module_name}:{target}] > "

    def do_back(self, _):
        """Return to the main shell"""
        return True

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
            for cmd in cmds:
                console.print(f"    [green]▶ {cmd}[/]")

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

    def _execute_flow(self, arg: str) -> None:
        """Default execution flow (override per module): build commands →
        interactive selection → run. Modules keep their bespoke flows by
        overriding this (they used to be called `do_preview`)."""
        if not session.target:
            notifier.error("No target set. Use 'set target <ip>' first.")
            return
        groups = self.build_commands()
        if not groups:
            return
        preview = PreviewSession(groups)
        chosen = preview.interactive()
        if chosen is None:
            notifier.warn("Cancelled.")
            return
        chosen = filter_aggressive_commands(chosen)
        results = run_commands(chosen, session.target)
        session.add_result(getattr(self, "module_name", "module"), results)

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
        res = execute_quiet(cmd, session.target, timeout=120)
        if res.stdout:
            print(res.stdout.rstrip())
        if res.stderr:
            print(res.stderr.rstrip())
        return True

    def do_run(self, arg: str):
        """run [--quiet] — EXECUTE the module flow (interactive selection).
        `preview` only shows the plan; `run` executes it. With --quiet:
        execute the top suggested command directly (pipe-able)."""
        if "--quiet" in (arg or "").split():
            self.quiet = True
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