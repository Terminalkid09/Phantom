"""
auto_shell.py — dedicated CLI shell for AUTO-MODE.

The autonomous kill chain deserves its own interface, exactly like the C2
has `c2`: `auto` with no arguments drops the operator into this shell,
where targets are managed as a LIST (the core shell only holds one),
flags are inspected/changed, the chain is planned dry, launched, resumed
from a checkpoint or a shared `.pm`, and handed off to the C2 on beacon.

This mirrors the Electron Auto-Mode panel 1:1 so the CLI is no longer
"auto squeezed inside the core shell".
"""

from __future__ import annotations

import cmd
import json
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from phantom.core.session import session
from phantom.utils.notifier import notifier

console = Console()

_GOALS = ("deep", "deliver", "complete_kill_chain", "footprint", "beacon",
          "creds", "identity", "post_exploit", "ad", "crack", "lateral",
          "cleanup")
_PROFILES = ("smb", "enterprise", "cloud", "financial", "government", "mobile")
# goals.engine_for honors "swarm" only for goals that declare a swarm chain;
# anything else falls back to the agent path with a printed note.
_ENGINES = ("agent", "swarm")


# ── banner / dashboard / status ────────────────────────────────────────────

def build_auto_banner() -> str:
    """Same PHANTOM wordmark family as core (red) and C2 (magenta),
    in cyan — AUTO-MODE is the intelligence layer."""
    return r"""
[bold cyan]
  ██████╗ ██╗  ██╗ █████╗ ███╗  ██╗████████╗ ██████╗ ███╗  ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗ ██║╚══██╔══╝██╔═══██╗████╗████║
  ██████╔╝███████║███████║██╔██╗██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚████║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚███║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
[/bold cyan]
  [dim]──────────────────────────────────────────────────────────[/dim]
  [bold cyan]PHANTOM.AUTO — Autonomous Kill Chain Engine[/bold cyan]  [dim]v3.5.0[/dim]
  [dim]Planner-driven agent · multi-target · sub-agents · checkpoint resume[/dim]
"""


def _elapsed() -> str:
    started = getattr(session, "engagement_started", None)
    if not started:
        return "0s"
    try:
        secs = max(0, int((datetime.now() - datetime.fromisoformat(started)).total_seconds()))
    except Exception:
        return "0s"
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def _separator() -> str:
    return "[dim]──────────────────────────────────────────[/dim]"


def loop_mod_budget_left(st) -> int:
    from phantom.automation.evolution.loop import MAX_GATE_RUNS_PER_DAY
    return max(0, MAX_GATE_RUNS_PER_DAY - int(st._d.get("gate_runs", 0)))


def pr_budget_left(st) -> int:
    from phantom.automation.evolution.loop import MAX_PRS_PER_DAY
    return max(0, MAX_PRS_PER_DAY - int(st._d.get("prs", 0)))


def _dashboard(targets: List[str], flags: Dict[str, Any]) -> Panel:
    tgt = ", ".join(targets) if targets else "—"
    active = [k for k in ("aggressive", "stealth", "speed", "llm",
                          "experience", "evolution") if flags.get(k)]
    parts = [f"[bold cyan]Targets:[/] [yellow]{tgt}[/]"]
    parts.append(f"[bold white]Goal:[/] {flags.get('goal')}")
    parts.append(f"[bold white]Profile:[/] {flags.get('profile')}")
    parts.append(f"[bold white]Agents:[/] {flags.get('agents') or 'auto'}")
    parts.append(f"[bold white]Flags:[/] {', '.join(active) or 'default'}")
    parts.append(f"[bold green]⏱ {_elapsed()}[/]")
    return Panel(
        "   ".join(parts),
        title="[bold]Phantom Auto-Mode Status[/]",
        border_style="cyan",
    )


def _status_bar(targets: List[str], flags: Dict[str, Any]) -> str:
    n = len(targets)
    tgt = f"{n} target(s)" if n else "no targets"
    active = [k for k in ("aggressive", "stealth", "speed", "llm",
                          "experience", "evolution") if flags.get(k)]
    flags_txt = (" · ".join(active) if active else "default")
    agents = f"-a{flags.get('agents')}" if flags.get("agents") else "-a"
    return (f"[bold cyan]▚ PHANTOM.AUTO[/] [dim]|[/] [yellow]{tgt}[/] "
            f"[dim]·[/] {flags.get('goal')} [dim]·[/] {flags_txt} [dim]·[/] "
            f"[bold white]{agents}[/] [dim]·[/] [bold green]⏱ {_elapsed()}[/]")


def _context_hint(targets: List[str], has_run: bool) -> str:
    hints = []
    if not targets:
        hints.append("targets add <email|username|ip|domain>")
        hints.append("scope add <cidr>")
    elif not has_run:
        hints.append("plan → launch")
        hints.append("resume <checkpoint|.pm>")
    else:
        hints.append("status")
        hints.append("export <file>.pm")
    hints.append("help")
    hints.append("manual")
    hints.append("c2")
    hints.append("back")
    return "[dim]▸ " + "   ".join(hints[:5]) + "[/dim]"


# ── the shell ──────────────────────────────────────────────────────────────

class AutoShell(cmd.Cmd):
    intro = ""
    prompt = "\033[1;36mAUTO\033[0m > "

    def __init__(self):
        super().__init__()
        self.targets: List[str] = []
        self.flags: Dict[str, Any] = {
            "aggressive": False, "stealth": False, "speed": False,
            "agents": 0, "goal": "deliver", "profile": "enterprise",
            "llm": False, "verbose": False, "experience": False,
            "evolution": False,
            # Scope-changing controls. `force_network` turns a CIDR into a
            # full-range engagement and `engine` picks agent vs swarm; both
            # were reachable only from the CLI, so the REPL could not run
            # either -- and `_announce_guardrails` read a flag that could
            # never be set, i.e. a guard that could not fire.
            "force_network": False, "engine": "agent",
        }
        self.events: Dict[str, List[Dict[str, Any]]] = {}
        self.has_run = False
        self._intr_count = 0
        self._last_intr = 0.0
        self._last_line = ""

    # ── lifecycle ─────────────────────────────────────────────────────────

    def preloop(self):
        if not getattr(session, "engagement_started", None):
            session.engagement_started = datetime.now().isoformat(timespec="seconds")
        if session.target and not self.targets:
            self.targets = [session.target]
        if session.scope and "scope" not in self.events:
            pass  # scope lives on session, shown by `scope`
        console.print(build_auto_banner())
        console.print(_dashboard(self.targets, self.flags))
        console.print(_separator())
        console.print(_context_hint(self.targets, self.has_run))
        console.print()

    def postcmd(self, stop, line):
        if line.strip():
            self._last_line = line.strip()
            try:
                console.print(_separator())
                console.print(_status_bar(self.targets, self.flags))
                console.print(_context_hint(self.targets, self.has_run))
            except Exception:
                pass
        return stop

    def cmdloop(self, intro=None):
        import time as _time

        self.preloop()
        if intro is not None:
            self.intro = intro
        if self.intro:
            self.stdout.write(str(self.intro) + "\n")
        stop = None
        try:
            while not stop:
                try:
                    line = input(self.prompt) if self.use_rawinput else self._raw_line()
                    line = self.precmd(line)
                    stop = self.onecmd(line)
                    stop = self.postcmd(stop, line)
                    self._intr_count = 0
                except KeyboardInterrupt:
                    now = _time.monotonic()
                    if now - self._last_intr > 2.0:
                        self._intr_count = 0
                    self._intr_count += 1
                    self._last_intr = now
                    if self._intr_count >= 2:
                        console.print("\n[dim]AUTO-MODE closed.[/dim]\n")
                        raise SystemExit(0)
                    console.print()
                    console.print(
                        "[bold yellow]^C  —  Ctrl+C again to exit, or keep typing.[/bold yellow]")
                    continue
        finally:
            self.postloop()

    def _raw_line(self):
        self.stdout.write(self.prompt)
        self.stdout.flush()
        line = self.stdin.readline()
        return line if line else "EOF"

    # ── event collection (run_auto_mode on_event) ─────────────────────────

    def _on_event(self, kind: str, data: dict):
        tgt = data.get("target") or (self.targets[0] if len(self.targets) == 1 else "*")
        ev = {"kind": kind, "at": time.time(), **data}
        self.events.setdefault(str(tgt), []).append(ev)
        if self.flags.get("verbose"):
            # The event's OWN wording via the shared contract. This used to
            # print `data.get('message')` — a field no emitter ever set, so
            # --verbose produced a column of empty lines and the operator
            # concluded the engine was doing nothing.
            from phantom.core.stream_contract import render_event
            rendered = render_event(kind, data, verbose=True)
            if rendered is not None:
                for line in rendered.lines:
                    console.print(f"  [dim]•[/] [cyan]{tgt}[/] {line}")

    # ── targets ───────────────────────────────────────────────────────────

    def do_targets(self, arg: str):
        """targets | targets add <t[,t...]> | targets rm <t> - manage the target list"""
        parts = arg.split()
        if not parts:
            if not self.targets:
                notifier.warn("No targets yet. Add with: targets add <email|username|ip|domain>")
                return
            for i, t in enumerate(self.targets, 1):
                console.print(f"  [cyan]{i}.[/] {t}")
            return
        cmd_, rest = parts[0].lower(), parts[1:]
        if cmd_ == "add":
            if not rest:
                notifier.error("Usage: targets add <target[,target...]>")
                return
            for chunk in " ".join(rest).split(","):
                t = chunk.strip()
                if t and t not in self.targets:
                    self.targets.append(t)
                    notifier.success(f"Target added: {t}")
                elif t:
                    notifier.warn(f"Target already present: {t}")
            return
        if cmd_ == "rm":
            if not rest:
                notifier.error("Usage: targets rm <target>")
                return
            t = " ".join(rest).strip()
            if t in self.targets:
                self.targets.remove(t)
                notifier.success(f"Target removed: {t}")
            else:
                notifier.error(f"Unknown target: {t}")
            return
        notifier.error("Usage: targets | targets add <t> | targets rm <t>")

    def complete_targets(self, text, line, begidx, endidx):
        parts = line.split()
        if len(parts) <= 2 and parts and parts[0].lower() in ("add", "rm"):
            return [t for t in self.targets if t.startswith(text)]
        return ["add", "rm"]

    # ── scope ─────────────────────────────────────────────────────────────

    def do_scope(self, arg: str):
        """scope | scope add <cidr> | scope rm <cidr> - authorized targets"""
        parts = arg.split()
        if not parts:
            if not session.scope:
                notifier.warn("No scope set. Add with: scope add <cidr|target>")
                return
            for i, s in enumerate(session.scope, 1):
                console.print(f"  [cyan]{i}.[/] {s}")
            return
        cmd_, rest = parts[0].lower(), parts[1:]
        if cmd_ == "add":
            if not rest:
                notifier.error("Usage: scope add <cidr|target>")
                return
            for chunk in " ".join(rest).split(","):
                s = chunk.strip()
                if s and s not in (session.scope or []):
                    session.scope = list(session.scope or []) + [s]
                    notifier.success(f"Scope added: {s}")
            return
        if cmd_ == "rm":
            if not rest:
                notifier.error("Usage: scope rm <cidr>")
                return
            s = " ".join(rest).strip()
            if s in (session.scope or []):
                session.scope = [x for x in session.scope if x != s]
                notifier.success(f"Scope removed: {s}")
            else:
                notifier.error(f"Not in scope: {s}")
            return
        notifier.error("Usage: scope | scope add <cidr> | scope rm <cidr>")

    # ── flags ─────────────────────────────────────────────────────────────

    _BOOL_KEYS = ("aggressive", "stealth", "speed", "llm", "verbose",
                  "experience", "evolution", "force_network")

    def do_flags(self, arg: str):
        """flags | flags <key> <value> - show/change run flags
        keys: aggressive|stealth|speed|llm|verbose|experience|evolution|
        force_network (on/off), agents (N), goal (<choices>),
        profile (<choices>), engine (agent|swarm)

        experience: cross-engagement learning memory. OFF (default) means
        the experience engine learns WITHIN this run only; ON persists the
        cause->repair cases to data/ so the next engagement starts smarter.
        evolution: self-improvement — stable uncovered failure patterns
        spawn a background authoring sub-agent that opens a reviewable PR
        (requires llm on + lab reachable; max 2 PRs/day)."""
        parts = arg.split()
        if not parts:
            table = Table(title="Auto-Mode Flags", border_style="cyan")
            table.add_column("Flag")
            table.add_column("Value")
            for k, v in self.flags.items():
                if k in self._BOOL_KEYS:
                    table.add_row(k, "on" if v else "off")
                elif k == "agents":
                    table.add_row(k, "auto" if not v else str(v))
                else:
                    table.add_row(k, str(v))
            console.print(table)
            return
        key, value = parts[0].lower(), " ".join(parts[1:]).strip()
        if key not in self.flags:
            notifier.error(f"Unknown flag: {key} (see `flags`)")
            return
        if not value:
            notifier.error(f"Usage: flags {key} <value>")
            return
        if key in self._BOOL_KEYS:
            val = value.lower() in ("on", "true", "1", "yes")
            if value.lower() not in ("on", "off", "true", "false", "1", "0", "yes", "no"):
                notifier.error(f"flags {key} accepts on/off")
                return
            self.flags[key] = val
        elif key == "agents":
            try:
                n = int(value)
                if n < 0:
                    raise ValueError
                self.flags["agents"] = n
            except ValueError:
                notifier.error("flags agents expects 0 (auto) or N >= 1")
                return
        elif key == "goal":
            if value not in _GOALS:
                notifier.error(f"goal must be one of: {', '.join(_GOALS)}")
                return
            self.flags["goal"] = value
        elif key == "profile":
            if value not in _PROFILES:
                notifier.error(f"profile must be one of: {', '.join(_PROFILES)}")
                return
            self.flags["profile"] = value
        elif key == "engine":
            if value.lower() not in _ENGINES:
                notifier.error(f"engine must be one of: {', '.join(_ENGINES)}")
                return
            self.flags["engine"] = value.lower()
        notifier.success(f"flags {key} = {self.flags[key]}")

    # ── plan (dry run) ────────────────────────────────────────────────────

    def do_plan(self, arg: str):
        """plan [target...] - dry-run the planned kill chain (executes nothing)"""
        targets = [t for t in arg.split(",") if t.strip()] or self.targets
        if not targets:
            notifier.error("No targets. Add with: targets add <target>")
            return
        from phantom.core.automode import run_auto_mode
        console.print(f"[cyan]─ Plan (dry-run) for: {', '.join(targets)} ─[/]")
        # One source of truth: the plan used to re-list the flags by hand and
        # had drifted, so the scope-changing controls never appeared in it.
        run_auto_mode(targets=targets, plan=True, **self._run_kwargs())

    # ── launch / resume ───────────────────────────────────────────────────

    def _run_kwargs(self) -> Dict[str, Any]:
        return dict(
            aggressive=bool(self.flags["aggressive"]),
            stealth=bool(self.flags["stealth"]),
            speed=bool(self.flags["speed"]),
            agents=int(self.flags["agents"]),
            goal=self.flags["goal"],
            profile=self.flags["profile"],
            llm=bool(self.flags["llm"]),
            verbose=bool(self.flags["verbose"]),
            experience=bool(self.flags["experience"]),
            evolution=bool(self.flags["evolution"]),
            engine=self.flags["engine"],
            force_network=bool(self.flags["force_network"]),
        )

    def do_review(self, arg: str):
        """review - self-improvement status: authored patterns, budgets,
        learned capabilities, beta PRs"""
        from phantom.automation.evolution.loop import EvolutionState
        from phantom.automation.evolution import gate as evo_gate
        from phantom.automation.guidance.learned import load_learned
        st = EvolutionState()
        table = Table(title="Evolution / Self-Improvement",
                      border_style="cyan")
        table.add_column("Item")
        table.add_column("Value")
        lab = evo_gate.lab_available()
        table.add_row("lab reachable", "yes" if lab else
                      "NO — no authoring, no PR, no beta load")
        table.add_row("authored patterns",
                      ", ".join(f"{k} -> {v}" for k, v in
                                sorted(st.authored().items())) or "none yet")
        table.add_row("gate budget today",
                      f"{loop_mod_budget_left(st)} left")
        table.add_row("PR budget today",
                      f"{pr_budget_left(st)} left")
        learned = load_learned()
        table.add_row("learned capabilities",
                      ", ".join(c.id for c in learned) or "none")
        console.print(table)
        console.print(
            "[dim]Enable with: flags evolution on (+ flags llm on). "
            "PRs land on auto-evolution/* — review and merge from dev.[/]")

    def do_launch(self, arg: str):
        """launch - run the autonomous kill chain on the current targets"""
        if arg.strip():
            for t in arg.split(","):
                t = t.strip()
                if t and t not in self.targets:
                    self.targets.append(t)
        if not self.targets:
            notifier.error("No targets. Add with: targets add <target>")
            return
        from phantom.core.automode import run_auto_mode
        # The engagement's protection level is stated BEFORE the run, not
        # discovered afterwards. If the operator is carrying an override from
        # a previous session this is the moment they can see it - and, with
        # strict mode on, the moment the run is refused.
        if not self._announce_guardrails():
            return
        self.has_run = True
        console.print(f"[cyan]─ Launching AUTO-MODE on: {', '.join(self.targets)} ─[/]")
        run_auto_mode(targets=self.targets, on_event=self._on_event,
                      handoff_c2=True, **self._run_kwargs())

    def do_run(self, arg: str):
        """run - refused: the whole-chain command here is `launch`

        `run` used to be an alias of `launch`, so one word meant two
        different things across the two shells: in the MANUAL shell `run`
        executes ONE module, in AUTO-MODE it silently started the entire kill
        chain. An operator who typed it by habit started an engagement. It is
        now an explicit refusal that names the right command instead.
        """
        notifier.error("`run` does not launch the kill chain in AUTO-MODE.")
        notifier.info("Use `launch` for the whole chain, or `manual` then "
                      "`run <module>` to execute one module.")

    def do_resume(self, arg: str):
        """resume <checkpoint.json|session.pm> - continue an interrupted engagement"""
        path = arg.strip()
        if not path:
            notifier.error("Usage: resume <checkpoint.json|session.pm>")
            return
        if not os.path.isfile(path):
            notifier.error(f"File not found: {path}")
            return
        target = ""
        cp_path = path
        if path.endswith(".pm"):
            from phantom.utils.session_bundle import import_session, read_bundle
            data = read_bundle(path)
            sess = data.get("session") or {}
            target = sess.get("target", "")
            result = import_session(path)
            if result.get("resume_path"):
                cp_path = result["resume_path"]
            console.print(f"[cyan]─ .pm imported:[/] {summarize_bundle(result)}")
        else:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    state = json.load(f)
                target = state.get("target", "")
            except (OSError, ValueError) as e:
                notifier.error(f"Cannot read checkpoint: {e}")
                return
        if target and target not in self.targets:
            self.targets.append(target)
        if session.target != target and target:
            session.target = target
        if not self.targets:
            notifier.error("No target in checkpoint/bundle; add one with: targets add <target>")
            return
        from phantom.core.automode import run_auto_mode
        self.has_run = True
        console.print(f"[cyan]─ Resuming from: {path} ─[/]")
        run_auto_mode(targets=self.targets, resume=cp_path,
                      on_event=self._on_event, handoff_c2=True,
                      **self._run_kwargs())

    # ── status / export / import ──────────────────────────────────────────

    def do_status(self, arg: str):
        """status - per-target event summary of the last run"""
        if not self.events:
            notifier.warn("No run data yet. Use: plan / launch / resume")
            return
        table = Table(title="Per-Target Run Status", border_style="cyan")
        table.add_column("Target")
        table.add_column("Events")
        table.add_column("Last")
        table.add_column("Waiting")
        for tgt, evs in self.events.items():
            last = evs[-1]["kind"] if evs else "-"
            waiting = sum(1 for e in evs if e["kind"] == "waiting")
            table.add_row(str(tgt), str(len(evs)), last, str(waiting))
        console.print(table)

    def do_export(self, arg: str):
        """export <file>.pm - export the current engagement to a portable .pm"""
        path = arg.strip()
        if not path:
            notifier.error("Usage: export <file>.pm")
            return
        from phantom.utils.session_bundle import export_session
        written = export_session(out_path=path)
        notifier.success(f"Session exported: {written}")

    def do_import(self, arg: str):
        """import <file>.pm - restore an engagement from a portable .pm"""
        path = arg.strip()
        if not path:
            notifier.error("Usage: import <file>.pm")
            return
        from phantom.utils.session_bundle import import_session
        try:
            result = import_session(path)
        except (FileNotFoundError, ValueError) as e:
            notifier.error(str(e))
            return
        if result.get("target") and result["target"] not in self.targets:
            self.targets.append(result["target"])
        console.print(f"[cyan]─ .pm imported:[/] {summarize_bundle(result)}")
        notifier.success(f"Session restored (findings: {result.get('findings', 0)}). "
                         "Use: status / resume <checkpoint> / back")

    # ── navigation ────────────────────────────────────────────────────────

    def do_manual(self, arg: str):
        """manual [<target>] - enter the MANUAL module workflow on the current engagement

        The classic module shell is a MODE of auto-mode, not a separate
        entry point: it shares the session target, scope and accumulated
        knowledge, so `suggest` / `run` after an auto run see the findings
        instead of a blank slate. `exit` from it returns here.
        """
        from phantom.core.shell import PhantomShell
        from phantom.utils.auto_session import auto_export
        if arg.strip() and not session.target:
            session.target = arg.strip()
        manual = PhantomShell()
        manual.auto_run = True
        console.print("[dim]Entering the MANUAL module shell — `exit` to "
                      "return to AUTO-MODE.[/]")
        try:
            manual.cmdloop()
        except KeyboardInterrupt:
            console.print("\n[dim]Returning to AUTO-MODE.[/]")
        finally:
            # Same guarantee as the standalone shell: the engagement is
            # persisted on EVERY close path, including a double Ctrl+C.
            try:
                exported = auto_export()
                if exported:
                    console.print(f"[dim]Session auto-saved: {exported}[/]")
            except Exception:
                pass

    def _announce_guardrails(self) -> bool:
        """State the protection level, and put it in the audit log.

        Called at launch so an override that has been lying around since a
        previous session is visible before anything is attempted against the
        target, not after. Returns False when strict mode refuses the run.

        Never raises: the reporting layer must not be able to break a launch,
        so a failure here degrades to "cannot tell" and allows the run.
        """
        try:
            from phantom.utils import guardrails as gr
            m = gr.build(scope=getattr(session, "scope", None),
                         targets=list(self.targets),
                         force_network=bool(self.flags.get("force_network", False)))
        except Exception as exc:
            # Never block a run on the reporting layer.
            console.print(f"[dim]guardrails: unavailable ({exc})[/dim]")
            return True
        # render() is DATA, not markup: it contains "[env]", "[config]",
        # "[run]" - and rich swallows those as (unknown) style tags, which
        # silently deleted the source attribution from the launch banner.
        # The source is the whole point of the line, so it has to survive.
        from rich.markup import escape
        console.print(f"[dim]{escape(gr.render(m))}[/dim]")
        overrides = m.overrides
        if overrides:
            console.print("[yellow]This engagement runs with "
                          f"{len(overrides)} safety control(s) disabled by "
                          "the operator. They will appear in the report.[/]")
        gr.snapshot_to_audit(m, event="guardrails_at_launch",
                             targets=list(self.targets))
        # Strict mode: the refusal happens HERE, before the run, with the
        # offending controls named. Refusing after the first action would be
        # theatre.
        blocking = m.blocking_overrides()
        if blocking:
            names = ", ".join(g.label for g in blocking)
            notifier.error(
                f"Strict guardrails is ON and {len(blocking)} protection(s) "
                f"are disabled: {names}.\n"
                f"Restore them with `guardrails enable <key>`, or turn strict "
                f"mode off (`guardrails disable strict_guardrails`).")
            gr.snapshot_to_audit(m, event="guardrails_blocked_launch",
                                 blocked=[g.key for g in blocking])
            return False
        return True

    def do_deps(self, arg: str):
        """deps [report|install <tool>...] - external tools Phantom needs

        Shows what is missing on this machine (Kali/WSL, other Linux, macOS,
        Windows) and how Phantom would install it. `install <tool>` asks first
        and never installs on a no. The Electron surface offers the same helper
        through /api/toolchain.
        """
        from phantom.core.shell.commands import ops
        ops.cmd_deps(self, arg)

    def do_guardrails(self, arg: str):
        """guardrails [list|why|enable <k>|disable <k>|record] - safety controls for this engagement

        Every scope/auth/transport control, whether it is on, and which layer
        decided that. An override an operator cannot see is how an engagement
        quietly runs with less protection than it was sold with — so the
        manifest also goes into every report and into the hash-chained audit
        log, not just to this screen.
        """
        from phantom.core.shell.commands.ops import cmd_guardrails
        cmd_guardrails(self, arg)

    def do_back(self, arg: str):
        """back - leave AUTO-MODE"""
        notifier.info("Leaving AUTO-MODE.")
        return True

    @staticmethod
    def _live_beacons():
        """The C2's beacon list, or None when the C2 is not running.

        None (never []) is what tells the TTL policy that liveness cannot be
        checked and only age applies: an empty list would mean "the C2 knows
        no beacons", which would expire every handoff of the run. The store's
        values carry no id, so each entry is keyed explicitly for the policy.
        """
        try:
            from phantom.core.c2_server import c2_state, server_instance
            thread = getattr(server_instance, "thread", None)
            if thread is None or not thread.is_alive():
                return None
            return [{"beacon_id": bid, **info}
                    for bid, info in c2_state.get_beacons().items()]
        except Exception:
            return None

    def _pending_handoffs(self):
        """Beacons this run established that are STILL offerable, newest first.

        The handoff event is emitted by run_auto_mode whether or not the
        operator took it, so `handoff` can still offer a C2 context for a
        beacon the auto-handoff skipped. A handoff older than the TTL - or
        pointing at a beacon the C2 no longer knows - is not offered, and the
        operator is told which one was dropped and why: a silently missing
        handoff is the same bug one layer up.
        """
        from phantom.utils import handoff_ttl
        found = []
        for events in self.events.values():
            for ev in events:
                if ev.get("kind") == "handoff" and ev.get("beacon_id"):
                    found.append(ev)
        found.sort(key=lambda ev: ev.get("at", 0.0), reverse=True)
        offerable, expired = handoff_ttl.partition(
            found, beacons=self._live_beacons())
        for record, reason in expired:
            console.print(
                f"[dim]handoff {record.get('beacon_id')} not offered: "
                f"{handoff_ttl.describe(reason)}[/dim]")
        return [str(r["beacon_id"]) for r in offerable]

    def do_handoff(self, arg: str):
        """handoff [list|beacon <id>|take [<id>]] - beacons this run handed to the C2

        AutoMode establishes beacons but used to only be able to hand over
        automatically, inside the run. This surfaces the same information as
        an explicit command: what is available, and a choice to take it.
        """
        parts = arg.split()
        sub = parts[0].lower() if parts else "list"
        beacons = self._pending_handoffs()

        if sub in ("list", ""):
            if not beacons:
                notifier.info("No beacon handoff from this run yet.")
                notifier.info("Run `launch` (or `resume`) first — a handoff "
                              "appears once a beacon has checked in.")
                return
            table = Table(title="Handoffs from this run", border_style="cyan")
            table.add_column("Beacon", style="cyan")
            table.add_column("Take it")
            for bid in beacons:
                table.add_row(bid, f"handoff take {bid}")
            console.print(table)
            return

        if sub == "beacon":
            if len(parts) < 2:
                notifier.error("Usage: handoff beacon <id>")
                return
            self.do_c2(parts[1])
            return

        if sub == "take":
            # `handoff take` with no id means "the one you just got", which
            # is the common case: an operator does not memorise ids.
            bid = parts[1] if len(parts) > 1 else (beacons[0] if beacons else "")
            if not bid:
                notifier.error("Nothing to take: this run produced no beacon "
                               "handoff. Run `handoff` to check.")
                return
            if beacons and bid not in beacons:
                notifier.warn(f"{bid} is not a handoff from this run — "
                              "opening the C2 anyway.")
            self.do_c2(bid)
            return

        notifier.error(f"Unknown handoff subcommand: {sub}")
        notifier.info("Usage: handoff [list | beacon <id> | take [<id>]]")

    def do_c2(self, arg: str):
        """c2 [<beacon-id>] - enter the C2 Control Plane on this engagement

        The C2 used to be reachable only through the MANUAL shell (or by
        re-launching the process with --c2), which made the operator walk
        through a surface they did not want just to use a beacon they already
        had. Passing a beacon id opens the C2 straight into that beacon's
        context; with no argument the global context is used, and a handoff
        from this run is offered.
        """
        from phantom.core.c2_shell import run_c2
        bid = (arg or "").strip() or None
        if bid is None:
            beacons = self._pending_handoffs()
            if beacons:
                bid = beacons[0]
                console.print(f"[dim]Using beacon from this run: {bid}[/]")
            else:
                notifier.info("No beacon handoff from this run — opening the "
                              "global C2 context.")
        console.print("[dim]Entering the C2 Control Plane — `exit` to return "
                      "to AUTO-MODE.[/]")
        try:
            run_c2(preferred_beacon=bid)
        except KeyboardInterrupt:
            console.print("\n[dim]Returning to AUTO-MODE.[/]")

    def do_context(self, arg: str):
        """context - show the current engagement context in one place

        Target, scope, run flags, whether a run happened, and which beacons
        are waiting. This is the answer to "what does Phantom think is going
        on right now", asked without reading three different commands.
        """
        table = Table(title="Engagement context", border_style="cyan")
        table.add_column("Field", style="cyan")
        table.add_column("Value")
        table.add_row("mode", "AUTO-MODE")
        table.add_row("session target", session.target or "-")
        table.add_row("targets",
                      ", ".join(self.targets) if self.targets else "-")
        scope = getattr(session, "scope", None)
        table.add_row("scope", str(scope) if scope else "[dim]none[/dim]")
        table.add_row("goal", str(self.flags.get("goal", "-")))
        table.add_row("profile", str(self.flags.get("profile", "-")))
        table.add_row("agents", str(self.flags.get("agents", 0)))
        table.add_row("engine", str(self.flags.get("engine", "-")))
        table.add_row("mode flags",
                      ", ".join(k for k in ("aggressive", "stealth", "speed",
                                            "llm", "experience", "evolution",
                                            "force_network")
                                if self.flags.get(k)) or "-")
        table.add_row("last run", "yes" if self.has_run else "no")
        beacons = self._pending_handoffs()
        table.add_row("beacon handoff",
                      ", ".join(beacons) if beacons else "[dim]none[/dim]")
        console.print(table)

    def do_workspace(self, arg: str):
        """workspace - list the surfaces of this engagement and how to reach them

        One place that answers "what can I do from here": the autonomous
        orchestrator, the manual modules, and the C2 control plane are three
        views of the SAME engagement, not three separate programs.
        """
        table = Table(title="Engagement workspaces", border_style="cyan")
        table.add_column("Surface", style="cyan")
        table.add_column("Enter with", style="green")
        table.add_column("For")
        table.add_row("AUTO-MODE", "(current)", "Planning, agents, launch")
        table.add_row("MANUAL", "manual", "Modules, AD graph, OSINT, report")
        table.add_row("C2 Control Plane", "c2 [<beacon>]",
                      "Listener, beacons, tasks, remote session")
        table.add_row("Timeline / evidence", "status", "Per-target run events")
        table.add_row("Scope", "scope", "CIDR list for this engagement")
        table.add_row("Session", "export <file>.pm", "Save/restore the engagement")
        console.print(table)

    def do_exit(self, arg: str):
        """exit - leave AUTO-MODE"""
        return self.do_back(arg)

    do_quit = do_exit

    def do_help(self, arg: str):
        if arg.strip():
            super().do_help(arg)
            return
        table = Table(title="Phantom Auto-Mode Commands", border_style="cyan")
        table.add_column("Command")
        table.add_column("Description")
        rows = [
            ("targets", "List targets | add <t[,t...]> | rm <t>"),
            ("scope", "List scope | add <cidr> | rm <cidr>"),
            ("flags", "Show/change run flags (aggressive, stealth, speed, agents, goal, profile, llm, experience, force_network, engine)"),
            ("plan", "Dry-run the planned kill chain (executes nothing)"),
            ("review", "Show the self-improvement status: authored patterns, budgets, learned capabilities, beta PRs"),
            ("launch", "Run the autonomous kill chain on the current targets"),
            ("resume", "Continue from a checkpoint.json or an imported .pm"),
            ("status", "Per-target event summary of the last run"),
            ("export", "Export the engagement to a portable <file>.pm"),
            ("import", "Restore an engagement from a <file>.pm"),
            ("manual", "Enter the MANUAL module shell on this engagement"),
            ("c2 [<beacon>]", "Enter the C2 Control Plane (optionally straight into a beacon)"),
            ("handoff", "Show the beacons this run handed over | take [<id>] to open one"),
            ("guardrails", "Show the safety controls for this engagement | enable/disable <key>"),
            ("context", "Show target, scope, flags, run state and pending beacons"),
            ("workspace", "List the surfaces of this engagement and how to reach them"),
            ("back", "Leave AUTO-MODE"),
        ]
        for c, d in rows:
            table.add_row(c, d)
        console.print(table)
        console.print("[dim]Type 'help <command>' for details.[/]")

    def default(self, line: str):
        notifier.error(f"Unknown command: {line}")
        notifier.info("Type 'help' for available commands.")


def summarize_bundle(result: Dict[str, Any]) -> str:
    from phantom.utils.session_bundle import summarize
    return summarize(result)


def run_auto_shell():
    """Start the interactive AUTO-MODE shell."""
    try:
        shell = AutoShell()
        shell.cmdloop()
    except SystemExit:
        pass
    except KeyboardInterrupt:
        console.print("\n[dim]AUTO-MODE closed.[/dim]\n")
