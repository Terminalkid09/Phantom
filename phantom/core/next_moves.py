"""next_moves.py — the manual core's ranked next moves.

`suggest` used to be a flat, per-module list of commands: the operator read
it, picked one, then walked the module flow (`use` -> `run` -> interactive
selection) to actually do anything. Three steps for what is really one
decision, and a second, different decision engine (`_next_step`) chose the
module for the adaptive `run`.

This module produces ONE ranked list both commands read:

  * concrete moves  — the state-aware commands the modules generate, tagged
    with evidence / trust / preflight by :mod:`suggest_meta`;
  * chain steps     — capabilities the planner would take next toward the
    engagement goal. They rank their module's commands higher (a "+chain
    bonus") and, when a module offers no concrete command but the chain
    needs that step, they appear as an executable row of their own: the
    planner's step is the WHY, the module's own top state-aware suggestion
    is the command shown and executed;
  * rejected paths  — what the planner considered and refused, with the real
    reason. "Why not kerberoast?" now has an answer instead of silence.

Every row shows exactly the command `run <n>` will execute, and it goes
through the same guards the module flow uses (scope + tool check +
aggressive confirmation). Nothing here decides policy — it only orders it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from phantom.core.session import session

# Modules whose state-aware suggestions feed the ranking. `wifi` is
# deliberately absent: its suggestions are unconditional interface setup
# (airmon-ng) that answers no finding, so it is noise in a network
# engagement. It stays reachable the normal way (`use wifi`).
SUGGEST_MODULES = ("scan", "web", "exploit", "brute", "osint", "payload",
                   "pivot", "wordlist")

# capability id -> manual module performing the equivalent step. The SHELL
# reads this map (as `_CAPABILITY_MODULE`) so the ranking and the adaptive
# `run` can never disagree on where a capability lives.
CAPABILITY_MODULE = {
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

# How much the planner's chain raises a module's commands in the ranking.
_CHAIN_BONUS = 0.15
# A chain step with no concrete command still needs a row: it is the move.
_STRUCTURAL_TRUST = 0.65
# How many commands with NO evidence behind them the ranked list may carry.
# They answer nothing found yet; they are the module's recipe book, and
# letting them fill the list is what made `suggest` feel mechanical.
_MAX_UNEVIDENCED = 3
_DEFAULT_PROFILE = "enterprise"
_NO_RUNNER = ("no-direct-runner", "manual-only", "no-auto-command")


def _display(command: str) -> str:
    """Command as the operator should read it (no internal AGGRESSIVE marker)."""
    return (command or "").replace(" AGGRESSIVE", "").strip()


@dataclass
class Move:
    """One ranked, directly executable next move."""
    index: int = 0
    title: str = ""                 # what the operator reads
    command: str = ""               # exact command `run <n>` executes (raw)
    module: str = ""                # owning module
    capability: str = ""            # planner capability, when from the chain
    why: str = ""
    trust: float = 0.5
    chain: bool = False             # ordered by the planner (kill-chain step)
    blockers: List[str] = field(default_factory=list)

    def runnable(self) -> bool:
        """True when `run <n>` can execute this move HERE, right now.

        A missing binary or an out-of-scope target is not a move: the row
        stays (the operator must see it) but it ranks below what can run.
        """
        if not self.command and not self.module:
            return False
        if any(b in _NO_RUNNER for b in self.blockers):
            return False
        return not any(b.startswith(("missing:", "out-of-scope"))
                       for b in self.blockers)

    def badge(self) -> str:
        marks = []
        if self.chain:
            marks.append("[cyan]plan[/]")
        if self.command:
            if self.trust >= 0.75:
                marks.append("[green]●●●[/]")
            elif self.trust >= 0.5:
                marks.append("[yellow]●●○[/]")
            else:
                marks.append("[red]●○○[/]")
        for blocker in self.blockers:
            marks.append(f"[red]{blocker}[/]")
        return " ".join(marks)


@dataclass
class RankedMoves:
    moves: List[Move] = field(default_factory=list)
    rejected: List[Dict[str, str]] = field(default_factory=list)
    goal: str = ""


# ---------------------------------------------------------------------------
# the target-type-first decision (shared with PhantomShell._next_step)
# ---------------------------------------------------------------------------

def engagement_goal() -> str:
    """The chain goal the manual core works toward with the live facts.

    Identity targets converge on the identity goal; everything else on the
    beacon chain (the same default the auto-mode uses).
    """
    try:
        from phantom.automation.guidance.targets import (
            classify_target, is_identity_target)
        if is_identity_target(classify_target(session.target)):
            return "identity"
    except Exception:
        pass
    return "beacon"


def base_move() -> Optional[Move]:
    """The target-type-first move: identity -> osint, blind network -> scan.

    This is the first decision the adaptive `run` has always made, now
    expressed ONCE and reused by the ranking (it used to be duplicated
    between `_next_step` and the module-count heuristic).
    """
    if not (session.target or "").strip():
        return None          # no target: nothing to aim a move at
    try:
        from phantom.automation.guidance.targets import (
            classify_target, is_identity_target)
    except Exception:
        return None
    try:
        ttype = classify_target(session.target)
        if is_identity_target(ttype):
            done = set((session.results or {}).keys())
            if "osint" not in done:
                return Move(
                    module="osint", trust=0.9,
                    why="identity target: build the dossier (emails, phones, "
                        "platforms) before touching any network")
            return Move(
                module="scan", trust=0.7,
                why="identity chain complete — map the victim's IP/network "
                    "position")
    except Exception:
        return None
    try:
        from phantom.core.knowledge import knowledge_summary
        counts = knowledge_summary()
    except Exception:
        counts = {}
    if counts.get("service", 0) == 0:
        return Move(module="scan", trust=0.7,
                    why="no services discovered yet — enumerate the target "
                        "first")
    return None


# ---------------------------------------------------------------------------
# candidate gathering
# ---------------------------------------------------------------------------

def _plan_signals() -> Tuple[str, List[dict], List[Dict[str, str]]]:
    """(goal, planner steps, rejected paths) from the live WorldModel.

    Never raises: without a WorldModel/registry the ranking simply has no
    chain signal and falls back to evidence alone.
    """
    goal = engagement_goal()
    try:
        from phantom.core.knowledge import session_wm
        from phantom.automation.planner import Planner
        from phantom.automation.guidance.commands import make_registry
        from phantom.automation.guidance.stealth import (
            StealthConfig, StealthEngine)
        from phantom.automation.guidance.threatmodel import BlueTeamModel
        wm = session_wm()
        profile = getattr(session, "threat_profile", "") or _DEFAULT_PROFILE
        stealth = StealthEngine(wm, StealthConfig(),
                                BlueTeamModel.for_profile(profile))
        plan = Planner(make_registry(), stealth).plan(wm, goal=goal,
                                                      max_steps=8)
        steps = [{
            "capability": s.capability.id,
            "reason": s.reason or s.capability.description or "",
            "exec_class": getattr(s.capability, "exec_class", "shell_command"),
        } for s in plan.steps]
        rejected = [r.to_dict()
                    for r in (getattr(plan, "rejected", None) or [])]
        return goal, steps, rejected
    except Exception:
        return goal, [], []


def _module_of(shell, module: str):
    try:
        return shell._instantiate_module(module) if shell is not None else None
    except Exception:
        return None


def _commands_of(instance) -> dict:
    try:
        return dict(instance.suggest_commands() or {})
    except Exception:
        return {}


def _module_top_command(instance) -> str:
    """First state-aware command a module would run (raw, marker intact)."""
    for cmds in _commands_of(instance).values():
        for cmd in (cmds or []):
            if (cmd or "").strip():
                return cmd.strip()
    return ""


def _command_moves(shell, chain_modules) -> List[Move]:
    """Concrete, evidence-tagged commands, one ``Move`` per command."""
    from phantom.core.suggest_meta import tag_suggestions
    out: List[Move] = []
    for module in SUGGEST_MODULES:
        instance = _module_of(shell, module)
        if instance is None:
            continue
        groups = _commands_of(instance)
        if not groups:
            continue
        for tagged in tag_suggestions(groups):
            chain = module in chain_modules
            blockers: List[str] = []
            if tagged.tool_missing:
                blockers.append(f"missing:{tagged.tool}")
            if tagged.already_ok:
                blockers.append("ran-ok")
            if tagged.out_of_scope:
                blockers.append("out-of-scope")
            out.append(Move(
                title=tagged.command,
                command=tagged.metadata.get("raw") or tagged.command,
                module=module, why=tagged.why,
                trust=min(1.0, round(tagged.trust + (_CHAIN_BONUS if chain
                                                     else 0.0), 2)),
                chain=chain, blockers=blockers))
    return out


def _chain_steps(shell, steps, moves) -> List[Move]:
    """Chain steps that no concrete command already represents.

    One row per module (the planner's first step for it wins): three
    identity capabilities all mapping to `osint` are one move, not three.
    The row's command is the module's own top state-aware suggestion, so
    the operator sees what will actually run — never a silent guess.
    """
    covered = {m.module for m in moves if m.module}
    out: List[Move] = []
    for step in steps:
        cap = step.get("capability", "")
        module = CAPABILITY_MODULE.get(cap, "")
        if not cap or (module and module in covered):
            continue
        if module:
            covered.add(module)
        command = ""
        instance = _module_of(shell, module) if module else None
        if instance is not None:
            command = _module_top_command(instance)
        blockers: List[str] = []
        if not module:
            blockers.append(
                "no-direct-runner"
                if step.get("exec_class", "shell_command") != "shell_command"
                else "manual-only")
        elif not command:
            blockers.append("no-auto-command")
        if command:
            title = _display(command)
        elif module:
            title = f"use {module}"
        else:
            title = cap            # no module yet: name the step, never "use "
        out.append(Move(
            title=title, command=command, module=module, capability=cap,
            why=step.get("reason", ""), chain=True,
            trust=_STRUCTURAL_TRUST, blockers=blockers))
    return out


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------

def rank_next_moves(shell=None, limit: int = 9,
                    remember: bool = True) -> RankedMoves:
    """The single ranked decision list, and the paths NOT taken.

    Ordering: the target-type-first move when nothing else covers its
    module, then trust (chain steps carry the planner bonus), with
    deterministic tie-breaks so two runs on the same facts are identical.

    `remember=False` computes the ranking without touching what `run <n>`
    will execute (used by the adaptive `_next_step`, which must not clobber
    the operator's numbered list).
    """
    goal, steps, rejected = _plan_signals()
    chain_modules = {CAPABILITY_MODULE.get(s.get("capability", ""), "")
                     for s in steps}
    chain_modules.discard("")

    base = base_move()
    # A move earns its place in the ranked list by EVIDENCE (it answers
    # something found) or by the CHAIN (the planner or the target-type-first
    # decision points there). The rest of a module's catalogue is still one
    # `use <module>` away — it is not a "next move", it is a recipe book,
    # and mixing the two is what made `suggest` feel mechanical.
    keep_modules = set(chain_modules)
    if base is not None and base.module:
        keep_modules.add(base.module)

    moves = _command_moves(shell, chain_modules)
    moves += _chain_steps(shell, steps, moves)
    if base is not None and not any(m.module == base.module for m in moves):
        moves.insert(0, base)

    # what can actually run here outranks what merely exists; then trust;
    # then the chain; then a stable tie-break so two runs are identical
    moves.sort(key=lambda m: (not m.runnable(), -m.trust, not m.chain,
                              m.title))

    # Keep every move that answers EVIDENCE found, points at the CHAIN, or
    # reports an honest gap (a step the manual core cannot run yet). Cap the
    # rest — the catalogue commands with nothing behind them — so a few
    # useful recipes remain without drowning the real next step.
    kept: List[Move] = []
    unevidenced = 0
    for move in moves:
        informational = any(b in _NO_RUNNER for b in move.blockers)
        if informational or move.why or move.module in keep_modules:
            kept.append(move)
            continue
        if unevidenced < _MAX_UNEVIDENCED:
            kept.append(move)
            unevidenced += 1

    ranked = RankedMoves(moves=kept[:max(1, limit)], rejected=rejected,
                         goal=goal)
    for i, move in enumerate(ranked.moves, 1):
        move.index = i
    if remember:
        session.pending_moves = ranked.moves
    return ranked


def pending() -> List[Move]:
    """The moves the last ranking remembered (what `run <n>` executes)."""
    return list(getattr(session, "pending_moves", None) or [])


def render_moves(ranked: RankedMoves, console=None) -> None:
    """Print the ranked list plus the rejected paths (the `suggest` front door)."""
    from phantom.utils.notifier import notifier
    if console is None:
        from rich.console import Console
        console = Console()
    if not ranked.moves:
        notifier.info("No next moves yet — set a target and scan first.")
        return
    console.print("[bold cyan]── NEXT MOVES (ranked, runnable) ──[/]")
    for move in ranked.moves:
        why = f"  [dim]why: {move.why}[/]" if move.why else ""
        console.print(f"  [{move.index:2}] {move.title}{why}  {move.badge()}")
    rejected = ranked.rejected[:4]
    if rejected:
        console.print("[bold cyan]── WHY NOT ──[/]")
        for r in rejected:
            console.print(f"  [dim]· {r.get('capability', '?')} "
                          f"for {r.get('fact', '?')}: "
                          f"{r.get('reason', '')}[/]")
    console.print(
        "  [dim]`run <n>` executes that move here · ●●● trust · missing:<tool>"
        " not installed · ran-ok already succeeded · plan = kill-chain step[/]")


def execute_move(shell, move: Move) -> bool:
    """Execute one ranked move through the normal guards.

    A concrete move is a command: scope + tool check + aggressive
    confirmation, exactly like a preview selection. A chain step that never
    resolved a command falls back to its module's top suggestion, and says
    so instead of pretending it ran the step.
    """
    from phantom.utils.notifier import notifier

    command = (move.command or "").strip()
    if not command:
        if move.module and not any(b in _NO_RUNNER for b in move.blockers):
            instance = _module_of(shell, move.module)
            command = _module_top_command(instance) if instance else ""
    if not command:
        notifier.warn(
            f"Nothing to execute for '{move.title}' — the manual core has no "
            f"direct runner for it yet (use `plan {move.module or ''}` to see "
            "the chain, or drive the module interactively).")
        return False

    from phantom.core.executor import run_commands
    from phantom.utils.aggressive import filter_aggressive_commands
    chosen = filter_aggressive_commands([command])
    if not chosen:
        notifier.warn("Aggressive move skipped.")
        return False
    results = run_commands(chosen, session.target)
    session.add_result(move.module or "suggest", results)
    return True
