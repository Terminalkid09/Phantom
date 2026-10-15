"""auto_help.py — ONE registry that decides what the AUTO shell's `help` shows
and what every `flags` key accepts.

The AUTO shell answered `help` with a hand-written table and `flags` with a
hand-written docstring. Both had drifted from the code they described:

  * `do_flags`' docstring told the operator ``goal (<choices>)`` and
    ``profile (<choices>)`` — literal placeholders that were never filled in,
    while the 12 goals and 6 profiles sat as constants in the same file. The
    operator asking "which goals exist?" was answered with the word
    "<choices>".
  * the `help` table's `flags` row listed the flag KEYS but not their values,
    and had already lost `verbose` and `evolution` — which the `flags` table
    itself prints. Help that knows less than the shell is help that lies.
  * `flags profile` with no value answered `Usage: flags profile <value>`:
    the accepted values appeared only after typing a WRONG one. The answer
    existed, hidden behind an error.

So the registry is the single source of truth: `do_help` renders from it,
`do_flags` validates and explains from it, and `tests/test_autoshell_help.py`
pins the two together (every `do_*` command must have a spec, every spec must
have a handler). Nothing here executes anything — it is presentation, and the
handlers stay where they were.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ── the vocabularies the flags validate against ─────────────────────────────
#: Goals are declared once, in `automation/goals.py`; this order is the one
#: `help` presents, from the broad sweep to the narrowest objective.
GOALS: Tuple[str, ...] = (
    "deep", "deliver", "complete_kill_chain", "footprint", "beacon",
    "creds", "identity", "post_exploit", "ad", "crack", "lateral", "cleanup",
)
#: Environment postures (see `swarm/profile_policy.py`: the profile decides
#: chain, difficulty and thin-surface policy — it is not a label).
PROFILES: Tuple[str, ...] = (
    "smb", "enterprise", "cloud", "financial", "government", "mobile",
)
#: `goals.engine_for` honours "swarm" only for goals that DECLARE a swarm
#: chain; anything else falls back to the agent path with a printed note.
ENGINES: Tuple[str, ...] = ("agent", "swarm")


# ── flags ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class FlagSpec:
    """One `flags <key>`: what it accepts, and what it does."""

    key: str
    kind: str                        # "bool" | "int" | "choice"
    help: str                        # shown in the flag table / `help flags`
    choices: Tuple[str, ...] = ()
    default: Any = None

    def accepts(self) -> str:
        """The accepted values, as the operator should read them."""
        if self.kind == "choice":
            return "one of: " + ", ".join(self.choices)
        if self.kind == "bool":
            return "on | off"
        return "a whole number (0 = auto, or N >= 1)"

    def render(self, value: Any) -> str:
        """The value as the flags table shows it."""
        if self.kind == "bool":
            return "on" if value else "off"
        if self.kind == "int":
            return "auto" if not value else str(value)
        return str(value)

    def valid(self, value: str) -> bool:
        text = (value or "").strip().lower()
        if self.kind == "bool":
            return text in ("on", "off", "true", "false", "1", "0", "yes", "no")
        if self.kind == "int":
            try:
                return int(text) >= 0
            except ValueError:
                return False
        return text in self.choices


FLAGS: Tuple[FlagSpec, ...] = (
    FlagSpec("aggressive", "bool", "louder and faster, fewer safe defaults",
             default=False),
    FlagSpec("stealth", "bool", "paranoid timing and low-noise capability mix",
             default=False),
    FlagSpec("speed", "bool", "prefer the shortest path over the quietest one",
             default=False),
    FlagSpec("agents", "int", "parallel sub-agents (0 = let the planner decide)",
             default=0),
    FlagSpec("goal", "choice", "what the run must achieve",
             choices=GOALS, default="deliver"),
    FlagSpec("profile", "choice",
             "the environment posture; it picks the chain and the difficulty",
             choices=PROFILES, default="enterprise"),
    FlagSpec("llm", "bool",
             "let the model reason; it never executes (proposals are gated)",
             default=False),
    FlagSpec("verbose", "bool",
             "stream every agent event through the shared contract",
             default=False),
    FlagSpec("experience", "bool",
             "persist cause->repair cases so the NEXT engagement starts smarter",
             default=False),
    FlagSpec("evolution", "bool",
             "self-improvement: author reviewable PRs for stable failure "
             "patterns (needs llm + lab)",
             default=False),
    FlagSpec("force_network", "bool",
             "engage a whole CIDR range instead of host discovery only",
             default=False),
    FlagSpec("force_profile", "bool",
             "keep the chosen profile even when it contradicts the target "
             "class (e.g. `mobile` for an IP that IS the phone)",
             default=False),
    FlagSpec("engine", "choice", "which orchestration engine to run",
             choices=ENGINES, default="agent"),
)

BY_KEY: Dict[str, FlagSpec] = {spec.key: spec for spec in FLAGS}

#: The boolean keys, derived (never hand-listed): a flag added to FLAGS above
#: is a boolean the moment its kind says so.
BOOL_KEYS: Tuple[str, ...] = tuple(s.key for s in FLAGS if s.kind == "bool")


def flag_keys() -> Tuple[str, ...]:
    return tuple(spec.key for spec in FLAGS)


def flag_by_key(key: str) -> Optional[FlagSpec]:
    return BY_KEY.get((key or "").strip().lower())


def default_flags() -> Dict[str, Any]:
    """The shell's flag dict, built FROM the registry.

    Derived on purpose: a flag that exists in the registry but not in the
    shell (or the reverse) is exactly the drift this module removes, and the
    test that pins them can only pass if they come from one place.
    """
    return {spec.key: spec.default for spec in FLAGS}


def flag_rows(flags: Dict[str, Any]) -> List[Tuple[str, str, str, str]]:
    """(key, value, accepts, help) for the flags table, in registry order."""
    return [(spec.key, spec.render(flags.get(spec.key)), spec.accepts(),
             spec.help) for spec in FLAGS]


def flags_summary() -> str:
    """The one-line description `help` gives for the `flags` command."""
    return ("Show or change every run flag: " + ", ".join(flag_keys()))


# ── commands ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CommandSpec:
    """One AUTO shell command as `help` presents it."""

    name: str
    usage: str
    description: str
    category: str
    #: the `do_<handler>` method on AutoShell (defaults to `name`)
    handler: str = ""
    aliases: Tuple[str, ...] = field(default_factory=tuple)
    #: extra prose shown by `help <command>`, when the usage needs more
    detail: str = ""

    @property
    def handler_name(self) -> str:
        return self.handler or self.name

    @property
    def names(self) -> Tuple[str, ...]:
        return (self.name,) + tuple(self.aliases)


#: Kept in the order an operator meets them: what the engagement contains,
#: how it is configured, how it runs, what it produced, where it can go next.
COMMANDS: List[CommandSpec] = [
    # ── the engagement ──
    CommandSpec("targets", "targets | targets add <t[,t...]> | targets rm <t>",
                "List the target list | add one or more | remove one",
                "Engagement", detail=(
                    "The AUTO shell holds a LIST of targets (the core shell "
                    "holds one). `add` accepts a comma-separated list.")),
    CommandSpec("scope", "scope | scope add <cidr> | scope rm <cidr>",
                "Show or change the authorized scope for this engagement",
                "Engagement", detail=(
                    "Network targets are REFUSED until a scope is declared: "
                    "the gate fails closed. For a lab/CTF, declare the "
                    "exception with PHANTOM_ALLOW_UNSCOPED=1 instead. (The "
                    "core manual shell spells this `set scope`.)")),

    # ── configuration ──
    CommandSpec("flags", "flags | flags <key> <value>",
                flags_summary(), "Configuration", detail=(
                    "`flags` with no argument lists every key with its current "
                    "value and its accepted values. `help flags` prints the "
                    "same table.")),

    # ── plan & run ──
    CommandSpec("plan", "plan [target...]",
                "Dry-run the planned kill chain (executes nothing)",
                "Plan & run"),
    CommandSpec("launch", "launch [target...]",
                "Run the autonomous kill chain on the current targets",
                "Plan & run", detail=(
                    "Refuses before starting when a prerequisite is missing "
                    "(no scope for network targets, no listener for a "
                    "callback-bound goal): the outcome is reported as "
                    "`blocked_preflight`, not as a goal that failed.")),
    CommandSpec("resume", "resume <checkpoint.json|session.pm>",
                "Continue from a checkpoint.json or an imported .pm",
                "Plan & run"),
    CommandSpec("run", "run",
                "Refused here: the whole-chain command is `launch`",
                "Plan & run", detail=(
                    "`run` executes ONE module and belongs to the MANUAL "
                    "shell. In AUTO-MODE it used to start the entire kill "
                    "chain, so one word meant two things across the two "
                    "shells; now it names the right command instead.")),

    # ── results ──
    CommandSpec("status", "status",
                "Per-target event summary of the last run", "Results"),
    CommandSpec("context", "context",
                "Show target, scope, flags, run state and pending beacons",
                "Results"),
    CommandSpec("workspace", "workspace",
                "List the surfaces of this engagement and how to reach them",
                "Results"),
    CommandSpec("review", "review",
                "Self-improvement status: authored patterns, budgets, "
                "learned capabilities, beta PRs", "Results"),

    # ── session ──
    CommandSpec("export", "export <file>.pm",
                "Export the engagement to a portable <file>.pm", "Session"),
    CommandSpec("import", "import <file>.pm",
                "Restore an engagement from a <file>.pm", "Session"),

    # ── other surfaces ──
    CommandSpec("manual", "manual [<target>]",
                "Enter the MANUAL module shell on this engagement",
                "Surfaces"),
    CommandSpec("c2", "c2 [<beacon>]",
                "Enter the C2 Control Plane (optionally straight into a beacon)",
                "Surfaces"),
    CommandSpec("handoff", "handoff [list | beacon <id> | take [<id>]]",
                "Show the beacons this run handed over | take one",
                "Surfaces"),

    # ── ops ──
    CommandSpec("guardrails",
                "guardrails [list | why | enable <k> | disable <k> | record]",
                "Show or change the safety controls for this engagement",
                "Ops"),
    CommandSpec("deps", "deps [report | install <tool> ...]",
                "External tools Phantom needs, and how it would install them",
                "Ops"),
    CommandSpec("social", "social [graph [--run|--json|--graphml F] | "
                "emails <addr>]",
                "Identity graph and account-existence checks", "Ops"),
    CommandSpec("llm", "llm [journal [refusals] | propose [n] | proposals | "
                "accept <id> | reject <id> [reason] | clear]",
                "What the model wanted, and why the deterministic layer "
                "allowed or refused it", "Ops"),

    # ── navigation ──
    CommandSpec("back", "back", "Leave AUTO-MODE", "Navigation"),
    CommandSpec("exit", "exit / quit",
                "Leave AUTO-MODE (alias of `back`)", "Navigation",
                handler="exit", aliases=("quit",)),
    CommandSpec("help", "help [command]",
                "List every command, or one command in detail — including "
                "every accepted flag value", "Navigation", handler="help"),
]

BY_NAME: Dict[str, CommandSpec] = {}
for _spec in COMMANDS:
    for _name in _spec.names:
        BY_NAME[_name] = _spec


def by_name(name: str) -> Optional[CommandSpec]:
    return BY_NAME.get((name or "").strip().lower())


def grouped(specs: Optional[List[CommandSpec]] = None
            ) -> List[Tuple[str, List[CommandSpec]]]:
    """Group in first-seen category order, so help reads as a workflow."""
    order: List[str] = []
    buckets: Dict[str, List[CommandSpec]] = {}
    for spec in (specs if specs is not None else COMMANDS):
        if spec.category not in buckets:
            buckets[spec.category] = []
            order.append(spec.category)
        buckets[spec.category].append(spec)
    return [(name, buckets[name]) for name in order]


def handler_names() -> Tuple[str, ...]:
    """Every `do_*` method the registry expects the shell to implement."""
    return tuple(spec.handler_name for spec in COMMANDS)
