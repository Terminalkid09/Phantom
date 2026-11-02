"""Shared UI primitives for the Phantom manual shell.

Module-level banner / status-bar / hint builders plus the shared Rich
``console``. Kept free of heavy imports (automation, C2, knowledge) so
``phantom.core.shell`` boots fast and every command module can reuse them
without import cycles — lazy imports stay inside the functions.
"""
from __future__ import annotations

import os
import sys

from dotenv import load_dotenv
from rich.console import Console

import phantom.core.shell as _pkg  # noqa: E402  (live console: reads the package attr at call time)
from phantom.core.session import session
from phantom.utils.notifier import notifier  # noqa: F401  (re-exported)


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


# ── prompt grammar ────────────────────────────────────────────────────────
# ONE grammar for every layer, so the operator can tell WHERE THEY ARE
# without decoding a colour. Phantom used to have four prompts with three
# different shapes (`phantom(10.0.0.5) > `, plain `[scan:10.0.0.5] > `,
# magenta `C2 (a1b2c3) > `, cyan `AUTO > `) and colour was the only thing
# telling the shell apart from a module — invisible in a log, in a report,
# and on a terminal without colour.
#
#   phantom(target) ❯              the manual shell
#   phantom(target/scan) ❯         inside a module (one layer down)
#   phantom ▸ C2(target) ❯         C2 console (a sub-shell, depth 2)
#   phantom ▸ auto(target) ❯       AUTO-MODE console (depth 2)
#
# The target never disappears, the layer is TEXT, and colour is a secondary
# cue that is dropped entirely when the terminal cannot take it.

_LAYER_COLOR = {
    "root": "\033[1;36m",     # bright cyan
    "module": "\033[36m",      # cyan
    "C2": "\033[1;35m",        # magenta
    "auto": "\033[1;33m",      # yellow
}
_RESET = "\033[0m"


def use_color() -> bool:
    """Whether the prompt may carry ANSI colour at all.

    Honours the NO_COLOR convention (https://no-color.org) and Phantom's own
    switch, and refuses colour on a redirected stream: a prompt written into
    a log file must not be full of escape sequences.
    """
    if os.getenv("NO_COLOR") or os.getenv("PHANTOM_NO_COLOR"):
        return False
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _prompt_glyph() -> str:
    """The prompt's closing mark, ASCII when the console cannot encode `❯`.

    `input(self.prompt)` writes the prompt through the CONSOLE encoding, not
    through Rich: on a cp1252 Windows console an unmappable glyph raises
    UnicodeEncodeError and the operator cannot type at all. Terminals on
    Windows, Linux and macOS are not equally capable, so the glyph is picked
    from the encoding instead of assumed.
    """
    enc = (getattr(sys.stdout, "encoding", "") or "utf-8").lower()
    return "❯" if enc.replace("-", "").replace("_", "") in ("utf8", "utf16", "utf32") else ">"


def build_prompt(layer: str = "", *, status: str = "", depth: int = 1,
                 status_color: str = "") -> str:
    """Build the prompt for a layer — the ONE function every shell uses.

    ``layer`` is empty at the main shell, a module name one layer down, or
    ``C2`` / ``auto`` for a sub-shell (``depth=2``). ``status`` adds a
    bracketed detail (the active beacon); ``status_color`` is the ANSI code
    that detail should carry (C2 liveness: green/yellow/red) and is ignored
    when colour is unavailable. ``glyph`` (the closing mark) is chosen from
    the console encoding, never assumed.
    """
    target = session.target or ""
    if depth >= 2 and layer:
        plain = f"phantom ▸ {layer}" + (f"({target})" if target else "")
    elif layer:
        plain = f"phantom({target}/{layer})" if target else f"phantom({layer})"
    else:
        plain = f"phantom({target})" if target else "phantom"

    status_txt = f" [{status}]" if status else ""
    glyph = _prompt_glyph()
    if not use_color():
        return f"{plain}{status_txt} {glyph} "

    key = layer if depth >= 2 else ("module" if layer else "root")
    code = _LAYER_COLOR.get(key, _LAYER_COLOR["root"])
    if status_txt and status_color:
        # the liveness colour is closed and the layer colour reopened, so the
        # prompt after the bracket keeps its own accent
        status_txt = f" [{status_color}{status}{code}]"
    return f"{code}{plain}{status_txt}{_RESET} {glyph} "


def layer_line(layer: str = "", depth: int = 1) -> str:
    """Plain-text answer to `where` — the prompt's information, on demand.

    Registered at EVERY layer (main shell, modules, C2, AUTO) under the same
    name, because a command that only works in one of four shells is the same
    confusion the shared prompt grammar exists to remove.
    """
    target = session.target or "—"
    scope = ", ".join(session.scope) if session.scope else "—"
    if depth >= 2 and layer:
        where = f"{layer} console  ('back' returns to the main shell)"
        path = f"phantom > {layer}({target})"
    elif layer:
        where = f"{layer} module  ('back' returns to the main shell)"
        path = f"phantom({target}/{layer})"
    else:
        where = "main shell  (below: use <module>, c2, agent)"
        path = f"phantom({target})"
    return (f"  layer  : {where}\n"
            f"  target : {target}\n"
            f"  scope  : {scope}\n"
            f"  prompt : {path}")


def status_signature() -> tuple:
    """The values `build_status_bar()` renders, as a comparable tuple.

    `postcmd` used to redraw a separator, nine counters and a hint line after
    EVERY command, so the output of the command itself scrolled away under
    chrome that had not changed. Comparing this signature lets the bar print
    only when something in it actually moved.
    """
    try:
        from phantom.core.knowledge import knowledge_summary
        counts = knowledge_summary()
        knowledge = (counts.get("service", 0), counts.get("creds", 0),
                     counts.get("vuln", 0),
                     counts.get("web_app", 0) + counts.get("hunt", 0))
    except Exception:
        knowledge = ()
    try:
        from phantom.core.c2_server import c2_state
        beacons = len(c2_state.get_beacons())
    except Exception:
        beacons = -1
    return (session.target or "", tuple(session.scope or ()), knowledge,
            beacons)


def ask_to_install(tool: str, cmd) -> bool:
    """Ask the operator, in the shell, before running a package manager.

    ONE policy for every door that can install software. There used to be two:
    `deps install` asked (and refused in a non-interactive shell) while
    `install <tool>` ran the package manager straight away — the audit called
    it "two doors, two policies". Both now call this.

    Defaults to NO on anything but an explicit yes, and treats a broken or
    non-interactive prompt as a refusal: an automated run must never install
    software on the operator's machine because a scan wanted a tool.
    """
    from rich.prompt import Confirm
    try:
        return bool(Confirm.ask(
            "Install " + tool + "?  ($ " + " ".join(map(str, cmd)) + ")",
            default=False))
    except Exception:
        return False


def _context_hint() -> str:
    """Faded one-line hint: what to do NEXT given the current state.
    Shown after every command so the operator never gets stuck reading
    docs — the shell tells you the obvious next move."""
    # THREE hints, one line: the fourth used to be a generic `run` that was
    # still proposed after the scan it belongs to. The list is state-driven,
    # so a satisfied step stops being suggested at all.
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
    return "[dim]▸ " + "   ".join(hints[:3]) + "[/dim]"


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

    Rendered by `postcmd` only when `status_signature()` CHANGED — redrawing
    an identical bar after every command pushed the command's own output
off the screen, which is the defect the signature exists to remove. The
    documented behaviour is "printed when the engagement state moves", not
    "printed after every command"."""
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
[bold bright_white]╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝[/bold bright_white]
  [dim]v3.0.0 · Offensive Security Framework · {now}[/dim]
"""


def print_transport_status(status: dict) -> None:
    from rich.table import Table
    table = Table(title="[bold]Transport Capability[/]", border_style="cyan")
    table.add_column("Channel", style="cyan", no_wrap=True)
    table.add_column("Status", style="white")
    table.add_column("Detail / how to enable", style="dim")
    for name, st in status.items():
        mark = "[green]ready[/]" if st.get("ready") else "[yellow]missing[/]"
        table.add_row(name, mark, st.get("detail", ""))
    _pkg.console.print(table)


def print_sandbox_status() -> None:
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
    _pkg.console.print(table)
    notifier.info("Install clamscan/yara or set PHANTOM_SANDBOX_VM_EXEC to "
                  "raise the gate from one engine to multi-engine + VM.")


def print_toolbelt_status() -> None:
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
    _pkg.console.print(table)
