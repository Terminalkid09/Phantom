"""Session & config commands: set/show/note/notes/history, sessions, profiles."""
from __future__ import annotations

import json
import os

from phantom.core.notes import show_notes
from phantom.core.scope import is_in_scope
from phantom.core.session import session
import phantom.core.shell as _sh  # live console: _sh.console resolves the package attr at call time (test patch point)
from phantom.utils.notifier import notifier


def cmd_save_profile(shell, name: str):
    """save-profile <name> — save current settings as a profile."""
    if not name.strip():
        notifier.error("Usage: save-profile <name>")
        return
    shell.save_profile(name.strip())


def cmd_load_profile(shell, name: str):
    """load-profile <name> — load a profile."""
    if not name.strip():
        notifier.error("Usage: load-profile <name>")
        return
    shell.load_profile(name.strip())


def cmd_list_profiles(shell, arg: str):
    """List all saved profiles."""
    profile_dir = os.path.expanduser("~/.phantom/profiles")
    if not os.path.exists(profile_dir):
        notifier.warn("No profiles found.")
        return
    profiles = [f.replace(".json", "") for f in os.listdir(profile_dir) if f.endswith(".json")]
    if not profiles:
        notifier.warn("No profiles found.")
        return
    _sh.console.print("[cyan]Available Profiles:[/]")
    for p in profiles:
        _sh.console.print(f"  [white]- {p}[/]")


def cmd_set(shell, arg: str):
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


def cmd_show(shell, arg: str):
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
        _sh.console.print(table)
    elif arg == "scope":
        if session.scope:
            _sh.console.print(f"[cyan]Scope: {', '.join(session.scope)}[/]")
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
        _sh.console.print(table)
        pending = wm.pending_hypotheses()
        if pending:
            _sh.console.print(f"[bold green]▶ {len(pending)} live hypothesis(es) "
                          "— type 'suggest' inside any module to see them.[/]")
        notifier.info("Findings here feed every module's suggestions and the report.")
    else:
        notifier.error("Usage: show session | show scope | show mode | show knowledge")


def cmd_note(shell, arg: str):
    """note "<text>" — add an inline note to the session"""
    text = arg.strip().strip('"').strip("'")
    if not text:
        notifier.error("Usage: note \"your note here\"")
        return
    session.add_note(text)
    notifier.success("Note added.")


def cmd_notes(shell, arg: str):
    """Display all notes in the current session"""
    show_notes()


def cmd_save_session(shell, name: str):
    """save-session <name> — save current session to disk"""
    name = name.strip()
    if not name:
        notifier.error("Usage: save-session <name>")
        return
    session.save(name)
    notifier.success(f"Session saved: {name}.json")


def cmd_load_session(shell, name: str):
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


def cmd_list_sessions(shell, arg: str):
    """List all saved sessions (manual .json + auto .pm bundles)"""
    saved = session.list_saved()
    if saved:
        _sh.console.print("[bold]Manual sessions:[/]")
        for s in saved:
            _sh.console.print(f"  [cyan]{s}[/]")
    try:
        from phantom.utils.auto_session import list_auto
        auto = list_auto()
    except Exception:
        auto = []
    if auto:
        _sh.console.print("[bold]Auto-session bundles (.pm, encrypted):[/]")
        for a in auto:
            _sh.console.print(f"  [cyan]{a['name']}[/]  [dim]target {a['target']} · "
                          f"{a['findings']} findings · {a['mtime']} · "
                          f"{a['size']} B[/]")
    if not saved and not auto:
        notifier.warn("No saved sessions.")


def cmd_export_session(shell, arg: str):
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


def cmd_import_session(shell, arg: str):
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
        _sh.console.print(f"  [cyan]{summarize(data)}[/]")
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


def cmd_history(shell, arg: str):
    """Show command history for this session"""
    if not session.history:
        notifier.warn("No commands in history.")
        return
    for entry in session.history:
        _sh.console.print(f"  [dim]{entry}[/]")


COMMANDS = {
    "save_profile": cmd_save_profile,
    "load_profile": cmd_load_profile,
    "list_profiles": cmd_list_profiles,
    "set": cmd_set,
    "show": cmd_show,
    "note": cmd_note,
    "notes": cmd_notes,
    "save_session": cmd_save_session,
    "load_session": cmd_load_session,
    "list_sessions": cmd_list_sessions,
    "export_session": cmd_export_session,
    "import_session": cmd_import_session,
    "history": cmd_history,
}
