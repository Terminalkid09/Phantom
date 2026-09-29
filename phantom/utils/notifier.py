import difflib

from rich.console import Console
from phantom.core.logger import logger

# Frozen-backend safety: when stdout is a Windows legacy console (or a pipe
# with a cp1252/ascii codec), every rich print containing non-latin1 glyphs
# (✔ ✘ ▶ ★ ═ …) raises UnicodeEncodeError and KILLS the calling thread —
# this silently terminated auto-mode runs in the Electron backend with
# zero events. Fix the console properly:
#   1. switch the console codepage to UTF-8 (65001)
#   2. enable VT processing so rich uses the ANSI renderer instead of the
#      legacy win32 renderer that encodes with the console codepage
#   3. reconfigure the stdio wrappers to UTF-8 with replace
import sys as _sys
import os as _os

if _os.name == "nt":
    try:
        import ctypes
        _k32 = ctypes.windll.kernel32
        _k32.SetConsoleOutputCP(65001)
        _k32.SetConsoleCP(65001)
        _h = _k32.GetStdHandle(-11)          # STD_OUTPUT_HANDLE
        if _h and _h != -1:
            _mode = ctypes.c_uint32(0)
            if _k32.GetConsoleMode(_h, ctypes.byref(_mode)):
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN
                _k32.SetConsoleMode(_h, _mode.value | 0x0004)
    except Exception:
        pass
    try:
        for _stream in (_sys.stdout, _sys.stderr):
            if (_stream is not None
                    and hasattr(_stream, "reconfigure")
                    and getattr(_stream, "encoding", "").lower()
                        not in ("utf-8", "utf8")):
                _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console()

class PhantomNotifier:
    """Centralized notification system for clear user feedback."""
    
    @staticmethod
    def success(message: str):
        console.print(f"[bold green][✔] {message}[/]")
        logger.info(f"SUCCESS: {message}")

    @staticmethod
    def error(message: str, exc: Exception = None, hint: str = ""):
        """One error shape everywhere: what failed, then what to do.

        The hint line is the point. An error that only names the problem
        makes the operator go read the source; every refusal in the shell
        can name its own remedy in the same place, so they all read the
        same way (and a capability refusal is never a dead end).

        A message that already starts with "Usage:" is RE-RENDERED through
        `usage()` instead of being printed raw. That keeps the ~30 legacy
        call sites coherent without editing each one (and without them
        drifting apart again): the shape is enforced by the renderer, not
        by every author remembering the convention.
        """
        text = str(message if message is not None else "")
        if text.strip().lower().startswith("usage:"):
            PhantomNotifier.usage("", text.split(":", 1)[1].strip(),
                                  hint=hint)
            return
        console.print(f"[bold red][✘] ERROR: {text}[/]")
        if hint:
            console.print(f"    [dim]↳ {hint}[/]")
        if exc:
            console.print(f"    [dim]{str(exc)}[/]")
            logger.error(f"ERROR: {text} | HINT: {hint} | EXCEPTION: {exc}")
        else:
            logger.error(f"ERROR: {text} | HINT: {hint}")

    @staticmethod
    def usage(command: str, syntax: str, hint: str = ""):
        """Uniform syntax refusal: `Usage: <command> <syntax>` + remedy.

        Also the funnel for every legacy `notifier.error("Usage: ...")`
        call site, so the box, the colour and the log tag are the same
        regardless of who refuses.
        """
        from rich.markup import escape
        line = " ".join(part for part in (command, syntax) if part).strip()
        console.print("[bold red][✘] ERROR: missing or invalid arguments[/]")
        console.print(f"    [white]Usage: {escape(line)}[/]")
        if hint:
            console.print(f"    [dim]↳ {escape(hint)}[/]")
        logger.error(f"USAGE: {line} | HINT: {hint}")

    @staticmethod
    def unknown(kind: str, value: str, options=None, hint: str = ""):
        """Uniform unknown-entity refusal, with a closest-match suggestion.

        `options` are the valid names; the nearest one is offered when it
        is close enough to be a likely typo (difflib, cutoff 0.6
        deliberately conservative — a wrong guess is worse than none).
        """
        close = ""
        try:
            opts = [str(o) for o in (options or [])]
            match = difflib.get_close_matches(str(value), opts, n=1,
                                              cutoff=0.6)
            close = match[0] if match else ""
        except Exception:
            close = ""
        msg = f"Unknown {kind}: '{value}'."
        if close:
            msg += f" Did you mean '{close}'?"
            hint = hint or f"closest match: {close}"
        PhantomNotifier.error(msg, hint=hint)

    @staticmethod
    def warn(message: str):
        console.print(f"[bold yellow][!] WARNING: {message}[/]")
        logger.warning(f"WARN: {message}")

    @staticmethod
    def status(message: str):
        console.print(f"[bold cyan][*] {message}[/]")
        logger.info(f"STATUS: {message}")

    @staticmethod
    def info(message: str):
        console.print(f"[dim][i] {message}[/]")

notifier = PhantomNotifier()
