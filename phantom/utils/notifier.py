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
    def error(message: str, exc: Exception = None):
        console.print(f"[bold red][✘] ERROR: {message}[/]")
        if exc:
            console.print(f"    [dim]{str(exc)}[/]")
            logger.error(f"ERROR: {message} | EXCEPTION: {exc}")
        else:
            logger.error(f"ERROR: {message}")

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
