from rich.console import Console
from phantom.core.logger import logger

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
