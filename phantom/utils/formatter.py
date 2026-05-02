"""
formatter.py – shortcuts for styled console output using rich.
"""

from rich.console import Console

console = Console()

def success(msg: str):
    console.print(f"[bold green][+][/] {msg}")

def warning(msg: str):
    console.print(f"[bold yellow][!][/] {msg}")

def error(msg: str):
    console.print(f"[bold red][!][/] {msg}")

def info(msg: str):
    console.print(f"[bold cyan][*][/] {msg}")

def section(title: str):
    console.print(f"\n[bold]-- {title} {'-' * (50 - len(title))}[/]\n")