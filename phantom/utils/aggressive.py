from rich.console import Console

console = Console()

def filter_aggressive_commands(commands: list) -> list:
    """Filter out aggressive commands unless user confirms."""
    aggressive = [c for c in commands if "AGGRESSIVE" in c]
    if aggressive:
        console.print(f"\n[bold red]You are about to run {len(aggressive)} aggressive command(s).[/]")
        console.print("[yellow]These can be noisy and may trigger IDS/IPS.[/]")
        confirm = input("  Are you sure? [y/N] ").strip().lower()
        if confirm != "y":
            return [c for c in commands if "AGGRESSIVE" not in c]
    return commands