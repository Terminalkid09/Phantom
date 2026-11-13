from rich.console import Console
from rich.table import Table
from phantom.core.session import session

console = Console()

def show_notes() -> None:
    """print all notes in the current session"""
    if not session.notes:
        console.print("[yellow] No notes in this session.[/]")
        return

    table = Table(title=f"Session notes - {session.target or 'no target'}")
    table.add_column("#", style="dim", width=4)
    table.add_column("Time", style="cyan", width=10)
    table.add_column("Note")

    for idx, note in enumerate(session.notes, start=1):
        # Notes imported from older sessions/bundles can be plain strings or
        # dicts written before `timestamp` existed. A display command must
        # not crash the shell over legacy engagement data.
        if isinstance(note, dict):
            timestamp = str(note.get("timestamp") or "")
            text = str(note.get("text") or "")
        else:
            timestamp, text = "", str(note)
        table.add_row(str(idx), timestamp, text)

    console.print(table)