import sys

from rich.console import Console
from typing import Dict, List, Optional, Tuple

console = Console()

def _stdin_is_tty() -> bool:
    """True only when a terminal is really attached (never raises)."""
    stream = getattr(sys, "stdin", None)
    if stream is None:
        return False
    try:
        return bool(stream.isatty())
    except Exception:
        return False


class PreviewSession:
    def __init__(self, groups: Dict[str, List[str]]) -> None:
        self.groups = groups
        self._flat: List[Tuple[str, str]] = []
        self._rebuild_flat()

    def _rebuild_flat(self) -> None:
        self._flat = [(g, c) for g, lst in self.groups.items() for c in lst]

    def _display(self):
        console.print()
        idx = 1
        for group, cmds in self.groups.items():
            if not cmds:
                continue
            suggested = group.upper().startswith("SUGGESTED")
            header_style = "bold green" if suggested else "bold cyan"
            console.print(f"  [{header_style}]-- {group} {'-' * (55 - len(group))}[/]")
            for cmd in cmds:
                is_aggressive = "AGGRESSIVE" in cmd
                clean_cmd = cmd.replace(" AGGRESSIVE", "").strip()
                warning = " [bold red]⚠ AGGRESSIVE[/]" if is_aggressive else ""
                prefix = "▶ " if suggested else ""
                cmd_style = "green" if suggested else "yellow"
                console.print(f"  [{idx:2}] [{cmd_style}]{prefix}{clean_cmd}[/]{warning}")
                idx += 1
        console.print("\n  [dim]edit <n> | remove <n> | add | run-group <name> | run <n> | run-all | cancel[/]\n")

    def edit(self, index: int, new_cmd: str) -> None:
        if 1 <= index <= len(self._flat):
            group, old_cmd = self._flat[index - 1]
            pos = self.groups[group].index(old_cmd)
            self.groups[group][pos] = new_cmd
            self._rebuild_flat()
            console.print(f"[green]Command {index} updated.[/]")
        else:
            console.print("[red]Invalid index.[/]")

    def remove(self, index: int) -> None:
        if 1 <= index <= len(self._flat):
            group, cmd = self._flat[index - 1]
            self.groups[group].remove(cmd)
            self._rebuild_flat()
            console.print(f"[green]Command {index} removed.[/]")
        else:
            console.print("[red]Invalid index.[/]")

    def add(self, group: str, cmd: str) -> None:
        group = group.upper()
        if group not in self.groups:
            self.groups[group] = []
        self.groups[group].append(cmd)
        self._rebuild_flat()
        console.print(f"[green]Added command to group '{group}'.[/]")

    def run_group(self, group_name: str) -> List[str]:
        group_name = group_name.upper()
        for key, cmds in self.groups.items():
            if key.upper() == group_name:
                return cmds
        console.print(f"[red]Group '{group_name}' not found. Available: {', '.join(self.groups)}[/]")
        return []

    def run_all(self) -> List[str]:
        return [cmd for _, cmd in self._flat]

    def run_single(self, index: int) -> Optional[List[str]]:
        """Return a list containing only the command at the given flat index."""
        if 1 <= index <= len(self._flat):
            return [self._flat[index - 1][1]]
        console.print("[red]Invalid index.[/]")
        return None

    def review(self) -> None:
        """Display-only: show the command plan WITHOUT executing anything.
        `preview` shows, `run` executes — no more 'run == preview'."""
        self._display()
        console.print(
            "  [dim]Execute with: run | run <n> | run-group <name> | run-all | cancel[/]")

    def group_names(self) -> List[str]:
        """Non-empty group names, in the order the module ranked them."""
        return [name for name, cmds in self.groups.items() if cmds]

    def non_interactive(self, group: str = "") -> Optional[List[str]]:
        """No terminal to answer the menu: never call `input()`.

        `use scan` + `run` piped into Phantom used to die with "Failed to
        enter module scan: EOF when reading a line" — the whole manual module
        shell could not be scripted, so no CI and no end-to-end run could
        touch it (measured with a piped stdin, 2026-10-26).

        With no terminal nobody can pick, so the fallback is the FIRST group
        the module itself ranked first (its primary move) and the line says
        so; `run-group <name>` and `run-all` are how a script asks for a
        different scope instead of guessing one.
        """
        self._display()
        names = self.group_names()
        if not names:
            console.print("[dim]Nothing to run — the module produced no "
                          "command group for the current state.[/]")
            return None
        if group:
            return self.run_group(group) or None
        console.print(
            f"  [dim]stdin is not a terminal: no menu to answer — running the "
            f"first group '{names[0]}'. Ask for another with `run-group "
            f"<name>` (available: {', '.join(names)}) or `run-all`.[/]")
        return self.run_group(names[0])

    def choose(self, group: str = "") -> Optional[List[str]]:
        """The menu when a human is there, the module's primary group when
        not (see `non_interactive`)."""
        if not _stdin_is_tty():
            return self.non_interactive(group)
        return self.interactive()

    def interactive(self) -> Optional[List[str]]:
        self._display()
        while True:
            try:
                choice = input("  > ").strip()
            except EOFError:
                # stdin closed while the menu was up (a script that never
                # asked for a group): a traceback here taught the operator
                # nothing. Fall back the same way a non-TTY run does.
                console.print("\n  [yellow]stdin closed — falling back to "
                              "the module's first group.[/]")
                names = self.group_names()
                return self.run_group(names[0]) if names else None
            if not choice:
                continue

            if choice == "cancel":
                return None

            if choice == "back":
                console.print("[dim]Use 'cancel' to exit preview, then 'back' to leave the module.[/]")
                continue

            if choice == "run-all":
                return self.run_all()

            if choice.startswith("run-group "):
                group = choice.split(maxsplit=1)[1]
                cmds = self.run_group(group)
                if cmds:
                    return cmds
                continue

            if choice == "run":
                # run without number → run-all
                return self.run_all()

            if choice.startswith("run "):
                # run with number → single command
                parts = choice.split(maxsplit=1)
                try:
                    idx = int(parts[1])
                    cmds = self.run_single(idx)
                    if cmds:
                        return cmds
                except (IndexError, ValueError):
                    console.print("[red]Usage: run <number>[/]")
                continue

            if choice == "preview":
                self._display()
                continue

            if choice == "help":
                console.print("[dim]Commands: edit <n>, remove <n>, add, run-group <name>, run <n>, run-all, preview, cancel, help[/]")
                continue

            if choice.startswith("edit "):
                parts = choice.split(maxsplit=1)
                try:
                    idx = int(parts[1])
                    new_cmd = input("  New command: ").strip()
                    self.edit(idx, new_cmd)
                    self._display()
                except (IndexError, ValueError):
                    console.print("[red]Usage: edit <number>[/]")
                continue

            if choice.startswith("remove "):
                parts = choice.split(maxsplit=1)
                try:
                    idx = int(parts[1])
                    self.remove(idx)
                    self._display()
                except (IndexError, ValueError):
                    console.print("[red]Usage: remove <number>[/]")
                continue

            if choice == "add":
                group = input("  Group name (e.g., NMAP, NETWORK, CUSTOM): ").strip().upper()
                if not group:
                    console.print("[red]Group name required.[/]")
                    continue
                cmd = input("  Command: ").strip()
                if not cmd:
                    console.print("[red]Command cannot be empty.[/]")
                    continue
                self.add(group, cmd)
                self._display()
                continue

            console.print("[red]Unknown command.[/]")