from rich.console import Console
from typing import Dict, List, Optional, Tuple

console = Console()

class PreviewSession:
    def __init__(self, groups: Dict[str, List[str]]):
        self.groups = groups
        self._flat: List[Tuple[str, str]] = []
        self._rebuild_flat()

    def _rebuild_flat(self):
        self._flat = [(g, c) for g, lst in self.groups.items() for c in lst]

    def _display(self):
        console.print()
        idx = 1
        for group, cmds in self.groups.items():
            if not cmds:
                continue
            console.print(f"  [bold cyan]-- {group} {'-' * (55 - len(group))}[/]")
            for cmd in cmds:
                is_aggressive = "AGGRESSIVE" in cmd
                clean_cmd = cmd.replace(" AGGRESSIVE", "").strip()
                warning = " [bold red]⚠ AGGRESSIVE[/]" if is_aggressive else ""
                console.print(f"  [{idx:2}] [yellow]{clean_cmd}[/]{warning}")
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
        if group_name not in self.groups:
            console.print(f"[red]Group '{group_name}' not found.[/]")
            return []
        return self.groups[group_name]

    def run_all(self) -> List[str]:
        return [cmd for _, cmd in self._flat]

    def run_single(self, index: int) -> List[str]:
        """Return a list containing only the command at the given flat index."""
        if 1 <= index <= len(self._flat):
            return [self._flat[index - 1][1]]
        else:
            console.print("[red]Invalid index.[/]")
            return []

    def interactive(self) -> Optional[List[str]]:
        self._display()
        while True:
            choice = input("  > ").strip()
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