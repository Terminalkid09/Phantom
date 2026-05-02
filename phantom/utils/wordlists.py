import os
from typing import List, Dict, Optional
from rich.console import Console
from rich.table import Table
from phantom.core.session import session

console = Console()

# default search paths
SEARCH_PATHS = [
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/usr/share/dirb/wordlists",
    "/usr/share/dirbuster/wordlists",
]

# simple category detection based on filename keywords
CATEGORIES = {
    "passwords":   ["rockyou", "fasttrack", "password", "unix-passwords", "crack", "john"],
    "directories": ["common", "big", "directory-list", "dirbuster", "dirb"],
    "subdomains":  ["subdomain", "dns", "hosts", "jhaddix"],
    "usernames":   ["user", "username", "names", "xato"],
    "web":         ["fuzz", "burp", "param", "xss", "sqli", "lfi"],
}


class WordlistManager:
    """
    Indexes, queries, and selects wordlists.
    The active wordlist path is stored in session.active_wordlist.
    """

    def __init__(self):
        self._index: List[Dict] = []   # each entry: {"name", "path", "size", "category"}
        self._built = False

    def _build_index(self) -> None:
        """Scan all SEARCH_PATHS and populate the index (once)."""
        if self._built:
            return
        for base in SEARCH_PATHS:
            if not os.path.isdir(base):
                continue
            for root, _, files in os.walk(base):
                for f in files:
                    if f.endswith((".txt", ".lst", ".dict")):
                        full_path = os.path.join(root, f)
                        try:
                            size_bytes = os.path.getsize(full_path)
                            self._index.append({
                                "name": f,
                                "path": full_path,
                                "size": size_bytes,
                                "category": self._categorize(f),
                            })
                        except OSError:
                            pass
        self._built = True

    def _categorize(self, filename: str) -> str:
        """Assign a category based on filename keywords."""
        name_low = filename.lower()
        for cat, keywords in CATEGORIES.items():
            if any(kw in name_low for kw in keywords):
                return cat
        return "other"

    def _format_size(self, size_bytes: int) -> str:
        """Human readable size (e.g., 12M, 456K, 789)."""
        if size_bytes > 1_000_000:
            return f"{size_bytes // 1_000_000}M"
        elif size_bytes > 1_000:
            return f"{size_bytes // 1_000}K"
        return f"{size_bytes}B"

    def _list(self, category: str = "") -> None:
        """Display indexed wordlists, optionally filtered by category."""
        if not self._index:
            console.print("[yellow]No wordlists found. Check SEARCH_PATHS or install seclists/wordlists.[/]")
            return
        filtered = self._index
        if category:
            filtered = [w for w in filtered if w["category"] == category]
        if not filtered:
            console.print(f"[yellow]No wordlists in category '{category}'.[/]")
            return

        table = Table(title="Available wordlists")
        table.add_column("Name", style="cyan")
        table.add_column("Category")
        table.add_column("Size", justify="right")
        table.add_column("Path", style="dim")

        for w in sorted(filtered, key=lambda x: (x["category"], x["name"])):
            table.add_row(w["name"], w["category"], self._format_size(w["size"]), w["path"])

        console.print(table)

    def _use(self, name_or_path: str) -> None:
        """Set active wordlist by name (first match) or absolute path."""
        if os.path.isabs(name_or_path) and os.path.isfile(name_or_path):
            session.active_wordlist = name_or_path
            console.print(f"[green][+] Active wordlist set to: {name_or_path}[/]")
            return

        # Search by name (case‑insensitive partial match)
        matches = [w for w in self._index if name_or_path.lower() in w["name"].lower()]
        if not matches:
            console.print(f"[red]Wordlist not found: {name_or_path}[/]")
            return
        if len(matches) == 1:
            w = matches[0]
            session.active_wordlist = w["path"]
            console.print(f"[green][+] Active wordlist set to: {w['name']} ({w['path']})[/]")
        else:
            console.print(f"[yellow]Multiple matches for '{name_or_path}':[/]")
            for i, w in enumerate(matches[:10], 1):
                console.print(f"  [{i}] {w['name']} ({self._format_size(w['size'])})")
            idx = input("  Select number (or 'cancel'): ").strip()
            if idx.isdigit() and 1 <= int(idx) <= len(matches):
                w = matches[int(idx)-1]
                session.active_wordlist = w["path"]
                console.print(f"[green][+] Active wordlist set to: {w['name']}[/]")

    def _search(self, keyword: str) -> None:
        """List all wordlists containing keyword in the filename."""
        matches = [w for w in self._index if keyword.lower() in w["name"].lower()]
        if not matches:
            console.print(f"[yellow]No wordlists contain '{keyword}'.[/]")
        else:
            for w in matches:
                console.print(f"  [cyan]{w['name']}[/] — {w['path']}")

    def _info(self, name: str) -> None:
        """Show detailed info about a specific wordlist (path, size, line count)."""
        matches = [w for w in self._index if name.lower() in w["name"].lower()]
        if not matches:
            console.print(f"[red]Wordlist not found: {name}[/]")
            return
        w = matches[0]
        # Count lines (approx)
        line_count = "?"
        try:
            with open(w["path"], "r", encoding="utf-8", errors="ignore") as f:
                line_count = sum(1 for _ in f)
        except Exception:
            pass
        console.print(f"  [bold]Name:[/] {w['name']}")
        console.print(f"  [bold]Path:[/] {w['path']}")
        console.print(f"  [bold]Size:[/] {self._format_size(w['size'])}")
        console.print(f"  [bold]Entries:[/] {line_count:,}" if isinstance(line_count, int) else f"  [bold]Entries:[/] {line_count}")
        console.print(f"  [bold]Category:[/] {w['category']}")

    def handle(self, args: str) -> None:
        """
        Dispatch function called from shell.do_wordlists.
        Args format: "list [category]", "use <name|path>", "search <keyword>", "info <name>"
        """
        self._build_index()
        parts = args.strip().split(maxsplit=1)
        cmd = parts[0].lower() if parts else "list"
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "list":
            self._list(arg)          # arg can be category name or empty
        elif cmd == "use":
            if not arg:
                console.print("[red]Usage: wordlists use <name|path>[/]")
            else:
                self._use(arg)
        elif cmd == "search":
            if not arg:
                console.print("[red]Usage: wordlists search <keyword>[/]")
            else:
                self._search(arg)
        elif cmd == "info":
            if not arg:
                console.print("[red]Usage: wordlists info <name>[/]")
            else:
                self._info(arg)
        else:
            console.print("[red]Unknown wordlists subcommand. Use: list, use, search, info[/]")