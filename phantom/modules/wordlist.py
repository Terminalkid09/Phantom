"""
wordlist.py - Interactive module for generating and mutating custom wordlists.
"""

import os
from phantom.modules.base_module import BaseModule
from phantom.core.session import session
from phantom.utils.notifier import notifier
from phantom.utils.wordlist_engine import (
    generate, save_wordlist, mutate_all, DEFAULT_CHARSETS
)
from rich.console import Console
from rich.table import Table

console = Console()


class WordlistModule(BaseModule):
    module_name = "wordlist"

    def do_generate(self, arg: str):
        """generate <pattern> [--sets <sets>] [--min N] [--max N] [--name <filename>] [--mutate]"""
        import shlex
        try:
            args = shlex.split(arg)
        except ValueError:
            notifier.error("Invalid arguments.")
            return

        pattern = ""
        opts = {'sets': None, 'min': None, 'max': None, 'name': None, 'mutate': False}
        i = 0
        while i < len(args):
            a = args[i]
            if a.startswith('--'):
                key = a[2:]
                if key in ('sets', 'name'):
                    i += 1
                    if i < len(args):
                        opts[key] = args[i]
                elif key in ('min', 'max'):
                    i += 1
                    if i < len(args):
                        try:
                            opts[key] = int(args[i])
                        except ValueError:
                            notifier.error(f"{key} must be integer.")
                            return
                elif key == 'mutate':
                    opts['mutate'] = True
                else:
                    notifier.warn(f"Unknown option --{key}")
            elif not pattern:
                pattern = a
            i += 1

        if not pattern:
            notifier.error("Usage: generate <pattern> [--sets ...] [--min N] [--max N] [--name <filename>] [--mutate]")
            console.print("[dim]Pattern tokens: a=lower A=upper 1=number s=symbol *=any[/]")
            return

        selected_sets = None
        if opts['sets']:
            selected_sets = [s.strip() for s in opts['sets'].split(',')]

        try:
            words = generate(pattern, selected_sets, opts['min'], opts['max'])
        except ValueError as e:
            notifier.error(str(e))
            return

        if not words:
            notifier.warn("No words generated. Check pattern/charset/min/max.")
            return

        if opts['mutate']:
            words = mutate_all(words)

        name = opts['name'] or f"wl_{pattern}_{len(words)}"
        wl_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'wordlists', 'custom')
        os.makedirs(wl_dir, exist_ok=True)
        path = os.path.join(wl_dir, f"{name}.txt")

        save_wordlist(path, words)
        session.active_wordlist = path
        notifier.success(f"Wordlist saved to: {path} ({len(words)} entries)")
        notifier.info(f"Active wordlist now set to: {name}")

    def _execute_flow(self, _):
        """Show sample output for default pattern"""
        sample = generate('aa1')
        console.print(f"[cyan]Sample (aa1):[/] {', '.join(sample[:5])}...")
        console.print("[dim]Tokens: a=lowercase A=uppercase 1=number s=symbol *=any[/]")

    def do_run(self, arg):
        """Alias for generate"""
        self.do_generate(arg)

    def do_list(self, _):
        """List all saved custom wordlists"""
        wl_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'wordlists', 'custom')
        if not os.path.isdir(wl_dir):
            notifier.warn("No custom wordlists found yet.")
            return
        files = sorted(f for f in os.listdir(wl_dir) if f.endswith('.txt'))
        if not files:
            notifier.warn("No custom wordlists found yet.")
            return
        table = Table(title="Custom Wordlists")
        table.add_column("Name", style="cyan")
        table.add_column("Size", justify="right")
        table.add_column("Path")
        for fn in files:
            full = os.path.join(wl_dir, fn)
            sz = os.path.getsize(full)
            table.add_row(fn[:-4], f"{sz//1024}K" if sz > 1024 else f"{sz}B", full)
        console.print(table)

    def build_commands(self) -> dict:
        return self._with_suggestions(
            {
                "GENERATOR": ["generate <pattern>", "mutate <existing>"],
            },
            self.suggest_commands(),
        )

    def suggest_commands(self) -> dict:
        """Wordlist generation seeded with target-derived tokens."""
        from phantom.modules.suggest import wordlist_suggestion_group
        return wordlist_suggestion_group()
