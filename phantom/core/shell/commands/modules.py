"""Module commands: use (enter a module), plugins (list)."""
from __future__ import annotations

import phantom.core.shell as _sh  # live console: _sh.console resolves the package attr at call time (test patch point)
from phantom.utils.notifier import notifier


def cmd_use(shell, arg: str):
    """use <module> — enter a module (built-in or plugin; aliases: s, o, w, e, b, p, h, v, a, r, wl)"""
    module_name = arg.strip().lower()
    if not module_name:
        notifier.error("Usage: use <module_name>")
        return

    # short aliases (with collision-safe mapping: sc/ex/pay/ha/pi/an/re)
    aliases = getattr(shell, "MODULE_ALIASES", {})
    module_name = aliases.get(module_name, module_name)

    modules = {
        "scan", "osint", "wifi", "web", "brute", "exploit",
        "payload", "handler", "pivot", "analyzer", "report",
        "wordlist", "c2",
    }

    # C2 is an operations center, not a BaseModule — route to do_c2
    if module_name == "c2":
        shell.do_c2("")
        return

    if module_name in modules:
        if shell._warn_identity_target(module_name):
            # identity target + network module: warn but still enter
            pass
        try:
            instance = shell._instantiate_module(module_name)
            if instance:
                hint = getattr(instance, "show_enter_hint", None)
                if callable(hint):
                    hint()
                instance.cmdloop()
        except Exception as e:
            notifier.error(f"Failed to enter module {module_name}: {e}")
        return

    # Plugin modules
    plugin_modules = getattr(shell, "_plugin_modules", {})
    if module_name in plugin_modules:
        try:
            cls = plugin_modules[module_name]
            instance = cls()
            instance.cmdloop()
        except Exception as e:
            notifier.error(f"Plugin {module_name} crashed: {e}")
        return

    notifier.error(f"Unknown module: {module_name}")
    notifier.info(f"Available: {', '.join(sorted(modules) + sorted(plugin_modules.keys()))}")


def cmd_plugins(shell, _):
    """plugins — list all loaded plugins."""
    plugin_modules = getattr(shell, "_plugin_modules", {})
    if not plugin_modules:
        notifier.warn("No plugins loaded.")
        return

    from rich.table import Table
    table = Table(title="Loaded Plugins", border_style="cyan")
    table.add_column("Plugin Name", style="bold green")
    table.add_column("Source", style="dim")

    for name, cls in plugin_modules.items():
        source = cls.__module__
        table.add_row(name, source)

    _sh.console.print(table)
    _sh.console.print(f"\n[dim]Use 'use <name>' to enter a plugin module.[/]")


COMMANDS = {
    "use": cmd_use,
    "plugins": cmd_plugins,
}
