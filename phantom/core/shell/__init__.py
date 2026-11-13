"""Phantom manual shell — modular command package.

Drop-in replacement for the old monolithic ``phantom/core/shell.py``:
every public name the old module exposed is re-exported here
(``PhantomShell``, ``console``, ``Console``, banner/status helpers), so
all existing imports keep working unchanged.

Layout:
    ui.py        shared banner / status-bar / hint builders + console
    registry.py  command registry (name -> handler)
    base.py      PhantomShell: loop + infrastructure + dynamic do_* wiring
    commands/    one module per command group (session/run/modules/...)
"""
from __future__ import annotations

from rich.console import Console  # noqa: F401  (public re-export)

from .base import PhantomShell  # noqa: F401
from .ui import (  # noqa: F401
    _context_hint,
    _engagement_elapsed,
    _target_type_tag,
    build_banner,
    build_banner_compact,
    build_dashboard,
    build_status_bar,
    console,
    load_phantom_env,
    print_sandbox_status,
    print_toolbelt_status,
    print_transport_status,
)

__all__ = [
    "PhantomShell",
    "Console",
    "console",
    "load_phantom_env",
    "_context_hint",
    "_engagement_elapsed",
    "_target_type_tag",
    "build_banner",
    "build_banner_compact",
    "build_dashboard",
    "build_status_bar",
    "print_sandbox_status",
    "print_toolbelt_status",
    "print_transport_status",
]
