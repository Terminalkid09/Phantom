"""Command registry for the Phantom manual shell.

Every shell command is a plain ``handler(shell, arg)`` function with its
original docstring (the docstring IS the ``help <cmd>`` text). Group
modules expose a ``COMMANDS`` dict; :func:`iter_commands` yields the full
map the shell class wires as ``do_*`` methods — so ``cmd.Cmd`` keeps
working (help, completion, precmd) with zero per-command boilerplate.
"""
from __future__ import annotations

from typing import Callable, Dict, Iterator, Tuple

Handler = Callable[..., object]


def iter_commands() -> Iterator[Tuple[str, Handler]]:
    """Yield (name, handler) for every registered shell command."""
    from .commands import session as _session
    from .commands import run as _run
    from .commands import modules as _modules
    from .commands import auto as _auto
    from .commands import ops as _ops
    from .commands import system as _system
    seen: Dict[str, Handler] = {}
    for group in (_session, _run, _modules, _auto, _ops, _system):
        for name, fn in vars(group).get("COMMANDS", {}).items():
            if name in seen:
                raise ValueError(f"duplicate shell command: {name}")
            seen[name] = fn
            yield name, fn


def command_names() -> Tuple[str, ...]:
    """All registered command names (contract-tested)."""
    return tuple(name for name, _ in iter_commands())
