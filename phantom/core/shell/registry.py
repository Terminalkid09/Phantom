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


def normalise_command_line(line: str) -> str:
    """Rewrite a HYPHENATED command name to its underscore form.

    ``cmd.Cmd.parseline`` ends the command name at the first character
    outside ``identchars``, and ``identchars`` contains no ``-``. So
    ``run-group "SERVICE ENUM"`` was parsed as the command ``run`` with the
    argument ``-group "SERVICE ENUM"``: the module executed its FIRST group
    instead of the named one — a scripted step that ran commands nobody
    asked for (measured 2026-10-28, `use scan` in a piped manual shell).

    The same split made every hyphenated command in the manual shell
    unreachable, including the ``export-session`` the reports and the
    AUTO-MODE summary tell the operator to type (the handler is registered
    as ``export_session``).

    Only the FIRST token is rewritten: a hyphen inside an argument
    (a filename, a range) is data and must survive verbatim. ``?cmd`` and
    ``!cmd`` keep their prefix semantics.
    """
    raw = str(line or "")
    stripped = raw.lstrip()
    if not stripped:
        return raw
    indent = raw[:len(raw) - len(stripped)]
    prefix = ""
    if stripped[0] in "?!":
        prefix, stripped = stripped[0], stripped[1:]
    head, sep, rest = stripped.partition(" ")
    return f"{indent}{prefix}{head.replace('-', '_')}{sep}{rest}"


def command_names() -> Tuple[str, ...]:
    """All registered command names (contract-tested)."""
    return tuple(name for name, _ in iter_commands())
