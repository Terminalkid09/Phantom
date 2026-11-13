"""
dynamics.py — per-run dynamic command shaping (auto-mode).

The agent never ships a static command: adapters synthesize the skeleton
from the WorldModel (target, ports, versions, creds), and this module
layers per-run variation on top so consecutive runs are not byte-identical
at the endpoint — the same reasoning the private tooling applies to
campaign builds, kept in the public core so it is exercised by the test
suite.

`DynCommandBuilder.shape()` rewrites ephemeral staging paths (/tmp/.x,
$env:TEMP\\x) inside a synthesized command with a fresh random value.
Seeded builders are deterministic (tests / scripted runs); seed 0 is
fresh per call (operator runs).
"""

from __future__ import annotations

import random
import re
import string
from typing import Optional

_EPHEMERAL_POOL = (".cache", ".update", ".session", ".sync", ".runtime",
                   ".tmp", ".local")

# /tmp/.<name> | $env:TEMP\<name>  (beacon-side staging paths)
_EPHEMERAL_RE = re.compile(r"(/tmp/\.\w+|\$env:TEMP\\[\w.\-]+|\$TMPDIR/\.\w+)")


class DynCommandBuilder:
    """Adds fresh per-run variation to synthesized commands."""

    def __init__(self, seed: int = 0) -> None:
        self._seed = seed
        self._rng = random.Random(seed) if seed else random.Random()

    def next_ephemeral(self, platform: str = "linux") -> str:
        base = self._rng.choice(_EPHEMERAL_POOL)
        suffix = "".join(self._rng.choice(string.ascii_lowercase)
                         for _ in range(4))
        if platform == "windows":
            return f"$env:TEMP\\{base}.{suffix}"
        if platform == "android":
            return f"$TMPDIR/.{suffix}{base}"
        return f"/tmp/.{suffix}{base}"

    def _os_hint(self, wm) -> str:
        try:
            for f in wm.find("os"):
                return str(f.value.get("name", "") or "")
        except Exception:
            return ""
        return ""

    def shape(self, command: str, wm, platform: str = "") -> str:
        """Return a per-run variant of a synthesized command.

        Any ephemeral staging path present in the command is replaced with
        a fresh random value, so two runs of the same capability never ship
        the same path to the endpoint. The SAME original path is rewritten
        to the SAME new value within a command (a dropper writes and then
        executes one file), while distinct paths get distinct values.
        """
        if not command or not _EPHEMERAL_RE.search(command):
            return command
        if not platform:
            hint = self._os_hint(wm).lower()
            platform = "windows" if "win" in hint else "linux"
        mapping = {}

        def _repl(match):
            original = match.group(0)
            if original not in mapping:
                mapping[original] = self.next_ephemeral(platform)
            return mapping[original]

        return _EPHEMERAL_RE.sub(_repl, command)


__all__ = ["DynCommandBuilder"]
