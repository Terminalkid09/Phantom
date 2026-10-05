"""postconditions.py — did a move produce what it PROMISED?

A capability declares the facts it is meant to establish (``effects``). A
clean exit code, or even "some finding", is not proof the move delivered:
a parser can emit a finding of an unrelated kind (effect drift) and the exit
code stays 0. This turns the declared effects into an explicit postcondition
so success can be judged on EVIDENCE — at least one declared effect observed
— and the un-met ones surfaced instead of silently passing.

Kept intentionally narrow: it consumes only the findings a single run
produced and the declared effect list, so it is pure and trivially testable.
"""
from __future__ import annotations

from typing import Any, Iterable, List, Tuple


def declared_effects_met(effects: Iterable[str],
                         findings: Iterable[Any]) -> Tuple[bool, List[str]]:
    """Return (met, missing).

    ``met`` is True when at least one DECLARED effect was observed among the
    findings, or when the capability declares no effects (nothing to verify).
    ``missing`` lists the declared effects that were not observed.
    """
    declared = [str(e).strip() for e in (effects or ()) if str(e).strip()]
    if not declared:
        return True, []
    produced = {str(getattr(f, "kind", "")).strip() for f in (findings or ())}
    missing = [e for e in declared if e not in produced]
    return (len(missing) < len(declared)), missing
