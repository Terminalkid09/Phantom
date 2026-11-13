"""Phase-specific advisors built on ``ai.router.ask``.

Each advisor returns DATA with a closed shape; none of them executes
anything, and every caller keeps its deterministic fallback.

Submodules are imported explicitly by their callers (``advisors.social``,
``advisors.exploit``, ...); this package deliberately imports nothing, so a
phase module cannot create an import cycle with the engine that uses it.
"""

__all__ = ["exploit", "finding", "osint", "social", "evolution"]
