"""quiet.py — the failures Phantom decides to swallow, made COUNTABLE.

The codebase wraps a lot of work in `try/except` because a broken optional
layer must never take down an engagement: a journal that cannot write, a cookie
jar that cannot be parsed, an audit append that fails on a full disk. That is
the right call. What was wrong is that the swallow was INVISIBLE — `except
Exception: pass` left no trace at all, so "this engagement ran with the audit
log degraded" was indistinguishable from "everything worked".

This module is the trace, and it is deliberately tiny: a `swallow(where, exc)`
call records a counter per call site, keeps the first and last message, and
`report()` prints the sites that swallowed something. It never raises, never
writes to disk on the hot path, and never changes control flow — it only makes
the decision observable afterwards (in `doctor`, in a report, in a test).

Use it where the alternative is a bare `except: pass`. Do NOT use it to hide a
failure you should be handling: `where` must name the thing that failed, so the
report tells an operator what to look at.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional

MAX_MESSAGE = 200


@dataclass
class QuietFailure:
    where: str
    count: int = 0
    first: str = ""
    last: str = ""
    exc_type: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {"where": self.where, "count": self.count,
                "first": self.first, "last": self.last,
                "exc_type": self.exc_type}


class QuietRegistry:
    """Counts swallowed failures per call site (bounded, thread-safe)."""

    def __init__(self, max_sites: int = 200) -> None:
        self.max_sites = max_sites
        self._lock = threading.Lock()
        self._sites: Dict[str, QuietFailure] = {}

    def swallow(self, where: str, exc: Optional[BaseException] = None,
                message: str = "") -> None:
        """Record one swallowed failure. NEVER raises."""
        try:
            where = str(where or "unknown")[:120]
            text = (message or str(exc or ""))[:MAX_MESSAGE]
            with self._lock:
                site = self._sites.get(where)
                if site is None:
                    if len(self._sites) >= self.max_sites:
                        return
                    site = QuietFailure(where=where, first=text)
                    self._sites[where] = site
                site.count += 1
                site.last = text
                if exc is not None:
                    site.exc_type = type(exc).__name__
        except Exception:
            pass          # the trace of a swallow must never itself raise

    # ---------------------------------------------------------------- views

    def sites(self) -> List[QuietFailure]:
        with self._lock:
            return sorted(self._sites.values(), key=lambda s: (-s.count, s.where))

    def total(self) -> int:
        with self._lock:
            return sum(s.count for s in self._sites.values())

    def reset(self) -> int:
        with self._lock:
            n = len(self._sites)
            self._sites = {}
            return n

    def report(self, limit: int = 20) -> str:
        sites = self.sites()
        if not sites:
            return "quiet failures: none recorded"
        lines = [f"quiet failures: {self.total()} swallowed at "
                 f"{len(sites)} site(s)"]
        for site in sites[:limit]:
            lines.append(f"  {site.count:>4}x {site.where}"
                         + (f"  [{site.exc_type}]" if site.exc_type else ""))
            if site.last:
                lines.append(f"        last: {site.last}")
        if len(sites) > limit:
            lines.append(f"  ... {len(sites) - limit} more site(s)")
        return "\n".join(lines)


registry = QuietRegistry()


def swallow(where: str, exc: Optional[BaseException] = None,
            message: str = "") -> None:
    """Module-level shorthand: `except Exception as e: quiet.swallow('audit', e)`."""
    registry.swallow(where, exc, message)
