"""cancellation.py — hierarchical cancellation for swarm workers.

ManusReview §4.2 / AutoModeBrief §12.7: a task needs a CANCellation token, not
just a timeout, and the stop has to reach children (a worker that spawns a
helper, a sub-tool) instead of being noticed only at the next drain.

A :class:`CancellationToken` is a small tree:

  * :meth:`cancel` flips the token and CASCADES to every live child, so one
    operator stop reaches the whole subtree at once;
  * :meth:`child` hands a worker its own token linked to the run's, so the
    worker can also be cancelled individually;
  * :meth:`raise_if_cancelled` / :attr:`cancelled` / :attr:`reason` let a hot
    loop check cheaply and surface the typed cause ("operator stop",
    "budget exhausted") rather than a bare stop.

The token carries a REASON, because "why did it stop?" is as important as
"that it stopped". It is thread-safe (a stop may come from another thread)
and idempotent (a second cancel keeps the first reason).
"""

from __future__ import annotations

import threading
from typing import List, Optional


class Cancelled(Exception):  # noqa: N818 — mirrors asyncio.CancelledError
    """Raised by :meth:`CancellationToken.raise_if_cancelled`."""

    def __init__(self, reason: str = "") -> None:
        self.reason = reason or "cancelled"
        super().__init__(self.reason)


class CancellationToken:
    """A cancellable node in a tree; cancelling a parent cancels its children."""

    def __init__(self, parent: Optional["CancellationToken"] = None,
                 reason: str = "") -> None:
        self._lock = threading.Lock()
        self._cancelled = False
        self._reason = ""
        self._children: List["CancellationToken"] = []
        self._parent = parent
        if parent is not None:
            parent._register(self)
            # a child born under an already-stopped parent is stopped at once
            if parent.cancelled:
                self.cancel(parent.reason or "parent cancelled")

    # -------------------------------------------------------------- tree

    def _register(self, child: "CancellationToken") -> None:
        with self._lock:
            if self._cancelled:
                already = True
            else:
                already = False
                self._children.append(child)
        if already:
            child.cancel(self._reason or "parent cancelled")

    def child(self, reason: str = "") -> "CancellationToken":
        """A new token under this one (cancels with the parent)."""
        return CancellationToken(parent=self, reason=reason)

    # ---------------------------------------------------------- control

    def cancel(self, reason: str = "") -> bool:
        """Cancel this node and cascade to children. Returns True the first
        time (a repeated cancel keeps the original reason and is a no-op)."""
        with self._lock:
            if self._cancelled:
                return False
            self._cancelled = True
            self._reason = reason or self._reason or "cancelled"
            children = list(self._children)
            self._children = []
            first = True
        for child in children:
            child.cancel(self._reason)
        return first

    # ------------------------------------------------------------ reads

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    @property
    def reason(self) -> str:
        return self._reason

    def raise_if_cancelled(self) -> None:
        if self._cancelled:
            raise Cancelled(self._reason)

    def subtree_size(self) -> int:
        """Live nodes under this one (including itself) — for tests/audit."""
        with self._lock:
            children = list(self._children)
        return 1 + sum(c.subtree_size() for c in children)


class NullToken(CancellationToken):
    """A token that is never cancelled (the default: no operator stop).

    Cancelling it still works, but the swarm passes one when no stop is
    wired so the hot-loop checks stay free of ``is None`` branches.
    """

    def __init__(self) -> None:
        super().__init__(parent=None)
