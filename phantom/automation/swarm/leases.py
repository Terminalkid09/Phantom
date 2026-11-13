"""leases.py — explicit ownership of a swarm ``(task, target)`` slot.

The board serializes COMMITS, but nothing owned the right to RUN a unit of
work: the scheduler's waves normally prevent a double run, yet a requeue or
a helper submitted right after a drain TIMEOUT could race a worker that is
still in flight and spend the task's budget twice. A lease makes ownership
explicit and testable:

  * :meth:`LeaseTable.claim` grants a slot to the FIRST owner of a free or
    EXPIRED lease, is idempotent for the same owner, and denies everyone
    else while the lease is live;
  * :meth:`LeaseTable.release` frees it (owner-checked);
  * :meth:`LeaseTable.renew` extends a live lease, so a long worker is not
    reclaimed out from under itself;
  * an expired lease is reclaimable, so a crashed worker cannot wedge a
    task forever.

The clock is injectable, so expiry is tested deterministically instead of
with a sleep.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

DEFAULT_TTL_S = 300.0


@dataclass
class Lease:
    """One live grant of a (task_id, target) slot to an owner."""

    owner: str
    task_id: str
    target: str
    ttl: float
    granted_at: float
    renewed_at: float
    meta: Dict[str, object] = field(default_factory=dict)


class LeaseTable:
    """Thread-safe (task_id, target) leases with a TTL."""

    def __init__(self, ttl: float = DEFAULT_TTL_S,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._ttl = float(ttl)
        self._clock = clock
        self._lock = threading.Lock()
        self._leases: Dict[Tuple[str, str], Lease] = {}
        self.granted = 0
        self.reclaimed = 0
        self.denied = 0
        self.released = 0

    # ------------------------------------------------------------ helpers

    def _live(self, lease: Lease, now: float) -> bool:
        return (now - lease.renewed_at) < lease.ttl

    # ------------------------------------------------------------- claims

    def claim(self, task_id: str, target: str, owner: str,
              ttl: Optional[float] = None) -> bool:
        """Grant ``(task_id, target)`` to ``owner``.

        True when the slot was free, expired (reclaimed) or already held by
        this same owner (idempotent). False when a DIFFERENT owner holds a
        live lease.
        """
        now = self._clock()
        key = (task_id, target)
        with self._lock:
            current = self._leases.get(key)
            if current is not None and self._live(current, now):
                if current.owner == owner:
                    current.renewed_at = now      # idempotent re-claim
                    return True
                self.denied += 1
                return False
            if current is not None:
                self.reclaimed += 1
            self._leases[key] = Lease(
                owner=owner, task_id=task_id, target=target,
                ttl=float(ttl if ttl is not None else self._ttl),
                granted_at=now, renewed_at=now)
            self.granted += 1
            return True

    def release(self, task_id: str, target: str, owner: str) -> bool:
        """Free the slot, but only for its owner (a stale owner is a no-op)."""
        key = (task_id, target)
        with self._lock:
            current = self._leases.get(key)
            if current is None or current.owner != owner:
                return False
            del self._leases[key]
            self.released += 1
            return True

    def renew(self, task_id: str, target: str, owner: str,
              ttl: Optional[float] = None) -> bool:
        """Extend a live lease owned by ``owner``. False if lost/expired."""
        now = self._clock()
        key = (task_id, target)
        with self._lock:
            current = self._leases.get(key)
            if (current is None or current.owner != owner
                    or not self._live(current, now)):
                return False
            current.renewed_at = now
            if ttl is not None:
                current.ttl = float(ttl)
            return True

    # -------------------------------------------------------------- reads

    def owner_of(self, task_id: str, target: str) -> Optional[str]:
        """The live owner, or None when free/expired."""
        now = self._clock()
        with self._lock:
            current = self._leases.get((task_id, target))
            if current is None or not self._live(current, now):
                return None
            return current.owner

    def active(self) -> int:
        """How many leases are live right now."""
        now = self._clock()
        with self._lock:
            return sum(1 for lease in self._leases.values()
                       if self._live(lease, now))

    def sweep(self) -> List[Tuple[str, str]]:
        """Drop expired leases; return the freed keys."""
        now = self._clock()
        with self._lock:
            dead = [key for key, lease in self._leases.items()
                    if not self._live(lease, now)]
            for key in dead:
                del self._leases[key]
        return dead
