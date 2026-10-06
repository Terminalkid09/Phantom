"""idempotency.py — one-run-per-key results for swarm tasks.

The lease (``swarm/leases.py``) owns a ``(task, target)`` slot while a worker
is IN FLIGHT. That still leaves the REQUeue case: once a worker finished, a
later wave that re-dispatches the same ``(task, target)`` — a retry, a
fan-out that rebuilt the DAG — would run the work a second time and spend
the budget twice, even though the result is already known.

An :class:`IdempotencyRegistry` closes that gap with the standard contract:

  * :meth:`begin` returns ``True`` the FIRST time a key is seen and ``False``
    afterwards, so a caller runs the work only when :meth:`begin` is True;
  * :meth:`complete` stores the outcome under the key;
  * :meth:`outcome` returns the stored outcome (or ``None``), so a repeat can
    reuse the result instead of recomputing it;
  * :meth:`fail` clears an in-progress claim so a crashed attempt can retry.

The registry is thread-safe and bounded: outcomes are kept for at most
``max_entries`` keys (insertion order), so a long run cannot grow it without
limit. Keys are strings; the swarm builds them from ``(task_id, target)``.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any, Dict, Optional

DEFAULT_MAX_ENTRIES = 512


class IdempotencyRegistry:
    """Thread-safe ``key -> outcome`` map that runs each key once."""

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self._max = max(1, int(max_entries))
        self._lock = threading.Lock()
        self._inflight: set = set()
        self._done: "OrderedDict[str, Any]" = OrderedDict()
        self.ran = 0
        self.skipped = 0

    def begin(self, key: str) -> bool:
        """Claim ``key`` for execution.

        True the first time (the caller should run the work); False when the
        key is already COMPLETED (a repeat) or already IN FLIGHT (a concurrent
        duplicate). A completed key never re-runs.
        """
        with self._lock:
            if key in self._done or key in self._inflight:
                self.skipped += 1
                return False
            self._inflight.add(key)
            self.ran += 1
            return True

    def complete(self, key: str, outcome: Any = None) -> None:
        """Mark ``key`` done and remember its outcome (bounded)."""
        with self._lock:
            self._inflight.discard(key)
            self._done[key] = outcome
            self._done.move_to_end(key)
            while len(self._done) > self._max:
                self._done.popitem(last=False)

    def fail(self, key: str) -> None:
        """Release an in-flight claim so a crashed attempt can retry."""
        with self._lock:
            self._inflight.discard(key)

    def outcome(self, key: str) -> Any:
        """The stored outcome for a completed key, else ``None``."""
        with self._lock:
            return self._done.get(key)

    def completed(self, key: str) -> bool:
        with self._lock:
            return key in self._done

    def in_flight(self, key: str) -> bool:
        with self._lock:
            return key in self._inflight

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {"completed": list(self._done), "inflight": sorted(
                self._inflight), "ran": self.ran, "skipped": self.skipped}

    @staticmethod
    def key_for(task_id: str, target: str) -> str:
        return f"{task_id}:{target}"
