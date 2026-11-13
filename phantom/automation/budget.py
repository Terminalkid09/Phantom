"""budget.py — per-target spend limits, separate from the run-wide budget.

The agent already carries a GLOBAL noise/recovery budget for one engagement,
and each worker has a planner-iteration *task* budget. What was missing is a
budget keyed by TARGET: in a multi-target run a single loud host could spend
the whole operation's allowance before the other targets were even reached,
and "why did the planner stop?" had no per-host answer.

A ``BudgetLedger`` keeps one :class:`TargetBudget` per target and answers
three questions without any clock in the ranking:

  * :meth:`spend` — may this target afford N more actions / R noise? It
    charges atomically and refuses once a limit would be exceeded, so the
    decision is a single boolean the worker can act on;
  * :meth:`exhausted` / :meth:`reason` — whether the target is done, and the
    operator-readable cause ("target noise budget exhausted" vs "actions");
  * :meth:`snapshot` — the audit view of what each target spent.

Limits are ``0`` = unlimited, so an engagement with no per-target policy is
byte-for-byte the previous behaviour: the ledger only ever *refuses* when a
limit was actually set. The clock is injectable and only used for the
first/last-seen stamps, never in an admission decision.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

# Spend kinds the ledger understands. Extended with a value <= 0 is a no-op,
# so a caller can charge only what it actually used.
KIND_ACTIONS = "actions"
KIND_NOISE = "noise"
KIND_REQUESTS = "requests"


@dataclass
class TargetBudget:
    """One target's allowance and what it has spent so far.

    A limit of ``0`` means UNLIMITED for that kind (the default), so absence
    of a policy is not the same as a policy of zero.
    """

    target: str
    max_actions: int = 0
    max_noise: float = 0.0
    max_requests: int = 0
    actions: int = 0
    noise: float = 0.0
    requests: int = 0
    first_seen: float = 0.0
    last_spend: float = 0.0

    def _over(self, kind: str, amount: float) -> bool:
        """Would charging ``amount`` of ``kind`` CROSS a set limit?

        Strict ``>``: a charge that exactly reaches the limit is allowed,
        the one past it is refused. Used by :meth:`BudgetLedger.spend`.
        """
        if kind == KIND_ACTIONS:
            return (self.max_actions > 0
                    and self.actions + amount > self.max_actions)
        if kind == KIND_NOISE:
            return (self.max_noise > 0
                    and self.noise + amount > self.max_noise)
        if kind == KIND_REQUESTS:
            return (self.max_requests > 0
                    and self.requests + amount > self.max_requests)
        return False

    def _at_limit(self, kind: str) -> bool:
        """Is ``kind`` already at (or past) its limit, so no positive charge
        could land? ``>=``: the budget is spent the moment it is reached."""
        if kind == KIND_ACTIONS:
            return 0 < self.max_actions <= self.actions
        if kind == KIND_NOISE:
            return 0 < self.max_noise <= self.noise
        if kind == KIND_REQUESTS:
            return 0 < self.max_requests <= self.requests
        return False

    def exhausted(self) -> bool:
        return (self._at_limit(KIND_ACTIONS) or self._at_limit(KIND_NOISE)
                or self._at_limit(KIND_REQUESTS))

    def reason(self) -> str:
        """Why the target is done, or '' when it still has room."""
        if self._at_limit(KIND_ACTIONS):
            return (f"target action budget exhausted "
                    f"({self.actions}/{self.max_actions})")
        if self._at_limit(KIND_NOISE):
            return (f"target noise budget exhausted "
                    f"({self.noise:.2f}/{self.max_noise:.2f})")
        if self._at_limit(KIND_REQUESTS):
            return (f"target request budget exhausted "
                    f"({self.requests}/{self.max_requests})")
        return ""

    def remaining(self) -> Dict[str, Optional[float]]:
        """Headroom per kind; ``None`` when that kind is unlimited."""
        return {
            KIND_ACTIONS: (None if self.max_actions <= 0
                           else max(0, self.max_actions - self.actions)),
            KIND_NOISE: (None if self.max_noise <= 0
                         else max(0.0, self.max_noise - self.noise)),
            KIND_REQUESTS: (None if self.max_requests <= 0
                            else max(0, self.max_requests - self.requests)),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "max_actions": self.max_actions, "max_noise": self.max_noise,
            "max_requests": self.max_requests,
            "actions": self.actions, "noise": round(self.noise, 4),
            "requests": self.requests,
            "exhausted": self.exhausted(), "reason": self.reason(),
            "remaining": self.remaining(),
        }


class BudgetLedger:
    """Thread-safe per-target budget table (creates a row on first touch)."""

    def __init__(self, default_actions: int = 0, default_noise: float = 0.0,
                 default_requests: int = 0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._default_actions = int(default_actions or 0)
        self._default_noise = float(default_noise or 0.0)
        self._default_requests = int(default_requests or 0)
        self._clock = clock
        self._lock = threading.Lock()
        self._rows: Dict[str, TargetBudget] = {}
        self.charged = 0
        self.refused = 0

    # ------------------------------------------------------------- setup

    def budget_for(self, target: str) -> TargetBudget:
        """The row for ``target``, created with the defaults on first use."""
        key = str(target)
        with self._lock:
            row = self._rows.get(key)
            if row is None:
                row = TargetBudget(
                    target=key, max_actions=self._default_actions,
                    max_noise=self._default_noise,
                    max_requests=self._default_requests,
                    first_seen=self._clock())
                self._rows[key] = row
            return row

    def set_limit(self, target: str, max_actions: Optional[int] = None,
                  max_noise: Optional[float] = None,
                  max_requests: Optional[int] = None) -> TargetBudget:
        """Override the limit of one kind for one target (0 = unlimited)."""
        row = self.budget_for(target)
        with self._lock:
            if max_actions is not None:
                row.max_actions = int(max_actions)
            if max_noise is not None:
                row.max_noise = float(max_noise)
            if max_requests is not None:
                row.max_requests = int(max_requests)
        return row

    # ------------------------------------------------------------ charge

    def spend(self, target: str, actions: int = 0, noise: float = 0.0,
              requests: int = 0) -> bool:
        """Charge a spend against ``target`` atomically.

        True when the target could afford it (and the charge landed); False
        when it would cross ANY set limit — in which case NOTHING is charged,
        so a refused worker does not half-consume the allowance.
        """
        row = self.budget_for(target)
        with self._lock:
            if (row._over(KIND_ACTIONS, actions)
                    or row._over(KIND_NOISE, noise)
                    or row._over(KIND_REQUESTS, requests)):
                self.refused += 1
                return False
            row.actions += int(actions)
            row.noise += float(noise)
            row.requests += int(requests)
            row.last_spend = self._clock()
            self.charged += 1
            return True

    # ------------------------------------------------------------- reads

    def exhausted(self, target: str) -> bool:
        return self.budget_for(target).exhausted()

    def reason(self, target: str) -> str:
        return self.budget_for(target).reason()

    def remaining(self, target: str) -> Dict[str, Optional[float]]:
        return self.budget_for(target).remaining()

    def targets(self) -> list:
        with self._lock:
            return sorted(self._rows)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            rows = {k: v.to_dict() for k, v in self._rows.items()}
        return {"targets": rows, "charged": self.charged,
                "refused": self.refused}


def ledger_from_config(getter: Optional[Callable[..., Any]] = None
                       ) -> BudgetLedger:
    """Build a ledger from ``budget.per_target_*`` config (0 = unlimited).

    Missing config (or a broken reader) yields an UNLIMITED ledger, so the
    default path never silently caps an engagement.
    """
    if getter is None:
        try:
            from phantom.utils import config as cfg
            getter = cfg.get
        except Exception:
            getter = None

    def _read(key: str, default: Any) -> Any:
        if getter is None:
            return default
        try:
            return getter(key, default)
        except Exception:
            return default

    def _as_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _as_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    return BudgetLedger(
        default_actions=_as_int(_read("budget.per_target_actions", 0)),
        default_noise=_as_float(_read("budget.per_target_noise", 0.0)),
        default_requests=_as_int(_read("budget.per_target_requests", 0)),
    )
