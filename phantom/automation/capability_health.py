"""capability_health.py — a persisted, queryable health score per capability.

AutoModeBrief §16 (P2.8) asks for a capability health score grounded in the
history of results. The IN-RUN blend already lives in ``EnterpriseBrain``
(a bounded [0.5x, 1.5x] success-rate prior over this engagement plus the
calibrated weights of previous ones). What was missing was a durable,
inspectable LEDGER: how each capability has actually fared over time, worst
first, so the operator and the report can answer "which move keeps failing?".

This module is that ledger — deliberately SEPARATE from the planner's
EnterpriseBrain so it never silently double-applies a second multiplier:

  * :meth:`CapabilityHealth.record` folds one real attempt (ok / not) into a
    per-capability row, tracking a consecutive-failure STREAK (a capability
    that fails three times in a row is a stronger signal than one that
    alternated), and decays old counts so the score tracks recency;
  * :meth:`health` returns a bounded [0, 1] posterior (Laplace-smoothed so a
    brand-new capability is neither trusted nor condemned), and
    :meth:`multiplier` maps it into the same regret-bounded [0.5, 1.5] band
    the planner uses — an AVAILABLE signal, not an imposed one;
  * :meth:`report` sorts worst-first, the operator view.

The store is JSON, bounded in size, written atomically and best-effort (a
broken store degrades to an empty one, never crashes a run).
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

DEFAULT_MAX_CAPABILITIES = 512

# Health -> planner multiplier band (regret-bounded, matching EnterpriseBrain)
BAND_LOW = 0.5
BAND_HIGH = 1.5
_MAX_ATTEMPTS = 200          # decay above this so the score tracks recency


def _default_path() -> str:
    try:
        from phantom.utils.paths import data_dir
        return os.path.join(data_dir(), "capability_health.json")
    except Exception:
        return "capability_health.json"


@dataclass
class CapHealth:
    """One capability's outcome history and derived health."""

    capability: str
    ok: int = 0
    fail: int = 0
    streak: int = 0            # +N consecutive ok, -N consecutive fail
    last_ok: float = 0.0
    last_fail: float = 0.0
    last_reason: str = ""

    def attempts(self) -> int:
        return self.ok + self.fail

    def success_rate(self) -> Optional[float]:
        total = self.attempts()
        return round(self.ok / total, 4) if total else None

    def health(self, prior: float = 0.5) -> float:
        """Laplace-smoothed success probability in [0, 1].

        One pseudo-success and one pseudo-failure keep a new capability at
        the neutral ``prior`` (0.5 by default) and stop a single sample from
        swinging the score.
        """
        return round((self.ok + prior) / (self.attempts() + 1.0), 4)

    def multiplier(self) -> float:
        """Health mapped into the regret-bounded planner band [0.5, 1.5]."""
        raw = BAND_LOW + self.health() * (BAND_HIGH - BAND_LOW)
        return round(min(BAND_HIGH, max(BAND_LOW, raw)), 4)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability": self.capability, "ok": self.ok, "fail": self.fail,
            "streak": self.streak, "last_ok": self.last_ok,
            "last_fail": self.last_fail, "last_reason": self.last_reason,
            "success_rate": self.success_rate(), "health": self.health(),
            "multiplier": self.multiplier(), "attempts": self.attempts(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapHealth":
        def _i(v, d=0):
            try:
                return int(v)
            except (TypeError, ValueError):
                return d

        def _f(v, d=0.0):
            try:
                return float(v)
            except (TypeError, ValueError):
                return d

        data = data or {}
        return cls(
            capability=str(data.get("capability") or ""),
            ok=_i(data.get("ok")), fail=_i(data.get("fail")),
            streak=_i(data.get("streak")),
            last_ok=_f(data.get("last_ok")), last_fail=_f(data.get("last_fail")),
            last_reason=str(data.get("last_reason") or ""),
        )


class CapabilityHealth:
    """Thread-safe, persisted per-capability outcome ledger."""

    def __init__(self, path: Optional[str] = None,
                 clock: Callable[[], float] = time.time,
                 max_capabilities: int = DEFAULT_MAX_CAPABILITIES) -> None:
        self.path = path if path is not None else _default_path()
        self._clock = clock
        self._max = max(1, int(max_capabilities))
        self._lock = threading.Lock()
        self._rows: Dict[str, CapHealth] = {}
        self._loaded = False

    # ------------------------------------------------------------- persist

    def load(self) -> "CapabilityHealth":
        """Read the store (best-effort: a broken file is an empty ledger)."""
        with self._lock:
            if self._loaded:
                return self
            self._loaded = True
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                return self
            rows = (data or {}).get("capabilities") or {}
            if isinstance(rows, dict):
                for cap, row in rows.items():
                    try:
                        self._rows[str(cap)] = CapHealth.from_dict(
                            {**row, "capability": cap})
                    except Exception:
                        continue
        return self

    def save(self) -> bool:
        """Write the store atomically (best-effort, never raises)."""
        self._ensure_loaded()
        with self._lock:
            payload = {"version": 1, "capabilities": {
                cap: {"ok": r.ok, "fail": r.fail, "streak": r.streak,
                      "last_ok": r.last_ok, "last_fail": r.last_fail,
                      "last_reason": r.last_reason}
                for cap, r in self._rows.items()}}
        try:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            tmp = f"{self.path}.tmp{os.getpid()}"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
            return True
        except OSError:
            return False

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    # -------------------------------------------------------------- record

    def record(self, capability: str, ok: bool, reason: str = "") -> CapHealth:
        """Fold one REAL attempt into the ledger (never for blocks/deferrals)."""
        self._ensure_loaded()
        cap = str(capability)
        now = self._clock()
        with self._lock:
            row = self._rows.get(cap)
            if row is None:
                row = CapHealth(capability=cap)
                self._rows[cap] = row
            if ok:
                row.ok += 1
                row.streak = row.streak + 1 if row.streak >= 0 else 1
                row.last_ok = now
            else:
                row.fail += 1
                row.streak = row.streak - 1 if row.streak <= 0 else -1
                row.last_fail = now
                row.last_reason = str(reason or "")[:200]
            if row.attempts() > _MAX_ATTEMPTS:
                row.ok //= 2
                row.fail //= 2
            self._evict_locked()
            return row

    def _evict_locked(self) -> None:
        """Keep the newest ``max_capabilities`` rows (by last activity)."""
        if len(self._rows) <= self._max:
            return
        ordered = sorted(self._rows.items(),
                         key=lambda kv: max(kv[1].last_ok, kv[1].last_fail))
        for cap, _ in ordered[:len(self._rows) - self._max]:
            del self._rows[cap]

    # --------------------------------------------------------------- reads

    def of(self, capability: str) -> Optional[CapHealth]:
        self._ensure_loaded()
        with self._lock:
            return self._rows.get(str(capability))

    def health(self, capability: str, prior: float = 0.5) -> float:
        row = self.of(capability)
        return row.health(prior) if row is not None else round(prior, 4)

    def multiplier(self, capability: str) -> float:
        row = self.of(capability)
        if row is None or row.attempts() == 0:
            return 1.0                      # unknown: neutral, never punished
        return row.multiplier()

    def report(self, limit: int = 0) -> List[Dict[str, Any]]:
        """Rows worst-health-first (the operator's 'what keeps failing?' view)."""
        self._ensure_loaded()
        with self._lock:
            rows = [r.to_dict() for r in self._rows.values()]
        rows.sort(key=lambda r: (r["health"], -r["attempts"], r["capability"]))
        return rows if not limit else rows[:limit]

    def snapshot(self) -> Dict[str, Any]:
        return {"capabilities": len(self._rows),
                "report": self.report()}


# lazy singleton used by the agent (file created on first save)
_singleton: Optional[CapabilityHealth] = None


def instance() -> CapabilityHealth:
    global _singleton
    if _singleton is None:
        _singleton = CapabilityHealth()
    return _singleton


def set_instance(health: Optional[CapabilityHealth]) -> None:
    global _singleton
    _singleton = health
