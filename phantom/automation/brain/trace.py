"""phantom.automation.brain.trace — the ordered ledger of arbitrated moves.

`agent._decisions` is a dict keyed by capability id: it holds only the LAST
decision per capability, so a re-decision erases the earlier one, the order
is lost, and nothing survives the run (or a checkpoint). The operator could
see the driver of the move that ran, never the sequence that led there, and
a resumed engagement could explain nothing about what it had already decided.

A `DecisionTrace` keeps that sequence: one entry per arbitrated move, with
the full `Decision` payload (driver, runner-up, contributions, profile,
search policy, signals, veto) plus the stage it was taken in. It is:

* BOUNDED — a long run cannot grow the checkpoint without limit;
* SERIALIZABLE — a resume keeps its decisions, so the report of a resumed
  run explains the whole run, not just its second half;
* DETERMINISTIC — no clocks in the ranking, only in the timestamps.

Nothing here decides anything: it records what the arbiter already decided,
so "why did it do that?" has an answer with a step number.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# how many entries a run keeps (the tail is dropped, like the noise ledger)
TRACE_LIMIT = 400


def _num(value: Any, default: float = 0.0) -> float:
    """Coerce a JSON scalar to float; a checkpoint is written with
    `default=str`, so a resumed run must not die on one bad field."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _text(value: Any, default: str = "") -> str:
    return str(value) if value not in (None, "") else default


@dataclass
class TraceEntry:
    """One arbitrated move: what was chosen, and what drove it."""

    seq: int
    capability: str
    stage: str = ""
    value: float = 0.0
    base: float = 0.0
    driver: str = ""
    runner_up: str = ""
    profile: str = ""
    search_policy: str = "adaptive"
    veto: str = ""
    contributions: Dict[str, float] = field(default_factory=dict)
    signals: Dict[str, Any] = field(default_factory=dict)
    ts: float = 0.0

    @property
    def vetoed(self) -> bool:
        return bool(self.veto)

    def explain(self) -> str:
        """One auditable line, in the same vocabulary as `Decision.explain`."""
        if self.veto:
            return (f"#{self.seq} {self.capability}: VETOED by the stealth "
                    f"lens ({self.veto})")
        band = f"x{self.value / self.base:.2f}" if self.base else "n/a"
        top = ", ".join(f"{k}={v:.2f}" for k, v in sorted(
            self.contributions.items(), key=lambda kv: -kv[1])[:2])
        return (f"#{self.seq} {self.capability}: {self.base:.2f} -> "
                f"{self.value:.2f} ({band}) driven by {self.driver}"
                f"{f' (runner-up {self.runner_up})' if self.runner_up else ''}"
                f"{f' [{top}]' if top else ''}"
                f" [{self.profile or '-'}/{self.search_policy}]")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq, "capability": self.capability, "stage": self.stage,
            "value": round(self.value, 4), "base": round(self.base, 4),
            "driver": self.driver, "runner_up": self.runner_up,
            "profile": self.profile, "search_policy": self.search_policy,
            "veto": self.veto,
            "contributions": {k: round(v, 4)
                              for k, v in self.contributions.items()},
            "signals": dict(self.signals), "ts": self.ts,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TraceEntry":
        data = data or {}
        contributions = data.get("contributions") or {}
        signals = data.get("signals") or {}
        return cls(
            seq=int(_num(data.get("seq"), 0)),
            capability=_text(data.get("capability")),
            stage=_text(data.get("stage")),
            value=_num(data.get("value")),
            base=_num(data.get("base")),
            driver=_text(data.get("driver")),
            runner_up=_text(data.get("runner_up")),
            profile=_text(data.get("profile")),
            search_policy=_text(data.get("search_policy"), "adaptive"),
            veto=_text(data.get("veto")),
            contributions={k: _num(v) for k, v in
                           (contributions.items()
                            if isinstance(contributions, dict) else ())},
            signals=dict(signals) if isinstance(signals, dict) else {},
            ts=_num(data.get("ts")),
        )


class DecisionTrace:
    """Ordered, bounded, serializable ledger of arbitrated moves."""

    def __init__(self, limit: int = TRACE_LIMIT) -> None:
        self.limit = int(limit)
        self.entries: List[TraceEntry] = []

    # ── recording ──────────────────────────────────────────────────────
    def note(self, decision: Any, stage: str = "") -> Optional[TraceEntry]:
        """Record one arbitrated move. Returns the entry, or None when it is
        indistinguishable from the previous decision for the same capability
        in the same stage.

        A planning pass rates every candidate on every pass, so a naive
        append would fill the ledger with the same decision repeated. What
        the operator needs is the HISTORY OF CHANGES: "the run chose X, then
        the world moved and it chose Y". A repeat changes nothing.
        """
        import time
        if decision is None:
            return None
        capability = str(getattr(decision, "capability", "") or "")
        driver = str(getattr(decision, "driver", "") or "")
        veto = str(getattr(decision, "veto", "") or "")
        value = float(getattr(decision, "value", 0.0) or 0.0)
        stamped = (getattr(decision, "profile", ""),
                   getattr(decision, "search_policy", ""))
        previous = self._last_for(capability)
        if previous is not None and previous.stage == stage \
                and previous.driver == driver and previous.veto == veto \
                and previous.value == value \
                and (previous.profile, previous.search_policy) == stamped:
            return None
        entry = TraceEntry(
            seq=len(self.entries) + 1,
            capability=capability,
            stage=stage,
            value=value,
            base=float(getattr(decision, "base", 0.0) or 0.0),
            driver=driver,
            runner_up=str(getattr(decision, "runner_up", "") or ""),
            profile=str(getattr(decision, "profile", "") or ""),
            search_policy=str(getattr(decision, "search_policy", "adaptive")
                              or "adaptive"),
            veto=veto,
            contributions={k: float(v) for k, v in
                           (getattr(decision, "contributions", {}) or {}).items()},
            signals=dict(getattr(decision, "signals", {}) or {}),
            ts=time.time(),
        )
        self.entries.append(entry)
        if len(self.entries) > self.limit:
            del self.entries[:-max(1, self.limit // 2)]
        return entry

    def add(self, entry: TraceEntry) -> TraceEntry:
        """Append a pre-built entry (checkpoint import, tests)."""
        self.entries.append(entry)
        if len(self.entries) > self.limit:
            del self.entries[:-max(1, self.limit // 2)]
        return entry

    # ── queries ────────────────────────────────────────────────────────
    def _last_for(self, capability: str) -> Optional[TraceEntry]:
        for entry in reversed(self.entries):
            if entry.capability == capability:
                return entry
        return None

    def of(self, capability: str) -> List[TraceEntry]:
        """Every recorded decision for one capability, oldest first."""
        return [e for e in self.entries if e.capability == capability]

    def of_stage(self, stage: str) -> List[TraceEntry]:
        return [e for e in self.entries if e.stage == stage]

    def last(self) -> Optional[TraceEntry]:
        return self.entries[-1] if self.entries else None

    def drivers(self) -> Dict[str, int]:
        """How often each lens actually made the decision (the audit view of
        "is the arbiter weighting what we think it is weighting?")."""
        out: Dict[str, int] = {}
        for entry in self.entries:
            if entry.veto:
                key = "veto"
            elif entry.driver:
                key = entry.driver
            else:
                continue
            out[key] = out.get(key, 0) + 1
        return out

    def explain_all(self, limit: int = 0) -> List[str]:
        """The trace as operator-readable lines (oldest first)."""
        entries = self.entries if not limit else self.entries[-limit:]
        return [e.explain() for e in entries]

    # ── serialization ──────────────────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        return {"entries": [e.to_dict() for e in self.entries]}

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "DecisionTrace":
        trace = cls()
        for entry in (data or {}).get("entries", []) or []:
            try:
                trace.entries.append(TraceEntry.from_dict(entry))
            except Exception:
                continue      # one unreadable entry never kills a resume
        return trace

    def __len__(self) -> int:
        return len(self.entries)

    def __bool__(self) -> bool:
        return bool(self.entries)

    def __iter__(self):
        return iter(self.entries)
