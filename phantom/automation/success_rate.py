"""success_rate.py — measure a run instead of estimating it.

"Ottimo success rate" is not something you can read off the logs by feel. A
run has three honest outcomes and one dishonest one:

* ``reached``  — the goal's terminal fact exists. The run worked.
* ``degraded`` — the planner could not reach this goal for this target class
  and settled on the fallback goal, and said so on the stream.
* ``halted``   — no usable path left; the halt reason names the gap.
* ``cycled``   — DISHONEST, and the one a success rate hides: the same move
  ran again with the same result. The run kept working, the information did
  not, and iterations burned. Measured directly from the event stream.

Usage (tests and scenario fixtures)::

    events = []
    result = run_autonomous(..., on_event=lambda k, d: events.append((k, d)))
    print(outcome(result, events, goal="deliver").verdict)

The module is deliberately deterministic and dependency-free: it reads the
event stream and the result dict, nothing else.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

# The terminal fact each goal lands in the run result. A goal missing from
# this map cannot be judged automatically — `outcome` will not claim it was
# reached, it will report `halted`/`ran` and the caller must judge.
GOAL_RESULT_KEYS: Dict[str, str] = {
    "deliver": "beacon_established",
    "beacon": "beacon_established",
    "complete_kill_chain": "beacon_established",
    "post_exploit": "beacon_established",
    "deep": "beacon_established",
    "footprint": "services_enumerated",
    "creds": "creds_found",
    "beacon_established": "beacon_established",
    "ad": "ad_domains",
    "crack": "cracked_hashes",
    "lateral": "lateral_movements",
    "cleanup": "cleanup_done",
}

#: A move repeated this many times with the same command is a cycle.
CYCLE_THRESHOLD = 3


@dataclass
class ScenarioOutcome:
    goal: str
    verdict: str                      # reached | degraded | halted | ran | cycled
    actions: int = 0
    iterations: int = 0
    cycles: Dict[str, int] = field(default_factory=dict)
    repeated_failures: Dict[str, int] = field(default_factory=dict)
    halt_reason: str = ""
    degraded: List[str] = field(default_factory=list)
    failures: int = 0

    @property
    def ok(self) -> bool:
        return self.verdict == "reached"

    @property
    def honest(self) -> bool:
        """A run that did not succeed but explained itself is still usable;
        a cycling run is not, however green the report looks."""
        return self.verdict != "cycled"

    def to_dict(self) -> Dict[str, Any]:
        return {"goal": self.goal, "verdict": self.verdict,
                "actions": self.actions, "iterations": self.iterations,
                "cycles": dict(self.cycles),
                "repeated_failures": dict(self.repeated_failures),
                "halt_reason": self.halt_reason, "degraded": list(self.degraded),
                "failures": self.failures, "honest": self.honest}


def goal_reached(result: dict, goal: str) -> bool:
    """Did the run's own result claim the goal's terminal fact?"""
    key = GOAL_RESULT_KEYS.get(goal)
    if not key:
        return False
    value = (result or {}).get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value > 0
    return bool(value)


def find_cycles(events: Iterable[Tuple[str, dict]],
                threshold: int = CYCLE_THRESHOLD) -> Dict[str, int]:
    """Moves whose EXACT command ran `threshold`+ times.

    Keyed by command (not capability): the same capability legitimately runs
    several times with different arguments as facts arrive; the same command
    string repeated is the run treading water.
    """
    seen: Counter = Counter()
    for kind, data in events:
        if kind != "run":
            continue
        command = str((data or {}).get("command") or "").strip()
        if command:
            seen[command] += 1
    return {cmd: n for cmd, n in seen.items() if n >= threshold}


def find_repeated_failures(events: Iterable[Tuple[str, dict]],
                           threshold: int = 2) -> Dict[str, int]:
    """The same capability failing with the SAME reason more than once."""
    seen: Counter = Counter()
    for kind, data in events:
        if kind != "failed":
            continue
        data = data or {}
        seen[f"{data.get('capability')}: {data.get('reason') or 'no reason'}"] += 1
    return {key: n for key, n in seen.items() if n >= threshold}


def outcome(result: dict, events: Iterable[Tuple[str, dict]],
            goal: str, iterations: int = 0) -> ScenarioOutcome:
    """Classify one run. `events` is the (kind, data) stream it emitted."""
    events = list(events)
    result = result or {}
    cycles = find_cycles(events)
    repeated = find_repeated_failures(events)
    halt_reason = next((str((d or {}).get("reason") or "")
                        for k, d in events if k == "halt"), "")
    degraded = sorted({str((d or {}).get("layer") or "?")
                       for k, d in events if k == "degraded"})
    failures = sum(1 for k, _ in events if k == "failed")
    actions = int(result.get("actions_taken")
                  or result.get("actions") or 0)

    if goal_reached(result, goal):
        verdict = "reached"
    elif cycles or repeated:
        verdict = "cycled"
    elif halt_reason:
        verdict = "halted"
    elif degraded:
        verdict = "degraded"
    else:
        verdict = "ran"
    return ScenarioOutcome(goal=goal, verdict=verdict, actions=actions,
                           iterations=iterations, cycles=cycles,
                           repeated_failures=repeated,
                           halt_reason=halt_reason, degraded=degraded,
                           failures=failures)


def summarize(outcomes: List[ScenarioOutcome]) -> Dict[str, Any]:
    """Success rate + the numbers that make it honest."""
    total = len(outcomes) or 1
    by_verdict: Counter = Counter(o.verdict for o in outcomes)
    return {
        "scenarios": len(outcomes),
        "reached": by_verdict.get("reached", 0),
        "success_rate": round(by_verdict.get("reached", 0) / total, 3),
        "cycled": by_verdict.get("cycled", 0),
        "halted": by_verdict.get("halted", 0),
        "degraded": by_verdict.get("degraded", 0),
        # a success rate that ignores cycling flatters the engine
        "honest_rate": round(
            sum(1 for o in outcomes if o.honest) / total, 3),
        "by_goal": {o.goal: o.verdict for o in outcomes},
    }
