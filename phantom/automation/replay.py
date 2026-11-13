"""replay.py — deterministic record/replay of AutoMode arbitration decisions.

The acceptance criterion for AutoMode is that, given the same target, scope,
tools, configuration, initial state and providers, two runs arbitrate the
SAME sequence of moves — and that a divergence can be EXPLAINED rather than
guessed. The arbiter (`brain/lenses.py`) is already pure: its ranking reads
only state, never elapsed time. What was missing was a way to CAPTURE the
exact decision inputs and REPRODUCE the decision trace offline, then diff
the two.

This module provides that, reusing the very ledger the agent already
persists (`brain/trace.py:DecisionTrace`):

  * :func:`record` rates a candidate set through one profile and returns a
    :class:`ReplayBundle` (the serializable scenario + the resulting trace);
  * :func:`replay` re-rates the SAME scenario through a fresh arbitrator and
    returns the decisions;
  * :func:`verify` compares a recorded trace with a replayed one and returns
    a :class:`ReplayReport` (`identical` plus a human diff of every move
    whose capability, driver, veto or value changed).

Because :func:`replay` is pure and clock-free, `verify(bundle).identical` is
the machine check the roadmap asks for: a deterministic trace reproduces, a
non-determinism bug shows up as a concrete diff line instead of a flaky run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from phantom.automation.brain.lenses import (
    Arbitrator,
    CapabilityView,
    WorldSignals,
    profile_for,
)
from phantom.automation.brain.trace import DecisionTrace, TraceEntry

_SIGNAL_FIELDS = (
    "visibility", "noise_ratio", "breaker_tripped", "foothold", "creds",
    "stall_class", "stage", "threat_intel_hot",
)


@dataclass
class ReplayScenario:
    """The exact inputs of one arbitration pass (serializable)."""

    profile: str = "balanced"
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    base_of: Dict[str, float] = field(default_factory=dict)
    signals: Dict[str, Any] = field(default_factory=dict)

    def build_views(self) -> List[CapabilityView]:
        views: List[CapabilityView] = []
        for raw in self.candidates or []:
            data = dict(raw or {})
            data["effects"] = tuple(data.get("effects", ()) or ())
            data["goal_facts"] = tuple(data.get("goal_facts", ()) or ())
            views.append(CapabilityView(**data))
        return views

    def build_signals(self) -> WorldSignals:
        raw = dict(self.signals or {})
        if "stall" in raw and "stall_class" not in raw:
            raw["stall_class"] = raw.pop("stall")
        kwargs = {k: raw[k] for k in _SIGNAL_FIELDS if k in raw}
        return WorldSignals(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        return {"profile": self.profile, "candidates": list(self.candidates),
                "base_of": dict(self.base_of), "signals": dict(self.signals)}

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ReplayScenario":
        data = data or {}
        return cls(
            profile=str(data.get("profile") or "balanced"),
            candidates=[dict(c) for c in (data.get("candidates") or [])],
            base_of={k: float(v) for k, v in
                     (data.get("base_of") or {}).items()},
            signals=dict(data.get("signals") or {}),
        )


@dataclass
class ReplayBundle:
    """A recorded arbitration: the inputs plus the trace they produced."""

    scenario: ReplayScenario = field(default_factory=ReplayScenario)
    trace: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"scenario": self.scenario.to_dict(), "trace": dict(self.trace)}

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ReplayBundle":
        data = data or {}
        return cls(scenario=ReplayScenario.from_dict(data.get("scenario")),
                   trace=dict(data.get("trace") or {}))


@dataclass
class ReplayReport:
    """The verdict of a replay: identical, or a concrete list of diffs."""

    identical: bool = True
    differences: List[str] = field(default_factory=list)
    recorded: List[TraceEntry] = field(default_factory=list)
    replayed: List[TraceEntry] = field(default_factory=list)

    def explain(self) -> str:
        if self.identical:
            return (f"replay identical: {len(self.replayed)} decision(s) "
                    "reproduced")
        return ("replay DIVERGED:\n" + "\n".join(self.differences))


def _scenario_of(profile: str, views: List[CapabilityView],
                 base_of: Dict[str, float],
                 signals: WorldSignals) -> ReplayScenario:
    return ReplayScenario(
        profile=str(profile),
        candidates=[{
            "id": v.id, "category": v.category,
            "opsec_cost": v.opsec_cost, "detection_risk": v.detection_risk,
            "stealth_level": v.stealth_level, "forceful": v.forceful,
            "effects": list(v.effects), "goal_facts": list(v.goal_facts),
            "success_prior": v.success_prior,
            "in_open_hypothesis": v.in_open_hypothesis,
        } for v in views],
        base_of={k: float(v) for k, v in base_of.items()},
        signals=signals.to_dict(),
    )


def _rate(scenario: ReplayScenario) -> List[Any]:
    """Rate every candidate with a FRESH arbitrator (pure, clock-free).

    Ordering mirrors the tribunal's opinion: viable moves by value (tie
    broken by id), then the vetoed ones (also value-ordered) so a veto is
    still auditable in the trace.
    """
    profile = profile_for(scenario.profile)
    arb = Arbitrator(profile)
    signals = scenario.build_signals()
    decisions = []
    for view in scenario.build_views():
        base = float(scenario.base_of.get(view.id, 1.0))
        decisions.append(arb.evaluate(view, base, signals))
    decisions.sort(key=lambda d: (bool(d.veto), -float(d.value), d.capability))
    return decisions


def trace_of(decisions: List[Any], stage: str = "") -> DecisionTrace:
    """Build a DecisionTrace from raw decisions (the recorded artifact)."""
    trace = DecisionTrace()
    for decision in decisions:
        trace.note(decision, stage=stage)
    return trace


def record(profile: str, views: List[CapabilityView],
           base_of: Dict[str, float], signals: WorldSignals,
           stage: str = "") -> ReplayBundle:
    """Capture a scenario and the decision trace it produces."""
    scenario = _scenario_of(profile, views, base_of, signals)
    trace = trace_of(_rate(scenario), stage=stage)
    return ReplayBundle(scenario=scenario, trace=trace.to_dict())


def replay(bundle: ReplayBundle) -> DecisionTrace:
    """Re-rate a recorded scenario deterministically."""
    stage = ""
    if bundle.trace.get("entries"):
        stage = str(bundle.trace["entries"][0].get("stage", "") or "")
    return trace_of(_rate(bundle.scenario), stage=stage)


def _key(entry: TraceEntry):
    return (entry.capability, entry.driver, entry.veto,
            round(entry.value, 4), round(entry.base, 4), entry.profile)


def verify(bundle: ReplayBundle) -> ReplayReport:
    """Compare the recorded trace with a fresh replay of its own inputs."""
    recorded = DecisionTrace.from_dict(bundle.trace).entries
    replayed = replay(bundle).entries
    report = ReplayReport(recorded=recorded, replayed=replayed)
    if len(recorded) != len(replayed):
        report.identical = False
        report.differences.append(
            f"length: recorded {len(recorded)} vs replayed {len(replayed)}")
    for i, (a, b) in enumerate(zip(recorded, replayed), start=1):
        if _key(a) == _key(b):
            continue
        report.identical = False
        fields = [
            name for name, va, vb in (
                ("capability", a.capability, b.capability),
                ("driver", a.driver, b.driver),
                ("veto", a.veto, b.veto),
                ("value", round(a.value, 4), round(b.value, 4)),
                ("base", round(a.base, 4), round(b.base, 4)),
                ("profile", a.profile, b.profile),
            ) if va != vb]
        report.differences.append(
            f"#{i} {a.capability}: fields changed [{'/'.join(fields) or '?'}] "
            f"recorded {a.driver or '-'} value {a.value:.2f} veto {a.veto or '-'} "
            f"!= replayed {b.driver or '-'} value {b.value:.2f} "
            f"veto {b.veto or '-'}")
    return report
