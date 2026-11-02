"""trust.py — how much authority a phase's model has EARNED.

The advisor used to carry fixed constants (±12 points, 2 positions, no pair
inversion above a 15-point gap). Those numbers were the same for a model that
had measured nothing and for one that beat the deterministic baseline on a
hundred rows, and they made a whole class of decisions impossible to change by
construction: a 19-point gap could never be flipped, even by a perfect model.

Authority is now derived from the *measured* eval gate the training pipeline
writes into the manifest (``eval_gate``: ``verdict``, ``n``, ``delta``,
``ci_low``, ``min_rows``). Three levels, and only one of them may move a
decision across a large score gap:

    observe  no promoted manifest, no gate, a rejected gate, or n < min_rows.
             The advisor is not even called: a model that has measured
             nothing decides nothing, and the deterministic order stands.
    nudge    the gate promoted, but the measured advantage is small
             (< ``DECIDE_DELTA``). It may reorder nearby candidates only
             (±12 points, 2 positions, no inversion above 15 points).
    decide   the gate promoted with a large, statistically-supported delta
             (``delta >= decide_delta(baseline)`` and a ``ci_low`` at least
             half that margin). The threshold is a SHARE OF THE HEADROOM the
             baseline left, not a fixed number: a fixed one is unreachable
             whenever the baseline is already strong. It may
             move further (±35 points, 5 positions, no inversion above 30).

The ladder is monotone in evidence: any doubt (a corrupt manifest, a missing
field) LOWERS it, and evidence is the default. There is exactly ONE way to
raise it without evidence — an explicit operator override
(``ai.authority`` / ``PHANTOM_AI_AUTHORITY``) — and it ANNOUNCES itself in the
run output instead of quietly widening the caps, because an operator who
asked for it must be able to read afterwards that the model was trusted
further than it earned. Hard invariants are untouched at every level: a model
can never add a candidate, change ``actionable``/``auto_execute``/``success``,
or emit anything executable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

LEVELS = ("observe", "nudge", "decide")

# Must equal ``training.gate.*``: the same threshold the promotion gate uses to
# call an advantage "large" is the one that unlocks the decide level. They are
# duplicated because the runtime must not import the training package
# (``training/`` is not shipped with the application), and
# ``tests/test_ai_trust.py`` pins them to each other.
#
# The threshold is HEADROOM-RELATIVE since 2026-10-30. The fixed 0.10 was
# unreachable when the baseline was 0.9021 (a perfect model wins at most
# 0.0979), so the top level could not be earned by any measurement — the
# ladder had a rung nothing could reach, which is worse than no rung.
DECIDE_DELTA = 0.10          # legacy constant: the floor of the old policy
DECIDE_HEADROOM = 0.30
DECIDE_DELTA_MIN = 0.02


def decide_delta(baseline: float = 0.0) -> float:
    """Mirror of ``training.gate.decide_delta`` (pinned by a test)."""
    try:
        base = float(baseline or 0.0)
    except (TypeError, ValueError):
        base = 0.0
    base = max(0.0, min(1.0, base))
    return round(max(DECIDE_DELTA_MIN, DECIDE_HEADROOM * (1.0 - base)), 4)

# The historical constants, kept as the ``nudge`` profile. ``advisors.exploit``
# re-exports them as BOUND / MAX_STEPS / GAP so existing imports keep working.
_NUDGE = {"bound": 0.12, "max_steps": 2, "gap": 0.15}
_DECIDE = {"bound": 0.35, "max_steps": 5, "gap": 0.30}
_OBSERVE = {"bound": 0.0, "max_steps": 0, "gap": 0.0}

# A `decide` level also needs a lower confidence bound that is meaningfully
# above zero: "the point estimate says +30 points" is not evidence when the
# interval straddles the baseline. The bar is HALF the required margin, not a
# fixed 0.05: that constant was the second half of the same unreachability
# (a +0.040 delta on a 0.90 baseline carries a ci_low near +0.015, which a
# fixed 0.05 rejected while the margin itself was satisfied).
_CI_SHARE = 0.5


@dataclass(frozen=True)
class Trust:
    """The authority one phase's model may exercise on the current call."""

    phase: str = ""
    level: str = "observe"
    bound: float = 0.0
    max_steps: int = 0
    gap: float = 0.0
    source: str = "none"
    reason: str = ""

    @property
    def active(self) -> bool:
        return self.level != "observe"


def _observe(phase: str, reason: str, *, strict: bool = False) -> Trust:
    """The deterministic order stands and the model is not called.

    The ONE exception is an operator who explicitly asked for a local model
    (``ai.mode=local``, e.g. ``--ai local``). That is a direct instruction to
    consult it, not an inference from a manifest, so it keeps the historical
    bounded profile (``nudge``) instead of being silenced — it is still not
    trusted with a large gap, because nothing about it has been measured.

    ``strict=True`` names the case where a measurement EXISTS and is negative
    (a rejected verdict, a sample below the row floor): no operator preference
    may turn negative evidence into authority, so the opt-in does not apply.
    """
    try:
        from phantom.automation.ai import config as ai_config
        if not strict and phase and ai_config.mode(phase) == "local":
            return Trust(phase=phase, level="nudge", source="none",
                         reason=("operator enabled a local model explicitly; "
                                 "unmeasured, so bounded to the nudge profile"),
                         **_NUDGE)
    except Exception:
        pass
    return Trust(phase=phase, level="observe", source="none", reason=reason,
                 **_OBSERVE)


def _gate(manifest: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    gate = manifest.get("eval_gate")
    return gate if isinstance(gate, dict) else None


def _measured_trust(phase: str, *, registry: Any = None) -> Trust:
    """The authority ``phase``'s model has EARNED (evidence only). Never raises.

    A broken manifest, an unreadable directory or a missing field is an
    ``observe`` with a reason: the caller keeps the deterministic order and the
    operator can read why the model was silent.
    """
    name = str(phase or "").strip()
    if not name:
        return _observe(name, "no phase named")
    try:
        if registry is None:
            from phantom.automation.ai.registry import ModelRegistry
            registry = ModelRegistry()
        manifest = registry.promoted(name)
    except Exception as exc:                      # unreadable models/ tree
        return _observe(name, f"model registry unreadable: {exc}")
    if not isinstance(manifest, dict):
        return _observe(name, f"no promoted model for {name}")

    gate = _gate(manifest)
    if gate is None:
        return _observe(name, "promoted manifest carries no eval_gate: "
                              "it has not been measured against a baseline")

    verdict = str(gate.get("verdict") or "").strip().lower()
    if verdict != "promote":
        return _observe(name, f"eval gate verdict is {verdict or 'missing'!r}",
                        strict=True)

    try:
        rows = int(gate.get("n") or 0)
    except (TypeError, ValueError):
        rows = 0
    try:
        min_rows = int(gate.get("min_rows") or 1)
    except (TypeError, ValueError):
        min_rows = 1
    if rows < min_rows:
        return _observe(name, f"eval gate measured {rows} row(s), below the "
                              f"{min_rows}-row floor", strict=True)

    try:
        delta = float(gate.get("delta") or 0.0)
    except (TypeError, ValueError):
        return _observe(name, "eval gate delta is not a number", strict=True)
    try:
        ci_low = float(gate.get("ci_low"))
    except (TypeError, ValueError):
        ci_low = 0.0

    # The threshold comes from the measurement: the gate writes the baseline
    # it compared against, and `decide_delta` turns that into the advantage
    # a model must win to earn the large-gap profile. A manifest that carries
    # no baseline falls back to the strictest reading (baseline 0), never to
    # the old fixed 0.10 that no model could reach on a strong baseline.
    try:
        baseline = float(gate.get("baseline") or 0.0)
    except (TypeError, ValueError):
        baseline = 0.0
    threshold = decide_delta(baseline)
    if delta < threshold:
        return Trust(phase=name, level="nudge", source="manifest",
                     reason=(f"gate promoted on {rows} rows, delta "
                             f"{delta:+.3f} < {threshold:.3f} "
                             f"({DECIDE_HEADROOM:.0%} of the "
                             f"{1.0 - baseline:.3f} headroom over a "
                             f"{baseline:.3f} baseline): nearby reordering "
                             f"only"),
                     **_NUDGE)
    ci_floor = round(_CI_SHARE * threshold, 4)
    if ci_low < ci_floor:
        return Trust(phase=name, level="nudge", source="manifest",
                     reason=(f"delta {delta:+.3f} but ci_low {ci_low:+.3f} < "
                             f"{ci_floor:.3f} (half the {threshold:.3f} "
                             f"margin): the interval is too close to the "
                             f"baseline, so no large-gap authority"),
                     **_NUDGE)
    return Trust(phase=name, level="decide", source="manifest",
                 reason=(f"gate promoted on {rows} rows, delta {delta:+.3f} "
                         f"(ci_low {ci_low:+.3f}) >= {threshold:.3f}, which is "
                         f"{DECIDE_HEADROOM:.0%} of the "
                         f"{1.0 - baseline:.3f} headroom a "
                         f"{baseline:.3f} baseline left: earned large-gap "
                         f"authority"),
                 **_DECIDE)


# `full` is the explicit "let the model steer" profile: within the ELIGIBLE
# candidates it may reorder freely. It still cannot add a move, change a
# flag, or emit anything executable — those are not caps, they are structure.
_OVERRIDE_PROFILES = {
    "nudge": _NUDGE,
    "decide": _DECIDE,
    "full": {"bound": 1.0, "max_steps": 99, "gap": 1.0},
}


def apply_authority(trust: Trust) -> Trust:
    """Apply the operator's ``ai.authority`` override, loudly.

    Evidence stays the default. This exists because a lab or a controlled
    engagement may WANT a model to steer past what its eval gate proved — the
    honest way to offer that is a switch that says so in the run output, not a
    constant somebody raises once and nobody can trace.
    """
    try:
        from phantom.automation.ai import config as ai_config
        level = ai_config.authority_override()
    except Exception:
        return trust
    if level == "auto":
        return trust
    profile = _OVERRIDE_PROFILES.get(level)
    if not profile:
        return trust
    try:
        from phantom.utils.notifier import notifier
        notifier.warn(
            f"AI authority OVERRIDDEN to '{level}' for phase "
            f"{trust.phase or '?'}: the ladder said '{trust.level}' "
            f"({trust.reason or 'no evidence'}) and the model will now reorder "
            f"candidates further than it earned. Hard invariants still hold: "
            f"no new candidate, no flag changes, nothing executable.")
    except Exception:
        pass
    return Trust(phase=trust.phase, level=level, source="operator-override",
                 reason=(f"operator override '{level}' "
                         f"(ladder: {trust.level})"),
                 **profile)


def trust_for(phase: str, *, registry: Any = None) -> Trust:
    """Public entry point: the measured ladder, plus an announced override."""
    return apply_authority(_measured_trust(phase, registry=registry))
