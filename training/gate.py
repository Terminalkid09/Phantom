"""gate.py — does this adapter actually beat the deterministic baseline?

The defect this module names: the promotion rule was ``score >= baseline`` on a
golden set of **three rows**. A three-row set has a resolution of 0.33, so one
lucky row moved the score by a third, a tie promoted a model that learned
nothing, and a model that was genuinely better by a nose could not be told
apart from noise. A number produced that way is not a measurement, and a
manifest promoted on it is a claim the repository cannot back.

So the gate is now a STATISTICAL decision, per row:

* the unit of evidence is one golden row scored twice — by the model and by
  the deterministic baseline Phantom already runs;
* the per-row differences are resampled (percentile bootstrap) to get a 95 %
  interval for the mean advantage;
* a promotion requires the whole interval to sit above zero, and requires
  enough rows for the interval to mean anything.

``MIN_ROWS`` is deliberately not 3. Below it the gate refuses with the sample
size in the reason instead of inventing significance: a small set can be a
smoke test, it cannot be a promotion argument.

``DECIDE_DELTA`` is the second threshold, and it belongs to the runtime rather
than to promotion: a model that is only a hair better earns a *nudge*, not the
authority to reorder a decision (`phantom.automation.ai.trust`). Keeping both
numbers here means the trainer, the gate and the runtime cannot drift.
"""

from __future__ import annotations

import math
import random
from typing import Any, Dict, List, Sequence, Tuple

#: A promotion below this many scored rows is refused, whatever the delta.
MIN_ROWS = 20
#: The mean advantage (and the CI's lower bound) must be strictly above this.
PROMOTE_DELTA = 0.0
#: An advantage this large is what earns real decision authority downstream.
#:
#: KEPT AS THE LEGACY VALUE ONLY: the effective threshold is
#: ``decide_delta(baseline)``, because a FIXED number is unreachable by
#: construction whenever the baseline is already high. Measured case
#: (2026-10-29): the exploit baseline scores ndcg 0.9021, so a PERFECT model
#: wins at most 0.0979 — the old 0.10 meant no model, however good, could ever
#: earn the ``decide`` level. The number was never measured against the
#: headroom it competes for.
DECIDE_DELTA = 0.10
#: Share of the REMAINING headroom (``1 - baseline``) that earns full
#: authority. 30% is a policy choice, and it is stated as one: a model that
#: recovers a third of everything still on the table is substantially better
#: than "a hair better", which is what ``nudge`` is for.
DECIDE_HEADROOM = 0.30
#: Floor for the same threshold, so a near-perfect baseline cannot make a
#: meaningless 0.5-point advantage "large".
DECIDE_DELTA_MIN = 0.02


def _round(value: float) -> float:
    return round(float(value), 6)


def decide_delta(baseline: float = 0.0) -> float:
    """The advantage that earns full decision authority, relative to headroom.

    ``baseline`` is the deterministic score the model is compared with (the
    same number ``bootstrap_ci`` reports), on the metric's own 0..1 scale.
    A gate that measured a 0.90 baseline leaves 0.10 of headroom, so asking
    for a FIXED 0.10 asked for 100% of it; this asks for
    ``DECIDE_HEADROOM`` of whatever is actually left, with a floor.

    Never raises: a garbage baseline is treated as 0.0 (the strictest case,
    which asks for the floor only — the promotion gate still has to pass on
    its own measured evidence).
    """
    try:
        base = float(baseline or 0.0)
    except (TypeError, ValueError):
        base = 0.0
    base = max(0.0, min(1.0, base))
    return round(max(DECIDE_DELTA_MIN, DECIDE_HEADROOM * (1.0 - base)), 4)


def bootstrap_ci(pairs: Sequence[Tuple[float, float]], *,
                 iters: int = 2000, alpha: float = 0.05,
                 seed: int = 7) -> Dict[str, Any]:
    """Percentile-bootstrap interval for ``model - baseline``, per row.

    ``pairs`` is ``[(model_score, baseline_score), ...]`` — ONE entry per
    golden row, never an aggregate. Aggregating first would throw away the
    variance the interval exists to expose.

    Deterministic for a given ``seed`` (``random.Random``) so CI and a laptop
    produce the same interval, and empty input returns zeros rather than an
    exception: a missing measurement is reported, not raised.
    """
    rows = [(float(model), float(baseline)) for model, baseline in pairs]
    n = len(rows)
    iters = max(1, int(iters))
    if not n:
        return {"n": 0, "score": 0.0, "baseline": 0.0, "delta": 0.0,
                "ci_low": 0.0, "ci_high": 0.0, "iters": iters, "seed": seed}

    score = sum(row[0] for row in rows) / n
    baseline = sum(row[1] for row in rows) / n
    deltas = [row[0] - row[1] for row in rows]

    rng = random.Random(seed)
    means: List[float] = []
    for _ in range(iters):
        total = 0.0
        for _ in range(n):
            total += deltas[rng.randrange(n)]
        means.append(total / n)
    means.sort()

    # Nearest-rank percentiles, clamped: a percentile outside the sample is a
    # bug, not a value, so it must not silently fall back to 0.
    def _at(fraction: float) -> float:
        index = int(math.floor(fraction * iters))
        return means[min(iters - 1, max(0, index))]

    return {
        "n": n,
        "score": _round(score),
        "baseline": _round(baseline),
        "delta": _round(score - baseline),
        "ci_low": _round(_at(alpha / 2.0)),
        "ci_high": _round(_at(1.0 - alpha / 2.0)),
        "iters": iters,
        "seed": seed,
    }


def decide(phase: str, pairs: Sequence[Tuple[float, float]], *,
           min_rows: int = MIN_ROWS, iters: int = 2000,
           alpha: float = 0.05, seed: int = 7) -> Dict[str, Any]:
    """Promote only when the measured advantage is above noise.

    Two independent ways to fail, each with its own reason, because they mean
    different things to the operator:

    * too few rows — nothing can be concluded, the fix is more data;
    * an interval that includes zero — the model may be better or worse, the
      fix is a better model (or a cheaper baseline).

    Never raises: a broken pair becomes a rejected gate, not a crashed
    training run.
    """
    result: Dict[str, Any] = dict(bootstrap_ci(pairs, iters=iters,
                                               alpha=alpha, seed=seed))
    result["phase"] = str(phase)
    result["min_rows"] = int(min_rows)
    reasons: List[str] = []

    n = int(result["n"])
    if n < int(min_rows):
        reasons.append(
            f"n={n} < min_rows={int(min_rows)}: too few rows to measure "
            f"(one row moves a {n}-row score by {1.0 / max(n, 1):.2f})")
    if float(result["delta"]) <= PROMOTE_DELTA:
        reasons.append(
            f"mean delta {result['delta']:+.3f} is not above "
            f"{PROMOTE_DELTA:+.3f}: the model does not beat the baseline")
    # Not `elif`: a tie is BOTH "does not beat the baseline" and "the
    # interval straddles zero", and the second sentence is the one that says
    # why more rows would not save it.
    if float(result["ci_low"]) <= PROMOTE_DELTA:
        reasons.append(
            f"95% CI [{result['ci_low']:+.3f}, {result['ci_high']:+.3f}] is "
            f"not above {PROMOTE_DELTA:+.3f}: the margin is not "
            f"distinguishable from noise")

    # The `decide` threshold TRAVELS WITH THE MEASUREMENT: the runtime reads
    # it from here instead of from a constant, so a manifest can never be
    # promoted on headroom-relative terms and then judged by a fixed number.
    result["decide_delta"] = decide_delta(result["baseline"])
    result["verdict"] = "reject" if reasons else "promote"
    result["reasons"] = reasons
    result["passed"] = not reasons
    return result
