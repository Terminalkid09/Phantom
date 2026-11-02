"""A promotion says WHAT it rests on, or it does not happen.

The defect this pins (measured 2026-11-02):
``models/evolution/2026-10-26-cpu-v3/manifest.json`` carried
``"promoted": true`` with ``eval == baseline == {"exact_match": 1.0}`` on
``golden_rows: 3`` and no ``eval_gate``. The runtime refused it
(``trust_for("evolution")`` is ``observe``), so nothing unsafe shipped, but the
FILE claimed a promotion the repository cannot back.

``build_manifest`` now derives the verdict from the evidence and records
``promotion_basis`` + ``promotion_reason`` beside it, and a caller cannot force
a claim the measurement does not carry.
"""

import json
from pathlib import Path

import pytest

from training.gate import MIN_ROWS
from training.manifest import (PROMOTING_BASES, build_manifest,
                               promotion_evidence, validate_manifest)

ROOT = Path(__file__).resolve().parents[1]
BASE = dict(phase="exploit", version="v-test", base_model="m", adapter="a")


def _manifest(**kw):
    return build_manifest(**BASE, **kw)


def _gate(verdict, **kw):
    gate = {"verdict": verdict, "n": 31, "min_rows": MIN_ROWS,
            "delta": 0.04, "ci_low": 0.01}
    gate.update(kw)
    return gate


def test_a_tie_is_not_evidence():
    manifest = _manifest(eval_metrics={"ndcg": 1.0},
                         baseline={"ndcg": 1.0}, extra={"golden_rows": 3})
    assert manifest["promoted"] is False
    assert ("tie" in manifest["promotion_reason"].lower()
            or "below" in manifest["promotion_reason"].lower())


def test_a_strict_win_on_three_rows_is_not_a_promotion():
    manifest = _manifest(eval_metrics={"ndcg": 0.9}, baseline={"ndcg": 0.5},
                         extra={"golden_rows": 3})
    assert manifest["promoted"] is False
    assert manifest["promotion_basis"] == "insufficient-rows"
    assert str(MIN_ROWS) in manifest["promotion_reason"]


def test_a_strict_win_above_the_row_floor_promotes_without_a_gate():
    manifest = _manifest(eval_metrics={"ndcg": 0.9}, baseline={"ndcg": 0.5},
                         extra={"golden_rows": MIN_ROWS})
    assert manifest["promoted"] is True
    assert manifest["promotion_basis"] == "strict-eval"
    # The weaker claim must SAY it is weaker: the runtime caps it at observe.
    assert "observe" in manifest["promotion_reason"].lower()


def test_a_loss_is_never_promoted():
    manifest = _manifest(eval_metrics={"ndcg": 0.4}, baseline={"ndcg": 0.5},
                         extra={"golden_rows": MIN_ROWS})
    assert manifest["promoted"] is False
    assert manifest["promotion_basis"] == "none"



def test_the_gate_verdict_decides_when_one_is_present():
    promoted = _manifest(eval_metrics={"ndcg": 0.94}, baseline={"ndcg": 0.90},
                         extra={"golden_rows": 31,
                                "eval_gate": _gate("promote")})
    assert promoted["promoted"] is True
    assert promoted["promotion_basis"] == "gate"

    rejected = _manifest(eval_metrics={"ndcg": 0.94}, baseline={"ndcg": 0.90},
                         extra={"golden_rows": 31,
                                "eval_gate": _gate("reject", ci_low=-0.01,
                                                   reasons=["CI straddles zero"])})
    assert rejected["promoted"] is False
    assert rejected["promotion_basis"] == "gate"
    assert "CI straddles zero" in rejected["promotion_reason"]


def test_a_rejected_gate_cannot_be_outvoted_by_a_larger_mean():
    """The mean looking better is exactly what a gate exists to disbelieve."""
    manifest = _manifest(eval_metrics={"ndcg": 0.99}, baseline={"ndcg": 0.10},
                         extra={"golden_rows": 31,
                                "eval_gate": _gate("reject")})
    assert manifest["promoted"] is False


def test_a_caller_cannot_force_a_promotion_the_measurement_denies():
    manifest = _manifest(promoted=True, eval_metrics={"ndcg": 1.0},
                         baseline={"ndcg": 1.0}, extra={"golden_rows": 3})
    assert manifest["promoted"] is False
    assert "refused" in manifest["promotion_reason"].lower()


def test_a_caller_may_still_withhold_a_promotion_that_was_earned():
    manifest = _manifest(promoted=False, eval_metrics={"ndcg": 0.94},
                         baseline={"ndcg": 0.90},
                         extra={"golden_rows": 31,
                                "eval_gate": _gate("promote")})
    assert manifest["promoted"] is False
    assert "withheld" in manifest["promotion_reason"].lower()


@pytest.mark.parametrize("case", [
    dict(eval_metrics={"ndcg": 1.0}, baseline={"ndcg": 1.0},
         extra={"golden_rows": 3}),
    dict(eval_metrics={"ndcg": 0.9}, baseline={"ndcg": 0.5},
         extra={"golden_rows": MIN_ROWS}),
    dict(eval_metrics={"ndcg": 0.94}, baseline={"ndcg": 0.90},
         extra={"golden_rows": 31, "eval_gate": _gate("promote")}),
])
def test_every_manifest_states_a_valid_basis_and_a_reason(case):
    manifest = _manifest(**case)
    assert manifest["promotion_basis"] in PROMOTING_BASES + ("insufficient-rows",
                                                             "none")
    assert str(manifest["promotion_reason"]).strip()
    if manifest["promoted"]:
        assert validate_manifest(manifest) == []


def test_promotion_evidence_never_raises_on_garbage():
    for evals, baseline in ((None, None), ({}, {}), ({"x": "nan"}, {"x": 1}),
                            ({"x": 1.0}, {})):
        promoted, basis, reason = promotion_evidence(evals, baseline, {})
        assert promoted is False
        assert basis in ("none", "insufficient-rows", "gate", "strict-eval")
        assert reason


def test_the_shipped_evolution_manifest_is_recorded_as_not_promoted():
    """The file on disk is the claim a reader believes. It must match the
    runtime's own refusal."""
    path = ROOT / "models" / "evolution" / "2026-10-26-cpu-v3" / "manifest.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["promoted"] is False, (
        "a 3-row tie is recorded as a promotion again")
    assert data["promotion_basis"] == "insufficient-rows"
    assert data["sha256"], "the adapter digest must survive the correction"


def test_the_runtime_agrees_with_the_file():
    from phantom.automation.ai.trust import trust_for
    trust = trust_for("evolution")
    assert trust.level == "observe"
    assert trust.active is False
