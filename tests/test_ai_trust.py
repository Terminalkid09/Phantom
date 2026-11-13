"""The advisor's authority is EARNED from a measured gate, not from constants.

Two properties are pinned here:

1. the ladder only goes UP with evidence and DOWN with doubt (a corrupt
   manifest is ``observe``, never a crash and never ``decide``);
2. a ``decide``-level model can actually change a decision the old ±12-point
   constants made unreachable — while ``nudge`` still cannot, and ``observe``
   never even calls the model.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from phantom.automation.ai import trust as trust_mod
from phantom.automation.ai.advisors import exploit as advisor
from phantom.automation.ai.registry import ModelRegistry
from phantom.automation.ai.trust import Trust, trust_for


def _manifest(tmp_path: Path, gate: dict, version: str = "v1") -> ModelRegistry:
    root = tmp_path / "project"
    folder = root / "models" / "exploit" / version
    folder.mkdir(parents=True)
    data = {
        "phase": "exploit",
        "version": version,
        "base_model": "Qwen/Qwen2.5-0.5B-Instruct",
        "sha256": "0" * 64,
        "trained_at": "2026-10-29T00:00:00Z",
        "eval": {"ndcg": 0.71},
        "baseline": {"ndcg": 0.63},
        "promoted": True,
        "eval_gate": gate,
    }
    (folder / "manifest.json").write_text(json.dumps(data), encoding="utf-8")
    return ModelRegistry(root)


class _Cand:
    """The smallest object the advisor reads (no AccessCandidate import)."""

    def __init__(self, cid: str, score: float, *, actionable: bool = True,
                 auto_execute: bool = True):
        self.id = cid
        self.score = score
        self.actionable = actionable
        self.auto_execute = auto_execute
        self.success = score / 100.0
        self.complexity = 0.2
        self.noise = 0.1
        self.access_level = 2
        self.access = "exec"
        self.kind = "cve"
        self.cve = ""
        self.port = ""
        self.product = ""
        self.version = ""
        self.module = None


def _answer(*ids: str) -> SimpleNamespace:
    return SimpleNamespace(ok=True, model="stub",
                           data={"ranked": [{"id": i} for i in ids]},
                           error="")


def test_no_manifest_is_observe_and_zero_influence(tmp_path):
    registry = ModelRegistry(tmp_path / "empty")
    got = trust_for("exploit", registry=registry)
    assert got.level == "observe"
    assert got.source == "none"
    assert got.bound == 0.0 and got.max_steps == 0 and got.gap == 0.0
    assert got.reason


def test_a_small_measured_delta_is_nudge(tmp_path):
    registry = _manifest(tmp_path, {"verdict": "promote", "n": 40,
                                    "delta": 0.04, "ci_low": 0.02,
                                    "min_rows": 20})
    got = trust_for("exploit", registry=registry)
    assert got.level == "nudge"
    assert got.source == "manifest"
    assert got.bound == 0.12 and got.max_steps == 2 and got.gap == 0.15


def test_a_large_supported_delta_is_decide(tmp_path):
    registry = _manifest(tmp_path, {"verdict": "promote", "n": 60,
                                    "delta": 0.30, "ci_low": 0.20,
                                    "min_rows": 20})
    got = trust_for("exploit", registry=registry)
    assert got.level == "decide"
    assert (got.bound, got.max_steps, got.gap) == (0.35, 5, 0.30)


def test_a_large_delta_whose_interval_touches_zero_only_nudges(tmp_path):
    registry = _manifest(tmp_path, {"verdict": "promote", "n": 60,
                                    "delta": 0.30, "ci_low": 0.01,
                                    "min_rows": 20})
    assert trust_for("exploit", registry=registry).level == "nudge"


def test_a_gate_measured_on_too_few_rows_does_nothing(tmp_path):
    # The old failure mode: promoted on n=3, where one row moves the score by
    # a third. It must not buy any authority.
    registry = _manifest(tmp_path, {"verdict": "promote", "n": 3,
                                    "delta": 0.9, "ci_low": 0.8,
                                    "min_rows": 20})
    assert trust_for("exploit", registry=registry).level == "observe"


def test_a_corrupt_manifest_is_observe_not_a_crash(tmp_path):
    folder = tmp_path / "project" / "models" / "exploit" / "v1"
    folder.mkdir(parents=True)
    (folder / "manifest.json").write_text("{oops", encoding="utf-8")
    got = trust_for("exploit",
                    registry=ModelRegistry(tmp_path / "project"))
    assert got.level == "observe"


def test_observe_never_calls_the_model(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("the model must not be called at observe")

    monkeypatch.setattr(advisor, "ask", _boom)
    cands = [_Cand("strong", 86.0), _Cand("weak", 61.0)]
    got = advisor.rerank(cands, trust=Trust(phase="exploit",
                                            level="observe",
                                            reason="nothing measured"))
    assert got.applied is False
    assert [c.id for c in got.ordered] == ["strong", "weak"]
    assert got.reason == "nothing measured"


def test_decide_can_invert_a_gap_the_old_constants_capped(monkeypatch):
    monkeypatch.setattr(advisor, "ask", lambda *a, **k: _answer("weak",
                                                              "strong"))
    cands = [_Cand("strong", 86.0), _Cand("weak", 61.0)]   # 25-point gap
    got = advisor.rerank(cands, trust=Trust(phase="exploit", level="decide",
                                            bound=0.35, max_steps=5,
                                            gap=0.30, source="manifest"))
    assert [c.id for c in got.ordered] == ["weak", "strong"]
    assert got.applied is True
    assert got.level == "decide"


def test_nudge_cannot_invert_the_same_gap(monkeypatch):
    monkeypatch.setattr(advisor, "ask", lambda *a, **k: _answer("weak",
                                                              "strong"))
    cands = [_Cand("strong", 86.0), _Cand("weak", 61.0)]
    got = advisor.rerank(cands, trust=Trust(phase="exploit", level="nudge",
                                            bound=0.12, max_steps=2,
                                            gap=0.15, source="manifest"))
    assert [c.id for c in got.ordered] == ["strong", "weak"]
    assert got.applied is False


def test_the_decide_threshold_matches_the_training_gate():
    from training.gate import DECIDE_DELTA as training_delta
    assert training_delta == trust_mod.DECIDE_DELTA


def test_the_decide_threshold_is_headroom_relative_in_both_modules():
    """The threshold the gate writes and the one the runtime applies agree.

    Measured defect (2026-10-29): the exploit baseline scores 0.9021, so a
    PERFECT model wins at most 0.0979 — the fixed 0.10 threshold made the
    ``decide`` level unreachable by ANY model, not just by ours.
    """
    from training import gate as training_gate

    for baseline in (0.0, 0.5, 0.9021, 0.95, 0.99):
        assert (training_gate.decide_delta(baseline)
                == trust_mod.decide_delta(baseline))
    assert training_gate.decide_delta(0.9021) < 0.0979
    # a near-perfect baseline cannot turn a meaningless advantage into authority
    assert training_gate.decide_delta(0.999) == training_gate.DECIDE_DELTA_MIN
    # ...and the threshold only shrinks as the baseline gets stronger
    assert (training_gate.decide_delta(0.0)
            > training_gate.decide_delta(0.5)
            > training_gate.decide_delta(0.9))


def test_a_strong_baseline_delta_can_now_reach_decide(tmp_path):
    """The case the fixed threshold silently refused.

    delta +0.0399 on a 0.9021 baseline is 41% of the whole headroom: a real
    advantage. The old constant asked for 0.10 (102% of it) and downgraded it
    to ``nudge`` for a reason that had nothing to do with the measurement.
    """
    # n=40, not 31: the ladder also requires TWICE the row floor for the
    # large-gap profile (`test_a_thin_sample_is_only_a_nudge`), and this test
    # is about the THRESHOLD formula, so it must hold the sample fixed and
    # comfortably above that bar instead of accidentally testing both rules.
    registry = _manifest(tmp_path, {"verdict": "promote", "n": 40,
                                    "delta": 0.0399, "ci_low": 0.0150,
                                    "baseline": 0.9021, "min_rows": 20})
    got = trust_for("exploit", registry=registry)
    assert got.level == "decide", got.reason
    assert "headroom" in got.reason


def test_a_thin_sample_is_only_a_nudge(tmp_path):
    """Measured 2026-11-03: a 23-row promotion earned the widest lever.

    The 23-row production corpus promoted a ranker at +0.130 over a 0.133
    headroom (97% of the room), so the ladder handed it +/-35 points and five
    positions on 23 generated rows. The row floor says "this is evidence at
    all"; the large-gap profile needs a bigger sample than that, and the
    reason must say which rule refused it.
    """
    registry = _manifest(tmp_path, {"verdict": "promote", "n": 31,
                                    "delta": 0.0399, "ci_low": 0.0150,
                                    "baseline": 0.9021, "min_rows": 20})
    got = trust_for("exploit", registry=registry)
    assert got.level == "nudge", got.reason
    assert "twice the" in got.reason
    assert got.bound == 0.12, "nudge keeps the small, real effect"


def test_a_weak_baseline_delta_of_the_same_size_is_only_a_nudge(tmp_path):
    """Same delta, different headroom: 0.04 is 4% of a 0.0 baseline's room."""
    registry = _manifest(tmp_path, {"verdict": "promote", "n": 31,
                                    "delta": 0.0399, "ci_low": 0.0150,
                                    "baseline": 0.0, "min_rows": 20})
    assert trust_for("exploit", registry=registry).level == "nudge"


def test_a_manifest_without_a_baseline_is_judged_strictly(tmp_path):
    """No baseline means no headroom claim: the strictest threshold applies."""
    registry = _manifest(tmp_path, {"verdict": "promote", "n": 40,
                                    "delta": 0.04, "ci_low": 0.02,
                                    "min_rows": 20})
    got = trust_for("exploit", registry=registry)
    assert got.level == "nudge"


def test_an_explicit_local_model_keeps_the_bounded_profile(tmp_path, monkeypatch):
    """``--ai local`` is an operator instruction, not an inference.

    A local model has no manifest and no measurement, so the ladder alone would
    silence it. Asking for it explicitly must still be honoured — but only with
    the historical bounded profile, never with ``decide`` authority.
    """
    monkeypatch.setenv("PHANTOM_AI_MODE", "local")
    monkeypatch.delenv("PHANTOM_AI_EXPLOIT_MODE", raising=False)
    empty = ModelRegistry(tmp_path / "empty")
    trust = trust_for("exploit", registry=empty)
    assert trust.level == "nudge"
    assert trust.source == "none"
    assert (trust.bound, trust.max_steps, trust.gap) == (0.12, 2, 0.15)
    assert "operator" in trust.reason


def test_a_rejected_gate_is_not_overridden_by_the_local_opt_in(tmp_path,
                                                              monkeypatch):
    """Negative evidence outranks the preference: reject + local stays observe."""
    monkeypatch.setenv("PHANTOM_AI_MODE", "local")
    monkeypatch.delenv("PHANTOM_AI_EXPLOIT_MODE", raising=False)
    registry = _manifest(tmp_path, {"verdict": "reject", "n": 40,
                                   "delta": -0.2, "ci_low": -0.3,
                                   "min_rows": 20})
    trust = trust_for("exploit", registry=registry)
    assert trust.level == "observe"
    assert trust.bound == 0.0 and trust.max_steps == 0
