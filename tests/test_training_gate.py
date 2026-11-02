"""The promotion gate must refuse a claim it cannot support.

Each test names a way the old rule (``score >= baseline``) promoted something
it had not measured: three rows, a tie, an interval that straddles zero.
The integration fixture deliberately ranks the CVE candidate first on EVERY
row: the deterministic baseline (``training.predict._baseline``) sorts
``(is_cve, -cvss)`` ascending and therefore prefers the NON-CVE id, so the
model's advantage is real and constant and the only variable left is the row
budget.
"""

import json

from training import eval as training_eval
from training import gate


def _pairs(n, model, baseline):
    return [(float(model), float(baseline)) for _ in range(n)]


def test_three_perfect_rows_are_refused_for_the_sample_size():
    decision = gate.decide("exploit", _pairs(3, 1.0, 0.0))
    assert decision["verdict"] == "reject"
    assert decision["n"] == 3
    assert any("min_rows" in reason for reason in decision["reasons"])


def test_a_tie_on_enough_rows_is_refused_for_the_interval():
    decision = gate.decide("exploit", _pairs(25, 0.5, 0.5))
    assert decision["verdict"] == "reject"
    assert decision["delta"] == 0.0
    assert any("CI" in reason for reason in decision["reasons"])


def test_a_consistent_advantage_promotes():
    decision = gate.decide("exploit", _pairs(25, 0.9, 0.7))
    assert decision["verdict"] == "promote"
    assert decision["reasons"] == []
    assert decision["delta"] == 0.2
    assert decision["ci_low"] > 0.0


def test_the_interval_is_deterministic_and_reports_plain_means():
    pairs = [(0.9, 0.5), (0.8, 0.7), (0.6, 0.6), (1.0, 0.4)]
    first = gate.bootstrap_ci(pairs)
    second = gate.bootstrap_ci(pairs)
    assert first == second
    assert first["n"] == 4
    assert first["score"] == round(sum(p[0] for p in pairs) / 4, 6)
    assert first["baseline"] == round(sum(p[1] for p in pairs) / 4, 6)
    assert first["ci_low"] <= first["delta"] <= first["ci_high"]


def test_an_empty_measurement_is_reported_not_raised():
    empty = gate.bootstrap_ci([])
    assert empty["n"] == 0
    assert empty["delta"] == 0.0
    assert gate.decide("exploit", [])["verdict"] == "reject"


def _write_jsonl(path, rows):
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n",
                    encoding="utf-8")
    return path


def _exploit_fixture(tmp_path):
    golden = [
        {"id": "e1", "phase": "exploit", "metric": "ndcg",
         "input": {"candidates": [{"id": "ssh_login", "access": "exec"},
                                  {"id": "CVE-2023-38408", "access": "exec",
                                   "cvss": 9.8}]},
         "expected": {"ranking": ["CVE-2023-38408", "ssh_login"]}},
        {"id": "e2", "phase": "exploit", "metric": "ndcg",
         "input": {"candidates": [{"id": "CVE-2021-41773", "access": "exec",
                                   "cvss": 9.8},
                                  {"id": "http_probe", "access": "info"}]},
         "expected": {"ranking": ["CVE-2021-41773", "http_probe"]}},
        {"id": "e3", "phase": "exploit", "metric": "ndcg",
         "input": {"candidates": [{"id": "redis_info",
                                   "access": "file_read"},
                                  {"id": "CVE-2022-0543", "access": "exec",
                                   "cvss": 10.0}]},
         "expected": {"ranking": ["CVE-2022-0543", "redis_info"]}},
    ]
    # Every row must carry a real advantage over `training.predict._baseline`,
    # which sorts `[(is_cve, -cvss)]` ASCENDING — i.e. it puts NON-CVE ids
    # first. So the expected ranking here puts the CVE first on all three
    # rows: the model's advantage is real and constant, and the only variable
    # left is the row budget.
    predictions = [{"id": row["id"], "prediction": row["expected"]}
                   for row in golden]
    return (_write_jsonl(tmp_path / "golden.jsonl", golden),
            _write_jsonl(tmp_path / "pred.jsonl", predictions))


def test_eval_reports_the_baseline_and_gates_on_the_row_scores(tmp_path):
    golden, predictions = _exploit_fixture(tmp_path)
    out = tmp_path / "result.json"
    code = training_eval.main([
        "--phase", "exploit", "--predictions", str(predictions),
        "--golden", str(golden), "--compare-baseline", "--gate",
        "--min-rows", "3", "--out", str(out), "--quiet"])
    assert code == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["baseline"]["n"] == 3
    assert result["delta"] == round(
        result["score"] - result["baseline"]["score"], 6)
    assert result["gate"]["verdict"] == "promote"
    assert result["gate"]["n"] == 3


def test_the_same_run_is_refused_when_the_row_budget_is_the_real_one(tmp_path):
    golden, predictions = _exploit_fixture(tmp_path)
    out = tmp_path / "result.json"
    code = training_eval.main([
        "--phase", "exploit", "--predictions", str(predictions),
        "--golden", str(golden), "--gate", "--min-rows", "20",
        "--out", str(out), "--quiet"])
    assert code == 1
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["gate"]["verdict"] == "reject"
    assert result["gate"]["reasons"]


# ── the decide threshold must be reachable ────────────────────────────────

def test_decide_delta_is_a_share_of_the_headroom_not_a_fixed_number():
    """A fixed 0.10 was 102% of the headroom over a 0.9021 baseline.

    Measured 2026-10-29: the exploit ranker's baseline is ndcg 0.9021, so no
    model — not even a perfect one — could reach delta 0.10 and earn the
    ``decide`` level. The threshold is now a share of what is actually left.
    """
    assert gate.decide_delta(0.9021) == round(gate.DECIDE_HEADROOM * 0.0979, 4)
    assert gate.decide_delta(0.9021) < 0.0979, (
        "the threshold must stay inside the headroom a real model could win")
    assert gate.decide_delta(0.0) == gate.DECIDE_HEADROOM
    assert gate.decide_delta(1.0) == gate.DECIDE_DELTA_MIN


def test_decide_delta_never_raises_on_garbage():
    assert gate.decide_delta(None) == gate.DECIDE_HEADROOM
    assert gate.decide_delta("nope") == gate.DECIDE_HEADROOM
    assert gate.decide_delta(-3) == gate.DECIDE_HEADROOM
    assert gate.decide_delta(9) == gate.DECIDE_DELTA_MIN


def test_a_promoted_measurement_carries_its_own_decide_threshold():
    """The runtime reads the threshold from the measurement, not a constant."""
    pairs = [(0.95, 0.90)] * 25
    decision = gate.decide("exploit", pairs)
    assert decision["verdict"] == "promote"
    assert decision["decide_delta"] == gate.decide_delta(decision["baseline"])
