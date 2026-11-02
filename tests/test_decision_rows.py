"""The decision log is the missing training data — pin what it must contain.

The ranker already has ``success``/``noise``/``complexity`` as features on both
sides, and measured 2026-11-01 the corpus was constant on all three: the
planner computes them, the session threw them away, and the model had nothing
to learn. These tests hold the wire in place: a logged row keeps the three
numbers, a converted row keeps them as candidate fields, and the label is an
OBSERVATION (what happened), not the planner's own score.
"""

from __future__ import annotations

import json

from types import SimpleNamespace

from phantom.automation.exploit import decision_log
from training import from_decisions


def _cand(cid, *, success=0.7, noise=0.3, complexity=0.4, port="443",
          service="https", cve=""):
    return SimpleNamespace(id=cid, cve=cve, port=port, service=service,
                           access="rce", success=success, noise=noise,
                           complexity=complexity)


def _outcome(attempted=True, vulnerable=False, rce=False, method="poc"):
    return SimpleNamespace(attempted=attempted, vulnerable=vulnerable,
                           rce=rce, method=method)


def test_a_logged_row_keeps_the_three_production_scores():
    row = decision_log.row(
        _cand("web_rce", success=0.94, noise=0.2, complexity=0.1),
        target="10.0.0.5", goal="deliver", mode="balanced",
        profile="enterprise", outcomes=[_outcome(vulnerable=True)],
        vulnerable=True, rce=True)
    cand = row["candidate"]
    assert cand["success"] == 0.94
    assert cand["noise"] == 0.2
    assert cand["complexity"] == 0.1
    assert row["outcome"]["rce"] is True
    assert row["context"]["web_surface"] is True


def test_the_row_carries_no_command_and_no_output():
    """The corpus must stay safe to train on and safe to publish."""
    row = decision_log.row(_cand("x"), outcomes=[_outcome()])
    keys = json.dumps(row).lower()
    assert "command" not in keys and "output" not in keys
    assert "evidence" not in keys


def test_telemetry_can_be_turned_off(tmp_path, monkeypatch):
    monkeypatch.setenv("PHANTOM_DECISION_ROWS", "0")
    assert decision_log.enabled() is False
    assert decision_log.record(_cand("web_rce")) is None


def test_a_broken_candidate_never_raises():
    """Telemetry that can fail an exploit sweep is a liability."""
    assert decision_log.record(SimpleNamespace()) is None
    assert decision_log.record(object()) is None


def test_rows_are_grouped_per_engagement_and_graded_by_what_happened():
    entries = []
    for cid, outcome in (("web_rce", _outcome(vulnerable=True, rce=True)),
                         ("scan_tcp", _outcome(attempted=True)),
                         ("beacon_deploy", _outcome(attempted=False))):
        entries.append(decision_log.row(
            _cand(cid), target="10.0.0.5", goal="deliver", mode="balanced",
            profile="enterprise", outcomes=[outcome],
            vulnerable=outcome.vulnerable, rce=outcome.rce))
    rows = from_decisions.build_rows(entries)
    assert len(rows) == 1
    ranking = rows[0]["expected"]["ranking"]
    # RCE, then the route that was never reached, then the one that failed
    assert ranking == ["web_rce", "beacon_deploy", "scan_tcp"]


def test_the_label_is_an_observation_not_the_planner_score():
    """Two candidates with identical scores must still be ordered by outcome."""
    entries = [decision_log.row(_cand("a"), outcomes=[_outcome(vulnerable=True)],
                               vulnerable=True),
               decision_log.row(_cand("b"), outcomes=[_outcome(attempted=True)])]
    row = from_decisions.build_rows(entries)[0]
    assert row["expected"]["ranking"][0] == "a"


def test_a_single_candidate_is_not_an_order():
    entries = [decision_log.row(_cand("only"), outcomes=[_outcome()])]
    assert from_decisions.build_rows(entries) == []


def test_the_last_outcome_of_a_candidate_wins():
    first = decision_log.row(_cand("a"), outcomes=[_outcome(attempted=True)],
                             vulnerable=False)
    later = decision_log.row(_cand("a"), outcomes=[_outcome(vulnerable=True)],
                             vulnerable=True)
    other = decision_log.row(_cand("b"), outcomes=[_outcome(attempted=True)])
    row = from_decisions.build_rows([first, later, other])[0]
    assert row["expected"]["ranking"][0] == "a"


def test_the_converted_row_trains_and_keeps_the_stat_columns():
    from training import ranker

    entries = [decision_log.row(_cand("web_rce", success=0.9),
                                outcomes=[_outcome(rce=True, vulnerable=True)],
                                vulnerable=True, rce=True),
               decision_log.row(_cand("scan_tcp", success=0.3, port="22",
                                      service="ssh"),
                                outcomes=[_outcome(attempted=True)])]
    row = from_decisions.build_rows(entries)[0]
    assert any("success" in c for c in row["input"]["candidates"])
    model = ranker.train([row], epochs=20)
    assert model.rank(row["input"])[0] == "web_rce"


def test_the_written_corpus_is_ranked_shape(tmp_path):
    entries = [decision_log.row(_cand("a"), outcomes=[_outcome(vulnerable=True)],
                                vulnerable=True),
               decision_log.row(_cand("b"), outcomes=[_outcome(attempted=True)])]
    path = from_decisions.write(from_decisions.build_rows(entries),
                                tmp_path / "exploit.decisions.jsonl")
    payload = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert set(payload) >= {"phase", "input", "expected"}
