"""The production-vocabulary corpus is only worth generating if something READS it.

Measured 2026-11-02, on this checkout: ``python -m training.prod_vocab
--report`` produced 23 rows, 23 scoreable, coverage 1.00 — and
``training.ranker.rows_for`` still read ``training/data/*.jsonl`` only. The
corpus existed, the docstring promised a drift guard in this very file, and no
ranker had ever trained on a single row of it. So the exported weights kept
capability ids (``beacon_deploy``, ``privesc_sudo``) while production emits
access ids (``noncve:service:ssh:22``, ``noncve:creds:ssh:root``): every per-id
weight was dead at runtime and the reranker could not move a decision.

These tests pin the WIRE and the drift guard, not the numbers: a row count that
moved because the corpus was retuned is fine, a corpus that stops being
scoreable (coverage 0.0 — the original gap C1) or a ranker whose weights name
ids the corpus never offered is not.
"""

from __future__ import annotations

import json

import pytest

from training import holdout, prod_vocab, ranker


def test_the_report_is_measured_and_still_scoreable():
    """Coverage above zero is the whole point of this module (gap C1)."""
    info = prod_vocab.report()
    assert info["rows"] == len(prod_vocab.build_rows())
    assert info["rows"] >= 2, "the corpus must contain an ordering at all"
    assert info["scoreable"] is not None
    assert 0.0 <= float(info["coverage"]) <= 1.0
    assert float(info["coverage"]) > 0.0, (
        "production scored NONE of the rows: the two vocabularies drifted "
        "apart again, which is the defect this corpus exists to expose")
    assert info["scoreable"] == info["rows"], (
        "a row was written that production cannot score; either the row must "
        "be reported as unscoreable or the candidate collection changed")


def test_check_passes_on_a_fresh_write_and_fails_when_stale(
        tmp_path, monkeypatch):
    """``--check`` is the drift guard the docstring points at."""
    golden = tmp_path / "exploit.production.jsonl"
    monkeypatch.setattr(prod_vocab, "GOLDEN_PATH", golden)

    assert prod_vocab.main(["--write"]) == 0
    assert golden.is_file(), "the write path must follow GOLDEN_PATH at CALL time"
    assert prod_vocab.main(["--check"]) == 0

    golden.write_text(golden.read_text(encoding="utf-8") + "{}\n",
                      encoding="utf-8")
    assert prod_vocab.main(["--check"]) == 1


def test_rows_for_reads_the_production_corpus(tmp_path, monkeypatch):
    """The wire: ``corpus='production'`` is the file prod_vocab writes."""
    golden_dir = tmp_path / "golden"
    golden_dir.mkdir()
    row = {
        "id": "prod-a",
        "phase": "exploit",
        "metric": "ndcg",
        "input": {"candidates": [{"id": "noncve:service:ssh:22"},
                                 {"id": "CVE-2021-41773"}]},
        "expected": {"ranking": ["CVE-2021-41773", "noncve:service:ssh:22"]},
    }
    path = golden_dir / "exploit.production.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    monkeypatch.setattr(holdout, "GOLDEN_DIR", golden_dir)

    train, test = ranker.rows_for("exploit", corpus="production")
    rows = train + test
    assert len(rows) == 1, rows
    # `rows_for` returns the row in the corpus shape the trainer consumes
    # (`phase/metric/input/expected`), not the generator's `id`.
    ids = {c["id"] for c in rows[0]["input"]["candidates"]}
    assert "noncve:service:ssh:22" in ids
    assert rows[0]["expected"]["ranking"][0] == "CVE-2021-41773"


def test_an_unknown_corpus_is_refused_by_name():
    with pytest.raises(ValueError) as exc:
        ranker.rows_for("exploit", corpus="golden")
    assert "production" in str(exc.value)


def test_a_weight_the_corpus_never_offers_is_flagged():
    """The exact defect: a weight keyed by an id production cannot emit."""
    rows = [{"input": {"candidates": [{"id": "noncve:service:ssh:22"},
                                      {"id": "CVE-2021-41773"}]},
             "expected": {"ranking": ["CVE-2021-41773",
                                      "noncve:service:ssh:22"]}}]
    inert = ranker.Ranker(weights={"CVE-2021-41773": 1.0, "beacon_deploy": 0.8})
    assert ranker.unscoreable_weight_ids(inert, rows) == ["beacon_deploy"]

    aligned = ranker.Ranker(weights={"CVE-2021-41773": 1.0,
                                     "noncve:service:ssh:22": -0.5})
    assert ranker.unscoreable_weight_ids(aligned, rows) == []

    zero = ranker.Ranker(weights={"beacon_deploy": 0.0})
    assert ranker.unscoreable_weight_ids(zero, rows) == [], (
        "a zero weight is not a claim about an id, so it is not a finding")


def test_a_single_candidate_row_is_not_an_ordering():
    rows = [{"input": {"candidates": [{"id": "only-one"}]}},
            {"input": {"candidates": [{"id": "a"}, {"id": "b"}]}}]
    assert ranker.scoreable_rows(rows) == 1
