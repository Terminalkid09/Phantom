"""A rejected model must not be written over a published one.

Measured 2026-11-02, on this checkout: ``python -m training.ranker --corpus
production --require-scoreable`` printed ``-> reject`` (n=8 < min_rows=20) and
then wrote ``models/exploit/ranker-2026-10-30/ranker.json`` anyway, because
``--out`` defaulted to that exact path. Two defects in one line:

* a model the gate had just refused replaced the weights file of an existing
  version directory, so "which model is live" stops being answerable from the
  tree (the flag's own help says a retrain must not reuse the version string);
* the default path hard-coded ``exploit`` while ``--phase`` accepts any phase,
  so a ``--phase finding`` run would have written into the exploit directory.

The rule pinned here: the gate decides whether weights are written, an
EXPLICIT ``--out`` is always honoured (an operator asking for a file gets one),
and the default path is derived from the phase the run was asked for.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from training import ranker as ranker_mod


class _StubRanker:
    """Enough of a model for the export path; the gate is what is under test."""

    weights: dict = {}

    def to_dict(self):
        return {"weights": {}, "version": "stub"}


def _stub_pipeline(monkeypatch, verdict):
    rows = [{"id": "r1", "input": {}, "expected": {}},
            {"id": "r2", "input": {}, "expected": {}}]
    monkeypatch.setattr(ranker_mod, "rows_for", lambda *a, **k: (rows, rows))
    monkeypatch.setattr(ranker_mod, "train", lambda *a, **k: _StubRanker())
    monkeypatch.setattr(ranker_mod, "evaluate",
                        lambda *a, **k: ([0.5], [0.9], ["r1"]))
    monkeypatch.setattr(ranker_mod, "inner_validation_score",
                        lambda *a, **k: 0.5)

    def _decide(phase, pairs):
        return {"verdict": verdict, "delta": -0.4, "ci_low": -0.9,
                "ci_high": -0.1, "reasons": ["stub: too few rows"]}

    monkeypatch.setattr("training.gate.decide", _decide)


def test_a_rejected_model_writes_no_weights(tmp_path, monkeypatch, capsys):
    _stub_pipeline(monkeypatch, "reject")
    monkeypatch.chdir(tmp_path)

    # a rejected run is non-zero (the file's existing convention), and it
    # writes nothing
    assert ranker_mod.main(["--corpus", "production"]) == 1

    assert not (tmp_path / "models").exists()
    assert "not exported" in capsys.readouterr().out


def test_an_explicit_out_is_still_written(tmp_path, monkeypatch):
    """Exporting a rejected model on purpose is a legitimate operator choice."""
    _stub_pipeline(monkeypatch, "reject")
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "inspect" / "ranker.json"

    assert ranker_mod.main(["--corpus", "production",
                            "--out", str(target)]) == 1
    assert target.is_file()


def test_the_default_path_follows_the_phase(tmp_path, monkeypatch):
    _stub_pipeline(monkeypatch, "promote")
    monkeypatch.chdir(tmp_path)

    assert ranker_mod.main(["--phase", "finding"]) == 0

    written = list((tmp_path / "models").rglob("ranker.json"))
    assert len(written) == 1
    assert written[0].parent.parent.name == "finding"
