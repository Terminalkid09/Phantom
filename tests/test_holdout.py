"""The holdout is a measurement, not a copy of the training set.

The pinned properties are the ones that make the number trustworthy: the split
is deterministic and content-addressed, a row cannot appear on both sides, the
converted expectation is the SAME shape the runtime produces, and a phase
without enough labelled rows is reported as unmeasurable instead of padded.
"""

from __future__ import annotations

import json

from training import holdout


def _row(phase: str, payload: dict, answer: dict, source: str = "x") -> dict:
    return {"phase": phase, "source": source,
            "messages": [
                {"role": "system", "content": "s"},
                {"role": "user", "content": json.dumps(payload)},
                {"role": "assistant", "content": json.dumps(answer)},
            ]}


def test_the_split_is_deterministic_and_partitions_the_corpus():
    row = _row("exploit", {"a": 1}, {"ranked": [{"id": "x"}]})
    first = holdout.bucket(row, 0.25)
    assert first == holdout.bucket(row, 0.25)
    assert first in (0, 1)
    # a different ratio moves the boundary, never the row's own hash
    assert holdout.bucket(row, 0.9) in (0, 1)


def test_exploit_expected_is_the_runtime_shape(tmp_path):
    # `to_eval` turns the model's `ranked` into the eval `ranking`; the
    # holdout must not re-implement that mapping.
    rows = []
    for index in range(40):
        rows.append(_row(
            "exploit",
            {"candidates": [{"id": f"c{index}"}], "goal": "deliver"},
            {"ranked": [{"id": f"c{index}"}], "reason": "only one"}))
    path = tmp_path / "exploit.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n",
                    encoding="utf-8")
    built = holdout.build("exploit", ratio=0.5, data_dir=tmp_path)
    assert built, "a 40-row corpus must produce a non-empty holdout"
    assert all(set(row["expected"]) == {"ranking"} for row in built)
    assert all(row["expected"]["ranking"] for row in built)
    assert all(row["phase"] == "exploit" for row in built)
    assert len({row["id"] for row in built}) == len(built)


def test_a_row_without_a_real_expectation_is_dropped(tmp_path):
    rows = [_row("exploit", {"candidates": []}, {"ranked": []}),
            _row("exploit", {"candidates": [{"id": "a"}]},
                 {"ranked": [{"id": "a"}]})]
    path = tmp_path / "exploit.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n",
                    encoding="utf-8")
    built = holdout.build("exploit", ratio=0.99, data_dir=tmp_path)
    # one row survives, the empty answer is not an expectation
    assert len(built) == 1
    assert built[0]["expected"]["ranking"] == ["a"]


def test_duplicates_are_collapsed(tmp_path):
    same = _row("exploit", {"candidates": [{"id": "a"}]},
                {"ranked": [{"id": "a"}]})
    path = tmp_path / "exploit.jsonl"
    path.write_text("\n".join(json.dumps(same) for _ in range(5)) + "\n",
                    encoding="utf-8")
    built = holdout.build("exploit", ratio=0.99, data_dir=tmp_path)
    assert len(built) == 1


def test_an_underpopulated_phase_is_reported_not_padded():
    report = holdout.report(["social"], ratio=0.25)
    assert report["social"]["n"] == 0
    assert report["social"]["measurable"] is False
