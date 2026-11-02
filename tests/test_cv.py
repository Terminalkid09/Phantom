"""The grouped k-fold harness: one target, one fold.

The corpus repeats a target across steps (same ``input`` payload), so a row-wise
split leaks the target into both sides and every fold looks better than
deployment. These tests pin the properties that make the number citable:

* the split is deterministic (same corpus -> same folds, no seed to forget);
* a payload group never straddles the boundary;
* with ``k <= n_groups`` every group is in exactly one validation fold, so the
  folds partition the corpus instead of re-measuring the same rows;
* a k larger than the number of groups is clamped, not padded with empty folds.

The summary is checked against the per-fold scores the harness itself reports,
so a mean cannot disagree with the folds it claims to summarise.
"""
import pytest

from training import cv


def _row(target, step=1, candidates=("scan_tcp", "web_rce")):
    """One corpus row: the payload a target shares, plus its own step."""
    return {
        "id": f"{target}-{step}",
        "input": {"goal": "deliver", "profile": "balanced",
                  "services": [{"port": "80", "service": "http"}],
                  "candidates": [{"id": cid} for cid in candidates],
                  "target": target},
        "expected": {"ranking": list(candidates)},
    }


def _corpus(groups=4, steps=3):
    return [_row(f"10.0.0.{n}", step) for n in range(groups)
            for step in range(1, steps + 1)]


class TestGroupedFolds:
    def test_the_same_corpus_yields_the_same_folds_twice(self):
        rows = _corpus()
        first = [[[r["id"] for r in fit], [r["id"] for r in val]]
                 for fit, val in cv.grouped_folds(rows, k=4)]
        second = [[[r["id"] for r in fit], [r["id"] for r in val]]
                  for fit, val in cv.grouped_folds(rows, k=4)]
        assert first == second

    def test_the_split_does_not_depend_on_the_order_rows_arrived_in(self):
        rows = _corpus()
        shuffled = list(reversed(rows))

        def partition(data):
            return sorted(sorted({cv.group_key(row) for row in validation})
                          for _, validation in cv.grouped_folds(data, k=4))

        assert partition(shuffled) == partition(rows)

    def test_a_payload_group_never_straddles_the_boundary(self):
        rows = _corpus(groups=5, steps=4)
        for fit, validation in cv.grouped_folds(rows, k=5):
            fit_groups = {cv.group_key(row) for row in fit}
            val_groups = {cv.group_key(row) for row in validation}
            assert not (fit_groups & val_groups)

    def test_every_group_is_in_exactly_one_validation_fold(self):
        rows = _corpus(groups=5, steps=4)
        seen = []
        for _, validation in cv.grouped_folds(rows, k=5):
            seen.extend(cv.group_key(row) for row in validation)
        groups = {cv.group_key(row) for row in rows}
        assert len(seen) == len(rows)          # every row validated once
        assert sorted(set(seen)) == sorted(groups)

    def test_rows_of_one_target_stay_together(self):
        rows = _corpus(groups=3, steps=3)
        for _, validation in cv.grouped_folds(rows, k=3):
            targets = {row["input"]["target"] for row in validation}
            assert len(targets) == 1, targets

    def test_k_larger_than_the_number_of_groups_is_clamped(self):
        rows = _corpus(groups=3, steps=2)
        folds = cv.grouped_folds(rows, k=50)
        assert len(folds) == 3
        assert all(validation for _, validation in folds)

    def test_a_single_group_is_not_measurable(self):
        assert cv.grouped_folds(_corpus(groups=1), k=5) == []
        assert cv.grouped_folds([], k=5) == []


class TestCrossValidate:
    def test_the_summary_agrees_with_the_folds_it_reports(self):
        rows = _corpus(groups=6, steps=3)

        def fit(fit_rows):
            return len(fit_rows)

        def score(_model, validation_rows):
            return [len(validation_rows) / 10.0] * len(validation_rows)

        report = cv.cross_validate(fit, score, rows, k=3)
        assert report["k"] == len(report["folds"]) == 3
        scores = [fold["score"] for fold in report["folds"]]
        assert report["mean"] == pytest.approx(sum(scores) / len(scores))
        assert report["min"] == min(scores)
        assert report["max"] == max(scores)
        assert report["n_groups"] == 6
        # each fold fits and validates on a real, disjoint slice
        for fold in report["folds"]:
            assert fold["fit"] > 0 and fold["validation"] > 0
            assert fold["fit"] + fold["validation"] == len(rows)

    def test_the_spread_is_reported_not_hidden(self):
        rows = _corpus(groups=4, steps=2)

        def score(_model, validation_rows):
            # a group-dependent score: balanced folds have equal widths, so the
            # spread has to come from WHICH target was held out
            return [float(row["input"]["target"].rsplit(".", 1)[1])
                    for row in validation_rows]

        report = cv.cross_validate(lambda fit_rows: None, score, rows, k=4)
        assert report["max"] > report["min"]
        assert report["stdev"] > 0

    def test_the_fit_function_receives_the_training_side_only(self):
        rows = _corpus(groups=4, steps=2)
        seen = []

        def fit(fit_rows):
            seen.append({cv.group_key(row) for row in fit_rows})
            return None

        report = cv.cross_validate(fit, lambda m, v: [1.0] * len(v), rows, k=4)
        assert len(seen) == report["k"]
        everything = {cv.group_key(row) for row in rows}
        for fit_groups in seen:
            assert fit_groups < everything      # a strict subset: one held out
            assert len(fit_groups) == 3

    def test_empty_input_is_a_zero_report_not_an_exception(self):
        report = cv.cross_validate(lambda r: None, lambda m, v: [], [], k=5)
        assert report["k"] == 0
        assert report["folds"] == []
        assert (report["mean"], report["stdev"], report["min"],
                report["max"]) == (0.0, 0.0, 0.0, 0.0)

    def test_one_group_is_a_zero_report(self):
        report = cv.cross_validate(lambda r: None,
                                   lambda m, v: [1.0] * len(v),
                                   _corpus(groups=1), k=5)
        assert report["k"] == 0 and report["n_groups"] == 1

    def test_a_scorer_that_returns_nothing_costs_that_fold_not_the_run(self):
        rows = _corpus(groups=3, steps=2)
        report = cv.cross_validate(lambda r: None, lambda m, v: [], rows, k=3)
        assert report["k"] == 3
        assert all(fold["score"] == 0.0 for fold in report["folds"])
