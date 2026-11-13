"""eval.py — measure a model against the phase's golden set, honestly.

A fine-tune is only useful if it beats the deterministic baseline on the task
it was trained for. This harness is deliberately small and dependency-free:
it consumes PREDICTIONS (a JSONL of ``{id, prediction}``) rather than loading
a model, so the same numbers can be produced on a laptop, in CI, or on the
GPU box that trained the adapter.

Metrics, per phase (``training.phases``):

    exact_match   extraction: the normalised value must match exactly
    ndcg          ranking: discounted gain of the predicted order
    brier         probability: 1 - mean((expected - predicted)^2)
    pass_at_1     code: the first candidate passes the supplied checker
    rubric        generation: a supplied rubric callable scores 0..1

All metrics are **higher-is-better**, because that is the direction the
manifest gate compares in. Brier is reported as skill (1 is perfect); the
raw mean squared error is in the detail for inspection.

Every report also carries a ``cv`` block: a grouped k-fold spread over the
same rows and the same metric, because the holdout is a single partition and
its mean alone cannot distinguish a model from a lucky split. The block is
reporting only — ``--gate`` never reads it, and ``k == 0`` says the spread is
not measurable rather than printing a zero.

Every report also carries a ``baseline_production`` block: how much of the
corpus the PRODUCTION access scorer (``AccessCandidate.score_for``) can judge
at all, and its ndcg over exactly those rows. It answers a different question
from ``baseline`` (the shipped deterministic ranker, scored on every row): a
coverage of zero says the corpus and the production scorer share no candidate
vocabulary, which is a gap in the DATA and not a model result — so the block
says that in words instead of reporting a zero nobody earned.

The promotion decision is NOT this module's mean score. ``--gate`` pairs the
model and the deterministic baseline row by row and hands the differences to
``training.gate``, which refuses a sample that is too small and a margin
whose interval includes zero. ``--write-manifest`` then applies the verdict
to the manifest, so a promotion is written by the same code that measured it
instead of by hand after reading a number.
"""

from __future__ import annotations

import argparse
import inspect
import json
import math
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from training import gate
from training.baseline_production import production_ranking, scoreable
from training.cv import cross_validate
from training.phases import PHASES, phase_config

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"


def _normalise(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _normalise(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return sorted((_normalise(v) for v in value),
                      key=lambda v: json.dumps(v, sort_keys=True))
    if isinstance(value, str):
        return " ".join(value.lower().split())
    return value


def exact_match(expected: Any, predicted: Any) -> float:
    return 1.0 if _normalise(expected) == _normalise(predicted) else 0.0


def ndcg(expected_ranking: List[str], predicted_ranking: List[str],
         k: int = 5) -> float:
    """NDCG@k with linear relevance (rank 0 is best)."""
    expected = [str(x) for x in expected_ranking or []]
    predicted = [str(x) for x in predicted_ranking or []][:k]
    if not expected or not predicted:
        return 0.0
    gains = {value: len(expected) - index
             for index, value in enumerate(expected)}
    dcg = sum(gains.get(value, 0) / math.log2(index + 2)
              for index, value in enumerate(predicted))
    ideal = sum(sorted(gains.values(), reverse=True)[:k][index] /
                math.log2(index + 2)
                for index in range(min(k, len(gains))))
    return round(dcg / ideal, 6) if ideal else 0.0


def brier(expected: float, predicted: float) -> float:
    return max(0.0, 1.0 - (float(expected) - float(predicted)) ** 2)


def _value(prediction: Any) -> Any:
    if isinstance(prediction, dict) and "value" in prediction:
        return prediction["value"]
    return prediction


def rubric_takes_context(rubric: Callable) -> bool:
    """True when a rubric wants the golden row's input as a third argument.

    The documented rubric contract is ``(expected, prediction)``; the social
    rubric also needs the row's context (the interest, the city, the order
    number a criterion refers to), so the two signatures coexist explicitly
    instead of by swallowing a TypeError at call time.
    """
    try:
        return len(inspect.signature(rubric).parameters) >= 3
    except (TypeError, ValueError):
        return False


def score_one(metric: str, expected: Any, prediction: Any, *,
              checker: Optional[Callable[[Any, Any], bool]] = None,
              rubric: Optional[Callable[[Any, Any], float]] = None,
              context: Optional[Dict[str, Any]] = None) -> float:
    if metric == "ndcg":
        exp = expected.get("ranking") if isinstance(expected, dict) else expected
        pred = (prediction.get("ranking") if isinstance(prediction, dict)
                else prediction)
        return ndcg(exp or [], pred or [])
    if metric == "brier":
        exp = expected.get("probability") if isinstance(expected, dict) \
            else expected
        pred = (prediction.get("probability")
                if isinstance(prediction, dict) else prediction)
        if exp is None or pred is None:
            return 0.0
        return brier(float(exp), float(pred))
    if metric == "pass_at_1":
        exp = expected.get("code") if isinstance(expected, dict) else expected
        pred = (prediction.get("code") if isinstance(prediction, dict)
                else prediction)
        if checker is not None:
            return 1.0 if checker(exp, pred) else 0.0
        options = exp if isinstance(exp, list) else [exp]
        return 1.0 if any(_normalise(pred) == _normalise(o)
                          for o in options) else 0.0
    if metric == "rubric":
        if rubric is None:
            return 0.0
        try:
            if rubric_takes_context(rubric):
                value = rubric(expected, prediction, context or {})
            else:
                value = rubric(expected, prediction)
            return max(0.0, min(1.0, float(value)))
        except Exception:
            return 0.0
    # exact_match, and the default for an unknown metric
    return exact_match(_value(expected), _value(prediction))


def evaluate(phase: str, golden: Iterable[dict],
             predictions: Dict[str, Any], *,
             checker: Optional[Callable[[Any, Any], bool]] = None,
             rubric: Optional[Callable[[Any, Any], float]] = None
             ) -> Dict[str, Any]:
    """Score predictions against golden records; deterministic output."""
    metric = phase_config(phase)["metric"]
    details: List[Dict[str, Any]] = []
    total = 0.0
    count = 0
    for record in golden:
        record_id = str(record.get("id") or "")
        record_metric = str(record.get("metric") or metric)
        prediction = predictions.get(record_id)
        score = score_one(record_metric, record.get("expected"), prediction,
                          checker=checker, rubric=rubric,
                          context=record.get("input") or {})
        total += score
        count += 1
        details.append({"id": record_id, "metric": record_metric,
                        "score": round(score, 6),
                        "predicted": prediction is not None})
    mean = round(total / count, 6) if count else 0.0
    return {"phase": phase, "metric": metric, "score": mean,
            "n": count, "details": details}


def load_jsonl(path: str | Path) -> List[dict]:
    out: List[dict] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def load_predictions(path: str | Path) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for row in load_jsonl(path):
        if isinstance(row, dict) and row.get("id") is not None:
            out[str(row["id"])] = row.get("prediction")
    return out


def check_gate(score: float, baseline: Optional[float]) -> bool:
    """A score is promotable when it is at least the baseline.

    Kept as the legacy single-number check (``--baseline``), which is a smoke
    test, NOT a promotion argument. Promotion goes through ``training.gate``:
    a tie on a three-row set passes this check and must never promote a model.
    """
    return baseline is None or float(score) >= float(baseline)


def baseline_predictions(phase: str, golden: Iterable[dict]) -> Dict[str, Any]:
    """The deterministic baseline's answer for every golden row, in eval shape.

    ``training.predict._baseline`` is the single definition of what Phantom
    does without a model, so it is imported rather than re-implemented: a
    second copy here would let the comparison drift from the runtime it is
    supposed to represent.
    """
    from training.predict import _baseline  # noqa: PLC0415 (no model load)
    out: Dict[str, Any] = {}
    for record in golden:
        record_id = str(record.get("id") or "")
        out[record_id] = _baseline(phase, record.get("input") or {})
    return out


def per_row_scores(result: Dict[str, Any]) -> Dict[str, float]:
    """id -> score, for pairing the model against the baseline row by row."""
    return {str(row.get("id")): float(row.get("score") or 0.0)
            for row in result.get("details") or []}


#: Folds in the grouped cross-validation. ``training.cv`` clamps this to the
#: number of payload groups, so a small set yields fewer folds rather than
#: empty ones.
CV_FOLDS = 5
CV_SEED = 7


def cross_validation_block(rows: Iterable[dict], *, k: int = CV_FOLDS,
                           seed: int = CV_SEED,
                           epochs: Optional[int] = None) -> Dict[str, Any]:
    """Grouped k-fold CV over ``rows`` — the spread one split cannot show.

    The holdout is ONE partition: on ~31 rows its resolution is ~0.03 per row,
    so "0.94 vs 0.90" and "0.93 vs 0.92" are the same evidence and a fold
    score of 0.9420 says nothing about whether 0.91 was luck. This block runs
    the same model over grouped folds and reports the SPREAD, so the single
    number is never quoted alone.

    Folds are grouped by payload (``training.cv``), not by row: the corpus
    repeats the same target with different step/expected, so a row-wise split
    puts one target's services in the fit set and its answers in validation —
    the model then memorises the target and every fold looks better than
    deployment.

    The fit and the scorer are the ones the holdout already uses: the fit is
    ``training.ranker.train`` over the fold's rows and the score is
    ``score_one("ndcg", ...)`` over the fold's validation rows. So the metric
    these folds report is **NDCG**, the same metric ``evaluate`` reports for a
    ranking phase — not a second, incomparable metric. ``ranker`` imports this
    module inside its own functions, so its import here is deferred: the
    dependency stays one-directional.

    NEVER a promotion input. ``--gate`` reads the row pairs from ``evaluate``
    and nothing from this block; a fold spread can make an operator distrust a
    number, and it must not be able to change a verdict.

    ``k == 0`` means "not measurable here" — fewer than two payload groups, or
    rows that are not a ranking task at all — and says why in ``reason``
    instead of returning ``mean=0.0``, which would read like a score nobody
    earned.
    """
    data = [row for row in (rows or []) if isinstance(row, dict)]
    block: Dict[str, Any] = {"k": 0, "folds": [], "mean": 0.0, "stdev": 0.0,
                             "min": 0.0, "max": 0.0, "n_groups": 0,
                             "reason": ""}
    if not any(isinstance(row.get("expected"), dict)
               and (row["expected"] or {}).get("ranking") for row in data):
        block["reason"] = ("not a ranking measurement: no row carries an "
                           "expected ranking, and the folds score NDCG")
        return block

    from training.ranker import EPOCHS, train  # noqa: PLC0415 (see docstring)

    def _fit(fit_rows: List[Dict[str, Any]]):
        return train(fit_rows, epochs=EPOCHS if epochs is None else epochs)

    def _score(model, validation_rows: Iterable[Dict[str, Any]]) -> List[float]:
        return [score_one("ndcg", row.get("expected") or {},
                          {"ranking": model.rank(row.get("input") or {})})
                for row in validation_rows]

    report = cross_validate(_fit, _score, data, k=k, seed=seed)
    block.update({key: report[key] for key in
                  ("k", "folds", "mean", "stdev", "min", "max",
                   "n_groups")})
    if not block["k"]:
        block["reason"] = (
            f"not measurable: {block['n_groups']} payload group(s) — a fold "
            f"has to validate on payloads it never fitted, so it needs at "
            f"least two")
    return block


def format_cv_line(block: Dict[str, Any]) -> str:
    """One human line for the fold spread, in the same voice as the scores.

    A missing measurement is printed as missing, never as ``mean=0.0000``:
    a zero is a number an operator can accidentally compare.
    """
    if not (block or {}).get("k"):
        reason = (block or {}).get("reason") or "not measured"
        return f"  cv: {reason}"
    return (f"  cv: k={block['k']} mean={float(block['mean']):.4f} "
            f"stdev={float(block['stdev']):.4f} "
            f"[{float(block['min']):.4f}, {float(block['max']):.4f}] "
            f"over {block['n_groups']} groups")


def production_baseline_block(rows: Iterable[dict]) -> Dict[str, Any]:
    """Could the PRODUCTION scorer have answered these rows at all?

    ``baseline`` above answers "does the shipped deterministic ranker beat the
    model on these rows"; this block answers a prior question that was being
    assumed: whether ``AccessCandidate.score_for`` and the corpus are even
    talking about the same candidates. They are not, and the measurement says
    so out loud — the corpus ranks CAPABILITY ids (``scan_tcp``,
    ``web_rce``, ``beacon_deploy``) while the production scorer ranks ACCESS
    candidates built from a service list, so on the golden set the two
    vocabularies share no id at all.

    ``mean_ndcg`` is therefore averaged over the SCOREABLE rows only. A row
    the production scorer cannot see is not a row it lost: averaging zeros in
    would turn "never asked" into "scores nothing", which is the same class
    of lie as quoting a holdout mean without its fold spread.

    Reporting only, like the cv block: ``--gate`` never reads this.
    """
    data = [row for row in (rows or []) if isinstance(row, dict)]
    block: Dict[str, Any] = {"rows_total": len(data), "rows_scoreable": 0,
                             "coverage": 0.0, "mean_ndcg": 0.0, "reason": ""}
    if not data:
        block["reason"] = "no rows: there is nothing for the scorer to judge"
        return block

    coverages: List[float] = []
    scores: List[float] = []
    for row in data:
        payload = row.get("input") or {}
        try:
            ranking = production_ranking(payload)
        except Exception:          # a reporting block must not kill the report
            ranking = {}
        coverages.append(float(ranking.get("coverage") or 0.0))

        expected = row.get("expected")
        expected_ranking = (expected.get("ranking")
                            if isinstance(expected, dict) else None)
        if not expected_ranking:
            continue
        try:
            judgeable = scoreable(payload)
        except Exception:
            judgeable = False
        if not judgeable:
            continue
        block["rows_scoreable"] += 1
        scores.append(ndcg(expected_ranking, ranking.get("ids") or []))

    block["coverage"] = round(sum(coverages) / len(coverages), 6)
    if scores:
        block["mean_ndcg"] = round(sum(scores) / len(scores), 6)
        block["reason"] = (f"the production scorer judged "
                           f"{len(scores)} of {len(data)} row(s)")
    else:
        block["reason"] = (
            "not measurable: the corpus and the production scorer "
            "(AccessCandidate.score_for) share no candidate id on any row — "
            "the data gap is in the corpus, not the model")
    return block


def format_production_baseline_line(block: Dict[str, Any]) -> str:
    """One human line for the production scorer's reach over the corpus.

    Same rule as the cv line: a missing measurement is printed as missing, so
    a reader cannot carry a ``0.0000`` away and compare it with something.
    """
    if not (block or {}).get("rows_scoreable"):
        reason = (block or {}).get("reason") or "not measured"
        return f"  production baseline: {reason}"
    return (f"  production baseline: mean_ndcg="
            f"{float(block['mean_ndcg']):.4f} on "
            f"{block['rows_scoreable']}/{block['rows_total']} rows "
            f"(corpus coverage {float(block['coverage']):.2f})")


def _write_json_atomic(path: str | Path, data: Any) -> None:
    """Replace a file in one step: a crash must not truncate a manifest."""
    target = Path(path)
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    handle = tempfile.NamedTemporaryFile(
        "w", delete=False, dir=str(target.parent), encoding="utf-8",
        newline="\n", prefix=target.name, suffix=".tmp")
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, target)
    except Exception:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def update_manifest(path: str | Path, phase: str, metric: str,
                    score: float, baseline_score: float,
                    decision: Dict[str, Any]) -> Dict[str, Any]:
    """Apply a gate decision to an EXISTING manifest, atomically.

    Promotion writes the measured numbers; rejection writes the reasons and
    demotes, and deliberately leaves ``eval``/``baseline`` alone so the old
    measurement is not replaced by a score nobody accepted.
    """
    target = Path(path)
    if not target.is_file():
        raise FileNotFoundError(f"manifest not found: {target}")
    manifest = json.loads(target.read_text(encoding="utf-8"))
    if str(manifest.get("phase") or phase) != phase:
        raise ValueError(
            f"manifest phase {manifest.get('phase')!r} != {phase!r}: refusing "
            f"to write another phase's result into it")
    manifest["eval_gate"] = dict(decision)
    if decision.get("verdict") == "promote":
        manifest["eval"] = {metric: round(float(score), 6)}
        manifest["baseline"] = {metric: round(float(baseline_score), 6)}
        manifest["promoted"] = True
    else:
        manifest["promoted"] = False
    _write_json_atomic(target, manifest)
    return manifest


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="training.eval",
        description="Score predictions against the phase golden set.")
    parser.add_argument("--phase", required=True, choices=list(PHASES))
    parser.add_argument("--predictions", required=True,
                        help="JSONL of {id, prediction}")
    parser.add_argument("--golden", default="",
                        help="override the golden JSONL path")
    parser.add_argument("--out", default="",
                        help="write the result JSON here")
    parser.add_argument("--baseline", type=float, default=None,
                        help="baseline score; exit 1 when below it")
    parser.add_argument("--compare-baseline", action="store_true",
                        help="score the deterministic baseline on the same "
                             "rows (in process, no model load)")
    parser.add_argument("--gate", action="store_true",
                        help="bootstrap-gate the promotion (implies "
                             "--compare-baseline)")
    parser.add_argument("--min-rows", type=int, default=gate.MIN_ROWS,
                        help=f"rows a gate needs (default {gate.MIN_ROWS})")
    parser.add_argument("--write-manifest", default="",
                        help="apply the gate verdict to this manifest.json")
    parser.add_argument("--no-rubric", action="store_true",
                        help="score rubric phases as 0 (no rubric callable)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    golden_path = Path(args.golden) if args.golden else \
        GOLDEN_DIR / f"{args.phase}.jsonl"
    golden = load_jsonl(golden_path)
    if not golden:
        print(f"no golden records at {golden_path}", file=sys.stderr)
        return 2
    predictions = load_predictions(args.predictions)
    rubric = None
    if not args.no_rubric and args.phase == "social":
        # A rubric-graded phase is scored with the built-in deterministic
        # rubric: without it this phase reports 0 for every answer, which is
        # not a measurement (see training/rubric.py).
        from training.rubric import social_rubric
        rubric = social_rubric
    result = evaluate(args.phase, golden, predictions, rubric=rubric)
    # The fold spread travels WITH the holdout number, so the two cannot be
    # told apart later by someone quoting only one of them. Reporting only:
    # `--gate` below reads the row pairs from `evaluate`, never this block.
    result["cv"] = cross_validation_block(golden)
    # A DIFFERENT question from `baseline` further down, which is the shipped
    # deterministic ranker scored on every row. This one is whether the
    # production access scorer can judge the corpus at all.
    result["baseline_production"] = production_baseline_block(golden)

    compare = bool(args.compare_baseline or args.gate)
    baseline_result: Optional[Dict[str, Any]] = None
    pairs: List[tuple] = []
    if compare:
        baseline_result = evaluate(
            args.phase, golden,
            baseline_predictions(args.phase, golden), rubric=rubric)
        result["baseline"] = {"score": baseline_result["score"],
                              "n": baseline_result["n"]}
        result["delta"] = round(
            float(result["score"]) - float(baseline_result["score"]), 6)
        model_rows = per_row_scores(result)
        base_rows = per_row_scores(baseline_result)
        # Only rows BOTH sides scored: a row the model did not answer is a
        # missing prediction, and counting it as a baseline win would inflate
        # every interval in the same direction.
        pairs = [(model_rows[rid], base_rows[rid])
                 for rid in model_rows if rid in base_rows]

    if args.gate:
        decision = gate.decide(args.phase, pairs, min_rows=args.min_rows)
        decision["baseline_flag"] = args.baseline
        result["gate"] = decision
        if args.write_manifest:
            try:
                update_manifest(args.write_manifest, args.phase,
                                result["metric"], result["score"],
                                float(result["baseline"]["score"]), decision)
            except (OSError, ValueError) as exc:
                print(f"cannot write manifest: {exc}", file=sys.stderr)
                return 2
            result["manifest"] = str(args.write_manifest)
        passed = decision["verdict"] == "promote"
    else:
        result["gate"] = {"baseline": args.baseline,
                          "passed": check_gate(result["score"],
                                               args.baseline)}
        passed = bool(result["gate"]["passed"])

    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    if not args.quiet:
        print(text)
        # stderr, because stdout is the JSON report: a human line mixed into
        # it would break every caller that parses it (`--out` aside).
        print(format_cv_line(result["cv"]), file=sys.stderr)
        print(format_production_baseline_line(result["baseline_production"]),
              file=sys.stderr)
    if args.gate and not passed and not args.quiet:
        for reason in result["gate"].get("reasons") or []:
            print(f"rejected: {reason}", file=sys.stderr)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
