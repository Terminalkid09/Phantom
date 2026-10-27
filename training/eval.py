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
"""

from __future__ import annotations

import argparse
import inspect
import json
import math
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

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
    """A score is promotable when it is at least the baseline."""
    return baseline is None or float(score) >= float(baseline)


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
    result["gate"] = {"baseline": args.baseline,
                      "passed": check_gate(result["score"], args.baseline)}
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    if not args.quiet:
        print(text)
    return 0 if result["gate"]["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
