"""cv.py — grouped k-fold, so a single holdout number is not the whole measurement.

``training.ranker`` measures itself on 31 holdout rows. That number is honest
but it is ONE number: a 31-row test set has a resolution of ~0.03 per row, so
"0.94 vs 0.90" and "0.93 vs 0.92" are the same evidence. Cross-validation over
the training corpus gives a second, independent view — the spread across folds
says how much of the score is the model and how much is which rows happened to
land in the test set.

The split is GROUPED, not by row, and that is the whole point: the corpus
repeats the same target (same ``input`` payload, different step/expected), so a
row-wise split puts the same target's services in the fit set and in the
validation set. The model then memorises the target instead of learning the
ordering rule, and every fold looks better than the deployment will be. Folds
are therefore assigned per payload: a ``group_key`` is never split.

Assignment is by the SHA-256 of ``(seed, group_key)``, ordered and dealt round
robin. Hashing makes the split independent of file order and of the row's
position in the corpus; dealing round robin (instead of bucketing by hash)
keeps the folds BALANCED, so with ``k <= n_groups`` every group is in exactly
one validation fold and no fold is empty.

Standard library only, and no import from ``training.ranker`` — the trainer
imports this module, not the other way round.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Callable, Dict, List, Sequence, Tuple

#: Below two folds "cross validation" is a single train/test split with extra
#: ceremony, so the clamp is two rather than one.
MIN_FOLDS = 2


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def group_key(row: Dict[str, Any]) -> str:
    """Stable 16-hex key of the payload a row belongs to.

    Rows of one target share the same ``input``: same services, same goal,
    same candidate table. Keying the group on the payload (not on the row id or
    the expected answer) is what makes "one target, one fold" enforceable.
    """
    payload = (row or {}).get("input") or {}
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()[:16]


def _hash_order(key: str, seed: int) -> str:
    return hashlib.sha256(f"{int(seed)}:{key}".encode("utf-8")).hexdigest()


def grouped_folds(rows: Sequence[Dict[str, Any]], k: int = 5,
                  seed: int = 7) -> List[Tuple[List[Dict[str, Any]],
                                                List[Dict[str, Any]]]]:
    """``k`` ``(fit, validation)`` pairs, split by payload group.

    ``k`` is clamped to the number of distinct groups (asking for 10 folds on
    3 targets would otherwise produce 7 empty ones). Every group lands in
    exactly one validation fold, and rows of a group never straddle the
    boundary — a row's validation fold is the fold of its payload.

    Returns ``[]`` for empty input: a caller reports "not measurable" instead
    of receiving a fold that validates on nothing.
    """
    data = [row for row in (rows or []) if isinstance(row, dict)]
    if not data:
        return []
    keys = [group_key(row) for row in data]
    groups = sorted(set(keys), key=lambda key: _hash_order(key, seed))
    folds = max(MIN_FOLDS, min(int(k), len(groups)))
    if folds < MIN_FOLDS or len(groups) < MIN_FOLDS:
        # One group can only be "measured" by fitting on the rows that measured
        # it, which is not a measurement. Said out loud rather than faked.
        return []

    buckets: List[set] = [set() for _ in range(folds)]
    for index, key in enumerate(groups):
        buckets[index % folds].add(key)

    return [([row for row, key in zip(data, keys) if key not in buckets[i]],
             [row for row, key in zip(data, keys) if key in buckets[i]])
            for i in range(folds)]


def cross_validate(
        fit_fn: Callable[[List[Dict[str, Any]]], Any],
        score_fn: Callable[[Any, List[Dict[str, Any]]], Sequence[float]],
        rows: Sequence[Dict[str, Any]], k: int = 5, seed: int = 7,
        ) -> Dict[str, Any]:
    """Run ``fit_fn``/``score_fn`` once per fold and summarise the scores.

    ``fit_fn(fit_rows) -> model`` and ``score_fn(model, validation_rows) ->
    [score, ...]`` (one score per validation row, on the metric's own 0..1
    scale) are injected, so the same harness scores the linear ranker, an
    adapter or a baseline without this module knowing any of them.

    ``stdev`` is the POPULATION deviation over the folds (the folds are the
    whole population of measurements we took, not a sample of them) and is
    reported next to the mean on purpose: a mean of 0.94 whose folds are
    0.99/0.94/0.89 is a different claim from 0.94/0.94/0.94, and the holdout
    cannot tell them apart.

    Empty input (or a single group) returns ``k=0`` and zeros instead of
    raising: "no measurement" is a value the caller can print.
    """
    data = [row for row in (rows or []) if isinstance(row, dict)]
    n_groups = len({group_key(row) for row in data})
    empty = {"k": 0, "folds": [], "mean": 0.0, "stdev": 0.0, "min": 0.0,
             "max": 0.0, "n_groups": n_groups}

    results: List[Dict[str, Any]] = []
    for fit_rows, validation_rows in grouped_folds(data, k=k, seed=seed):
        if not fit_rows or not validation_rows:
            continue
        model = fit_fn(fit_rows)
        scores = [float(value) for value in (score_fn(model, validation_rows)
                                             or [])]
        # An empty score list is a broken scorer, not a zero: it is reported as
        # 0.0 with the fold's row count beside it, so the reader can see that
        # the fold was skipped rather than measured badly.
        score = sum(scores) / len(scores) if scores else 0.0
        results.append({"fit": len(fit_rows),
                        "validation": len(validation_rows),
                        "score": round(score, 6)})
    if not results:
        return empty

    values = [row["score"] for row in results]
    mean = sum(values) / len(values)
    stdev = (math.sqrt(sum((value - mean) ** 2 for value in values)
                       / len(values)) if len(values) > 1 else 0.0)
    return {
        "k": len(results),
        "folds": results,
        "mean": round(mean, 6),
        "stdev": round(stdev, 6),
        "min": round(min(values), 6),
        "max": round(max(values), 6),
        "n_groups": n_groups,
    }
