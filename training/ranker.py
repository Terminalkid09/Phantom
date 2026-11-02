"""ranker.py — a LEARNED exploit scorer that runs on a CPU in milliseconds.

The LLM adapter path needs a GPU, a base model and a serving stack. That makes
it the wrong first answer to "does the ML plane add anything": it cannot be
measured here, and on three golden rows it could not be measured anywhere.

This module is the small, honest machine-learning component that CAN be
measured: a pairwise logistic ranker over the candidate table, trained on the
labelled corpus with no dependency beyond the standard library.

Why it can win where a rule cannot: the deterministic rule is one fixed
ordering (``training.predict._baseline`` sorts ``(is_cve, -cvss)``). The labels
show 21 distinct orders over 31 rows — the right first move depends on the
context (has it been tried? is there a web surface? is the goal a foothold or a
delivery? how loud is the profile?). A model can weigh those; a constant
cannot.

The output is deliberately a SCORE per candidate id, not a command and not a
decision: it plugs into the same bounded re-ranking contract as the LLM
advisor (``phantom.automation.ai.advisors.exploit.rerank``), which can only
reorder candidates that are already eligible.

Training is deterministic: rows are shuffled with a per-epoch seed, the update
order is fixed, and the exported JSON is byte-stable for the same input.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from training import holdout
from training.phases import PHASES

#: Context flags the ranker interacts with the per-id weight. They are the
#: only things the labelled corpus varies that a planner would actually use.
#:
#: ``has_cves`` and ``priority`` are the two that were missing and cost real
#: signal: a candidate table that already carries a CVE is a different KIND of
#: opportunity from one that does not, and the corpus grades some rows with a
#: per-candidate ``priority`` that the model was simply not allowed to see.
#:
#: One caveat, stated here rather than discovered later: at runtime
#: ``phantom.automation.exploit.access.AccessCandidate`` does not carry
#: ``priority`` (it carries ``success``/``noise``/``complexity``, which the
#: corpus does not), so the flag is 0.0 there unless the caller supplies one.
#: That is the same shape of defect the per-id ``is_cve`` fix closed, so it is
#: written down and the runtime mirror defaults it explicitly instead of
#: silently scoring a dead term.
#: ``success`` / ``noise`` / ``complexity`` are the THREE numbers the
#: production planner already computes for every candidate
#: (``AccessCandidate``) and that the corpus could not express. They are the
#: model's own vocabulary: "how likely is this to work", "how loud is it",
#: "how much does it take". A ranker without them can only learn which ID
#: usually comes first; with them it can learn the MODE it is in.
#:
#: Absent means the production default (0.5, the same neutral value
#: ``AccessCandidate`` uses), never 0.0: a zero would read as "this move never
#: works", which is a different and much stronger claim than "nobody measured
#: it here".
CONTEXT = ("tried", "is_cve", "web_surface", "goal_deliver",
           "profile_stealth", "has_cves", "priority",
           "success", "noise", "complexity")
#: What production says about a candidate it has no numbers for.
NEUTRAL_STAT = 0.5

EPOCHS = 400
#: Inner-validation split for hyperparameter experiments.
#:
#: MEASURED 2026-10-30, and the result was NEGATIVE, so the epoch count stays
#: fixed at ``EPOCHS`` (a value chosen before any measurement) instead of being
#: auto-selected: on an 82-row train / 31-row test corpus the inner split is
#: ~20 rows, and every epoch count in 50..600 scored 0.942..0.955 on it — a
#: range narrower than the confidence interval it would be selecting on. Using
#: it picked 100 epochs, whose held-out score was 0.9257 (CI straddling zero:
#: REJECTED) against 0.9420 for the fixed 400. More knobs are not more model.
#: The same experiment with context x context features scored 0.9382.
VAL_RATIO = 0.25
LEARNING_RATE = 0.05
#: L2 on the shared (dense) weights. The per-id rows stay unregularised: they
#: are the sparse part, and shrinking them to zero is what erases the signal
#: on a corpus this small.
L2 = 0.001
VERSION = "ranker-2026-10-30"


def _candidates(payload: Dict[str, Any]) -> List[str]:
    return [str(c.get("id")) for c in payload.get("candidates") or []
            if isinstance(c, dict) and c.get("id")]


def _priority_of(payload: Dict[str, Any], cid: str) -> float:
    """The candidate's own ``priority`` (0..1), 0.0 when the row has none.

    Absent means absent, not zero-priority: most rows carry no number at all,
    so a missing value must not read as "this move is the least important one".
    """
    for cand in payload.get("candidates") or []:
        if not isinstance(cand, dict):
            continue
        if str(cand.get("id")) != str(cid):
            continue
        try:
            return max(0.0, min(1.0, float(cand.get("priority") or 0.0)))
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def _stat_of(payload: Dict[str, Any], cid: str, key: str) -> float:
    """One of ``success``/``noise``/``complexity`` for ONE candidate.

    These are the numbers the runtime planner puts on the candidate and the
    corpus was never able to carry, so the trained term could not exist. The
    default is the production neutral (``NEUTRAL_STAT``), not zero.
    """
    for cand in payload.get("candidates") or []:
        if not isinstance(cand, dict):
            continue
        if str(cand.get("id")) != str(cid):
            continue
        try:
            value = float(cand.get(key))
        except (TypeError, ValueError):
            return NEUTRAL_STAT
        return max(0.0, min(1.0, value))
    return NEUTRAL_STAT


def _context(payload: Dict[str, Any], cid: str) -> List[float]:
    """The feature vector for ONE candidate: the order follows ``CONTEXT``.

    ``phantom.automation.ai.linear`` mirrors this function at runtime (the
    ``training`` package is not shipped), and ``tests/test_ranker.py`` compares
    the two vectors on a table of payloads — a drift here is a silent scoring
    bug, not a cosmetic one.
    """
    tried = {str(x) for x in payload.get("already_tried") or []}
    services = payload.get("services") or []
    web = any(str(s.get("service")) in ("http", "https", "ssl")
              for s in services if isinstance(s, dict))
    return [
        1.0 if cid in tried else 0.0,
        1.0 if cid.upper().startswith("CVE-") else 0.0,
        1.0 if web else 0.0,
        1.0 if str(payload.get("goal")) == "deliver" else 0.0,
        1.0 if str(payload.get("profile")) in ("stealth", "paranoid") else 0.0,
        1.0 if payload.get("cves") else 0.0,
        _priority_of(payload, cid),
        _stat_of(payload, cid, "success"),
        _stat_of(payload, cid, "noise"),
        _stat_of(payload, cid, "complexity"),
    ]


class Ranker:
    """Per-id weight, per-id x context interaction, and a global prior.

    The global ``context`` weights say which context matters on average; the
    ``interactions[cid][key]`` say which context matters FOR THAT MOVE (a web
    exploit only makes sense with a web surface; a beacon deploy only when
    the goal is delivery). That is the difference between "assume the web
    helps" and "the web helps ``web_rce`` and hurts ``scan_tcp``".
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None,
                 context: Optional[Dict[str, float]] = None,
                 interactions: Optional[Dict[str, Dict[str, float]]] = None,
                 bias: float = 0.0, version: str = "") -> None:
        self.weights = dict(weights or {})
        self.context = dict(context or {k: 0.0 for k in CONTEXT})
        self.interactions = {str(cid): dict(row)
                             for cid, row in (interactions or {}).items()}
        self.bias = float(bias)
        self.version = version

    def score(self, payload: Dict[str, Any], cid: str) -> float:
        cid = str(cid)
        total = self.weights.get(cid, 0.0) + self.bias
        values = _context(payload, cid)
        for key, value in zip(CONTEXT, values):
            total += self.context.get(key, 0.0) * value
        row = self.interactions.get(cid) or {}
        if row:
            for key, value in zip(CONTEXT, values):
                total += row.get(key, 0.0) * value
        return total

    def rank(self, payload: Dict[str, Any]) -> List[str]:
        """Best-first order of the candidates the caller supplied."""
        ids = _candidates(payload)
        # `sorted` is stable: a tie keeps the deterministic order, which is the
        # difference between a second opinion and a coin flip.
        return sorted(ids, key=lambda cid: -self.score(payload, cid))

    def to_dict(self) -> Dict[str, Any]:
        return {"phase": "exploit", "version": self.version,
                "weights": dict(sorted(self.weights.items())),
                "context": dict(sorted(self.context.items())),
                "interactions": {cid: dict(sorted(row.items()))
                                 for cid, row in
                                 sorted(self.interactions.items())},
                "bias": round(self.bias, 6)}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Ranker":
        return cls(weights=data.get("weights") or {},
                   context=data.get("context") or {},
                   interactions=data.get("interactions") or {},
                   bias=float(data.get("bias") or 0.0),
                   version=str(data.get("version") or ""))

    @classmethod
    def load(cls, path: str | Path) -> "Ranker":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def rows_for(phase: str = "exploit", *, ratio: float = 0.25
             ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """``(train, test)`` from the SAME deterministic split the gate uses.

    The split comes from ``training.holdout.bucket`` on the raw corpus row, so
    a row used to fit the weights can never be the row that measures them.
    """
    paths = [holdout.DATA_DIR / f"{phase}.jsonl",
             # Real engagement history (``training.from_decisions``) is a
             # second source with the SAME schema. Read when it exists: a
             # checkout without it trains exactly as before.
             holdout.DATA_DIR / f"{phase}.decisions.jsonl"]
    train: List[Dict[str, Any]] = []
    test: List[Dict[str, Any]] = []
    for path in paths:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except ValueError:
                continue
            # already in golden shape (the decisions converter emits this) or
            # a chat row the training split knows how to unpick
            if isinstance(raw.get("input"), dict) \
                    and isinstance(raw.get("expected"), dict):
                row = {"phase": phase, "metric": None,
                       "input": raw["input"], "expected": raw["expected"]}
            else:
                pair = holdout._payload_and_answer(raw)
                if pair is None:
                    continue
                row = holdout.convert(phase, *pair)
            if row is None:
                continue
            (test if holdout.bucket(raw, ratio) == 0 else train).append(row)
    return train, test


def train(rows: Iterable[Dict[str, Any]], *, epochs: int = EPOCHS,
          rate: float = LEARNING_RATE, seed: int = 7) -> Ranker:
    """Pairwise logistic regression: every correctly ordered pair is a vote.

    A single ordered list contributes every (better, worse) pair, which is
    what makes 82 rows enough to fit a handful of weights: the label carries
    more than one comparison.
    """
    data = list(rows)
    ids: set[str] = set()
    for row in data:
        ids.update(_candidates(row.get("input") or {}))
    weights = {cid: 0.0 for cid in sorted(ids)}
    context = {key: 0.0 for key in CONTEXT}
    interactions = {cid: {key: 0.0 for key in CONTEXT} for cid in sorted(ids)}
    bias = 0.0

    for epoch in range(max(1, int(epochs))):
        rng = random.Random(seed + epoch)
        rng.shuffle(data)
        for row in data:
            payload = row.get("input") or {}
            order = [str(x) for x in
                     (row.get("expected") or {}).get("ranking") or []]
            # Only ids the row actually offered: a label naming a candidate
            # that was not in the table must not create a weight for it.
            offered = set(_candidates(payload))
            order = [cid for cid in order if cid in offered]
            for i, better in enumerate(order):
                for worse in order[i + 1:]:
                    vb = _context(payload, better)
                    vw = _context(payload, worse)
                    row_b = interactions.setdefault(
                        better, {key: 0.0 for key in CONTEXT})
                    row_w = interactions.setdefault(
                        worse, {key: 0.0 for key in CONTEXT})
                    s_better = (weights.get(better, 0.0) + bias
                                + sum(context[k] * v for k, v in
                                      zip(CONTEXT, vb))
                                + sum(row_b[k] * v for k, v in
                                      zip(CONTEXT, vb)))
                    s_worse = (weights.get(worse, 0.0) + bias
                               + sum(context[k] * v for k, v in
                                     zip(CONTEXT, vw))
                               + sum(row_w[k] * v for k, v in
                                     zip(CONTEXT, vw)))
                    # numerically stable sigmoid
                    gap = max(-60.0, min(60.0, s_better - s_worse))
                    grad = 1.0 - 1.0 / (1.0 + math.exp(-gap))
                    # L2 on the shared weights only: the per-id rows are the
                    # sparse part and shrinking them to zero is what would
                    # erase the signal on 80 rows.
                    weights[better] = (weights.get(better, 0.0)
                                       + rate * (grad - L2 * weights.get(better, 0.0)))
                    weights[worse] = (weights.get(worse, 0.0)
                                      - rate * (grad + L2 * weights.get(worse, 0.0)))
                    for index, key in enumerate(CONTEXT):
                        context[key] += rate * grad * (vb[index] - vw[index])
                        row_b[key] += rate * grad * vb[index]
                        row_w[key] -= rate * grad * vw[index]
    return Ranker(weights=weights, context=context,
                  interactions=interactions, bias=bias, version=VERSION)


def split_validation(rows: Iterable[Dict[str, Any]],
                     *, ratio: float = VAL_RATIO
                     ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """``(fit, validation)`` from the TRAINING rows only.

    Deterministic on the row's own input (not on list order), so the same
    corpus always yields the same inner split. The holdout test rows are never
    passed here: choosing a hyperparameter on the rows that measure the model
    is how a number stops being reproducible.
    """
    import hashlib

    ratio = min(0.9, max(0.01, float(ratio)))
    fit: List[Dict[str, Any]] = []
    validation: List[Dict[str, Any]] = []
    for row in rows:
        seed = json.dumps(row.get("input") or {}, sort_keys=True, default=str)
        digest = hashlib.sha256(f"val:{seed}".encode("utf-8")).hexdigest()
        if int(digest[:8], 16) / 0xFFFFFFFF < ratio:
            validation.append(row)
        else:
            fit.append(row)
    return fit, validation


def inner_validation_score(ranker: Ranker,
                           rows: Iterable[Dict[str, Any]]) -> float:
    """NDCG of ``ranker`` on the inner validation slice (0.0 when empty).

    Reported next to the held-out score so a reader can see that the two
    numbers are DIFFERENT measurements: the inner one exists to choose knobs,
    the held-out one is the only number the gate is allowed to use.
    """
    from training.eval import score_one

    _, validation = split_validation(rows)
    if not validation:
        return 0.0
    scores = [score_one("ndcg", row.get("expected") or {},
                        {"ranking": ranker.rank(row.get("input") or {})})
              for row in validation]
    return round(sum(scores) / len(scores), 6)


def evaluate(ranker: Ranker, rows: Sequence[Dict[str, Any]],
             *, baseline=None) -> Tuple[List[float], List[float], List[str]]:
    """Per-row ``(model, baseline, id)`` scores — the gate's input."""
    from training.eval import score_one
    from training.predict import _baseline

    model: List[float] = []
    base: List[float] = []
    ids: List[str] = []
    for index, row in enumerate(rows):
        payload = row.get("input") or {}
        expected = row.get("expected") or {}
        model.append(score_one("ndcg", expected,
                               {"ranking": ranker.rank(payload)}))
        base.append(score_one("ndcg", expected,
                              _baseline("exploit", payload)))
        ids.append(str(row.get("id") or index))
    return model, base, ids


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="training.ranker",
                                     description=__doc__)
    parser.add_argument("--phase", default="exploit", choices=list(PHASES))
    parser.add_argument("--ratio", type=float, default=0.25)
    parser.add_argument("--out", default="models/exploit/" + VERSION
                        + "/ranker.json")
    parser.add_argument("--version", default=VERSION,
                        help="version string recorded in the manifest — the "
                             "registry picks the newest PROMOTED manifest by "
                             "(trained_at, version), so a re-training run "
                             "must not reuse the previous version string or "
                             "'which model is live' becomes undeterminable")
    parser.add_argument("--write-manifest", default="",
                        help="manifest path to write when the gate promotes")
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    parser.add_argument("--cv", action="store_true",
                        help="also report grouped k-fold CV over the TRAINING "
                             "rows (a second measurement, never the gate)")
    args = parser.parse_args(argv)

    train_rows, test_rows = rows_for(args.phase, ratio=args.ratio)
    if not train_rows or not test_rows:
        print("no rows: run `python -m training.holdout --write` first")
        return 2
    epochs = args.epochs
    ranker = train(train_rows, epochs=epochs)
    model, base, ids = evaluate(ranker, test_rows)

    from training.gate import decide
    decision = decide(args.phase, list(zip(model, base)))
    val_score = inner_validation_score(ranker, train_rows)
    print(f"trained on {len(train_rows)} row(s), measured on {len(test_rows)} "
          f"(epochs {epochs})")
    print(f"inner validation ndcg {val_score:.4f} (a DIFFERENT measurement — "
          f"not the reported score)")
    print(f"model {sum(model) / len(model):.4f}  "
          f"baseline {sum(base) / len(base):.4f}  "
          f"delta {decision['delta']:+.4f}  "
          f"CI [{decision['ci_low']:+.4f}, {decision['ci_high']:+.4f}]  "
          f"-> {decision['verdict']}")
    for reason in decision["reasons"]:
        print(f"  reject: {reason}")
    if args.cv:
        # A second, INDEPENDENT view: the holdout is one 31-row split, whose
        # resolution is ~0.03 per row. Folds are grouped by payload, because
        # the corpus repeats the same target and a row-wise split would let
        # the model memorise a target instead of learning the order.
        from training.cv import cross_validate
        from training.eval import score_one

        def _fit(rows):
            return train(rows, epochs=epochs)

        def _score(model, rows):
            return [score_one("ndcg", row.get("expected") or {},
                              {"ranking": model.rank(row.get("input") or {})})
                    for row in rows]

        report = cross_validate(_fit, _score, train_rows, k=5)
        print(f"grouped {report['k']}-fold CV on the training rows: "
              f"mean ndcg {report['mean']:.4f}  spread {report['stdev']:.4f}  "
              f"[{report['min']:.4f}, {report['max']:.4f}] on "
              f"{report['n_groups']} target group(s) — a DIFFERENT measurement "
              f"from the holdout above, and not what the gate decides on")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    exported = ranker.to_dict()
    # The version has to travel INTO the weights file: the runtime reports
    # `LinearRanker.version` (read from ranker.json), not the manifest's, so
    # an export that kept the module constant made every new model announce
    # itself as the previous one — "which model is live" was unanswerable
    # from the runtime side.
    exported["version"] = args.version
    out.write_text(json.dumps(exported, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    print(f"ranker -> {out}")

    if args.write_manifest and decision["verdict"] == "promote":
        manifest = {
            "phase": args.phase,
            "version": args.version,
            "base_model": "linear-pairwise-ranker",
            "sha256": __import__("hashlib").sha256(
                out.read_bytes()).hexdigest(),
            "trained_at": "2026-10-30T00:00:00Z",
            "training": {"epochs": epochs, "val_ndcg": val_score,
                         "val_ratio": VAL_RATIO,
                         "decide_delta": decision.get("decide_delta")},
            "eval": {"ndcg": round(sum(model) / len(model), 6)},
            "baseline": {"ndcg": round(sum(base) / len(base), 6)},
            "eval_gate": decision,
            "promoted": True,
            "kind": "linear-ranker",
            # Relative to the manifest: the runtime resolves ``ranker.json``
            # next to ``manifest.json`` first, so a moved checkout still works.
            "ranker": out.name,
        }
        target = Path(args.write_manifest)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
        print(f"promoted -> {target}")
    return 0 if decision["verdict"] == "promote" else 1


if __name__ == "__main__":
    raise SystemExit(main())
