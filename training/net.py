"""net.py — a small neural ranker over the SAME corpus, objective and gate.

The linear ranker is the component that can be measured here; this is the
nonlinear version of the same thing, added because a linear score cannot
express what actually decides the order: an interaction between the context
and the move (a web exploit matters because there IS a web surface — the
linear model can only give it one fixed weight) and a choice that depends on
the target group rather than on any single feature.

Design constraints, all deliberate:

* SAME INPUT, SAME SPLIT, SAME METRIC. ``rows_for`` / ``holdout.bucket`` /
  ``training.eval.score_one`` / ``training.gate.decide`` — unchanged. A model
  measured on a different split or a different metric is not comparable, and
  comparing it would be the whole point of writing it.
* SAME ARTEFACT SHAPE. JSON next to a ``manifest.json`` with ``kind: mlp`` and
  the score, so promotion is the same act for both models.
* numpy is a TRAINING dependency only. The runtime counterpart
  (``phantom.automation.ai.net``) does the forward pass in plain Python, like
  ``ai/linear.py``: the shipped tool must not gain a numerical stack to score
  twenty candidates.
* IT REFUSES TO PROMOTE ITSELF ON THIS CORPUS. 34 rows and a few hundred
  parameters is a memorisation machine, not a model: ``MIN_ROWS`` is checked
  BEFORE any training and the run exits 1 with the reason. That is not
  timidity, it is the difference between a number that means something and a
  number that only looks higher.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from training.phases import PHASES
from training.ranker import CONTEXT, VERSION, _candidates, _context, rows_for

VERSION_NET = "net-2026-11-01"

#: Parameters the network actually fits: (len(CONTEXT) + n_ids) * HIDDEN + 2 *
#: HIDDEN + 1. A ranker trained with fewer rows than this memorises the rows it
#: was shown and reports a number nobody can reproduce on the next target.
MIN_ROWS_PER_PARAM = 2.0
#: Absolute floor, independent of the parameter count: below this, the holdout
#: rows the gate measures on are single digits and the CI is meaningless.
MIN_ROWS = 150
HIDDEN = 8
EPOCHS = 300
RATE = 0.05
SEED = 7


def n_params(n_ids: int, hidden: int = HIDDEN) -> int:
    return (len(CONTEXT) + int(n_ids)) * hidden + 2 * hidden + 1


class NetRanker:
    """``score = tanh(W1 . [context | onehot(id)] + b1) . W2 + b2``.

    Kept import-compatible with ``training.ranker.Ranker`` for the parts the
    harness uses (``rank(payload)``), so ``evaluate`` and the gate run it with
    no branch of their own.
    """

    def __init__(self, ids: Sequence[str], W1: List[List[float]],
                 b1: List[float], W2: List[float], b2: float,
                 version: str = VERSION_NET) -> None:
        self.ids = [str(i) for i in ids]
        self.W1 = [[float(v) for v in row] for row in W1]
        self.b1 = [float(v) for v in b1]
        self.W2 = [float(v) for v in W2]
        self.b2 = float(b2)
        self.version = version

    # -- features ---------------------------------------------------------
    def features(self, payload: Dict[str, Any], cid: str) -> List[float]:
        base = _context(payload, cid)
        onehot = [0.0] * len(self.ids)
        cid = str(cid)
        if cid in self.ids:
            onehot[self.ids.index(cid)] = 1.0
        return [float(v) for v in base] + onehot

    def score(self, payload: Dict[str, Any], cid: str) -> float:
        import math

        x = self.features(payload, cid)
        hidden = [math.tanh(sum(w * v for w, v in zip(row, x)) + b)
                  for row, b in zip(self.W1, self.b1)]
        return sum(w * h for w, h in zip(self.W2, hidden)) + self.b2

    def rank(self, payload: Dict[str, Any]) -> List[str]:
        ids = _candidates(payload)
        # stable sort: an exact tie keeps the deterministic order
        return sorted(ids, key=lambda cid: -self.score(payload, cid))

    # -- artifact ---------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {"phase": "exploit", "kind": "mlp", "version": self.version,
                "context": list(CONTEXT), "ids": self.ids,
                "W1": [[round(v, 8) for v in row] for row in self.W1],
                "b1": [round(v, 8) for v in self.b1],
                "W2": [round(v, 8) for v in self.W2],
                "b2": round(self.b2, 8), "hidden": len(self.b1)}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetRanker":
        return cls(ids=data.get("ids") or [], W1=data.get("W1") or [],
                   b1=data.get("b1") or [], W2=data.get("W2") or [],
                   b2=float(data.get("b2") or 0.0),
                   version=str(data.get("version") or VERSION_NET))

    @classmethod
    def load(cls, path: str | Path) -> "NetRanker":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _pairs(rows: Iterable[Dict[str, Any]]) -> List[Tuple[str, str, List[float],
                                                         List[float]]]:
    """``(better, worse, x_better, x_worse)`` for every labelled pair."""
    out: List[Tuple[str, str, List[float], List[float]]] = []
    for row in rows:
        payload = row.get("input") or {}
        offered = set(_candidates(payload))
        order = [str(x) for x in
                 (row.get("expected") or {}).get("ranking") or []]
        order = [cid for cid in order if cid in offered]
        for index, better in enumerate(order):
            for worse in order[index + 1:]:
                out.append((better, worse, _context(payload, better),
                            _context(payload, worse)))
    return out


def train(rows: Iterable[Dict[str, Any]], *, hidden: int = HIDDEN,
          epochs: int = EPOCHS, rate: float = RATE,
          seed: int = SEED) -> NetRanker:
    """Pairwise logistic loss, plain SGD, deterministic.

    The objective is the one the linear ranker optimises — every correctly
    ordered pair is a vote — so a difference in the score is a difference in
    the MODEL, not in what "correct" means.
    """
    import numpy as np

    data = list(rows)
    ids = sorted({cid for row in data
                  for cid in _candidates(row.get("input") or {})})
    rng = np.random.default_rng(seed)
    dim = len(CONTEXT) + len(ids)
    W1 = rng.normal(0.0, 0.1, size=(hidden, dim))
    b1 = np.zeros(hidden)
    W2 = rng.normal(0.0, 0.1, size=hidden)
    b2 = 0.0

    def vec(payload: Dict[str, Any], cid: str) -> np.ndarray:
        base = _context(payload, cid)
        onehot = [0.0] * len(ids)
        if str(cid) in ids:
            onehot[ids.index(str(cid))] = 1.0
        return np.array([float(v) for v in base] + onehot, dtype=float)

    # ONE place decides what a labelled pair is (`_ordered_pairs`), so the
    # trainer and anything that re-derives pairs cannot disagree.
    pairs = [(vec(row.get("input") or {}, better),
              vec(row.get("input") or {}, worse))
             for row in data
             for better, worse in _ordered_pairs(row)]

    for _epoch in range(max(1, int(epochs))):
        order = rng.permutation(len(pairs)) if pairs else []
        for index in order:
            xb, xw = pairs[index]
            hb = np.tanh(W1 @ xb + b1)
            hw = np.tanh(W1 @ xw + b1)
            sb = float(hb @ W2 + b2)
            sw = float(hw @ W2 + b2)
            gap = max(-60.0, min(60.0, sb - sw))
            lam = 1.0 - 1.0 / (1.0 + np.exp(-gap))   # dL/d(s_b) magnitude
            dW2 = lam * (hb - hw)
            gb = (lam * W2) * (1.0 - hb ** 2)
            gw = (-lam * W2) * (1.0 - hw ** 2)
            W1 += rate * np.outer(gb, xb)
            W1 += rate * np.outer(gw, xw)
            b1 += rate * (gb + gw)
            W2 += rate * dW2
    return NetRanker(ids=ids, W1=W1, b1=b1, W2=W2, b2=b2)


def _ordered_pairs(row: Dict[str, Any]) -> List[Tuple[str, str]]:
    """The labelled (better, worse) pairs a row contributes."""
    payload = row.get("input") or {}
    offered = set(_candidates(payload))
    order = [str(x) for x in
             (row.get("expected") or {}).get("ranking") or []]
    order = [cid for cid in order if cid in offered]
    return [(order[i], order[j]) for i in range(len(order))
            for j in range(i + 1, len(order))]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="training.net", description=__doc__)
    parser.add_argument("--phase", default="exploit", choices=list(PHASES))
    parser.add_argument("--ratio", type=float, default=0.25)
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    parser.add_argument("--hidden", type=int, default=HIDDEN)
    parser.add_argument("--out", default="models/exploit/" + VERSION_NET
                        + "/net.json")
    parser.add_argument("--write-manifest", default="")
    parser.add_argument("--cv", action="store_true")
    parser.add_argument("--force", action="store_true",
                        help="train anyway, below the data floor (never "
                             "promotes: the manifest is not written)")
    args = parser.parse_args(argv)

    train_rows, test_rows = rows_for(args.phase, ratio=args.ratio)
    if not train_rows or not test_rows:
        print("no rows: run `python -m training.holdout --write` first")
        return 2

    ids = {cid for row in train_rows for cid in _candidates(row.get("input") or {})}
    params = n_params(len(ids), args.hidden)
    total_rows = len(train_rows) + len(test_rows)
    floor = max(MIN_ROWS, int(MIN_ROWS_PER_PARAM * params))
    print(f"rows {total_rows} ({len(train_rows)} train / {len(test_rows)} "
          f"holdout) | params {params} | floor {floor} rows "
          f"({MIN_ROWS_PER_PARAM}/param, min {MIN_ROWS})")
    if total_rows < floor and not args.force:
        print(f"REFUSING TO TRAIN: {total_rows} rows for {params} parameters "
              f"is memorisation, not learning — the holdout would measure the "
              f"fit to itself. Collect {floor - total_rows} more labelled "
              f"decisions (production vocabulary) and rerun, or pass --force "
              f"to inspect the fit knowing the number means nothing.")
        return 1

    ranker = train(train_rows, hidden=args.hidden, epochs=args.epochs)
    from training.gate import decide
    from training.ranker import evaluate

    model, base, _ids = evaluate(ranker, test_rows)
    decision = decide(args.phase, list(zip(model, base)))
    print(f"model {sum(model) / len(model):.4f}  "
          f"baseline {sum(base) / len(base):.4f}  "
          f"delta {decision['delta']:+.4f}  "
          f"CI [{decision['ci_low']:+.4f}, {decision['ci_high']:+.4f}]  "
          f"-> {decision['verdict']}")
    for reason in decision["reasons"]:
        print(f"  reject: {reason}")

    if args.cv:
        from training.cv import cross_validate
        from training.eval import score_one

        def _fit(rows):
            return train(rows, hidden=args.hidden, epochs=args.epochs)

        def _score(fitted, rows):
            return [score_one("ndcg", row.get("expected") or {},
                              {"ranking": fitted.rank(row.get("input") or {})})
                    for row in rows]

        report = cross_validate(_fit, _score, train_rows, k=5)
        print(f"grouped {report['k']}-fold CV: mean {report['mean']:.4f}  "
              f"spread {report['stdev']:.4f} on {report['n_groups']} groups "
              f"(a DIFFERENT measurement, not what the gate decides on)")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(ranker.to_dict(), indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    print(f"net -> {out}")

    # A model trained under the data floor is written for inspection and
    # NEVER promoted: the manifest is what the runtime reads.
    under_floor = total_rows < floor
    if args.write_manifest and decision["verdict"] == "promote" and not under_floor:
        manifest = {
            "phase": args.phase, "version": VERSION_NET,
            "base_model": "mlp-pairwise-ranker", "kind": "mlp",
            "sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
            "trained_at": "2026-11-01T00:00:00Z",
            "training": {"epochs": args.epochs, "hidden": args.hidden,
                         "rows": total_rows, "params": params,
                         "min_rows": floor, "min_rows_per_param":
                         MIN_ROWS_PER_PARAM},
            "eval": {"ndcg": round(sum(model) / len(model), 6)},
            "baseline": {"ndcg": round(sum(base) / len(base), 6)},
            "eval_gate": decision, "promoted": True, "net": out.name,
        }
        target = Path(args.write_manifest)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
        print(f"promoted -> {target}")
        return 0
    return 0 if (decision["verdict"] == "promote" and not under_floor) else 1


if __name__ == "__main__":
    raise SystemExit(main())
