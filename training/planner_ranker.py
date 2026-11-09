"""planner_ranker.py — the CPU capability ranker the planner can really use.

``training.ranker`` fits the EXPLOIT question (which access path on this box)
over ids like ``noncve:service:ssh:22``.  The planner asks a different
question in a different vocabulary: which CAPABILITY (``scan_tcp``,
``web_creds``, ``beacon_deploy``) should run next for this fact, goal and
profile.  A model trained on the first cannot score the second, which is why
``--ai integrated`` used to report "no promoted manifest for phase 'planner'"
after every run.

This module fits the planner question directly.  Features are the facts the
planner already has on every candidate — category, stealth level, declared
effects, opsec cost, detection risk, ``forceful`` — plus the decision context
(goal, fact, stealthy profile, noise breaker, facts already held) and the
candidate id itself.  Interactions are explicit: ``goal=deliver|effect:beacon``
is a different weight from ``effect:beacon``.  That is what lets the model
learn "passive first when stealthy" instead of one global id order.

The label comes from ``training.planner_vocab``'s declared rubric; the
baseline recorded in each row is the static reverse index.  The gate therefore
measures exactly the claim: context-aware reordering of the same eligible set.

No GPU, no torch, standard library only.  Training is deterministic.

    python -m training.planner_ranker --write-manifest \
        models/planner/<version>/manifest.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from phantom.automation.ai.planner_features import features
from training import holdout
from training.gate import decide

PHASE = "planner"
VERSION = "planner-2026-11-08"
DEFAULT_CORPUS = (Path(__file__).resolve().parent / "golden"
                  / "planner.jsonl")
EPOCHS = 300
LEARNING_RATE = 0.08
L2 = 0.002


def _score(weights: Dict[str, float], vector: Dict[str, float]) -> float:
    return sum(weights.get(key, 0.0) * value for key, value in vector.items())


def rank(weights: Dict[str, float], payload: Dict[str, Any]) -> List[str]:
    ids = [str(row.get("id")) for row in payload.get("candidates") or []
           if isinstance(row, dict) and row.get("id")]
    return sorted(ids, key=lambda cid: -_score(weights, features(payload, cid)))


def train(rows: Iterable[Dict[str, Any]], *, epochs: int = EPOCHS,
          rate: float = LEARNING_RATE, l2: float = L2,
          seed: int = 7) -> Dict[str, float]:
    """Pairwise logistic regression over the rubric's ordered pairs."""
    data = list(rows)
    weights: Dict[str, float] = {}
    keys = set()
    for row in data:
        payload = row.get("input") or {}
        for cid in (row.get("expected") or {}).get("ranking") or []:
            keys.update(features(payload, str(cid)))
    for key in sorted(keys):
        weights[key] = 0.0

    for epoch in range(max(1, int(epochs))):
        rng = random.Random(seed + epoch)
        rng.shuffle(data)
        for row in data:
            payload = row.get("input") or {}
            offered = {str(c.get("id")) for c in payload.get("candidates") or []
                       if isinstance(c, dict)}
            order = [str(cid) for cid in
                     (row.get("expected") or {}).get("ranking") or []
                     if str(cid) in offered]
            for index, better in enumerate(order):
                for worse in order[index + 1:]:
                    vb = features(payload, better)
                    vw = features(payload, worse)
                    gap = max(-60.0, min(60.0,
                                         _score(weights, vb)
                                         - _score(weights, vw)))
                    grad = 1.0 - 1.0 / (1.0 + math.exp(-gap))
                    for key in set(vb) | set(vw):
                        delta = vb.get(key, 0.0) - vw.get(key, 0.0)
                        weights[key] = (weights.get(key, 0.0)
                                        + rate * (grad * delta
                                                  - l2 * weights.get(key, 0.0)))
    return weights


def evaluate(weights: Dict[str, float],
             rows: Sequence[Dict[str, Any]]) -> Tuple[List[float], List[float]]:
    from training.eval import score_one

    model: List[float] = []
    base: List[float] = []
    for row in rows:
        payload = row.get("input") or {}
        expected = row.get("expected") or {}
        model.append(score_one("ndcg", expected,
                               {"ranking": rank(weights, payload)}))
        baseline = (row.get("baseline") or {}).get("ranking") or []
        base.append(score_one("ndcg", expected, {"ranking": baseline}))
    return model, base


def load_rows(path: Path = DEFAULT_CORPUS) -> List[Dict[str, Any]]:
    if not path.is_file():
        return []
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if (isinstance(row, dict) and isinstance(row.get("input"), dict)
                and isinstance(row.get("expected"), dict)
                and len((row.get("input") or {}).get("candidates") or []) >= 2):
            rows.append(row)
    return rows


def split(rows: Sequence[Dict[str, Any]], ratio: float = 0.4
          ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    train_rows: List[Dict[str, Any]] = []
    test_rows: List[Dict[str, Any]] = []
    for row in rows:
        (test_rows if holdout.bucket(row, ratio) == 0 else train_rows).append(row)
    return train_rows, test_rows


def to_dict(weights: Dict[str, float], version: str = VERSION
            ) -> Dict[str, Any]:
    # LinearRanker keeps per-id weights in ``weights`` and feature weights in
    # ``context``. This model has no per-id term: every weight is a feature
    # (or an interaction) keyed by name, so the whole map belongs in context.
    return {
        "phase": PHASE,
        "version": version,
        "kind": "linear-ranker",
        "context_keys": sorted(weights),
        "weights": {},
        "context": {key: round(value, 6) for key, value in
                    sorted(weights.items())},
        "interactions": {},
        "bias": 0.0,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="training.planner_ranker",
                                     description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--ratio", type=float, default=0.4)
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    parser.add_argument("--version", default=VERSION)
    parser.add_argument("--out", default="",
                        help="weights path (written only when the gate "
                             "promotes, unless named explicitly)")
    parser.add_argument("--write-manifest", default="")
    parser.add_argument("--require-scoreable", action="store_true")
    args = parser.parse_args(argv)

    rows = load_rows(Path(args.corpus))
    if not rows:
        print(f"no rows in {args.corpus}: run `python -m training.planner_vocab "
              f"--write` first")
        return 2
    train_rows, test_rows = split(rows, args.ratio)
    if not train_rows or not test_rows:
        print(f"unusable split: {len(train_rows)} train / {len(test_rows)} test")
        return 2

    weights = train(train_rows, epochs=args.epochs)
    model, base = evaluate(weights, test_rows)
    decision = decide(PHASE, list(zip(model, base)))
    print(f"trained on {len(train_rows)} row(s), measured on "
          f"{len(test_rows)} (epochs {args.epochs})")
    print(f"model {sum(model) / len(model):.4f}  "
          f"baseline {sum(base) / len(base):.4f}  "
          f"delta {decision['delta']:+.4f}  "
          f"CI [{decision['ci_low']:+.4f}, {decision['ci_high']:+.4f}]  "
          f"-> {decision['verdict']}")
    for reason in decision["reasons"]:
        print(f"  reject: {reason}")

    if args.require_scoreable:
        offered = {str(c.get("id")) for row in rows
                   for c in (row.get("input") or {}).get("candidates") or []
                   if isinstance(c, dict)}
        offenders = [key for key, value in weights.items()
                     if key.startswith("id:") and abs(value) > 1e-9
                     and key[3:] not in offered]
        if offenders:
            print(f"REFUSED: {len(offenders)} id weight(s) name a capability "
                  f"the corpus never offered: {', '.join(offenders[:8])}",
                  file=sys.stderr)
            return 3

    if not args.out and decision["verdict"] != "promote":
        print("not exported: the gate did not promote this model")
        return 1
    out = Path(args.out or f"models/{PHASE}/{args.version}/ranker.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    exported = to_dict(weights, args.version)
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(exported, indent=2, sort_keys=True) + "\n")
    print(f"ranker -> {out}")

    if args.write_manifest and decision["verdict"] == "promote":
        trained_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        manifest = {
            "phase": PHASE,
            "version": args.version,
            "base_model": "linear-pairwise-ranker",
            "sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
            "trained_at": trained_at,
            "training": {"epochs": args.epochs, "rows": len(train_rows),
                         "corpus": Path(args.corpus).name},
            "eval": {"ndcg": round(sum(model) / len(model), 6)},
            # The registry requires baseline to be metric -> number only.
            # What was compared is recorded next to it, not inside it.
            "baseline": {"ndcg": round(sum(base) / len(base), 6)},
            "baseline_meta": {
                "kind": "static-fact-order",
                "note": ("compared against the static _FACT_SOURCES order, "
                         "NOT the learned rubric"),
            },
            "eval_gate": decision,
            "measurement": {"mode": "holdout", "rows": len(test_rows),
                            "folds": 0},
            "promoted": True,
            "kind": "linear-ranker",
            "ranker": out.name,
        }
        target = Path(args.write_manifest)
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        print(f"promoted -> {target}")
    return 0 if decision["verdict"] == "promote" else 1


if __name__ == "__main__":
    raise SystemExit(main())
