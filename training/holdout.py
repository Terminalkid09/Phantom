"""holdout.py — turn the labelled corpus into a REAL golden set.

The golden files shipped with the repository are three hand-written rows per
phase. Three rows cannot measure anything: one row moves the score by 0.33, so
``training.gate`` refuses to promote on them and it is right to. Meanwhile the
labelled corpus collected from real runs is much larger
(``training/data/exploit.jsonl`` 113 rows, ``finding`` 90, ``evolution`` 328).

This module bridges the two: it converts corpus rows into the exact golden
shape ``training.eval`` consumes, and splits them deterministically so the set
used for measurement is never the set used for training.

Two rules keep it honest:

* **one converter.** The expected value is produced by
  ``training.predict.to_eval`` — the SAME function the runtime uses to turn a
  model answer into an eval shape. Re-implementing it here would let the
  benchmark drift from the thing it measures.
* **deterministic split, by content.** A row goes to the holdout when the
  SHA-256 of its canonical JSON falls in the first ``ratio`` of the space. No
  counter, no filesystem order, no random seed to forget: the same corpus
  always yields the same holdout, and a row can never be on both sides.

The output is ``training/golden/<phase>.holdout.jsonl`` — a separate file on
purpose, so the three-row smoke set stays exactly as it is and nothing that
already points at ``<phase>.jsonl`` changes meaning.

Usage::

    python -m training.holdout                  # report only
    python -m training.holdout --write          # write the holdout files
    python -m training.holdout --phase exploit --ratio 0.3 --write

Phases whose corpus is too small to reach ``training.gate.MIN_ROWS`` are
REPORTED as unmeasurable, not padded: padding a holdout with rows the model
trained on is how a benchmark starts lying.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from training.phases import PHASE_ORDER

DATA_DIR = Path(__file__).resolve().parent / "data"
GOLDEN_DIR = Path(__file__).resolve().parent / "golden"


def _canonical(row: Dict[str, Any]) -> str:
    return json.dumps(row, sort_keys=True, ensure_ascii=False, default=str)


def bucket(row: Dict[str, Any], ratio: float) -> int:
    """0 when the row belongs to the holdout, 1 when it belongs to training.

    ``ratio`` is clamped to (0, 1): a 0 holdout is a configuration mistake, not
    an empty measurement, and a 1.0 holdout would leave nothing to train on.
    """
    ratio = min(0.9, max(0.01, float(ratio)))
    digest = hashlib.sha256(_canonical(row).encode("utf-8")).hexdigest()
    return 0 if int(digest[:8], 16) / 0xFFFFFFFF < ratio else 1


def _payload_and_answer(row: Dict[str, Any]) -> Optional[tuple]:
    """``(payload, answer)`` from a chat row, or None when it is not usable.

    The corpus is ``{messages: [system, user, assistant], phase, source}``;
    the user message is the JSON the model saw and the assistant message is
    the JSON it answered. Anything else is skipped, not guessed.
    """
    messages = row.get("messages") or []
    if not isinstance(messages, list) or len(messages) < 3:
        return None
    try:
        payload = json.loads(str(messages[1].get("content") or ""))
        answer = json.loads(str(messages[2].get("content") or ""))
    except (ValueError, TypeError, AttributeError):
        return None
    if not isinstance(payload, dict) or not isinstance(answer, dict):
        return None
    return payload, answer


def convert(phase: str, payload: Dict[str, Any],
            answer: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """One corpus row -> one golden row, or None when the shape does not fit.

    The expected value comes from ``training.predict.to_eval`` and is then
    wrapped the way the golden files wrap it (``ranking`` / ``value`` /
    ``open_ports`` / ``probability``), because a golden row is
    ``{expected: <that shape>}``.
    """
    from training.predict import to_eval

    shaped = to_eval(phase, answer, payload)
    if not shaped:
        return None
    # An EMPTY answer is not an expectation: ``{"ranking": []}`` would score
    # the model on nothing and silently reward an empty prediction.
    empty = (not shaped.get("ranking") and "ranking" in shaped) or \
            (not shaped.get("value") and "value" in shaped) or \
            (not shaped.get("open_ports") and "open_ports" in shaped)
    if empty:
        return None
    return {"phase": phase, "metric": None, "input": payload,
            "expected": shaped}


def build(phase: str, *, ratio: float = 0.25,
          data_dir: Path = DATA_DIR) -> List[Dict[str, Any]]:
    """The holdout rows for one phase (deterministic, deduplicated)."""
    path = Path(data_dir) / f"{phase}.jsonl"
    if not path.is_file():
        return []
    rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except ValueError:
                continue
            if bucket(raw, ratio) != 0:
                continue
            pair = _payload_and_answer(raw)
            if pair is None:
                continue
            row = convert(phase, *pair)
            if row is None:
                continue
            # Dedupe on the CONTENT, not the id: the corpus repeats the same
            # observation from different runs, and a duplicate row would
            # double-count one fact in the bootstrap.
            key = _canonical(row)
            if key in seen:
                continue
            seen.add(key)
            row["id"] = (f"{phase}-h{len(rows) + 1:03d}-"
                         f"{hashlib.sha256(key.encode('utf-8')).hexdigest()[:8]}")
            rows.append(row)
    return rows


def report(phases: Iterable[str] = PHASE_ORDER, *, ratio: float = 0.25,
           min_rows: Optional[int] = None,
           data_dir: Path = DATA_DIR) -> Dict[str, Dict[str, Any]]:
    """Per-phase counts and whether the set can measure anything at all."""
    if min_rows is None:
        from training.gate import MIN_ROWS
        min_rows = MIN_ROWS
    out: Dict[str, Dict[str, Any]] = {}
    for phase in phases:
        rows = build(phase, ratio=ratio, data_dir=data_dir)
        out[phase] = {"phase": phase, "n": len(rows),
                      "min_rows": int(min_rows),
                      "measurable": len(rows) >= int(min_rows),
                      "rows": rows}
    return out


def write(phases: Iterable[str] = PHASE_ORDER, *, ratio: float = 0.25,
          out_dir: Path = GOLDEN_DIR,
          data_dir: Path = DATA_DIR) -> Dict[str, str]:
    """Write ``<phase>.holdout.jsonl`` and return ``{phase: path}``."""
    written: Dict[str, str] = {}
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for phase, info in report(phases, ratio=ratio, data_dir=data_dir).items():
        if not info["n"]:
            continue
        target = out_dir / f"{phase}.holdout.jsonl"
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            for row in info["rows"]:
                handle.write(json.dumps(row, sort_keys=True,
                                        ensure_ascii=False) + "\n")
        written[phase] = str(target)
    return written


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="training.holdout",
                                     description=__doc__)
    parser.add_argument("--phase", action="append", default=[],
                        help="phase to build (default: all)")
    parser.add_argument("--ratio", type=float, default=0.25,
                        help="fraction of the corpus used for measurement")
    parser.add_argument("--write", action="store_true",
                        help="write the holdout files")
    parser.add_argument("--out-dir", default=str(GOLDEN_DIR))
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    args = parser.parse_args(argv)

    phases = args.phase or list(PHASE_ORDER)
    info = report(phases, ratio=args.ratio,
                  data_dir=Path(args.data_dir))
    print(f"{'phase':<12}{'n':>6}{'min':>6}  measurable")
    for phase in phases:
        row = info[phase]
        print(f"{phase:<12}{row['n']:>6}{row['min_rows']:>6}  "
              f"{'yes' if row['measurable'] else 'NO — not enough labelled rows'}")
    if args.write:
        written = write(phases, ratio=args.ratio,
                        out_dir=Path(args.out_dir),
                        data_dir=Path(args.data_dir))
        for phase, path in written.items():
            print(f"{phase}: wrote {info[phase]['n']} row(s) -> {path}")
    if not any(row["measurable"] for row in info.values()):
        print("no phase has enough rows to be measured", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
