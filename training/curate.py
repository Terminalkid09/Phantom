"""curate.py — the filter between "collected" and "trainable".

A dataset built from real runs carries artefacts that teach the wrong thing:
truncated outputs, one-word answers, duplicated episodes, and — because the
model reads target-controlled text — prompt-injection strings that were
captured from a banner or a bio. Training on those teaches the model to obey
them.

This module drops them and reports WHY, so a dataset can be audited:

    short / long / empty        length and shape
    invalid                     missing roles or unparseable JSON answer
    poison                      instruction-injection markers in the prompt
    duplicate                   same conversation already kept

``--workers`` parallelises the per-record checks (the expensive part is
JSON parsing on large datasets) but the OUTPUT order is the input order:
parallelism must never make a dataset non-reproducible.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from training.phases import PHASE_ORDER, PHASES

MIN_CHARS = 16
MAX_CHARS = 12000
DEFAULT_WORKERS = 1

_POISON = (
    "ignore previous instructions",
    "ignore all previous",
    "disregard the above",
    "forget your instructions",
    "system prompt",
    "you are now",
    "jailbreak",
    "developer mode",
)
_POISON_RE = re.compile("|".join(re.escape(p) for p in _POISON),
                        re.IGNORECASE)


def _content(record: dict) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for message in record.get("messages") or []:
        if isinstance(message, dict):
            role = str(message.get("role") or "")
            if role in ("system", "user", "assistant"):
                out[role] = str(message.get("content") or "")
    return out


def _conversation_key(record: dict) -> str:
    parts = _content(record)
    blob = "\x1f".join(parts.get(role, "") for role in
                       ("system", "user", "assistant"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def check(record: dict, *, min_chars: int = MIN_CHARS,
          max_chars: int = MAX_CHARS) -> Tuple[Optional[str], str]:
    """(reason_to_drop, detail). A kept record returns (None, "")."""
    if not isinstance(record, dict):
        return "invalid", "not an object"
    phase = str(record.get("phase") or "")
    if phase not in PHASES:
        return "invalid", f"unknown phase {phase!r}"
    parts = _content(record)
    if not parts.get("user") or "assistant" not in parts:
        return "invalid", "missing user/assistant role"
    answer = parts["assistant"].strip()
    if not answer:
        return "short", "empty answer"
    if len(answer) < min_chars:
        return "short", f"answer is {len(answer)} chars"
    total = sum(len(value) for value in parts.values())
    if total > max_chars:
        return "long", f"conversation is {total} chars"
    try:
        parsed = json.loads(answer)
    except ValueError:
        # Every phase's label is JSON. A non-JSON "answer" is either a
        # template artefact or prose the model must not learn to emit.
        return "invalid", "assistant answer is not JSON"
    if parsed in ({}, [], "", None):
        return "short", "empty JSON answer"
    blob = parts.get("user", "")
    if _POISON_RE.search(blob):
        match = _POISON_RE.search(blob)
        return "poison", f"injection marker {match.group(0)!r}"
    if _POISON_RE.search(answer):
        return "poison", "injection marker in the answer"
    return None, ""


def curate(records: Iterable[dict], *, min_chars: int = MIN_CHARS,
           max_chars: int = MAX_CHARS, workers: int = DEFAULT_WORKERS
           ) -> Tuple[List[dict], Dict[str, int]]:
    """Filter records; output order == input order, even with workers."""
    rows = list(records)
    if workers and workers > 1:
        with ThreadPoolExecutor(max_workers=int(workers)) as pool:
            checks = list(pool.map(
                lambda row: check(row, min_chars=min_chars,
                                  max_chars=max_chars), rows))
    else:
        checks = [check(row, min_chars=min_chars, max_chars=max_chars)
                  for row in rows]

    report = {"input": len(rows), "kept": 0, "short": 0, "long": 0,
              "invalid": 0, "poison": 0, "duplicate": 0}
    kept: List[dict] = []
    seen = set()
    for row, (reason, _detail) in zip(rows, checks):
        if reason:
            report[reason] = report.get(reason, 0) + 1
            continue
        key = _conversation_key(row)
        if key in seen:
            report["duplicate"] += 1
            continue
        seen.add(key)
        kept.append(row)
    report["kept"] = len(kept)
    return kept, report


def _load_jsonl(path: Path) -> List[dict]:
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


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="training.curate",
        description="Drop short, duplicated, poisoned or invalid examples.")
    parser.add_argument("--in", dest="source", required=True,
                        help="input .jsonl or a directory of them")
    parser.add_argument("--out", dest="target", required=True,
                        help="output .jsonl or directory")
    parser.add_argument("--phase", default="all",
                        choices=list(PHASE_ORDER) + ["all"])
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--min-chars", type=int, default=MIN_CHARS)
    parser.add_argument("--max-chars", type=int, default=MAX_CHARS)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    source, target = Path(args.source), Path(args.target)
    files = sorted(source.glob("*.jsonl")) if source.is_dir() else [source]
    if not target.suffix:
        target.mkdir(parents=True, exist_ok=True)
    else:
        files = files[:1]

    for path in files:
        records = _load_jsonl(path)
        if args.phase != "all":
            records = [r for r in records if r.get("phase") == args.phase]
        kept, report = curate(records, min_chars=args.min_chars,
                              max_chars=args.max_chars,
                              workers=args.workers)
        out_path = (target if target.suffix else target / path.name)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
            for record in kept:
                handle.write(json.dumps(record, sort_keys=True,
                                        ensure_ascii=False) + "\n")
        manifest = dict(report)
        manifest["phase"] = args.phase
        manifest["source"] = str(path)
        out_path.with_suffix(".manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        if not args.quiet:
            print(f"{path.name}: kept {report['kept']}/{report['input']} "
                  f"-> {out_path} ({report})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
