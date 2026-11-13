"""prod_baseline.py — the ordering the PRODUCTION scorer would produce.

The promotion gate kept comparing a candidate against
``training.predict._baseline`` because the corpus carried no deterministic
ordering. Writing one BY HAND would have been an unmeasured number — exactly
the defect the `--baseline production` flag exists to close.

So the ordering is not authored here, it is *called*: every candidate in the
row is turned into the runtime's own ``AccessCandidate`` and scored with
``score_for(mode)``, then sorted with the same key the ranker-free runtime
uses. The stored baseline is therefore the real competitor, and it can be
regenerated at any time with ``python -m training.ranker --stamp-corpus``.

``load_corpus``/``stamp_corpus`` never invent a field: a row whose candidates
produce no ordering is reported, not filled in.
"""

from __future__ import annotations

import dataclasses
import json
import os
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Sequence


def corpus_path(phase: str = "exploit") -> str:
    """The shipped production-vocabulary corpus for ``phase``."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "golden", f"{phase}.production.jsonl")


def load_corpus(path: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _candidate(raw: Dict[str, Any], target: str = ""):
    """One corpus candidate as the RUNTIME's object, not a copy of the schema."""
    from phantom.automation.exploit.access import AccessCandidate

    known = {f.name for f in dataclasses.fields(AccessCandidate)}
    payload = {key: value for key, value in raw.items() if key in known}
    if target and not payload.get("target"):
        payload["target"] = target
    return AccessCandidate(**payload)


def candidates_from_row(row: Dict[str, Any]) -> List[Any]:
    payload = row.get("input") or {}
    target = str(payload.get("target") or "")
    out = []
    for raw in payload.get("candidates") or []:
        if isinstance(raw, dict) and raw.get("id"):
            out.append(_candidate(raw, target))
    return out


def candidate_ids(row: Dict[str, Any]) -> List[str]:
    return [str(c.id) for c in candidates_from_row(row)]


def production_ranking(row: Dict[str, Any]) -> List[str]:
    """The ids in the order the ranker-free runtime would try them.

    Mirrors ``phantom.automation.ai.advisors.exploit._base_scores`` (an
    explicit ``score`` wins, otherwise ``score_for(mode)``) and the runtime
    sort key: actionable first, then auto-execute, then score, access level,
    complexity, noise and finally the id — the same tie-breaks, so a tie is
    reproduced identically instead of being broken differently here.
    """
    payload = row.get("input") or {}
    mode = str(payload.get("mode") or "balanced")
    scored = []
    for cand in candidates_from_row(row):
        score = float(getattr(cand, "score", 0.0) or 0.0)
        if score <= 0.0:
            score = float(cand.score_for(mode))
        scored.append((cand, score))
    if not scored:
        return []
    scored.sort(key=lambda pair: (
        0 if pair[0].actionable else 1,
        0 if pair[0].auto_execute else 1,
        -pair[1],
        -int(pair[0].access_level or 0),
        float(pair[0].complexity if pair[0].complexity is not None else 1.0),
        float(pair[0].noise if pair[0].noise is not None else 1.0),
        str(pair[0].id),
    ))
    return [str(cand.id) for cand, _ in scored]


def validated_ranking(row: Dict[str, Any]) -> Dict[str, List[str]]:
    """The row's STORED ordering, proven to be a permutation of its candidates.

    A stored rank that names an id the row never offered (or omits one) is a
    corrupt baseline, not a baseline: it would score the model against a
    candidate that does not exist and quietly move the measured delta.
    """
    stored = row.get("deterministic_rank")
    if isinstance(stored, dict):
        stored = stored.get("ranking")
    if not isinstance(stored, list) or not stored:
        raise ValueError(f"row {row.get('id')!r} carries no deterministic_rank")
    ranking = [str(item) for item in stored]
    known = set(candidate_ids(row))
    if not known:
        raise ValueError(f"row {row.get('id')!r} carries no candidates")
    if len(ranking) != len(known) or set(ranking) != known:
        missing = sorted(known - set(ranking))
        unknown = sorted(set(ranking) - known)
        raise ValueError(
            f"row {row.get('id')!r}: deterministic_rank is not a permutation "
            f"of its candidates (missing={missing}, unknown={unknown})")
    return {"ranking": ranking}


def stamp_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """A copy of ``row`` carrying the computed production ordering."""
    ranking = production_ranking(row)
    if not ranking:
        return dict(row)
    stamped = dict(row)
    stamped["deterministic_rank"] = ranking
    return stamped


def stamp_rows(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [stamp_row(row) for row in rows]


def stamp_corpus(path: Optional[str] = None, *,
                 phase: str = "exploit") -> Any:
    """Rewrite ``path`` with a ``deterministic_rank`` on every stampable row.

    Returns ``(written, total)``. The write is atomic (temp file + rename) and
    the on-disk shape stays one JSON object per line with sorted keys, which
    is how the shipped corpus is already formatted.
    """
    target = path or corpus_path(phase)
    rows = load_corpus(target)
    stamped = stamp_rows(rows)
    written = sum(1 for before, after in zip(rows, stamped)
                  if after.get("deterministic_rank"))
    directory = os.path.dirname(os.path.abspath(target)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".corpus-", suffix=".jsonl",
                               dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            for row in stamped:
                fh.write(json.dumps(row, ensure_ascii=False,
                                    sort_keys=True) + "\n")
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return written, len(rows)
