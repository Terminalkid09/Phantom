"""baseline_production.py — is the PRODUCTION scorer even measurable on our corpus?

The measurement this module exists for, taken on 2026-10-31:

* the training corpus asks about CAPABILITY ids — ``scan_tcp``, ``http_probe``,
  ``web_rce``, ``beacon_deploy``, ``privesc_sudo`` — the vocabulary of
  ``automation/guidance/kit.py``;
* the deterministic scorer Phantom actually ships,
  ``access.AccessCandidate.score_for``, orders ACCESS candidates that
  ``access.collect_candidates`` builds out of a service list, and names them
  ``noncve:service:redis:6379`` or a CVE id;
* the intersection of the two, on the golden set, is EMPTY.

That is why "the production baseline is not measurable" — and the reason is not
a missing column. Adding ``success``/``noise``/``complexity`` to corpus rows
would not help: production never reads those ids at all, so it would produce no
ordering to compare against. The honest fix is MORE ROWS in the production
vocabulary (service sets whose access candidates a rubric can order), not more
columns on the existing rows.

So this module does not pretend. It returns the production ordering when there
is one, the COVERAGE of the corpus ids it can account for, and a reason
otherwise — so the gap becomes a number in the eval report instead of a
sentence in a document that nobody re-checks.

Reporting only: nothing here feeds the promotion gate or a score.
"""

from __future__ import annotations

from typing import Any, Dict, List

def _empty(reason: str = "") -> Dict[str, Any]:
    """A fresh zero-coverage block.

    A shared module-level literal would hand every caller the same list and
    dict objects, so one caller that appends to ``ids`` would poison the next
    report. Fresh containers, every time.
    """
    return {"ids": [], "scores": {}, "corpus_ids": [], "shared": [],
            "coverage": 0.0, "reason": reason}


def _corpus_ids(payload: Dict[str, Any]) -> List[str]:
    """The ids the payload asks about, in the payload's own order.

    ``candidates`` is a list of dicts in every row we have seen, but a report
    must not die on the one row that is not: anything unusable contributes no
    id, which lowers the coverage instead of raising.
    """
    rows = payload.get("candidates")
    if not isinstance(rows, (list, tuple)):
        return []
    ids: List[str] = []
    for row in rows:
        if isinstance(row, dict):
            value = str(row.get("id") or "")
        else:
            value = str(row or "")
        if value and value not in ids:
            ids.append(value)
    return ids


def _reason(corpus_ids: List[str], ids: List[str],
            shared: List[str]) -> str:
    """One sentence naming why there is, or is not, a measurement."""
    if not corpus_ids:
        return ("the payload asks about no candidates, so there is no "
                "ordering to be right or wrong about")
    if not ids:
        return ("no production candidates could be built from this payload's "
                "services: score_for has nothing to order")
    if not shared:
        return ("the two vocabularies share no id: the corpus asks about "
                "capability ids (recon/exploit/post moves) while production "
                "scores the access candidates it builds from services")
    if len(ids) < 2:
        return ("only one production candidate came out of this payload: a "
                "single item has no ordering to score")
    if len(shared) == len(corpus_ids):
        # Every id the payload asks about is a production candidate, and there
        # are at least two of them: this row IS measurable. A reason here would
        # turn a real measurement into a warning.
        return ""
    return (f"only {len(shared)} of {len(corpus_ids)} corpus ids are "
            f"production candidates, so the orderings are not comparable")


def production_ranking(payload: dict, mode: str = "balanced") -> Dict[str, Any]:
    """The production ordering for ``payload``, and how much of it is in scope.

    ``ids`` is ``score_for(mode)`` descending, ties broken by id so two runs on
    the same payload are identical — a baseline that reorders itself between
    runs cannot be compared with anything.

    ``shared`` is that same ordering RESTRICTED to the ids the payload asked
    about, which is the only part a corpus label can be scored against.
    """
    try:
        data = payload if isinstance(payload, dict) else {}
        corpus_ids = _corpus_ids(data)

        # Imported here rather than at module level: this is a training-side
        # report, and it should not drag the whole application (and its
        # optional dependencies) into an import of `training.*`.
        from phantom.automation.exploit import access

        services = data.get("services")
        candidates = access.collect_candidates(
            services=services if isinstance(services, (list, tuple)) else [],
            target=str(data.get("target") or ""),
            # include_nvd=True would query NVD over the network. A training
            # report has to be reproducible offline: a third party answering
            # (or not) must not change the baseline it is compared against.
            include_nvd=False,
            include_non_cve=True,
        )

        scored = [(str(c.id), float(c.score_for(mode)))
                  for c in (candidates or [])]
        scored.sort(key=lambda pair: (-pair[1], pair[0]))
        ids = [cid for cid, _score in scored]
        scores = {cid: score for cid, score in scored}
        wanted = set(corpus_ids)
        shared = [cid for cid in ids if cid in wanted]
        coverage = (len(shared) / float(len(corpus_ids))) if corpus_ids else 0.0

        return {
            "ids": ids,
            "scores": scores,
            "corpus_ids": corpus_ids,
            "shared": shared,
            "coverage": coverage,
            "reason": _reason(corpus_ids, ids, shared),
        }
    except Exception:
        # This runs inside `training.eval`, and a crash there costs the whole
        # report — every score, not just this block. A payload this module
        # cannot read is a coverage of zero with a reason, never an exception.
        return _empty("the payload could not be turned into production "
                      "candidates")


def scoreable(payload: dict, mode: str = "balanced") -> bool:
    """Can the production ordering be scored against this payload's label?

    Only when EVERY corpus id is a production candidate AND production has at
    least two of them: one candidate is not an ordering, and a partial overlap
    would score the model against an order that only covers half the field.
    """
    block = production_ranking(payload, mode=mode)
    return bool(block.get("coverage") == 1.0 and len(block.get("ids") or []) >= 2)
