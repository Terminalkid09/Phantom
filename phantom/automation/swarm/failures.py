"""Failure attribution: WHOSE fault is a failed task, and where it goes.

Two kinds, routed differently (the D5 brainstorming decision):

* ``task`` — the decomposition is wrong: the planner found no move
  (actions == 0 despite needs met) or partial progress proves execution
  works but the provides are unreachable as specified. Routed to the
  orchestrator: bounded requeue with a rotated profile (replan-lite).
* ``agent`` — the execution is wrong: the worker crashed, stalled, or
  acted and learned nothing. Routed to learning: priors already recorded
  the loss; the failure is additionally packaged as a Triage FailureCase
  for the evolution loop (human PR gate unchanged).

A hardened target that simply resists is "agent" by these rules (acted,
nothing learned): a different profile/seed is the honest next try, not
a redecomposition.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List, Optional

TASK = "task"
AGENT = "agent"


def classify(task, result, crashed: bool = False) -> str:
    """Attribute a failed task result. Empty string when result.ok."""
    if getattr(result, "ok", False):
        return ""
    if crashed:
        return AGENT
    actions = int(getattr(result, "actions_taken", 0) or 0)
    staged = getattr(result, "staged", None) or []
    if actions <= 0:
        # planner found no viable move though the needs were met: the
        # task as specified cannot proceed — decompose differently.
        return TASK
    if not staged:
        # acted and learned nothing (stall or total resistance):
        # execution quality issue, try a different mind.
        return AGENT
    # partial progress proves execution works; the provides mapping is
    # wrong — replan, don't just retry harder.
    return TASK


def missing_provides(task, board, target: str) -> List[str]:
    """Provides-facts still absent after the run (for the case file)."""
    missing = []
    staged_kinds: set = set()
    for fact in (task.provides or ()):
        if not board.has(target, fact):
            missing.append(fact)
    return missing


def case_id_for(technique: str, cause: str, missing_fact: str) -> str:
    """Stable case id so repeated operations aggregate (MIN_OCCURRENCES)."""
    raw = f"{technique}|{cause}|{missing_fact}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def package_case(task, target: str, result, board=None,
                 registry=None):
    """Package an agent-failure as a Triage FailureCase (never raises).

    Default verdict is "unstable" (n=1 < MIN_OCCURRENCES): a single
    operation observes, it does not convict. The evolution loop
    aggregates by case_id across operations.
    """
    from phantom.automation.brain.triage import Triage
    from phantom.automation.failure_taxonomy import classify_failure
    from .profiles import technique
    tech = technique(task.goal, getattr(task, "profile", "") or "balanced")
    missing = missing_provides(task, board, target) if board is not None \
        else sorted(task.provides or ())
    cause = str(getattr(result, "stall", "") or "unknown")
    cid = case_id_for(tech, cause, missing[0] if missing else "")
    pattern = {
        "cause": cause,
        "failure_kind": classify_failure(result),
        "missing_fact": missing[0] if missing else "",
        "n": 1,
        "technique": tech,
        "sig_hash": cid,
        "phase": str(getattr(task, "goal", "")),
        "evidence": (f"swarm task {task.id} goal={task.goal} "
                     f"profile={getattr(task, 'profile', '') or 'balanced'} "
                     f"target={target} actions={result.actions_taken} "
                     f"failures={result.failures} note={result.note}")[:500],
    }
    try:
        triage = Triage(registry=registry)
        return triage.package(pattern, case_id=cid,
                              stall_class=result.stall or "",
                              profile=getattr(task, "profile", "") or "")
    except Exception:
        return None


def persist_cases(cases: List[dict], path: str) -> int:
    """Append packaged cases as JSONL (one per line). Returns count."""
    if not cases or not path:
        return 0
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            for case in cases:
                fh.write(json.dumps(case) + "\n")
        return len(cases)
    except OSError:
        return 0
