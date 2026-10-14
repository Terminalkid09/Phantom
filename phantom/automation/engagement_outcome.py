"""
engagement_outcome.py — JobLifecycle ≠ EngagementOutcome (P0).

The auto-mode job lifecycle (`phantom/api/server.py::AutoJob`, states
``planning → running → stopping → cancelled|completed|failed``) answers
"is the process still working?". It cannot answer the question an operator
actually has: **did the engagement reach anything?**

Before this module, ``completed`` meant "the process returned", so a run
that deployed nothing, reached no goal and was refused on every move read
exactly like a run that walked the whole kill chain. The report was honest,
the job state was not, and the UI had only the job state.

This module is the missing second axis. It is deliberately:

* **pure** — no I/O, no planner import at module level, so it can be called
  from the report writer, the CLI orchestrator and the API thread alike;
* **conservative** — ``completed_goal`` is emitted ONLY when the run itself
  affirms the goal's terminal fact. Everything else degrades to a token
  that says what is actually known;
* **single-sourced** — the set of callback-dependent goals lives here, so
  the preflight policy (`automode_policy.callback_preflight`) and the
  fail-closed gate in `automode.run_auto_mode` cannot drift apart.

Vocabulary (the audit's list plus ``cancelled``, which is a real, distinct
operator action and must not be reported as a failure):

    not_started              the job never began executing
    blocked_preflight        a prerequisite (C2 callback) was missing; the
                             run FAILED CLOSED before doing any work
    running                  still executing (live jobs only)
    partial                  work was done and evidence exists, but the goal
                             was not reached
    completed_goal           the goal's terminal fact is present — success
    completed_without_goal   the run finished having produced nothing
    failed_infrastructure    the engine crashed / could not run
    failed_policy            refused by a guardrail (scope, approval)
    failed_capability        nothing could run: every move was unavailable
    awaiting_operator        the chain yielded control (e.g. a handoff) and
                             the outcome is decided by the operator
    cancelled                stopped by the operator
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

#: Every outcome token, in reporting order.
OUTCOMES = (
    "not_started",
    "blocked_preflight",
    "running",
    "partial",
    "completed_goal",
    "completed_without_goal",
    "failed_infrastructure",
    "failed_policy",
    "failed_capability",
    "awaiting_operator",
    "cancelled",
)

#: The ONLY token that means the goal was reached. Used by success metrics
#: and by anything that must not flatter a run.
GOAL_REACHED_OUTCOMES = frozenset({"completed_goal"})

#: Terminal (no longer moving) tokens.
TERMINAL_OUTCOMES = frozenset(OUTCOMES) - {"not_started", "running"}

#: Goals whose success REQUIRES a beacon to call back: deploying without a
#: listener can only burn the engagement. This is the single source for the
#: preflight policy AND the orchestrator's fail-closed gate.
CALLBACK_GOALS = frozenset({
    "beacon", "deliver", "complete_kill_chain", "post_exploit", "deep",
})

#: Human labels, for CLI and UI. Kept here so every surface renders the same
#: words for the same token.
OUTCOME_LABELS: Dict[str, str] = {
    "not_started": "not started",
    "blocked_preflight": "blocked before start (prerequisite missing)",
    "running": "running",
    "partial": "partial (goal not reached)",
    "completed_goal": "goal reached",
    "completed_without_goal": "finished without reaching the goal",
    "failed_infrastructure": "failed (infrastructure)",
    "failed_policy": "failed (policy refusal)",
    "failed_capability": "failed (no runnable capability)",
    "awaiting_operator": "awaiting operator",
    "cancelled": "cancelled by operator",
}

#: Result keys that count as EVIDENCE OF PROGRESS for the "partial vs
#: nothing" decision. Counts compare > 0; booleans are taken as-is. Kept as
#: a superset of the agent's `_finalize` counters so a new counter only has
#: to be added here to feed the outcome.
_PROGRESS_KEYS = (
    "beacon_established", "persistence_installed", "system_privilege",
    "beacon_injected", "cleanup_done", "creds_found", "services_enumerated",
    "hunt_anomalies", "identity_profiles", "victim_ips", "phishes_sent",
    "ad_domains", "ad_creds", "cracked_hashes", "lateral_movements",
    "stolen_cookies", "bt_devices", "cdp_cookie_sets", "socks_proxies",
    "trojan_bundles", "inferences", "hypotheses_confirmed",
    "actions_taken",
)


def needs_callback(goal: str) -> bool:
    """Does reaching ``goal`` require a beacon callback to the C2?"""
    return str(goal or "").strip().lower() in CALLBACK_GOALS


def outcome_label(token: str) -> str:
    return OUTCOME_LABELS.get(str(token or ""), str(token or ""))


def outcome_is_success(token: str) -> bool:
    return str(token or "") in GOAL_REACHED_OUTCOMES


def _as_count(value: Any) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _goal_reached(goal: str, result: Dict[str, Any]) -> bool:
    """Did the run affirm its own terminal fact?

    The agent stamps an explicit ``goal_reached`` in its result (it is the
    same fact check its drive loop used), so that is authoritative. Only
    when the key is absent (the swarm path, an older checkpoint) do we fall
    back to the key-based map in `success_rate`. A goal outside both is
    NEVER reported as reached — silence is not success.
    """
    result = result or {}
    if "goal_reached" in result:
        return bool(result.get("goal_reached"))
    try:
        from phantom.automation.success_rate import goal_reached as _gr
        return bool(_gr(result, goal))
    except Exception:
        return False


def has_progress(result: Dict[str, Any]) -> bool:
    """Any evidence that the run did something real."""
    result = result or {}
    return any(_as_count(result.get(k)) > 0 for k in _PROGRESS_KEYS)


def missing_goal_facts(goal: str, result: Dict[str, Any]) -> List[str]:
    """The goal's terminal facts the run did NOT produce (report material).

    Only available when the agent stamped them; the swarm path reports an
    empty list rather than inventing a gap.
    """
    result = result or {}
    missing = result.get("goal_facts_missing")
    if isinstance(missing, (list, tuple)):
        return [str(m) for m in missing]
    return []


def derive_target_outcome(goal: str, result: Optional[Dict[str, Any]] = None,
                          *, preflight_blocked: bool = False,
                          cancelled: bool = False, error: str = "",
                          awaiting_operator: bool = False,
                          policy_blocked: bool = False) -> str:
    """One target's engagement outcome.

    Precedence (each step is the FIRST true one):

    1. ``preflight_blocked`` — the run deliberately refused to start.
    2. ``error``             — the engine crashed.
    3. ``cancelled``         — the operator stopped it.
    4. ``awaiting_operator`` — control was yielded on purpose.
    5. ``policy_blocked``    — a guardrail refused the goal outright.
    6. the goal's terminal fact is present → ``completed_goal``.
    7. nothing could run at all (no actions, only failures)
       → ``failed_capability``.
    8. evidence exists → ``partial``; otherwise ``completed_without_goal``.

    A caller that cannot justify a token never gets one: this function has
    no "assume success" branch.
    """
    result = result or {}
    if preflight_blocked:
        return "blocked_preflight"
    if error:
        return "failed_infrastructure"
    if cancelled:
        return "cancelled"
    if awaiting_operator:
        return "awaiting_operator"
    if policy_blocked:
        return "failed_policy"
    if _goal_reached(goal, result):
        return "completed_goal"
    failures = int(_as_count(result.get("failures")))
    actions = int(_as_count(result.get("actions_taken")))
    if has_progress(result):
        return "partial"
    if failures > 0 and actions <= 0:
        # nothing ran and things failed: the toolset, not the target, is the
        # explanation. Distinct from "ran and found nothing".
        return "failed_capability"
    return "completed_without_goal"


def derive_engagement(goal: str, per_target: Dict[str, str],
                      *, error: str = "") -> Dict[str, Any]:
    """Aggregate per-target outcomes into the engagement-level answer.

    The engagement reaches the goal only when EVERY target did — a campaign
    that delivered on one host out of five is ``partial``, never
    ``completed_goal``. Mixed results are ``partial``; all-failure keeps the
    first non-success token so the cause survives aggregation.
    """
    per_target = {str(t): str(o) for t, o in (per_target or {}).items()}
    outcomes = list(per_target.values())
    if not outcomes:
        token = "failed_infrastructure" if error else "not_started"
    elif all(o == "completed_goal" for o in outcomes):
        token = "completed_goal"
    elif any(o == "completed_goal" for o in outcomes):
        token = "partial"
    elif all(o in ("blocked_preflight",) for o in outcomes):
        token = "blocked_preflight"
    elif len(set(outcomes)) == 1 and outcomes[0] in TERMINAL_OUTCOMES:
        token = outcomes[0]
    else:
        # mixed non-success: keep the most informative (least generic) token
        ordered = [t for t in ("blocked_preflight", "failed_infrastructure",
                               "failed_policy", "failed_capability",
                               "cancelled", "awaiting_operator", "partial",
                               "completed_without_goal") if t in outcomes]
        token = ordered[0] if ordered else "partial"
    return {
        "goal": goal,
        "outcome": token,
        "label": outcome_label(token),
        "goal_reached": token in GOAL_REACHED_OUTCOMES,
        "targets": per_target,
        "reached": [t for t, o in per_target.items()
                    if o in GOAL_REACHED_OUTCOMES],
        "partial": [t for t, o in per_target.items() if o == "partial"],
        "failed": [t for t, o in per_target.items()
                   if o.startswith("failed") or o == "completed_without_goal"],
    }


# ---------------------------------------------------------------------------
# swarm path: derive the goal from the shared board (the swarm has no
# per-target `result`, it has facts on a board)
# ---------------------------------------------------------------------------

def board_goal_reached(goal: str, board: Any,
                       targets: Iterable[str]) -> bool:
    """Does the board hold a terminal fact for ``goal`` on any target?

    The board's finding kinds mirror the goal-fact vocabulary (``beacon``,
    ``creds``, ``ad_creds``, ``pivot`` …), so the same registry that decides
    the agent's goal decides the swarm's. Never raises: a board without
    ``count`` reports "not reached" rather than inventing success.
    """
    try:
        from phantom.automation.goals import GOALS
        facts = list(GOALS.get(goal, GOALS["complete_kill_chain"]).facts)
        if not facts:
            facts = list(GOALS["complete_kill_chain"].facts)
    except Exception:
        facts = ["beacon"]
    for target in (targets or []):
        for fact in facts:
            try:
                if int(board.count(str(target), str(fact)) or 0) > 0:
                    return True
            except Exception:
                continue
    return False
