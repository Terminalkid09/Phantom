"""Swarm orchestration: fact-driven tasks over a shared blackboard.

The swarm is the migration target of auto-mode::

    target -> Orchestrator -> SwarmTasks (DAG by facts) -> WorkerAgents
           -> commit to blackboard -> adjudication/learning

Vocabulary (deliberately distinct from the C2 ``TypedTask`` in
``phantom/core/task_policy.py``, which authorizes beacon verbs):

* :class:`SwarmTask` — one unit of work: a goal on a set of targets,
  released only when its ``needs`` facts are committed, publishing its
  ``provides`` facts. ``exploit`` waits for ``service`` without any
  hardcoded chain: the DAG emerges from the facts.
* :class:`Board` — the blackboard: committed WorldModels per target.
  Workers NEVER write it live; they run on a snapshot and return staged
  findings the orchestrator commits under lock (first-writer-wins per
  finding key). Shared reads, private scratch, mediated commit — the
  prerequisite for two agents reasoning differently on the same task.
* :func:`run_swarm` — build board + tasks, drain through one
  :class:`phantom.automation.orchestrator.Orchestrator` pool PER TARGET
  (a shared semaphore caps total workers operation-wide) with
  ready-gates, return the summary.
"""
from __future__ import annotations

from .board import Board
from .llm import LLMApproval, consult
from .tasks import (
    ACTING_CAP,
    CHAIN_TEMPLATES,
    CONTACT_EXPLOIT,
    CONTACT_NONE,
    CONTACT_RECON,
    MAX_AGENTS_CEILING,
    MAX_AGENTS_DEFAULT,
    SwarmTask,
    build_tasks,
)
from .profile_policy import (
    POLICY as PROFILE_POLICY,
    ProfilePolicy,
    ProfileTargetCheck,
    chain_for_profile,
    check_profile_target,
    difficulty_for,
    policy_for,
    reason_hint_for,
    thin_surface_for,
)
from .worker import TaskResult, run_swarm_task

__all__ = [
    "Board",
    "PROFILE_POLICY",
    "ProfilePolicy",
    "ProfileTargetCheck",
    "chain_for_profile",
    "check_profile_target",
    "difficulty_for",
    "policy_for",
    "reason_hint_for",
    "thin_surface_for",
    "LLMApproval",
    "SwarmTask",
    "TaskResult",
    "build_tasks",
    "consult",
    "run_swarm",
    "run_swarm_task",
    "CHAIN_TEMPLATES",
    "CONTACT_NONE",
    "CONTACT_RECON",
    "CONTACT_EXPLOIT",
    "ACTING_CAP",
    "MAX_AGENTS_DEFAULT",
    "MAX_AGENTS_CEILING",
]


def run_swarm(targets, chain="", runner=None, profile="enterprise",
              max_agents=MAX_AGENTS_DEFAULT, budget=10, seed=0,
              aggressive=False, on_event=None, drain_timeout=120.0,
              priors=None, failure_log=None, llm_approval=None,
              advisor_factory=None, seed_facts=None, scope_list=None,
              reason_profile="", toolchain=None,
              resilient_stager: bool = True, budgets=None, cancel=None,
              idempotency=None):
    """Run one swarm operation: tasks by chain template, one
    orchestrator+pool PER TARGET (shared semaphore caps total workers),
    commit to the board. Deterministic given a deterministic runner +
    seed (required by the suite).

    ``chain`` empty means "derive it from ``profile``" (see
    ``profile_policy``); pass an explicit template to override.

    TWO distinct knobs, deliberately named apart:

    * ``profile`` — the ENVIRONMENT class of the target (enterprise,
      cloud, financial, smb, government, mobile): what the box looks
      like, which drives the chain's vocabulary.
    * ``reason_profile`` — the REASONING objective (balanced,
      evidence_first, stealth_first, force_first). It was previously
      unreachable from the CLI: `auto --swarm --reason X` was a silent
      no-op. Tasks with no explicit profile take this one; priors-based
      learning still overrides it when no explicit choice is given.

    ``priors`` (a TechniquePriors, tmp-path in tests) learns which
    reasoning profile delivers each goal: omit it and tasks run with
    their explicit profile (or none). ``failure_log`` (path) persists
    packaged agent-failures as JSONL for the evolution loop; omit it
    and cases stay in the returned summary only. ``llm_approval`` gates
    every LLM consult (default denied); ``advisor_factory`` injects the
    advisor (seam for tests). ``seed_facts`` ({target: [staged...]})
    pre-commits operator-known facts (manual recon seed) so workers
    never rediscover them; the DAG releases downstream tasks at once.
    ``scope_list`` (CIDRs/hosts, [] = warn-and-continue like the agent
    path): network targets outside it are REFUSED upfront, before any
    worker thread exists; identity targets are always allowed (they
    are the subject, scope gates machines).

    ``toolchain`` (a `ToolRegistry`) is the operator's REAL tools; the
    CLI and the auto-mode engine inject one. Omit it (tests, bare
    environments) and workers plan against the offline default.
    """
    from phantom.automation.belief import WorldModel
    from phantom.automation.guidance.commands import make_registry
    from phantom.automation.orchestrator import Orchestrator

    from .llm import LLMApproval
    from .scheduler import schedule
    targets = [t for t in (targets or []) if t]
    if not targets:
        return {"ok": False, "reason": "no targets", "tasks": []}
    refused = _refuse_out_of_scope(targets, scope_list or [])
    if refused:
        return {"ok": False,
                "reason": "out of scope: %s (scope=%s)" % (
                    ", ".join(refused), ",".join(scope_list or [])),
                "tasks": []}
    if not chain:
        # no explicit --chain: the ENVIRONMENT profile decides the start
        # (mobile opens with the scan, not a direct web chain; cloud is
        # identity-led). An explicit --chain always wins.
        chain = chain_for_profile(profile)
    board = Board(targets)
    # Per-TARGET budget: separate from the run-wide budget above. Derived
    # from config when not injected, and UNLIMITED unless a limit was set.
    from phantom.automation.budget import ledger_from_config
    from .cancellation import NullToken
    from .idempotency import IdempotencyRegistry
    board.budgets = budgets if budgets is not None else ledger_from_config()
    # Cancellation tree + one-run-per-key registry (shared by every worker).
    cancel = cancel if cancel is not None else NullToken()
    idempotency = (idempotency if idempotency is not None
                   else IdempotencyRegistry())
    tasks = build_tasks(chain, targets, seed=seed, budget=budget,
                        aggressive=aggressive)
    if reason_profile:
        # an explicit --reason on the CLI outranks the priors picker
        for task in tasks:
            if not task.profile:
                task.profile = reason_profile
    if seed_facts:
        # operator-known truth lands before the first gate check, so
        # downstream tasks release immediately (no rediscovery)
        for target, staged in (seed_facts or {}).items():
            if target in board.targets():
                board.commit("seed", target, list(staged or []))
    registry = make_registry()
    sink: dict = {"failures": [], "cases": [], "actions": 0}
    approval = llm_approval if llm_approval is not None else LLMApproval()
    width = max(1, min(int(max_agents or 1), MAX_AGENTS_CEILING))

    def _make_worker():
        return lambda action, ctx: _dispatch(
            action, board, runner=runner, profile=profile,
            aggressive=aggressive, on_event=on_event, priors=priors,
            registry=registry, sink=sink, llm_approval=approval,
            advisor_factory=advisor_factory, toolchain=toolchain,
            resilient_stager=resilient_stager, cancel=cancel,
            idempotency=idempotency,
            scope_list=list(scope_list or []))

    def _orch_factory(sem, per_pool):
        return Orchestrator(
            wm=WorldModel(target="swarm"), stealth=None,
            worker=_make_worker(),
            max_agents=max(1, int(per_pool or 1)),
            global_slot=sem,
        )

    summary = schedule(None, board, tasks, drain_timeout=drain_timeout,
                       priors=priors, registry=registry, sink=sink,
                       grouped=True, orch_factory=_orch_factory,
                       ceiling=MAX_AGENTS_CEILING, max_agents=width)
    summary["ok"] = all(t["status"] == "done" for t in summary["tasks"])
    summary["board_ref"] = board  # live board: merge/report downstream
    summary["budgets"] = board.budgets.snapshot()
    summary["idempotency"] = idempotency.snapshot()
    if failure_log:
        from .failures import persist_cases
        summary["cases_persisted"] = persist_cases(
            summary["evolution_cases"], failure_log)
    return summary


def _refuse_out_of_scope(targets, scope_list) -> list:
    """Network targets outside the engagement scope, up front (fail
    fast, before any thread exists). Identity targets are the subject
    and always pass — scope gates machines, never people."""
    if not scope_list:
        return []
    try:
        from phantom.automation.guidance.targets import (
            classify_target, is_identity_target)
        from phantom.core.scope import is_in_scope
    except Exception:
        return []
    refused = []
    for target in targets:
        try:
            if is_identity_target(classify_target(target)):
                continue
            if not is_in_scope(target, scope_list):
                refused.append(target)
                try:
                    from phantom.automation import decision_audit as _audit
                    _audit.record("scope_decision", target=target,
                                  decision="deny",
                                  scope=",".join(scope_list or []),
                                  reason="target outside engagement scope")
                except Exception:
                    pass
        except Exception:
            continue
    return refused


def _dispatch(action, board, runner=None, profile="enterprise",
              aggressive=False, on_event=None, priors=None,
              registry=None, sink=None, llm_approval=None,
              advisor_factory=None, scope_list=None, toolchain=None,
              resilient_stager: bool = True, cancel=None, idempotency=None):
    """Orchestrator worker: run every target of the action's task, commit
    staged findings, report task-level success. Exceptions never escape
    (the pool marks the action FAILED and keeps draining) — a crashed
    worker is attributed as an agent-failure with its case packaged.

    LLM: the worker's internal advisor runs only under session approval;
    an agent-kind failure additionally triggers ONE approved consult
    (validated suggestions surfaced on the failure record, never
    committed as facts). Without approval the request is recorded for
    the operator and nothing touches a transport.
    """
    from .llm import SESSION, consult
    from .scheduler import commit_result
    from .worker import TaskResult
    if cancel is None:
        from .cancellation import NullToken
        cancel = NullToken()
    if idempotency is None:
        from .idempotency import IdempotencyRegistry
        idempotency = IdempotencyRegistry()
    task = action.task
    sink = sink if sink is not None else {"failures": [], "cases": []}
    tried = sink.setdefault("tried", {})
    import threading as _t
    tried_lock = sink.setdefault("lock", _t.Lock())

    def _events(kind, data):
        if on_event:
            on_event(kind, data)

    session_llm = bool(llm_approval is not None
                       and llm_approval.state == SESSION)
    ok_all = True
    # per-target actions run their origin only; dynamic extras get
    # their OWN pool+action next wave (every target owns its pool).
    # Legacy whole-task actions fall back to the full effective set.
    scope = getattr(action, "targets", None)
    if not scope:
        scope = task.effective_targets(board)
    # A (task, target) RUN slot is leased for the duration of the worker:
    # a requeue or helper racing a still-in-flight worker is denied instead
    # of double-spending the task budget. The lease is always released.
    lease_owner = (getattr(action, "capability_id", "")
                   or f"{task.id}:{id(action)}")
    budgets = getattr(board, "budgets", None)
    if budgets is None:
        # a board shape that predates the ledger (test doubles): attach an
        # unlimited one so the dispatch contract is unchanged.
        from phantom.automation.budget import BudgetLedger
        budgets = board.budgets = BudgetLedger()
    for target in scope:
        # An operator stop reaches every worker between targets.
        if cancel.cancelled:
            _events("cancelled", {"task": task.id, "target": target,
                                  "reason": cancel.reason})
            ok_all = False
            break
        # Per-target budget is checked BEFORE the lease: an exhausted
        # target is skipped with a typed reason instead of charging a run.
        if budgets.exhausted(target):
            _events("budget_exhausted", {"task": task.id, "target": target,
                                         "reason": budgets.reason(target)})
            ok_all = False
            continue
        # One run per (task, target): a re-dispatch of an already-SUCCEEDED
        # unit reuses the prior result instead of spending the budget twice.
        idem_key = idempotency.key_for(task.id, target)
        if not idempotency.begin(idem_key):
            _events("idempotent_skip", {"task": task.id, "target": target})
            prior = idempotency.outcome(idem_key)
            if prior is not None:
                ok_all = ok_all and bool(getattr(prior, "ok", False))
            continue
        if not board.leases.claim(task.id, target, lease_owner):
            idempotency.fail(idem_key)   # not our run: let the owner finish
            _events("lease_denied", {"task": task.id, "target": target,
                                     "owner": lease_owner})
            continue
        try:
            worker_profile = getattr(action, "worker_profile", None)
            if worker_profile is None:
                worker_profile = task.profile
            worker_avoid = getattr(action, "worker_avoid", None)
            if worker_avoid is None:
                worker_avoid = task.avoid_caps
            worker_seed = getattr(action, "worker_seed", None)

            def _capture(kind, data, _t=target):
                if kind == "run" and (data or {}).get("capability"):
                    with tried_lock:
                        tried.setdefault((task.id, _t), set()).add(
                            data["capability"])
                _events(kind, {**data, "task": task.id, "target": _t})

            try:
                result = run_swarm_task(
                    task, target, board, runner=runner, profile=profile,
                    aggressive=aggressive, llm=session_llm,
                    worker_profile=worker_profile,
                    worker_avoid=worker_avoid, worker_seed=worker_seed,
                    toolchain=toolchain,
                    scope_list=list(scope_list or []) if scope_list else None,
                    resilient_stager=resilient_stager,
                    on_event=_capture,
                )
            except Exception as exc:  # noqa: BLE001 — pool contract
                from .failures import AGENT, package_case
                idempotency.fail(idem_key)   # crashed: a retry may still run
                task.attempts += 1
                task.status = "failed"
                task.failure_kind = AGENT
                task.note = f"crashed: {str(exc)[:200]}"
                crashed = TaskResult(task_id=task.id, target=target, ok=False,
                                     crashed=True, note=task.note)
                record = {"task": task.id, "goal": task.goal,
                          "profile": task.profile or "balanced",
                          "target": target,
                          "kind": AGENT, "stall": "", "failures": 0,
                          "actions": 0, "note": task.note,
                          "llm_requested": True, "llm_suggestions": []}
                sink["failures"].append(record)
                suggestions, why = _consult(task, target, board, llm_approval,
                                            advisor_factory, registry,
                                            "worker crashed", _events)
                record["llm_suggestions"] = suggestions
                record["llm_state"] = why
                case = package_case(task, target, crashed, board=board,
                                    registry=registry)
                if case is not None:
                    try:
                        sink["cases"].append(case.to_dict())
                    except Exception:
                        pass
                _events("failed", {"task": task.id, "target": target,
                                   "output": str(exc)[:200]})
                ok_all = False
                continue
            record = commit_result(board, task, target, result,
                                   priors=priors, registry=registry, sink=sink)
            try:
                actions = int(getattr(result, "actions_taken", 0) or 0)
                sink["actions"] = int(sink.get("actions", 0)) + actions
                # charge the target for what the worker actually spent
                budgets.spend(target, actions=actions)
            except Exception:
                pass
            if record is not None and record.get("kind") == "agent":
                record["llm_requested"] = True
                suggestions, why = _consult(
                    task, target, board, llm_approval, advisor_factory,
                    registry,
                    f"task failed "
                    f"({result.stall or result.note or 'no progress'})",
                    _events)
                record["llm_suggestions"] = suggestions
                record["llm_state"] = why
            _events("task_target", {"task": task.id, "target": target,
                                    "ok": result.ok,
                                    "staged": len(result.staged)})
            # what the task actually produced: emitted as a verbose-only event
            # so the default stream stays readable and `--verbose` shows it
            _events("task_found", {"task": task.id, "target": target,
                                   "findings": _staged_lines(result.staged)})
            # idempotency: a SUCCESS is remembered (never re-run); a failed
            # attempt is released so a policy-driven retry can still run.
            if result.ok:
                idempotency.complete(idem_key, result)
            else:
                idempotency.fail(idem_key)
            ok_all = ok_all and result.ok
        finally:
            board.leases.release(task.id, target, lease_owner)
    return ok_all


def _staged_lines(staged) -> List[str]:
    """`kind:key = value` for a worker's staged facts (secrets stay local)."""
    from phantom.core.stream_contract import fact_line
    lines = []
    for item in (staged or [])[:20]:
        if not isinstance(item, dict):
            continue
        line = fact_line(item.get("kind", ""), item.get("key", ""),
                         item.get("value", ""))
        if line:
            lines.append(line)
    return lines


def _consult(task, target, board, llm_approval, advisor_factory,
             registry, reason, emit):
    """Request-then-consult: without approval only the request is
    recorded (stream-visible for the operator); with approval one
    validated consult runs over the COMMITTED facts (context, not zero)."""
    from .llm import consult
    wm = board.worldmodel(target)
    if llm_approval is None or not llm_approval.allows():
        if llm_approval is not None:
            llm_approval.request(
                f"LLM second opinion on {task.id} ({target}): {reason}",
                context=f"goal={task.goal} profile={task.profile or 'balanced'}")
        emit("llm_request", {"task": task.id, "target": target,
                             "reason": reason})
        return [], "denied"
    suggestions, why = consult(task, wm, llm_approval,
                               advisor_factory=advisor_factory,
                               registry=registry)
    emit("llm_consult", {"task": task.id, "target": target,
                         "state": why, "count": len(suggestions)})
    return suggestions, why
