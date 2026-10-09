"""
automode.py — Phantom Auto Mode Orchestrator
Completa kill chain autonoma: enumeration → exploit → post-exploitation.
"""

import os
import time
import threading
from typing import Callable, Optional, List

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


def _callback_preflight(targets, goal: str) -> None:
    """Callback-plausibility policy (automode_policy), announced through
    THIS module's notifier: the orchestrator owns the announcer."""
    from phantom.core.automode_policy import callback_preflight
    return callback_preflight(targets, goal, notifier=notifier)


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
                      evolution_mode: str = "code"):
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
        evolution_mode=evolution_mode)


def _run_agent_campaign(targets, goal, profile, aggressive, paranoid, speed,
                        scope_list, agents, verbose=False,
                        on_event: Optional[Callable[[str, dict], None]] = None,
                        llm: bool = False, state_dir: str = "",
                        experience: bool = False,
                        evolution: bool = False,
                        identity_active: bool = False,
                        stop_event: Optional[threading.Event] = None):
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
    return run_campaign(
        targets=targets, profile=profile, aggressive=aggressive,
        paranoid=paranoid, speed=speed, goal=goal,
        scope_list=scope_list, max_agents=max_agents,
        workers_per_target=workers_per_target,
        on_event=_make_agent_stream(verbose, on_event),
        state_dir=state_dir or None,
        threat_intel=_threat_intel_feed(), persist_learning=True, llm=llm,
        experience=experience, evolution=evolution,
        identity_active=identity_active, stop_event=stop_event)


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
        notifier.warn(f"Core sync fallita ({target}): {exc}")
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
    result, summary, merged = _run_swarm_operation(
        resolved, goal, profile, aggressive, speed, agents,
        verbose, on_event, llm, resilient_stager=resilient_stager,
        resume=resume, experience=experience, evolution=evolution)
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


def _run_swarm_operation(targets, goal, profile, aggressive, speed,
                         agents, verbose=False, on_event=None,
                         llm: bool = False, budget: int = 10,
                         resilient_stager: bool = True,
                         resume: str = "", experience: bool = False,
                         evolution: bool = False):
    """Swarm engine for run_auto_mode: fact-driven tasks over a shared
    board, then merge into the manual session. Returns
    (result, summary, merged) where result speaks the legacy keys the
    reporting tail already understands.

    The agent-path-only flags are announced HERE, once, instead of once per
    caller: --resume/--experience/--evolution are checkpoint/evolution
    features of the agent path and are ignored on the swarm path."""
    for _flag, _name in ((resume, "--resume"),
                         (experience, "--experience"),
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
        notifier.warn("c2.transport_backend=go: il listener Python NON viene "
                      "avviato — lancia il data plane Go (`c2d`) così i due non "
                      "si contendono la porta")
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
            notifier.warn(f"C2 bind {bind_host}:{port} non disponibile qui "
                          f"— fallback loopback 127.0.0.1:{port} (solo lab "
                          f"locale: i beacon remoti non rientrano)")
            bind_host = "127.0.0.1"
        else:
            notifier.warn(f"C2 listener non avviabile su {bind_host}:{port} "
                          f"(porta occupata?) — proseguo senza listener")
            return False
    notifier.status(f"Avvio listener C2 su {bind_host}:{port} "
                    f"(HTTPS/mTLS auto; dial {dial_host})")
    try:
        srv.start(host=bind_host, port=port, use_ssl=True)
        return True
    except Exception as exc:
        notifier.warn(f"Auto-start listener C2 fallito: {exc}")
        return False


def run_auto_mode(targets=None, aggressive: bool = False, stealth: bool = False,
                  speed: bool = False, plan: bool = False, agents: int = 0,
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
                   force_profile: bool = False) -> None:
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
        notifier.error("Nessun target specificato. Usa: auto <target> [target2, ...]")
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
    if not scope_list:
        # A-6: auto-mode FAILS CLOSED without a scope (the
        # agent gate refuses unless the operator explicitly
        # opted out) — the notice explains why up front.
        _warn_missing_scope(resolved)

    if plan:
        for t in resolved:
            p, tt, chain, _goal_facts = _dry_run_plan(
                t, goal, profile, aggressive, stealth, speed)
            console.print(f"\n[bold cyan]{t}[/] ({tt}, {chain} chain)")
            if not p.steps:
                console.print("  [dim](goal già soddisfatto o nessun percorso)[/]")
            else:
                for i, s in enumerate(p.steps, 1):
                    console.print(
                        f"  {i}. [white]{s.capability.id}[/] "
                        f"[dim](cost {s.capability.opsec_cost}, "
                        f"{s.capability.stealth_level})[/] — {s.reason}")
        notifier.info("Dry-run completato: nessuna azione eseguita.")
        return

    # Fully automatic kill chain: the C2 listener must be up BEFORE any
    # beacon deploy so a deployed beacon has somewhere to check in. The
    # operator never has to start it manually — _ensure_c2_listener brings
    # its own listener (HTTPS + auto-generated mTLS material) unless
    # c2.listener_auto_start is off, binding c2.bind (every interface by
    # default) and dialing the derived beacon-facing address.
    _ensure_c2_listener()

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
            _note.append("--evolution richiede --llm (l'author è l'LLM): "
                         "flag ignorata")
        if beta:
            _note.append("--beta: le capability dalle PR auto-evolution "
                         "aperte verranno caricate dopo il gate (lab "
                         "incluso)")
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
                notifier.info("[beta] nessuna PR auto-evolution aperta")
        except Exception as _exc:
            notifier.warn(f"[beta] load fallito: {_exc}")

    # ONE goal table decides the engine (goals.GOALS: facts + chain +
    # engine): --engine swarm is honored for goals that DECLARE a
    # swarm chain, anything else falls back to the agent path with a
    # note (honest, not silent).
    engine, engine_note = _engine_for(goal, engine)
    if engine_note:
        notifier.warn(engine_note)

    if len(resolved) == 1:
        if engine == "swarm":
            _run_swarm_branch(
                resolved, goal, profile, aggressive, speed, agents,
                verbose, on_event, llm, out_root, started_wall, handoff_c2,
                resilient_stager, resume, experience, evolution)
            return
        state_path = resume or os.path.join(out_root, "checkpoint.json")
        result, agent = _run_agent_single(
            resolved[0], goal, profile, aggressive, stealth, speed,
            scope_list, agents, verbose, on_event, llm,
            state_path=state_path, experience=_experience_enabled(experience),
            evolution=evolution, stop_event=stop_event,
            reason_profile=reason_profile, cell_loop=cell_loop,
            cell_stages=cell_stages, resilient_stager=resilient_stager,
            identity_active=identity_active,
            evolution_mode=("proposal" if only_markdown else "code"))
        tdir, paths = _write_agent_reports(agent, profile, out_root, resolved[0])
        # auto-mode -> manual core: everything the agent learned is merged
        # into the session + manual WorldModel, so `map`, `suggest`,
        # `exploit`, `payload` and the report all see the same truth.
        _merged = _merge_results_to_session(agent, resolved[0])
        if _merged:
            notifier.info(
                "Core sync: " + ", ".join(
                    f"{k}={v}" for k, v in sorted(_merged.items())) +
                " (visibili ora anche nel core manuale)")
        _print_agent_single_tail(result, paths, agent, goal,
                                 started_wall, out_root)
        if result.get("beacon_established"):
            beacon_id = result.get("beacon_id") or ""
            if handoff_c2:
                _handoff_c2(beacon_id)
            elif on_event is not None:
                on_event("handoff", {"beacon_id": beacon_id})
        else:
            notifier.warn("Nessun beacon stabilito: niente handoff. "
                          "Usa 'c2' -> 'beacons' per monitorare callback")
        return

    if engine == "swarm":
        _run_swarm_branch(
            resolved, goal, profile, aggressive, speed, agents,
            verbose, on_event, llm, out_root, started_wall, handoff_c2,
            resilient_stager, resume, experience, evolution)
        return
    campaign = _run_agent_campaign(
        resolved, goal, profile, aggressive, stealth, speed,
        scope_list, agents, verbose, on_event, llm,
        state_dir=out_root, experience=_experience_enabled(experience),
        evolution=evolution, identity_active=identity_active,
        stop_event=stop_event)
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
    if first_beacon:
        if handoff_c2:
            _handoff_c2(first_beacon)
        elif on_event is not None:
            on_event("handoff", {"beacon_id": first_beacon})
    else:
        notifier.info("Nessun beacon stabilito. Usa 'c2' per monitorare.")
