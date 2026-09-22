"""
automode.py — Phantom Auto Mode Orchestrator
Completa kill chain autonoma: enumeration → exploit → post-exploitation.
"""

import os
import re
import time
import ipaddress
import threading
from typing import Callable, Optional, List

from rich.console import Console
from phantom.core.session import session, KB_STATUS_DEFAULT
from phantom.core.session_bridge import (merge_agent_into_session,
                                         seed_findings_from_session)
from phantom.utils.notifier import notifier
from phantom.utils.network import get_lhost

console = Console()


# -----------------------------------------------------------------------------
# Agent routing (auto -> planner agent -> swarm tasks)
# -----------------------------------------------------------------------------

_MAX_CIDR_HOSTS = 256


def _extract_networks(raw_targets: List[str]) -> List[str]:
    """CIDR/subnet tokens in the raw target list (e.g. 10.0.0.0/24)."""
    nets = []
    for raw in raw_targets or []:
        for token in raw.split(","):
            token = token.strip()
            if "/" in token:
                try:
                    ipaddress.ip_network(token, strict=False)
                    nets.append(token)
                except ValueError:
                    continue
    return nets


def _expand_targets(raw_targets: List[str],
                    scope_list: Optional[List[str]] = None) -> List[str]:
    """Expand CIDR ranges and comma lists into a deduped target list,
    filtered by the engagement scope when provided."""
    from phantom.core.scope import is_in_scope
    out: List[str] = []
    seen = set()

    def _add(t: str) -> None:
        if not t or t in seen:
            return
        if scope_list:
            # identity targets (email/username/phone) are the engagement
            # SUBJECT and are always in scope — the scope list gates the
            # machines (ip/domain/url), not the person being assessed
            from phantom.automation.guidance.targets import (
                classify_target,
                is_identity_target,
            )
            ttype = classify_target(t)
            if not is_identity_target(ttype) and not is_in_scope(t, scope_list):
                notifier.warn(f"{t} fuori scope, ignorato")
                return
        seen.add(t)
        out.append(t)

    for raw in raw_targets:
        for token in raw.split(","):
            token = token.strip()
            if not token:
                continue
            if "/" in token:
                try:
                    net = ipaddress.ip_network(token, strict=False)
                except ValueError:
                    _add(token)  # e.g. a URL path, not a CIDR
                    continue
                # Bound the iteration BEFORE materializing: a /8 input would
                # otherwise allocate 16M strings in RAM just to truncate
                # them to the first 256. Never build the full host list.
                hosts = []
                for i, h in enumerate(net.hosts()):
                    if i >= _MAX_CIDR_HOSTS:
                        break
                    hosts.append(str(h))
                if not hosts:
                    hosts = [str(net.network_address)]
                if net.num_addresses > _MAX_CIDR_HOSTS:
                    notifier.warn(
                        f"{token}: {net.num_addresses} host, espansione "
                        f"limitata a {_MAX_CIDR_HOSTS}")
                for h in hosts:
                    _add(str(h))
            else:
                _add(token)
    return out


def _stream_agent_event(kind: str, data: dict, verbose: bool = False) -> None:
    tag = f"[bold blue]{data.get('target', '')}[/] " if data.get("target") else ""
    if kind == "run":
        # the operator must see WHAT is running, the REAL command and WHY:
        # capability banner + stealth badge + actual command + planner reason
        cap_name = data.get("banner") or data.get("capability")
        stealth = data.get("stealth_level") or ""
        badge = {"paranoid": "⚡paranoid", "active": "●active",
                 "aggressive": "🎯aggressive"}.get(stealth, "")
        line = f"{tag}{cap_name}"
        if badge:
            line += f"  [dim]{badge}[/]"
        line += f"  (cost {data.get('cost', '?')})"
        notifier.info(line)
        cmd = data.get("command") or ""
        reason = data.get("reason") or ""
        if cmd and reason:
            # real command + planner reason on the same line: the operator
            # sees both the action and the thinking behind it
            notifier.info(f"{tag}    $ {cmd[:200]}")
            notifier.info(f"{tag}      why: {reason[:180]}")
        elif cmd:
            notifier.info(f"{tag}    $ {cmd[:200]}")
        elif reason and verbose:
            notifier.info(f"{tag}      why: {reason[:180]}")
    elif kind == "plan":
        steps = data.get("steps", [])
        notifier.info(f"{tag}plan: {' -> '.join(steps)} "
                      f"(strategy={data.get('strategy') or '-'})")
    elif kind == "inference":
        if verbose:
            for f in data.get("findings", []):
                notifier.info(f"{tag}[infer] {f.get('kind')}:{f.get('key')} "
                              f"→ {f.get('value')}")
    elif kind == "reason":
        if verbose:
            for h in data.get("hypotheses", []):
                notifier.info(f"{tag}[reason] {h.get('capability')} :: "
                              f"{h.get('reason')} (prio {h.get('priority')})")
    elif kind == "hypothesis":
        if verbose:
            for r in data.get("resolved", []):
                notifier.info(f"{tag}[hypothesis] {r.get('capability')} "
                              f"→ {r.get('status')}")
    elif kind == "found":
        values = data.get("values") or {}
        parts = []
        for fkey in (data.get("findings") or [])[:6]:
            v = values.get(fkey)
            if v:
                parts.append(f"{fkey} = {str(v)[:60]}")
            else:
                parts.append(fkey)
        notifier.success(f"{tag}{data.get('capability')}: {', '.join(parts)}")
    elif kind == "note":
        notifier.info(f"{tag}{data.get('capability')}: "
                      f"{data.get('detail', 'no new findings')}")
    elif kind == "blocked":
        notifier.warn(f"{tag}{data.get('capability')} bloccata: "
                      f"{data.get('reason', '')[:120]}")
    elif kind == "tool_missing":
        notifier.warn(f"{tag}{data.get('capability')}: tool mancanti "
                      f"{', '.join(data.get('tools', []))}")
    elif kind == "failed":
        # prefer the human reason; fall back to raw output, then a generic
        # line so a failed step never prints as a bare "Failed:"
        out = data.get("reason") or data.get("output") or "execution failed"
        notifier.error(f"{tag}{data.get('capability')}: {str(out)[:120]}")
    elif kind == "beacon_up":
        notifier.success(f"{tag}BEACON UP in C2 ({data.get('beacon_id', '')})")
    elif kind == "handoff":
        notifier.success(f"{tag}HANDOFF: beacon {data.get('beacon_id', '')} "
                         f"sotto controllo operatore — nessun cleanup automatico")
    elif kind == "halt":
        notifier.warn(f"{tag}halt: {data.get('reason', '')}")


def _make_agent_stream(verbose: bool = False,
                       on_event: Optional[Callable[[str, dict], None]] = None):
    """Factory for the shared agent event stream.

    The CLI renderer remains the default consumer. Electron and other local
    frontends can subscribe to the same events without duplicating the agent.
    """
    def _stream(kind: str, data: dict) -> None:
        if on_event is not None:
            try:
                on_event(kind, data)
            except Exception:
                # A frontend must never interrupt the engagement engine.
                pass
        _stream_agent_event(kind, data, verbose=verbose)
    return _stream


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
                      cell_loop: bool = False,
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
        cell_loop=cell_loop, cell_stages=cell_stages,
        evolution_mode=evolution_mode)


def _run_agent_campaign(targets, goal, profile, aggressive, paranoid, speed,
                        scope_list, agents, verbose=False,
                        on_event: Optional[Callable[[str, dict], None]] = None,
                        llm: bool = False, state_dir: str = "",
                        experience: bool = False,
                        evolution: bool = False,
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
        experience=experience, evolution=evolution, stop_event=stop_event)


def _handoff_c2(beacon_id: str) -> None:
    notifier.success("=" * 56)
    notifier.success("OPERATOR HANDOFF: la kill chain si ferma qui.")
    notifier.success("Il beacon passa sotto il tuo controllo nel "
                     "terminale C2: ispeziona e fai il cleanup a mano.")
    notifier.success("=" * 56)
    from phantom.core.c2_shell import run_c2
    run_c2(preferred_beacon=beacon_id or None)


def _report_out_dir() -> str:
    from phantom.utils.paths import sessions_dir
    return os.path.join(sessions_dir(), f"auto_{int(time.time())}")


def _safe_target_dir(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", target)


def _merge_results_to_session(agent, target: str) -> dict:
    """Bridge an auto-mode agent's findings into the manual session. Never
    raises: a bridge failure must not abort a finished engagement."""
    try:
        return merge_agent_into_session(agent, target) or {}
    except Exception as exc:            # pragma: no cover - defensive
        notifier.warn(f"Core sync fallita ({target}): {exc}")
        return {}


def _write_agent_reports(agent, profile: str, out_root: str, target: str):
    from datetime import datetime as _dt
    from phantom.automation.reporting import RawReport, ClientReport, ReportWriter
    raw = RawReport.from_agent(agent)
    raw.ended = _dt.now().isoformat(timespec="seconds")
    tdir = os.path.join(out_root, _safe_target_dir(target))
    return tdir, ReportWriter(tdir).write(
        raw, ClientReport.from_agent(agent, profile))


def _print_report_paths(paths: dict) -> None:
    for k, p in paths.items():
        console.print(f"  [cyan]{k}[/]: {p}")


def _fmt_elapsed(seconds: float) -> str:
    """Human-readable duration: "3m 12s", "45s", "1h 2m 3s"."""
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


# goal -> swarm chain template. Goals without a swarm chain (cleanup…)
# fall back to the single-agent path with a notice (honest, not silent).
_GOAL_CHAIN = {
    "footprint": "footprint", "identity": "identity", "creds": "creds",
    "web": "web",
    "beacon": "full", "deliver": "full", "complete_kill_chain": "full",
    "deep": "deep", "post_exploit": "deep", "ad": "deep",
    "crack": "deep", "lateral": "deep",
}


def _stream_swarm_event(kind: str, data: dict, verbose: bool = False,
                        on_event=None) -> None:
    """Swarm events onto the operator stream (mirrors the agent event
    vocabulary where it overlaps so consoles need no new renderer)."""
    if kind == "task_target":
        if data.get("ok"):
            notifier.success(
                f"Swarm {data.get('task')} @ {data.get('target')}: "
                f"+{data.get('staged', 0)} finding(s) committed")
        else:
            notifier.warn(
                f"Swarm {data.get('task')} @ {data.get('target')}: "
                f"no provides ({data.get('staged', 0)} staged)")
    elif kind == "failed":
        notifier.warn(f"Swarm {data.get('task')}: {data.get('output', '')[:120]}")
    elif kind == "llm_request":
        notifier.warn(f"Swarm chiede LLM: {data.get('reason', '')[:140]} "
                      f"(approva: POST /api/automode/llm {{\"allow\": true}})")
    elif kind == "llm_consult":
        notifier.info(f"Swarm×LLM ({data.get('state', '')}): "
                      f"{data.get('count', 0)} suggerimenti validati")
    if on_event is not None:
        try:
            on_event(kind, data)
        except Exception:
            pass


def _run_swarm_operation(targets, goal, profile, aggressive, speed,
                         agents, verbose=False, on_event=None,
                         llm: bool = False, budget: int = 10):
    """Swarm engine for run_auto_mode: fact-driven tasks over a shared
    board, then merge into the manual session. Returns
    (result, summary, merged) where result speaks the legacy keys the
    reporting tail below already understands."""
    from phantom.automation.swarm import run_swarm
    from phantom.automation.swarm.llm import LLMApproval
    from phantom.core.session_bridge import merge_board_into_session

    chain = _GOAL_CHAIN.get(goal, "")
    if not chain:
        return None
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
    summary = run_swarm(
        targets, chain=chain, profile=profile, aggressive=aggressive,
        max_agents=agents or 10, budget=budget, llm_approval=approval,
        seed_facts=seed or None, scope_list=list(session.scope or []),
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


def _write_swarm_summary(summary: dict, out_root: str, target: str) -> dict:
    """Persist the swarm operation summary (board_ref excluded: live
    objects, not JSON). Returns {"summary": path} like the report writer."""
    import json as _json
    clean = {k: v for k, v in (summary or {}).items() if k != "board_ref"}
    os.makedirs(out_root, exist_ok=True)
    path = os.path.join(out_root, "swarm_summary.json")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            _json.dump(clean, fh, indent=2, default=str)
    except OSError as exc:
        notifier.warn(f"Swarm summary non salvato: {exc}")
        return {}
    return {"summary": path}


def _print_swarm_tail(result: dict, summary: dict, out_root: str,
                      started_wall: float, goal: str, on_event,
                      handoff_c2: bool) -> None:
    """Shared reporting tail for swarm runs (single + campaign): stage
    ladder, totals, merge note. No checkpoint file exists for swarm —
    re-running merges the committed session seed, so downstream tasks
    release at once instead of rediscovering."""
    elapsed = _fmt_elapsed(time.time() - started_wall)
    tasks = summary.get("tasks", []) if summary else []
    done = sum(1 for t in tasks if t.get("status") == "done")
    if goal == "deep":
        st = result.get("stages") or {}
        ladder = " ".join(
            f"{k}={'✔' if st.get(k) else '—'}" for k in
            ("deliver", "post_exploit", "ad", "crack", "lateral"))
        notifier.success(
            f"Swarm deep completato (⏱ {elapsed}): "
            f"{done}/{len(tasks)} task, beacon={result.get('beacon_established')}, "
            f"persistenza={result.get('persistence_installed')}, "
            f"system/root={result.get('system_privilege')}, "
            f"AD creds={result.get('ad_creds')}, "
            f"cracked={result.get('cracked_hashes')}, "
            f"lateral={result.get('lateral_movements')}, "
            f"azioni={result.get('actions_taken')}")
        notifier.info(f"Stage ladder: {ladder}")
    else:
        notifier.success(
            f"Swarm {goal} completo (⏱ {elapsed}): {done}/{len(tasks)} task, "
            f"beacon={result.get('beacon_established')}, "
            f"persistenza={result.get('persistence_installed')}, "
            f"creds={result.get('creds_found')}, "
            f"azioni={result.get('actions_taken')}")
    notifier.info(f"⏱ Tempo totale engagement: {elapsed}.")
    if result.get("beacon_established"):
        notifier.info("Nessun handoff automatico dallo swarm: apri 'c2' -> "
                      "'beacons' per prendere in carico i callback.")
    else:
        notifier.warn("Nessun beacon stabilito: niente handoff. "
                      "Usa 'c2' -> 'beacons' per monitorare callback")


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

    Binds the derived beacon-facing address from get_c2_endpoint() (a real
    local address), never 0.0.0.0 by default; when that address is not
    bindable here (e.g. a public NAT address from PHANTOM_C2_HOST) it falls
    back to the loopback for local-lab runs and says so loudly. Returns
    True when a listener is up afterwards, False otherwise (the run then
    continues listener-less: beacons deploy but cannot check in)."""
    from phantom.core.c2_server import server_instance
    from phantom.utils.network import get_c2_endpoint
    srv = server if server is not None else server_instance
    if srv.thread and srv.thread.is_alive():
        return True
    from phantom.utils import config as cfg
    if not cfg.get("c2.listener_auto_start", True):
        notifier.warn("c2.listener_auto_start is off and no C2 listener is "
                      "up: deployed beacons cannot check in — start one "
                      "with `c2` -> listener start")
        return False
    host, port = get_c2_endpoint()
    if not _probe_bind(host, port):
        if host != "127.0.0.1" and _probe_bind("127.0.0.1", port):
            notifier.warn(f"C2 {host}:{port} non bindabile qui (NAT/IP non "
                          f"locale?) — fallback loopback 127.0.0.1:{port} "
                          f"(solo lab locale: i beacon remoti non rientrano)")
            host = "127.0.0.1"
        else:
            notifier.warn(f"C2 listener non avviabile su {host}:{port} "
                          f"(porta occupata o indirizzo non locale) — "
                          f"proseguo senza listener")
            return False
    notifier.status(f"Avvio listener C2 su {host}:{port} (HTTPS/mTLS auto)...")
    try:
        srv.start(host=host, port=port, use_ssl=True)
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
                  resume: str = "",
                  stop_event: Optional[threading.Event] = None,
                   reason_profile: str = "",
                   cell_loop: bool = False,
                   cell_stages: Optional[List[str]] = None,
                   only_markdown: bool = False,
                   engine: str = "agent",
                   force_network: bool = False) -> None:
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

    # senior network triage: a CIDR/subnet input gets host discovery +
    # surface ranking BEFORE the assault, so the agent pool works the
    # richest hosts first instead of spraying full chains on random IPs
    # from the address range. Discovery only runs when a network token
    # was actually given; identity targets are never triaged.
    networks = _extract_networks(raw)
    if networks:
        # ONE engine: discovery + enrichment + exposure ranking all live
        # in netmap (the same code the `map` command and Electron use), so
        # the assault pool and the network map always see the same truth.
        from phantom.core.netmap import triage_networks
        notifier.info(
            f"Network triage: host discovery su {', '.join(networks)}...")
        tri = triage_networks(networks)
        ranked = [r["ip"] for r in tri.get("ranked", [])]
        if ranked:
            alive_n = len(tri.get("hosts", []))
            notifier.success(
                f"Host discovery: {alive_n} vivi, ordinati per "
                f"superficie d'attacco (top: {', '.join(ranked[:5])})")
            # senior semantics: the CIDR expansion is REPLACED by the
            # discovered + ranked hosts. Only the operator's explicit
            # per-host tokens survive the swap (operator intent first,
            # then discovered hosts ranked by attack surface). This avoids
            # the trap where the 256-host expansion already contains the
            # discovered IPs, which would silently keep the whole range.
            explicit = [
                t.strip()
                for tok in raw for t in tok.split(",")
                if t.strip() and "/" not in t
                and t.strip() not in networks
            ]
            seen = set(explicit)
            ranked = [h for h in ranked
                      if not (h in seen or seen.add(h))]
            resolved = explicit + ranked
        else:
            notifier.warn(
                "Nessun host esposto rilevato o nmap assente: espansione "
                "CIDR classica (host a caso nella rete)")

    # RANGE POLICY: a CIDR/range token authorizes discovery (-sn +
    # ranking, already done above), never an assault. Engaging N hosts
    # with full chains needs explicit operator intent per host, or the
    # force flag with its disclaimer. A range is not intent. Dry-run
    # (--plan) always passes: it executes nothing.
    if networks and not force_network and not plan:
        if len(resolved) > 1 or any("/" in t for t in raw):
            notifier.info("Network scope: discovery-only di default "
                          "(host vivi + ranking, nessun engagement).")
            for t in resolved[:20]:
                console.print(f"  [cyan]{t}[/]")
            if len(resolved) > 20:
                console.print(f"  [dim]... +{len(resolved) - 20} altri "
                              f"(vedi network map)[/]")
            notifier.info("Per ingaggiare: riesegui con host espliciti "
                          "oppure --force-network (full engagement, loud).")
            return
    if networks and force_network:
        notifier.warn(
            f"FORCE-NETWORK attivo: engagement completo su {len(resolved)} "
            f"host ({', '.join(resolved[:5])}"
            f"{', ...' if len(resolved) > 5 else ''}). Scansioni, exploit "
            f"e brute force gireranno su tutta la rete.")

    notifier.success("=" * 25 + " PHANTOM AUTO-MODE (agent) " + "=" * 25)
    # auto-profile: a phone-number target (or any mobile-classified
    # target) defaults to the mobile defender model when the operator left
    # the default profile untouched — explicit --profile choices win.
    if profile == "enterprise":
        from phantom.automation.guidance.targets import classify_target
        if any(classify_target(t) in ("phone", "mobile") for t in resolved):
            profile = "mobile"
            notifier.info("Target mobile rilevato -> profilo difensivo: mobile")

    notifier.info(f"Target: {', '.join(resolved)}")
    notifier.info(f"Goal: {goal} | profile: {profile} | "
                  f"stealth={'paranoid' if stealth else 'on'} | "
                  f"aggressive={aggressive} | speed={speed} | "
                  f"verbose={verbose} | agents={agents or 'auto'} | "
                  f"llm={'on' if llm else 'off'} | "
                  f"experience={'global' if experience else 'run-only'}")
    if not scope_list:
        try:
            from phantom.automation.guidance.targets import (
                classify_target, is_identity_target)
            net_targets = [t for t in resolved
                           if not is_identity_target(classify_target(t))]
        except Exception:
            net_targets = list(resolved)
        if net_targets:
            notifier.warn(
                "NESSUNO SCOPE impostato su target di rete: l'auto-mode "
                "non rifiuterà nulla da solo. Imposta 'set scope "
                "<cidr,...>' (o scope_list) prima di run reali — un "
                "typo nel target o un CIDR largo colpiscono davvero.")

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
    # c2.listener_auto_start is off, binding the derived beacon-facing
    # address instead of 0.0.0.0.
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

    if len(resolved) == 1:
        if engine == "swarm" and goal in _GOAL_CHAIN:
            for _flag, _name in ((resume, "--resume"),
                                 (experience, "--experience"),
                                 (evolution, "--evolution")):
                if _flag:
                    notifier.warn(
                        f"{_name} ignorato sullo swarm path "
                        f"(checkpoint/evolution sono del path agent)")
            notifier.success("=" * 25 + " PHANTOM AUTO-MODE (swarm) " + "=" * 25)
            result, summary, _merged = _run_swarm_operation(
                resolved, goal, profile, aggressive, speed, agents,
                verbose, on_event, llm)
            paths = _write_swarm_summary(summary, out_root, resolved[0])
            if _merged:
                notifier.info(
                    "Core sync: " + ", ".join(
                        f"{k}={v}" for k, v in sorted(_merged.items())) +
                    " (visibili ora anche nel core manuale)")
            _print_swarm_tail(result, summary, out_root, started_wall,
                              goal, on_event, handoff_c2)
            return
        if engine == "swarm":
            notifier.warn(f"Swarm has no chain for goal '{goal}': agent path")
        state_path = resume or os.path.join(out_root, "checkpoint.json")
        result, agent = _run_agent_single(
            resolved[0], goal, profile, aggressive, stealth, speed,
            scope_list, agents, verbose, on_event, llm,
            state_path=state_path, experience=experience,
            evolution=evolution, stop_event=stop_event,
            reason_profile=reason_profile, cell_loop=cell_loop,
            cell_stages=cell_stages,
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
        elapsed = _fmt_elapsed(time.time() - started_wall)
        if goal == "deep":
            st = result.get("stages") or {}
            ladder = " ".join(
                f"{k}={'✔' if st.get(k) else '—'}" for k in
                ("deliver", "post_exploit", "ad", "crack", "lateral"))
            notifier.success(
                f"Deep engagement completato (⏱ {elapsed}): "
                f"beacon={result.get('beacon_established')}, "
                f"persistenza={result.get('persistence_installed')}, "
                f"system/root={result.get('system_privilege')}, "
                f"AD creds={result.get('ad_creds')}, "
                f"cracked={result.get('cracked_hashes')}, "
                f"lateral={result.get('lateral_movements')}, "
                f"azioni={result.get('actions_taken')}")
            notifier.info(f"Stage ladder: {ladder}")
        else:
            notifier.success(
                f"Deliver completo (⏱ {elapsed}): beacon={result.get('beacon_established')}, "
                f"persistenza={result.get('persistence_installed')}, "
                f"creds={result.get('creds_found')}, "
                f"victim_ips={result.get('victim_ips')}, "
                f"ipotesi={result.get('hypotheses')} "
                f"({result.get('hypotheses_confirmed')} confermate), "
                f"azioni={result.get('actions_taken')}")
        notifier.info("Report (raw operatore + client sanificato):")
        _print_report_paths(paths)
        notifier.info(f"⏱ Tempo totale engagement: {elapsed}.")
        notifier.info(
            f"Checkpoint: {os.path.join(out_root, 'checkpoint.json')} — "
            "riprendi con `auto <target> --resume <file>` o condividi "
            "con `export-session` (.pm)")
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

    if engine == "swarm" and goal in _GOAL_CHAIN:
        for _flag, _name in ((resume, "--resume"),
                             (experience, "--experience"),
                             (evolution, "--evolution")):
            if _flag:
                notifier.warn(
                    f"{_name} ignorato sullo swarm path "
                    f"(checkpoint/evolution sono del path agent)")
        notifier.success("=" * 25 + " PHANTOM AUTO-MODE (swarm) " + "=" * 25)
        result, summary, merged = _run_swarm_operation(
            resolved, goal, profile, aggressive, speed, agents,
            verbose, on_event, llm)
        _write_swarm_summary(summary, out_root, ",".join(resolved))
        if merged:
            for t, counts in merged.items():
                if counts:
                    notifier.info(
                        f"Core sync [{t}]: " + ", ".join(
                            f"{k}={v}" for k, v in sorted(counts.items())))
        _print_swarm_tail(result, summary, out_root, started_wall,
                          goal, on_event, handoff_c2)
        return
    if engine == "swarm":
        notifier.warn(f"Swarm has no chain for goal '{goal}': agent path")
    campaign = _run_agent_campaign(
        resolved, goal, profile, aggressive, stealth, speed,
        scope_list, agents, verbose, on_event, llm,
        state_dir=out_root, experience=experience, evolution=evolution,
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
    notifier.success(
        f"Campaign completata (⏱ {elapsed}): {campaign.get('beacons')} beacon, "
        f"{campaign.get('persistent')} persistenti, "
        f"{campaign.get('compromised_creds')} creds.")
    notifier.info(f"⏱ Tempo totale campagna: {elapsed}.")
    notifier.info("Report (per-target + campaign):")
    for k, p in {**per_target, **cpaths}.items():
        console.print(f"  [cyan]{k}[/]: {p}")
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
