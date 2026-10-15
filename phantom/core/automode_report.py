"""
automode_report.py — the end-of-run reporting tail for auto-mode runs.

What a finished engagement prints (stage ladder, totals, report paths,
checkpoint note, swarm summary) lives here, so the orchestrator
(automode.py) only decides WHO runs and then calls the tail. Formatting is
pinned by tests/test_automode_report.py.
"""

from __future__ import annotations

import os
import re
import time
from typing import Optional

from rich.console import Console

from phantom.utils.notifier import notifier

console = Console()


def fmt_elapsed(seconds: float) -> str:
    """Human-readable duration: "3m 12s", "45s", "1h 2m 3s"."""
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def safe_target_dir(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", target)


def report_out_dir() -> str:
    from phantom.utils.paths import sessions_dir
    return os.path.join(sessions_dir(), f"auto_{int(time.time())}")


def write_agent_reports(agent, profile: str, out_root: str, target: str):
    from datetime import datetime as _dt
    from phantom.automation.reporting import RawReport, ClientReport, ReportWriter
    raw = RawReport.from_agent(agent)
    raw.ended = _dt.now().isoformat(timespec="seconds")
    # P0: the end-of-run report states the ENGAGEMENT outcome, so "completed"
    # in the job lifecycle and "reached nothing" in the outcome can never be
    # read as the same thing.
    try:
        from phantom.automation.engagement_outcome import (
            derive_target_outcome, outcome_label)
        _tok = derive_target_outcome(
            getattr(agent, "goal", "") or "",
            getattr(agent, "result", None) or {})
        raw.outcome = _tok
        raw.outcome_label = outcome_label(_tok)
    except Exception:
        pass
    tdir = os.path.join(out_root, safe_target_dir(target))
    return tdir, ReportWriter(tdir).write(
        raw, ClientReport.from_agent(agent, profile))


def write_phase_report(agent, profile: str, out_root: str, stage: str,
                       index: int = 0, total: int = 0,
                       ok: Optional[bool] = None):
    """Write the report for ONE stage of a run, as it ends.

    The requirement is explicit: an artifact at the end of EVERY phase of
    whatever goal, so a run that only reached `identity` produces a phase
    report exactly like the five-stage `deep` ladder does. Files land under
    ``<out_root>/phases/<NN>_<stage>/`` so the ladder reads in order and a
    later stage can never overwrite an earlier one.

    Returns the paths dict, or {} when it could not be written. NEVER raises:
    a finished phase must not die because an artifact failed. If ``out_root``
    is empty (a direct `run_autonomous` call with no engagement directory)
    nothing is written — silently, because there is nowhere to write.
    """
    if not out_root:
        return {}
    try:
        from datetime import datetime as _dt
        from phantom.automation.engagement_outcome import (
            derive_target_outcome, outcome_label)
        from phantom.automation.reporting import (
            ClientReport, RawReport, ReportWriter)
        raw = RawReport.from_agent(agent)
        raw.ended = _dt.now().isoformat(timespec="seconds")
        raw.phase = stage
        raw.phase_index = int(index or 0)
        raw.phase_total = int(total or 0)
        raw.phase_ok = None if ok is None else bool(ok)
        # The phase outcome is judged on THIS stage's own terminal fact, so a
        # satisfied stage is `completed_goal` and an unsatisfied one is
        # `partial`/`completed_without_goal` — never silently "success".
        try:
            _wm = getattr(agent, "wm", None)
            _res = {
                "goal_reached": bool(ok),
                "actions_taken": len(getattr(_wm, "actions_taken", []) or []),
                "failures": len(getattr(_wm, "failures", []) or []),
            }
        except Exception:
            _res = {"goal_reached": bool(ok)}
        _tok = derive_target_outcome(
            getattr(agent, "goal", "") or stage, _res)
        raw.outcome = _tok
        raw.outcome_label = outcome_label(_tok)
        tdir = os.path.join(out_root, "phases",
                            f"{int(index or 0):02d}_{safe_target_dir(stage) or 'phase'}")
        return ReportWriter(tdir).write(
            raw, ClientReport.from_agent(agent, profile))
    except Exception as exc:
        notifier.warn(f"Phase report not written ({stage}): {exc}")
        return {}


def print_report_paths(paths: dict) -> None:
    for k, p in paths.items():
        console.print(f"  [cyan]{k}[/]: {p}")


def write_swarm_summary(summary: dict, out_root: str, target: str) -> dict:
    """Persist the swarm operation summary (board_ref excluded: live
    objects, not JSON). Returns {"summary": path} like the report writer."""
    import json as _json
    clean = {k: v for k, v in (summary or {}).items() if k != "board_ref"}
    path = os.path.join(out_root, "swarm_summary.json")
    try:
        # makedirs INSIDE the try: the contract is "warn and return {}",
        # never raise at the end of a finished engagement.
        os.makedirs(out_root, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            _json.dump(clean, fh, indent=2, default=str)
    except OSError as exc:
        notifier.warn(f"Swarm summary not saved: {exc}")
        return {}
    return {"summary": path}


def print_swarm_tail(result: dict, summary: dict, out_root: str,
                     started_wall: float, goal: str, on_event=None,
                     handoff_c2: bool = True) -> None:
    """Shared reporting tail for swarm runs (single + campaign): stage
    ladder, totals, merge note. No checkpoint file exists for swarm —
    re-running merges the committed session seed, so downstream tasks
    release at once instead of rediscovering."""
    elapsed = fmt_elapsed(time.time() - started_wall)
    tasks = summary.get("tasks", []) if summary else []
    done = sum(1 for t in tasks if t.get("status") == "done")
    if goal == "deep":
        st = result.get("stages") or {}
        ladder = " ".join(
            f"{k}={'✔' if st.get(k) else '—'}" for k in
            ("deliver", "post_exploit", "ad", "crack", "lateral"))
        notifier.success(
            f"Swarm deep complete (⏱ {elapsed}): "
            f"{done}/{len(tasks)} task, beacon={result.get('beacon_established')}, "
            f"persistence={result.get('persistence_installed')}, "
            f"system/root={result.get('system_privilege')}, "
            f"AD creds={result.get('ad_creds')}, "
            f"cracked={result.get('cracked_hashes')}, "
            f"lateral={result.get('lateral_movements')}, "
            f"actions={result.get('actions_taken')}")
        notifier.info(f"Stage ladder: {ladder}")
    else:
        notifier.success(
            f"Swarm {goal} complete (⏱ {elapsed}): {done}/{len(tasks)} task, "
            f"beacon={result.get('beacon_established')}, "
            f"persistence={result.get('persistence_installed')}, "
            f"creds={result.get('creds_found')}, "
            f"actions={result.get('actions_taken')}")
    notifier.info(f"⏱ Total engagement time: {elapsed}.")
    if result.get("beacon_established"):
        notifier.info("No automatic handoff from the swarm: open 'c2' -> "
                      "'beacons' to take charge of the callbacks.")
    else:
        notifier.warn("No beacon established: nothing to hand off. "
                      "Use 'c2' -> 'beacons' to monitor callbacks")


def print_agent_single_tail(result: dict, paths: dict, agent, goal: str,
                            started_wall: float, out_root: str) -> str:
    """Reporting tail for a single-target agent run: totals (deep ladder
    when goal=deep), report paths, learning receipt, checkpoint note.
    Returns the formatted elapsed string; the beacon handoff stays in the
    orchestrator."""
    elapsed = fmt_elapsed(time.time() - started_wall)
    if goal == "deep":
        st = result.get("stages") or {}
        ladder = " ".join(
            f"{k}={'✔' if st.get(k) else '—'}" for k in
            ("deliver", "post_exploit", "ad", "crack", "lateral"))
        notifier.success(
            f"Deep engagement complete (⏱ {elapsed}): "
            f"beacon={result.get('beacon_established')}, "
            f"persistence={result.get('persistence_installed')}, "
            f"system/root={result.get('system_privilege')}, "
            f"AD creds={result.get('ad_creds')}, "
            f"cracked={result.get('cracked_hashes')}, "
            f"lateral={result.get('lateral_movements')}, "
            f"actions={result.get('actions_taken')}")
        notifier.info(f"Stage ladder: {ladder}")
    else:
        notifier.success(
            f"Deliver complete (⏱ {elapsed}): beacon={result.get('beacon_established')}, "
            f"persistence={result.get('persistence_installed')}, "
            f"creds={result.get('creds_found')}, "
            f"victim_ips={result.get('victim_ips')}, "
            f"hypotheses={result.get('hypotheses')} "
            f"({result.get('hypotheses_confirmed')} confirmed), "
            f"actions={result.get('actions_taken')}")
    notifier.info("Report (raw operator + sanitized client):")
    print_report_paths(paths)
    # end-of-run LEARNING receipt: what this run recorded and what the
    # next one will do differently (the visible half of the loop)
    try:
        from phantom.automation.agent import experience_receipt
        notifier.info(experience_receipt(agent.experience))
    except Exception:
        pass
    notifier.info(f"⏱ Total engagement time: {elapsed}.")
    notifier.info(
        f"Checkpoint: {os.path.join(out_root, 'checkpoint.json')} — "
        "resume with `auto <target> --resume <file>` or share it "
        "with `export-session` (.pm)")
    return elapsed


def print_campaign_tail(campaign: dict, per_target: dict, cpaths: dict,
                        elapsed: str) -> str:
    """Reporting tail for a campaign run: totals + per-target/campaign
    report paths. `elapsed` is precomputed by the orchestrator (the clock
    stops when the last agent finishes, not when the reports are written).
    Returns the elapsed string."""
    notifier.success(
        f"Campaign complete (⏱ {elapsed}): {campaign.get('beacons')} beacon(s), "
        f"{campaign.get('persistent')} persistent, "
        f"{campaign.get('compromised_creds')} creds.")
    notifier.info(f"⏱ Total campaign time: {elapsed}.")
    notifier.info("Report (per-target + campaign):")
    for k, p in {**per_target, **cpaths}.items():
        console.print(f"  [cyan]{k}[/]: {p}")
    return elapsed
