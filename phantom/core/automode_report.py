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
    tdir = os.path.join(out_root, safe_target_dir(target))
    return tdir, ReportWriter(tdir).write(
        raw, ClientReport.from_agent(agent, profile))


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
        notifier.warn(f"Swarm summary non salvato: {exc}")
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
    print_report_paths(paths)
    # end-of-run LEARNING receipt: what this run recorded and what the
    # next one will do differently (the visible half of the loop)
    try:
        from phantom.automation.agent import experience_receipt
        notifier.info(experience_receipt(agent.experience))
    except Exception:
        pass
    notifier.info(f"⏱ Tempo totale engagement: {elapsed}.")
    notifier.info(
        f"Checkpoint: {os.path.join(out_root, 'checkpoint.json')} — "
        "riprendi con `auto <target> --resume <file>` o condividi "
        "con `export-session` (.pm)")
    return elapsed


def print_campaign_tail(campaign: dict, per_target: dict, cpaths: dict,
                        elapsed: str) -> str:
    """Reporting tail for a campaign run: totals + per-target/campaign
    report paths. `elapsed` is precomputed by the orchestrator (the clock
    stops when the last agent finishes, not when the reports are written).
    Returns the elapsed string."""
    notifier.success(
        f"Campaign completata (⏱ {elapsed}): {campaign.get('beacons')} beacon, "
        f"{campaign.get('persistent')} persistenti, "
        f"{campaign.get('compromised_creds')} creds.")
    notifier.info(f"⏱ Tempo totale campagna: {elapsed}.")
    notifier.info("Report (per-target + campaign):")
    for k, p in {**per_target, **cpaths}.items():
        console.print(f"  [cyan]{k}[/]: {p}")
    return elapsed
