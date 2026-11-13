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


def _ai_last_call() -> str:
    """The newest AI-plane call, in one sentence: model, phase, verdict.

    `--ai integrated` routes every phase through `ai.router.ask`, which writes
    one telemetry line per call. Reading it back is what lets the report say
    "the model was asked and answered" instead of implying it.
    """
    try:
        import json
        from phantom.automation.ai import telemetry
        path = telemetry.telemetry_path()
        if not path.exists():
            return "no model call was ever recorded"
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-5:]
        for line in reversed(lines):
            try:
                row = json.loads(line)
            except ValueError:
                continue
            when = time.strftime("%H:%M:%S", time.localtime(float(row.get("ts", 0))))
            verdict = ("schema ok" if row.get("schema_ok")
                       else f"failed: {row.get('error') or 'no schema'}")
            return (f"last model call {when} phase={row.get('phase')} "
                    f"model={row.get('model') or '?'} ({verdict})")
        return "no model call was ever recorded"
    except Exception as exc:
        return f"telemetry unreadable ({exc})"


def ai_participation(agent) -> str:
    """Did a model take part in this run, and could it have changed it?

    TWO different AI paths exist and they are not the same feature:

    * ``--ai integrated|local|cloud`` — the trained per-phase planes
      (`phantom.automation.ai`), Qwen-based, each phase with its own adapter.
      This is the one an "AI run" means; it is OFF unless configured.
    * the local GGUF advisor (`--llm`) — a separate, non-gating suggester.

    A lab run with the AI on and one with it off produced the same result. The
    honest answer is usually that no model call was made at all — the plane
    was off, or integrated had no promoted manifest and fell back to an
    endpoint nobody was serving — and in that case both runs ARE the same
    deterministic plan. This line is the difference between "the model
    reasoned and agreed" and "the model was never asked".
    """
    parts = []
    try:
        from phantom.automation.ai import config as ai_config
        active = {p: ai_config.mode(p) for p in ai_config.PHASES
                  if ai_config.mode(p) != "off"}
    except Exception as exc:
        active, parts = {}, [f"AI: plane not importable ({exc})"]
    if not parts:
        if not active:
            parts.append("AI: OFF (ai.mode=off) — the deterministic plan, by "
                         "design")
        else:
            parts.append("AI: " + ", ".join(
                f"{p}={m}" for p, m in sorted(active.items())))
            parts.append(_ai_last_call())

    arbiter = getattr(getattr(agent, "planner", None), "arbiter", None)
    if arbiter is not None:
        try:
            summary = arbiter.summary()
            # `accepted/rejected` alone reads as "the model had no effect"
            # even when it was never asked. `asked` and `proposals` separate
            # "consulted and abstained" from "consulted and agreed", and
            # `abstained` makes a silent run visible (measured 2026-11-08:
            # the live line said only "0 accepted / 0 rejected / 0 changed"
            # while telemetry named the missing planner manifest).
            parts.append(
                f"arbiter: {summary.get('asked', 0)} asked / "
                f"{summary.get('proposals', 0)} proposal(s) / "
                f"{summary.get('accepted', 0)} accepted / "
                f"{summary.get('rejected', 0)} rejected / "
                f"{summary.get('changed', 0)} changed / "
                f"{summary.get('abstained', 0)} abstained — "
                f"{summary.get('note', '')}")
        except Exception as exc:
            parts.append(f"arbiter: unreadable ({exc})")

    advisor = getattr(agent, "llm_advisor", None)
    if advisor is not None and getattr(advisor, "enabled", False):
        parts.append(_advisor_line(advisor))
    return " · ".join(parts)


def _advisor_line(advisor) -> str:
    """The separate `--llm` advisor's contribution, or why there was none."""

    def _count(name: str) -> int:
        # an agent double in a test (or a partial advisor) may not carry the
        # counters at all: "unknown" must read as 0 here, never as a crash at
        # the very end of a finished engagement.
        try:
            return int(getattr(advisor, name, 0) or 0)
        except (TypeError, ValueError):
            return 0

    calls = _count("calls")
    accepted = _count("accepted")
    if calls == 0:
        reason = str(getattr(advisor, "_error", "") or "no model backend")
        return (f"advisor (--llm): enabled but it never called a model "
                f"({reason}) — no suggestion reached the planner")
    return (f"advisor (--llm): consulted {calls} time(s), {accepted} "
            "suggestion(s) front-loaded into the planner's order")


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
    notifier.info(ai_participation(agent))
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
