"""stream_contract.py — ONE event vocabulary, ONE renderer.

The engagement engines emit ~40 event kinds. Three renderers consumed them
(CLI agent, CLI swarm, API/UI) and each knew a DIFFERENT subset: the CLI
rendered 12, the API 17, the swarm 2. Everything else was emitted and then
dropped at the display layer — including the stall diagnosis ("you are stuck
because X, change the angle to Y") and six failure sites. The engagement
looked like it had stopped reasoning because the reasoning never reached the
operator. That is the bug this module closes.

Contract:

* :data:`LEVELS` — ``info | success | warn | error | dim``. The CLI maps a
  level to a notifier call, the API to its log level. Text is PLAIN: styling
  belongs to the consumer, never to the event.
* :data:`EVENTS` — ``kind -> EventSpec`` (level, renderer, verbose_only,
  fields). ``fields`` names the structured extras a UI may keep.
* :func:`render_event` — ``(kind, data, verbose) -> Rendered | None``.
* An UNCLASSIFIED kind still renders, marked with its raw name, instead of
  disappearing. The fallback is a safety net, not a crutch: the invariant
  test asserts every kind the engines actually emit is classified here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

LEVELS = ("info", "success", "warn", "error", "dim")

# finding kinds whose VALUES must never leave the box: the `found` stream
# (CLI + persisted session mirror) carries summaries, never jars.
COOKIE_VALUE_KINDS = ("stolen_cookies", "cdp_cookies")


def safe_value(kind: str, value: Any) -> str:
    """Operator-visible value summary for a finding.

    Cookie jars stay local (WorldModel + gitignored session files): the
    stream only ever says HOW MANY. Everything else renders as the first
    values joined. ONE function so the agent, the swarm and any future
    emitter cannot drift apart on this again.
    """
    if kind in COOKIE_VALUE_KINDS:
        n = value.get("count", "?") if isinstance(value, dict) else "?"
        return f"{n} cookie(s) — values stay local"
    if isinstance(value, dict):
        return ", ".join(str(x) for x in list(value.values())[:3])
    return str(value)


def fact_line(kind: str, key: str, value: Any) -> str:
    """`kind:key = summary` — the one operator-visible form of a finding."""
    if not kind or not key:
        return ""
    summary = safe_value(kind, value)
    return f"{kind}:{key}" + (f" = {summary}" if summary else "")

# stealth badge per stealth level (shared by the CLI and the UI)
_STEALTH_BADGE = {"paranoid": "[paranoid]", "active": "[active]",
                  "aggressive": "[aggressive]"}


@dataclass
class Rendered:
    """One rendered event: a level, the lines to show, the structured extras."""
    kind: str
    level: str
    lines: List[str]
    fields: Dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    @property
    def head(self) -> str:
        """The one-line summary — what a UI log entry shows (the structured
        extras travel in `fields`); the CLI prints every line."""
        return self.lines[0] if self.lines else ""


@dataclass(frozen=True)
class EventSpec:
    level: str
    renderer: Callable[[Dict[str, Any]], List[str]]
    verbose_only: bool = False
    fields: Tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _tag(data: dict) -> str:
    target = data.get("target") or ""
    return f"[{target}] " if target else ""


def _clip(value: Any, limit: int = 200) -> str:
    text = str(value or "").replace("\n", " ").strip()
    return text[:limit]


def _first(*values: Any, limit: int = 200) -> str:
    for value in values:
        if value:
            return _clip(value, limit)
    return ""


def _found_parts(data: dict) -> List[str]:
    """``key = value`` per finding, degrading to the bare key when the emit
    site carried no value (the ``banner_ssh:`` the operator saw).

    Tolerant on purpose: a renderer must never degrade to the generic net
    because an emitter handed it an unexpected shape.
    """
    values = data.get("values")
    values = values if isinstance(values, dict) else {}
    parts = []
    for key in (data.get("findings") or [])[:6]:
        if not isinstance(key, str):
            key = str(key)
        value = values.get(key)
        parts.append(f"{key} = {_clip(value, 60)}" if value else key)
    return parts


def _hypotheses(data: dict) -> List[str]:
    out = []
    for h in data.get("hypotheses") or []:
        capability = h.get("capability") or h.get("capability_id") or "?"
        out.append(f"{capability} — {_clip(h.get('reason'), 120)}"
                   + (f" (prio {h.get('priority')})"
                      if h.get("priority") is not None else ""))
    return out


# ---------------------------------------------------------------------------
# renderers
# ---------------------------------------------------------------------------

def _r_run(d: dict) -> List[str]:
    name = d.get("banner") or d.get("capability") or "?"
    badge = _STEALTH_BADGE.get(d.get("stealth_level") or "", "")
    head = f"[▶] Running: {_tag(d)}{name}"
    if badge:
        head += f" {badge}"
    if d.get("cost") is not None:
        head += f" (cost {d.get('cost')})"
    lines = [head]
    if d.get("command"):
        lines.append(f"    $ {_clip(d.get('command'), 200)}")
    if d.get("reason"):
        lines.append(f"      why: {_clip(d.get('reason'), 180)}")
    return lines


def _r_found(d: dict) -> List[str]:
    capability = d.get("capability") or "?"
    parts = _found_parts(d)
    suffix = " (partial: salvaged from a timeout)" if d.get("partial") else ""
    return [f"[+] {_tag(d)}{capability}: {', '.join(parts) or 'no findings'}"
            f"{suffix}"]


def _r_plan(d: dict) -> List[str]:
    steps = d.get("steps") or []
    if not steps:
        return [f"[≡] {_tag(d)}Plan: goal reached or no path "
                f"({d.get('strategy') or '-'})"]
    shown = " -> ".join(steps[:8])
    more = f" …+{len(steps) - 8}" if len(steps) > 8 else ""
    return [f"[≡] {_tag(d)}Plan ({d.get('strategy') or 'generic'}): "
            f"{shown}{more}"]


def _r_inference(d: dict) -> List[str]:
    out = []
    for f in (d.get("findings") or [])[:4]:
        if not isinstance(f, dict):
            continue          # `found` uses a bare key list; never crash on it
        value = f.get("value")
        if isinstance(value, dict):
            detail = ", ".join(str(x) for x in list(value.values())[:3] if x)
        else:
            detail = _clip(value, 60)
        out.append(f"{f.get('kind')}:{f.get('key')}"
                   + (f" = {detail}" if detail else ""))
    return [f"[~] {_tag(d)}Inference: {'; '.join(out)}"] if out else []


def _r_reason(d: dict) -> List[str]:
    hypotheses = _hypotheses(d)[:3]
    return ([f"[?] {_tag(d)}Hypothesis: {'; '.join(hypotheses)}"]
            if hypotheses else [])


def _r_hypothesis(d: dict) -> List[str]:
    resolved = d.get("resolved") or []
    if not resolved:
        return []
    shown = "; ".join(f"{r.get('capability')} → {r.get('status')}"
                      for r in resolved[:6])
    return [f"[?] {_tag(d)}Closed: {shown}"]


def _r_stall(d: dict) -> List[str]:
    """The diagnosis: WHY the run is stuck and what class to try instead."""
    strategies = ", ".join(d.get("strategies") or []) or "-"
    return [f"[!] Stuck {_tag(d)}{d.get('stall') or 'stall'}: "
            f"{_clip(d.get('reason'), 160)} | try: {strategies}"
            + (f" | policy: {d.get('policy')}" if d.get("policy") else "")]


def _r_llm_command(d: dict) -> List[str]:
    decided = d.get("decided_by") or "auto-policy"
    why = d.get("reason") or ""
    return [f"[LLM] {decided} ran: $ {_clip(d.get('command'), 160)}"
            + (f" — {_clip(why, 100)}" if why else "")]


def _r_llm_refused(d: dict) -> List[str]:
    lines = [line for line in str(d.get("lines") or "").splitlines() if line]
    return lines or ["[LLM] the auto-gate refused the proposals"]


def _r_blocked(d: dict) -> List[str]:
    return [f"[!] Blocked {_tag(d)}{d.get('capability')}: "
            f"{_clip(d.get('reason'), 140)}"]


def _r_failed(d: dict) -> List[str]:
    reason = _first(d.get("reason"), d.get("output"), "execution failed")
    return [f"[ERROR] Failed: {_tag(d)}{d.get('capability')} — {reason}"]


def _r_error(d: dict) -> List[str]:
    return [f"[ERROR] {_tag(d)}{d.get('capability')}: "
            f"{_first(d.get('detail'), d.get('reason'), 'error')}"]


def _r_note(d: dict) -> List[str]:
    return [f"[~] {_tag(d)}{d.get('capability')}: "
            f"{d.get('detail') or 'no new findings'}"]


def _r_tool_missing(d: dict) -> List[str]:
    return [f"[!] {_tag(d)}{d.get('capability')}: missing tool(s) "
            f"{', '.join(d.get('tools') or [])}"]


def _r_deferred(d: dict) -> List[str]:
    return [f"[~] {_tag(d)}{d.get('capability')}: precondition not met yet"]


def _r_recover(d: dict) -> List[str]:
    return [f"[!] Recovery {d.get('recovery') or '?'} {_tag(d)}"
            f"{d.get('detail') or 're-arming failed capabilities'}"]


def _r_halt(d: dict) -> List[str]:
    lines = [f"[!] {_tag(d)}{d.get('reason') or 'stopped'}"]
    # WHY the goal was unreachable: the planner's rejected candidates carry
    # the concrete reason (stealth-gated / tool missing / already failed /
    # needs a fact that can no longer be produced). Without these the
    # operator only ever saw "no affordable path to goal".
    for r in (d.get("rejected") or [])[:4]:
        if not isinstance(r, dict):
            continue
        lines.append(
            f"    · {r.get('capability') or '?'} for '{r.get('fact') or '?'}'"
            f": {r.get('reason') or 'not chosen'}")
    if d.get("rejected_total"):
        lines.append(f"    ({d['rejected_total']} candidate(s) rejected in "
                     "total — `plan <goal>` shows the full list)")
    return lines


def _r_waiting(d: dict) -> List[str]:
    return [f"[~] {_tag(d)}{d.get('detail') or 'waiting for the human'}"
            + (f" ({d.get('remaining')}s left)"
               if d.get("remaining") is not None else "")]


def _r_success(d: dict) -> List[str]:
    return [f"[+] {_tag(d)}{d.get('detail') or 'step complete'}"]


def _r_done(d: dict) -> List[str]:
    bits = []
    for key in ("beacon_established", "persistence_installed",
                "system_privilege", "creds_found", "victim_ips",
                "lateral_movements", "cracked_hashes", "actions_taken"):
        if d.get(key) not in (None, 0, False):
            bits.append(f"{key}={d[key]}")
    stages = d.get("stages") or {}
    if isinstance(stages, dict) and stages:
        hit = ", ".join(k for k, v in stages.items() if v)
        if hit:
            bits.append(f"stages: {hit}")
    return [f"[+] Done {_tag(d)}{' | '.join(bits) or 'run finished'}"]


def _r_start(d: dict) -> List[str]:
    return [f"[▶] Start {_tag(d)}goal={d.get('goal') or '?'} "
            f"worker={d.get('worker') or 'lead'}"
            + (" [aggressive]" if d.get("aggressive") else "")]


def _r_stage(d: dict) -> List[str]:
    idx = d.get("index")
    total = d.get("total")
    where = f" ({idx}/{total})" if idx is not None and total else ""
    return [f"[≡] Stage{where} {_tag(d)}{d.get('stage') or '?'} — "
            f"{d.get('detail') or ('satisfied' if d.get('satisfied') else 'no move viable')}"]


def _r_resumed(d: dict) -> List[str]:
    return [f"[~] {_tag(d)}Resumed from {d.get('checkpoint') or '?'}"]


def _r_gate(d: dict) -> List[str]:
    return [f"[~] {_tag(d)}Gate '{d.get('fact')}' opened after "
            f"{d.get('waited')}s"]


def _r_shared(d: dict) -> List[str]:
    return [f"[~] {_tag(d)}Peer {d.get('kind')} learned from "
            f"{d.get('from_target') or 'a peer'}"]


def _r_llm(d: dict) -> List[str]:
    caps = [h.get("capability") or h.get("capability_id")
            for h in (d.get("hypotheses") or [])]
    caps = [c for c in caps if c]
    return [f"[~] {_tag(d)}LLM extra hypotheses (advisory, never authorized): "
            f"{', '.join(caps) or '-'}"]


def _r_llm_request(d: dict) -> List[str]:
    where = f" {_tag(d).strip()}" if _tag(d) else ""
    return [f"[!] LLM requested{where}: {_clip(d.get('reason'), 140)} "
            "(approve: POST /api/automode/llm {\"allow\": true})"]


def _r_llm_consult(d: dict) -> List[str]:
    return [f"[~] {_tag(d)}LLM consult ({d.get('state') or '?'}): "
            f"{d.get('count', 0)} validated suggestion(s)"]


def _r_beacon_up(d: dict) -> List[str]:
    return [f"[★] BEACON UP: {_tag(d)}{d.get('beacon_id') or ''}"]


def _r_unverified(d: dict) -> List[str]:
    """A capability ran but its declared postcondition was not observed.

    This is the single most important line in the whole stream: it is the
    difference between "the tool exited 0" and "the effect was proven". It has
    to READ as a caveat, not as decoration - an operator who skims the stream
    must not come away believing an unverified move succeeded.
    """
    cap = d.get("capability") or d.get("cap") or ""
    detail = str(d.get("detail") or "").strip()
    head = f"[!] Unverified{_tag(d)}"
    if cap:
        head += f": {cap}"
    return [f"{head} - {detail}" if detail else
            f"{head} - the declared effect was not observed"]


def _r_handoff(d: dict) -> List[str]:
    where = f" {_tag(d).strip()}" if _tag(d) else ""
    return [f"[★] Handoff{where}: beacon {d.get('beacon_id') or ''} is "
            "the operator's — no automatic cleanup"]


def _r_edge(d: dict) -> List[str]:
    return [f"[~] Edge {_tag(d)}{d.get('address')} -> "
            f"{d.get('provider') or 'origin unknown'} "
            f"(confidence {d.get('confidence')})"]


def _r_triage(d: dict) -> List[str]:
    return [f"[~] Triage {_tag(d)}{d.get('patterns') or 0} pattern(s), "
            f"{len(d.get('cases') or [])} case(s)"]


def _r_advice(d: dict) -> List[str]:
    return [f"[~] Advice {_tag(d)}"
            f"{_clip(d.get('recommendation') or d.get('reason'), 160)}"]


def _r_escalation(d: dict) -> List[str]:
    return [f"[!] Escalation {_tag(d)}"
            f"{_clip(d.get('reason') or d.get('detail') or d.get('kind'), 160)}"]


def _r_attack_graph(d: dict) -> List[str]:
    return [f"[~] Graph {_tag(d)}nodes={d.get('nodes', '?')} "
            f"edges={d.get('edges', '?')} "
            f"paths={d.get('paths', d.get('paths_to_domain', '?'))}"]


def _r_fuzz(d: dict) -> List[str]:
    families = ", ".join(d.get("families") or []) or "-"
    return [f"[~] Fuzz {_tag(d)}{d.get('requests', '?')} request(s), "
            f"{d.get('findings', 0)} finding(s), families: {families}"]


def _r_roster(d: dict) -> List[str]:
    cells = d.get("cells") or d.get("roster") or []
    names = [c.get("cell_id") if isinstance(c, dict) else str(c)
             for c in cells][:8]
    listed = ", ".join(n for n in names if n) or "cells bound"
    return [f"[~] Roster {_tag(d)}{listed}"]


def _r_stage_scope(d: dict) -> List[str]:
    return [f"[~] {_tag(d)}Stage '{d.get('stage')}' acting as "
            f"{d.get('acting_cap') or '?'} "
            f"({len(d.get('cells') or [])} cell(s))"]


def _r_cell_scope(d: dict) -> List[str]:
    cells = d.get("cells") or {}
    hidden = 0
    for c in cells.values():
        if isinstance(c, dict):
            hidden += int(c.get("hidden") or 0)
    return [f"[~] Cell scope {_tag(d)}{len(cells)} cell(s), "
            f"{d.get('shared_facts', '?')} shared fact(s), "
            f"{hidden} hidden from their cell"]


def _r_parallel_reasoning(d: dict) -> List[str]:
    return [f"[~] Parallel reasoning {_tag(d)}{d.get('threads', '?')} quiet "
            f"cell(s), consensus={d.get('consensus') or '-'}"]


def _r_plan_graph(d: dict) -> List[str]:
    return [f"[~] Plan graph {_tag(d)}{len(d.get('nodes') or [])} node(s), "
            f"{len(d.get('edges') or [])} edge(s), "
            f"critical={len(d.get('critical_path') or [])}"]


def _r_identity_field(d: dict) -> List[str]:
    """The identity FIELD DAG: what we know, and which field to widen first."""
    nodes = d.get("nodes") or []
    known = sum(1 for n in nodes if isinstance(n, dict) and n.get("known"))
    nxt = ", ".join(str(x) for x in (d.get("next") or [])) or "-"
    critical = ", ".join(str(x) for x in (d.get("critical_path") or [])) or "-"
    return [f"[~] {_tag(d)}Identity field graph: {len(nodes)} node(s) "
            f"({known} known), {len(d.get('edges') or [])} deduction(s) | "
            f"widen first: {nxt} | spine: {critical}"]


def _r_plan_variants(d: dict) -> List[str]:
    """B3: which plan variant won, and by how much."""
    scores = d.get("scores") or {}
    shown = ", ".join(f"{k}={v:.3f}" for k, v in
                      sorted(scores.items(), key=lambda kv: (-kv[1], kv[0])))
    head = (f"[≡] {_tag(d)}Plan variants -> {d.get('winner') or '?'} "
            f"({d.get('label') or '-'}): {d.get('rule') or '-'}")
    return [head] + ([f"    {shown}"] if shown else [])


def _r_cadence(d: dict) -> List[str]:
    return [f"[~] Cadence {_tag(d)}{d.get('phase')}: attempt "
            f"{d.get('attempt')} delivered={d.get('delivered')} — "
            f"{_clip(d.get('detail'), 140)}"]


def _r_pin(d: dict) -> List[str]:
    return [f"[~] {_tag(d)}Job fingerprint pinned "
            f"({', '.join(f'{k}={v}' for k, v in list(d.items())[:3])})"]


def _r_experience(d: dict) -> List[str]:
    return [f"[~] Experience {_tag(d)}"
            f"{', '.join(f'{k}={v}' for k, v in list(d.items())[:4])}"]


def _r_learning_receipt(d: dict) -> List[str]:
    return [f"[brain] {_clip(d.get('detail'), 300)}"]


def _r_sandbox(d: dict) -> List[str]:
    return [f"[~] Sandbox {_tag(d)}{d.get('capability')}: "
            f"{d.get('detail') or 'pre-flight'}"
            + (f" (sample {d.get('sample')})" if d.get("sample") else "")]


_HYP_MARK = {"proposed": "[?]", "probing": "[?]",
             "confirmed": "[+]", "refuted": "[ERROR]"}


def _r_hypothesis_lifecycle(d: dict, verb: str) -> List[str]:
    return [f"{_HYP_MARK.get(verb, '[?]')} {_tag(d)}Hypothesis {verb} "
            f"{d.get('id') or '?'} "
            f"({_clip(d.get('chain'), 100) or d.get('goal') or '-'})"
            + (f" confidence={d.get('confidence')}"
               if d.get("confidence") is not None else "")
            + (f" — {_clip(d.get('reason'), 120)}" if d.get("reason") else "")]


def _r_hunt_probe(d: dict) -> List[str]:
    """Behavioural hunt probe line: what was sent and what it revealed."""
    req = d.get("request") or {}
    return [f"[~] {_tag(d)}{req.get('probe', '')} "
            f"{req.get('method', 'GET')} {req.get('path', '')} "
            f"→ {req.get('signals', '')}".replace("  ", " ").strip()]


def _r_swarm_task(d: dict) -> List[str]:
    if d.get("ok"):
        return [f"[+] Swarm {_tag(d)}{d.get('task')}: "
                f"+{d.get('staged', 0)} finding(s) committed"]
    return [f"[!] Swarm {_tag(d)}{d.get('task')}: no provides "
            f"({d.get('staged', 0)} staged)"]


def _r_swarm_found(d: dict) -> List[str]:
    """What each swarm task actually produced — the detail `--verbose`
    used to promise and never deliver on the swarm path."""
    rows = [str(x) for x in (d.get("findings") or []) if str(x)]
    head = (f"[~] Swarm {_tag(d)}{d.get('task')}: "
            f"{len(rows)} staged fact(s)")
    return [head] + [f"      - {r}" for r in rows[:20]]


def _r_decision(d: dict) -> List[str]:
    """One arbitrated move: the lens that drove it and by how much."""
    return [f"[~] {_tag(d)}Decision {_clip(d.get('detail'), 200)}"]


def _r_contradiction(d: dict) -> List[str]:
    """A probe measured something the model REFUSED to believe.

    The belief revision kept the stronger stored value, so the move learned
    nothing new — but the operator has to see that the differential fired,
    otherwise it is indistinguishable from "the probe found nothing".
    """
    return [f"[!] {_tag(d)}Contradiction on {d.get('finding') or '?'}: "
            f"kept '{_clip(d.get('stored'), 80)}' over "
            f"'{_clip(d.get('value'), 80)}' "
            f"(stored confidence {d.get('confidence')})"]


def _r_degraded(d: dict) -> List[str]:
    return [f"[!] {_tag(d)}reasoning degraded: "
            f"{d.get('layer') or 'layer'} unavailable "
            f"({_clip(d.get('detail'), 140)}) — fell back to raw priority"]


def _r_worker(d: dict) -> List[str]:
    """Sub-agent lifecycle: queued -> started -> finished."""
    phase = str(d.get("phase") or "?")
    who = d.get("worker") or d.get("target") or "?"
    if phase == "queued":
        return [f"[~] sub-agent {who} queued (pool of "
                f"{d.get('pool', '?')} slots)"]
    if phase == "start":
        return [f"[>] sub-agent {who} started "
                f"({d.get('role') or 'lead'}, "
                f"{d.get('workers', 1)} worker(s)) "]
    return [f"[+] sub-agent {who} finished in {d.get('seconds', '?')}s: "
            f"{d.get('actions', 0)} action(s), "
            f"{d.get('failures', 0)} failure(s), "
            f"{'goal met' if d.get('goal_met') else 'goal NOT met'}"]


def _r_gap(d: dict) -> List[str]:
    hints = ", ".join(d.get("hints") or []) or "-"
    policy = d.get("policy") or ""
    # on a thin surface the "missing fact" is the surface itself, and the
    # PROFILE (not the learned gap) chose the families below
    missing = d.get("missing") or ("a surface" if policy else "?")
    return [f"[~] {_tag(d)}GAP after {d.get('failed', 0)} failure(s)"
            f"{' [' + str(d.get('stall')) + ']' if d.get('stall') else ''}"
            f"{' [thin surface: ' + str(policy) + ']' if policy else ''}: "
            f"what is still worth trying is '{missing}' "
            f"-> re-arming {hints}"]


def _r_generic(d: dict) -> List[str]:
    """Safety net: never drop an event. Prefer any human field the emitter
    provided, and always show the raw kind so an unclassified event is
    visible as unclassified instead of silent."""
    human = _first(d.get("detail"), d.get("reason"), d.get("message"),
                   d.get("text"), d.get("output"))
    capability = d.get("capability") or d.get("capability_id")
    parts = [p for p in (capability, human) if p]
    return [f"[?] {_tag(d)}{' — '.join(parts) or '(unclassified event)'}"]


# ---------------------------------------------------------------------------
# the registry
# ---------------------------------------------------------------------------

EVENTS: Dict[str, EventSpec] = {
    # progress / lifecycle
    "start": EventSpec("info", _r_start),
    "stage": EventSpec("info", _r_stage),
    "run": EventSpec("info", _r_run,
                     fields=("command", "reason", "stealth",
                             "capability", "banner")),
    "plan": EventSpec("info", _r_plan, fields=("strategy",)),
    "decision": EventSpec("dim", _r_decision, verbose_only=True,
                         fields=("capability", "driver", "stage")),
    "resumed": EventSpec("info", _r_resumed),
    "waiting": EventSpec("info", _r_waiting),
    "beacon_up": EventSpec("success", _r_beacon_up, fields=("beacon_id",)),
    "handoff": EventSpec("info", _r_handoff, fields=("beacon_id",)),
    # Emitted by agent.py when a capability ran but its declared postcondition
    # was not observed. It had no renderer, so it fell through to the generic
    # "[?]" line - which made the most consequential event in the stream the
    # least legible one, and kept the event-vocabulary gate red so any NEW
    # kind could ship unclassified.
    "unverified": EventSpec("warn", _r_unverified,
                            fields=("capability", "detail")),
    "success": EventSpec("success", _r_success),
    "done": EventSpec("success", _r_done),
    "sandbox": EventSpec("dim", _r_sandbox, verbose_only=True),
    "cadence": EventSpec("dim", _r_cadence, verbose_only=True),

    # findings / reasoning
    "found": EventSpec("success", _r_found, fields=("capability",)),
    "note": EventSpec("dim", _r_note, fields=("capability",)),
    "inference": EventSpec("dim", _r_inference, verbose_only=True),
    "reason": EventSpec("dim", _r_reason, verbose_only=True),
    "hypothesis": EventSpec("dim", _r_hypothesis, verbose_only=True),
    "hypothesis_proposed": EventSpec(
        "dim", lambda d: _r_hypothesis_lifecycle(d, "proposed"),
        verbose_only=True),
    "hypothesis_probing": EventSpec(
        "dim", lambda d: _r_hypothesis_lifecycle(d, "probing"),
        verbose_only=True),
    "hypothesis_confirmed": EventSpec(
        "success", lambda d: _r_hypothesis_lifecycle(d, "confirmed"),
        verbose_only=True),
    "hypothesis_refuted": EventSpec(
        "error", lambda d: _r_hypothesis_lifecycle(d, "refuted"),
        verbose_only=True),
    "stall": EventSpec("warn", _r_stall, fields=("stall", "strategies")),
    "contradiction": EventSpec("warn", _r_contradiction,
                              fields=("capability", "finding", "stored")),
    "advice": EventSpec("dim", _r_advice, verbose_only=True),
    "escalation": EventSpec("warn", _r_escalation),
    "llm": EventSpec("dim", _r_llm, verbose_only=True),
    "llm_request": EventSpec("warn", _r_llm_request),
    "llm_consult": EventSpec("dim", _r_llm_consult, verbose_only=True),
    # the model's CONCRETE commands, decided by the deterministic auto-gate:
    # the operator must be able to see afterwards what the run executed on its
    # own, and what it refused to execute and why (`fields` keeps both).
    "llm_command": EventSpec("success", _r_llm_command,
                             fields=("command", "reason", "decided_by")),
    "llm_command_empty": EventSpec("warn", _r_llm_command,
                                  fields=("command", "reason")),
    "llm_refused": EventSpec("warn", _r_llm_refused, fields=("lines",)),

    # structure / cells
    "roster": EventSpec("dim", _r_roster, verbose_only=True),
    "stage_scope": EventSpec("dim", _r_stage_scope, verbose_only=True),
    "cell_scope": EventSpec("dim", _r_cell_scope, verbose_only=True),
    "parallel_reasoning": EventSpec("dim", _r_parallel_reasoning,
                                    verbose_only=True),
    "plan_graph": EventSpec("dim", _r_plan_graph, verbose_only=True),
    "plan_variants": EventSpec("dim", _r_plan_variants, verbose_only=True,
                              fields=("winner", "rule", "scores")),
    "identity_field": EventSpec("dim", _r_identity_field,
                               verbose_only=True,
                               fields=("next", "critical_path", "nodes")),
    "gate": EventSpec("dim", _r_gate),
    "shared": EventSpec("dim", _r_shared, verbose_only=True),
    "pin": EventSpec("dim", _r_pin, verbose_only=True),
    "experience": EventSpec("dim", _r_experience, verbose_only=True),
    "learning_receipt": EventSpec("info", _r_learning_receipt),
    "fuzz_complete": EventSpec("dim", _r_fuzz, verbose_only=True),
    "edge": EventSpec("dim", _r_edge, verbose_only=True),
    "triage": EventSpec("dim", _r_triage, verbose_only=True),
    "hunt_probe": EventSpec("dim", _r_hunt_probe, verbose_only=True),
    "attack_graph": EventSpec("dim", _r_attack_graph, verbose_only=True),

    # failures / refusals
    "failed": EventSpec("error", _r_failed, fields=("capability",)),
    "error": EventSpec("error", _r_error, fields=("capability",)),
    "blocked": EventSpec("warn", _r_blocked, fields=("capability",)),
    "tool_missing": EventSpec("warn", _r_tool_missing, fields=("capability",)),
    "deferred": EventSpec("dim", _r_deferred, fields=("capability",)),
    "recover": EventSpec("warn", _r_recover),
    # `rejected`/`goal` are part of the payload, not just rendered text: the
    # UI needs the structured why (which capability, which fact, which
    # reason) to show a halt that is actionable instead of a dead end.
    "halt": EventSpec("warn", _r_halt,
                      fields=("goal", "rejected", "rejected_total",
                              "stale")),
    "degraded": EventSpec("warn", _r_degraded,
                          fields=("layer", "capability")),
    "gap": EventSpec("info", _r_gap,
                     fields=("missing", "goal", "hints", "policy")),
    "worker": EventSpec("info", _r_worker,
                        fields=("worker", "phase", "role", "goal_met")),

    # swarm
    "task_target": EventSpec("info", _r_swarm_task, fields=("task", "target")),
    "task_found": EventSpec("dim", _r_swarm_found, verbose_only=True),
}


def render_event(kind: str, data: Optional[dict] = None,
                 verbose: bool = False) -> Optional[Rendered]:
    """Render one event for BOTH the CLI and the API/UI.

    Returns None only when the kind is registered as verbose-only and the
    stream is not verbose. An unregistered kind renders through the generic
    safety net (marked ``[?]``) so nothing is ever dropped silently.
    """
    data = dict(data or {})
    spec = EVENTS.get(kind)
    if spec is None:
        spec = EventSpec("dim", _r_generic)
    elif spec.verbose_only and not verbose:
        return None
    try:
        lines = [line for line in spec.renderer(data) if line]
    except Exception as exc:      # a renderer must never break an engagement
        lines = [f"[?] {kind}: unrenderable event ({type(exc).__name__})"]
    if not lines:
        return None
    fields = {name: data.get(name) for name in spec.fields
              if data.get(name) is not None}
    # the UI reads the badge as `stealth`; the engine emits `stealth_level`
    if data.get("stealth_level"):
        fields["stealth"] = data["stealth_level"]
    return Rendered(kind=kind, level=spec.level, lines=lines, fields=fields)
