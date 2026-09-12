"""evolution/loop.py — trigger + orchestration for self-improvement.

Trigger (deterministic, not an LLM opinion): the experience engine's
`finish()` consolidation reports a STABLE failure pattern whose remedy
is NOT covered by any existing capability. Only then does the evolution
sub-agent spawn — in a background thread, so the main chain continues
(the main run never blocks on authoring).

Flow:
    stable pattern -> spawn worker -> author(write/gate/repair loop)
        -> gate-clean? -> publish (branch + PR) + mark beta-usable
        -> not clean?  -> postmortem only, case tagged authoring-failed

Governance baked in (agreed):
    * off by default; enabled with --evolution or flags evolution on
    * the lab must be reachable: no lab, no proof, no PR, no auto-load
    * daily budgets on gate runs and opened PRs (quota hygiene)
    * never edits engine code (sandbox enforces it mechanically)
"""

from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[3]
STATE_DIR = PROJECT_ROOT / "data" / "evolution"
STATE_FILE = STATE_DIR / "state.json"

MAX_GATE_RUNS_PER_DAY = 5
MAX_PRS_PER_DAY = 2

# cause classes the author should try to solve with a NEW capability
# (mirrors experience._AUTHORABLE_CAUSES — environmental causes such as
# dep-missing cannot be fixed by a capability file and are excluded)
AUTHORABLE_CAUSES = {"waf_blocked", "not_found", "unsupported"}


def _already_authoring(sig_hash: str, state: "EvolutionState") -> bool:
    """Idempotence: a pattern already authored (capability merged or
    beta-usable) must not spawn a second authoring worker. The state file
    keeps the sig -> proposal-id map exactly for this."""
    return sig_hash in state.authored()

try:  # quiet import for environments without the experience package
    from phantom.automation.brain.experience import cases as _cases
except Exception:  # pragma: no cover
    _cases = None


class EvolutionState:
    """Small JSON state: daily counters + authored case bookkeeping."""

    def __init__(self, path: Path = STATE_FILE) -> None:
        self.path = path
        self._d: Dict = {}
        self._load()

    def _load(self) -> None:
        try:
            self._d = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            self._d = {}
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if self._d.get("day") != today:
            self._d = {"day": today, "gate_runs": 0, "prs": 0,
                       "cases": self._d.get("cases", {})}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._d, indent=2),
                                 encoding="utf-8")
        except OSError:
            pass

    def can_gate(self) -> bool:
        return self._d.get("gate_runs", 0) < MAX_GATE_RUNS_PER_DAY

    def count_gate(self) -> None:
        self._d["gate_runs"] = self._d.get("gate_runs", 0) + 1
        self._save()

    def can_pr(self) -> bool:
        return self._d.get("prs", 0) < MAX_PRS_PER_DAY

    def count_pr(self) -> None:
        self._d["prs"] = self._d.get("prs", 0) + 1
        self._save()

    def authorings(self, sig_hash: str) -> Dict:
        return self._d.setdefault("cases", {}).setdefault(
            sig_hash, {"attempts_total": 0, "successes": 0})

    def authored(self) -> Dict[str, str]:
        """sig_hash -> proposal id for every in-flight or successfully
        authored pattern (used for idempotence — never author the same
        gap twice)."""
        return self._d.setdefault("authored", {})

    def mark_authored(self, sig_hash: str, pid: str) -> None:
        self.authored()[sig_hash] = pid
        self._save()

    def clear_authored(self, sig_hash: str) -> None:
        """Release the reservation (authoring failed — a future run may
        retry with its dynamic attempt budget)."""
        self.authored().pop(sig_hash, None)
        self._save()

    def record_authoring(self, sig_hash: str, ok: bool) -> None:
        c = self.authorings(sig_hash)
        c["attempts_total"] += 1
        if ok:
            c["successes"] += 1
        self._save()

    def author_success_rate(self, sig_hash: str) -> float:
        c = self.authorings(sig_hash)
        tot = c.get("attempts_total", 0)
        return (c.get("successes", 0) / tot) if tot else 0.0


def stable_uncovered_patterns(exp_result: Dict, wm,
                              registry) -> List[Dict]:
    """Patterns from experience.finish() that (a) are stable enough to
    learn from and (b) no existing capability covers the remedy fact."""
    out: List[Dict] = []
    for pat in exp_result.get("authorable", []):
        cause = pat.get("cause", "")
        if cause not in AUTHORABLE_CAUSES:
            continue
        fact = pat.get("missing_fact", "")
        if not fact:
            continue
        if any(fact in c.effects for c in registry.all()):
            continue  # covered: the planner can already chase this fact
        out.append(pat)
    return out


def _sig_hash(pat: Dict) -> str:
    # honour a caller-supplied sig_hash (the agent pins it before spawn so
    # the reservation and the worker agree on identity)
    if pat.get("sig_hash"):
        return str(pat["sig_hash"])
    raw = f"{pat.get('signature_summary', '')}|{pat.get('technique', '')}" \
          f"|{pat.get('cause', '')}"
    import hashlib
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:10]


def maybe_spawn(patterns: List[Dict], advisor, wm,
                emit: Optional[Callable] = None, state: EvolutionState = None,
                lab_ok: bool = True) -> List[str]:
    """Spawn background authoring workers for the given patterns.
    Returns the proposal ids spawned. NEVER blocks the caller."""
    state = state or EvolutionState()
    spawned: List[str] = []
    for pat in patterns:
        h = _sig_hash(pat)
        if _already_authoring(h, state):
            continue
        if not lab_ok:
            _emit_note(emit, "evolution skipped: lab unreachable "
                             "(no proof, no PR)")
            continue
        if not state.can_gate():
            _emit_note(emit, "evolution daily gate budget exhausted")
            break
        pid = f"{datetime.now(timezone.utc).strftime('%Y%m%d')}-{h}"
        # reserve BEFORE spawning: two runs in the same session must never
        # author the same gap (the worker releases on failure)
        state.mark_authored(h, pid)
        th = threading.Thread(
            target=_worker, args=(pid, pat, advisor, state, emit),
            daemon=True, name=f"evolution-{h}")
        th.start()
        spawned.append(pid)
        _emit_note(emit, f"evolution sub-agent spawned for pattern {h} "
                         f"(proposal {pid})")
    return spawned


def _worker(pid: str, pat: Dict, advisor, state: EvolutionState,
            emit: Optional[Callable]) -> None:
    from phantom.automation.evolution import author as author_mod
    from phantom.automation.evolution import publish as publish_mod
    from phantom.automation.evolution.sandbox import Sandbox

    h = pat.get("sig_hash") or _sig_hash(pat)
    case = dict(pat)
    case["sig_hash"] = h
    sb = Sandbox(pid)
    try:
        stats = {"author_success_rate": state.author_success_rate(h)}
        result = author_mod.author(pid, case, advisor, sandbox=sb,
                                   case_stats=stats)
    except author_mod.AuthorUnavailable as exc:
        _emit_note(emit, f"evolution {pid}: author unavailable ({exc})")
        return

    state.record_authoring(h, result.ok)
    if not result.ok:
        state.clear_authored(h)   # release: a future run may retry
        _emit_note(emit, f"evolution {pid}: authoring failed after "
                         f"{result.attempts} attempt(s) — postmortem in "
                         "docs/evolution/")
        return

    state.count_gate()  # the author loop already ran the gate per attempt
    pub = publish_mod.publish(pid, result, state)
    if pub.ok:
        _emit_note(emit, f"evolution {pid}: {pub.detail}")
    else:
        _emit_note(emit, f"evolution {pid}: publish deferred — {pub.detail}")


def _emit_note(emit: Optional[Callable], detail: str) -> None:
    if emit is None:
        return
    try:
        emit("note", capability="evolution", detail=detail)
    except Exception:
        pass
