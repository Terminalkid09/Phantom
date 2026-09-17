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
import os
import re
import tempfile
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
# `--oM` proposals run on their OWN budget: a markdown dossier costs no gate
# run and no lab, and spending the authored-capability budget on documents
# would starve the code path.
MAX_PROPOSALS_PER_DAY = 5
STATE_SCHEMA_VERSION = 2

# how a learning gap is closed
MODE_CODE = "code"          # the author writes a capability (LLM + gate + lab)
MODE_PROPOSAL = "proposal"  # `--oM`: a reviewed markdown dossier, no code
MODES = (MODE_CODE, MODE_PROPOSAL)

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
    """Small JSON state: daily counters + authored case bookkeeping.

    P1-3 hardening (was: read_text/write_text, last-writer-wins):
      * every save is temp-file + os.replace (a crash mid-write can no
        longer leave a torn/empty state file);
      * the read-check-write cycle runs under a cross-process file lock
        (same primitive as the audit log), so two AutoMode runs cannot
        both pass `can_gate()` and double-admit;
      * schema_version marks the file so future migrations are possible.
    """

    def __init__(self, path: Path = STATE_FILE) -> None:
        self.path = path
        self._lock = threading.Lock()   # intra-process
        self._d: Dict = {}
        self._load()

    # ── cross-process lock (msvcrt/fcntl, mirrors audit_log) ────────────

    def _locked_fd(self):
        """Acquire an exclusive advisory lock on a sidecar lock file; the
        state file itself is replaced atomically, so the lock lives on a
        stable sibling that never gets swapped under us."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            os.close(fd)
            raise
        return fd

    @staticmethod
    def _unlock_fd(fd: int) -> None:
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            os.close(fd)

    def _load(self) -> None:
        try:
            self._d = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(self._d, dict):
                self._d = {}
        except Exception:
            self._d = {}
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if self._d.get("day") != today:
            self._d = {"day": today, "gate_runs": 0, "prs": 0,
                       "proposals": 0,
                       "cases": self._d.get("cases", {}),
                       "authored": self._d.get("authored", {})}
        self._d.setdefault("schema_version", STATE_SCHEMA_VERSION)

    def _save(self) -> None:
        """Atomic persist: temp file + os.replace inside the caller's lock."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                dir=str(self.path.parent), prefix=".state-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(self._d, fh, indent=2)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.path)   # atomic on POSIX + Windows
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except OSError:
            pass

    def _locked(self, fn: Callable[[], object]) -> object:
        """Run fn under BOTH the thread lock and the cross-process lock,
        reloading from disk first so a sibling process's writes are seen."""
        with self._lock:
            fd = self._locked_fd()
            try:
                self._load()          # fresh read: no stale decisions
                result = fn()
                self._save()
                return result
            finally:
                self._unlock_fd(fd)

    # ── daily budgets (P1-4: atomic reservation, not check-then-act) ────

    def can_gate(self) -> bool:
        return self._d.get("gate_runs", 0) < MAX_GATE_RUNS_PER_DAY

    def count_gate(self) -> None:
        self._d["gate_runs"] = self._d.get("gate_runs", 0) + 1
        self._save()

    def reserve_gate_slot(self) -> bool:
        """Atomically claim one gate slot: returns False (and claims
        nothing) when the daily budget is exhausted. Replaces the old
        can_gate()-spawn-...-count_gate() window where N concurrent
        workers could all pass the check before any counted."""
        def _claim():
            if self._d.get("gate_runs", 0) >= MAX_GATE_RUNS_PER_DAY:
                return False
            self._d["gate_runs"] = self._d.get("gate_runs", 0) + 1
            return True
        return bool(self._locked(_claim))

    def can_pr(self) -> bool:
        return self._d.get("prs", 0) < MAX_PRS_PER_DAY

    def count_pr(self) -> None:
        self._d["prs"] = self._d.get("prs", 0) + 1
        self._save()

    def reserve_pr_slot(self) -> bool:
        """Atomic claim of one PR slot (same rationale as the gate slot)."""
        def _claim():
            if self._d.get("prs", 0) >= MAX_PRS_PER_DAY:
                return False
            self._d["prs"] = self._d.get("prs", 0) + 1
            return True
        return bool(self._locked(_claim))

    def reserve_proposal_slot(self) -> bool:
        """Atomically claim one PROPOSAL slot (separate budget from the
        authored-capability gate runs)."""
        def _claim():
            if self._d.get("proposals", 0) >= MAX_PROPOSALS_PER_DAY:
                return False
            self._d["proposals"] = self._d.get("proposals", 0) + 1
            return True
        return bool(self._locked(_claim))

    def proposals_today(self) -> int:
        return int(self._d.get("proposals", 0) or 0)

    def authorings(self, sig_hash: str) -> Dict:
        return self._d.setdefault("cases", {}).setdefault(
            sig_hash, {"attempts_total": 0, "successes": 0})

    def authored(self) -> Dict[str, str]:
        """sig_hash -> proposal id for every in-flight or successfully
        authored pattern (used for idempotence — never author the same
        gap twice)."""
        return self._d.setdefault("authored", {})

    def mark_authored(self, sig_hash: str, pid: str) -> None:
        """Reserve a pattern under the cross-process lock (two runs in
        different processes must not both reserve the same gap)."""
        def _mark():
            self.authored()[sig_hash] = pid
        self._locked(_mark)

    def clear_authored(self, sig_hash: str) -> None:
        """Release the reservation (authoring failed — a future run may
        retry with its dynamic attempt budget)."""
        def _clear():
            self.authored().pop(sig_hash, None)
        self._locked(_clear)

    def record_authoring(self, sig_hash: str, ok: bool) -> None:
        def _rec():
            c = self.authorings(sig_hash)
            c["attempts_total"] = c.get("attempts_total", 0) + 1
            if ok:
                c["successes"] = c.get("successes", 0) + 1
        self._locked(_rec)

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
                lab_ok: bool = True, mode: str = MODE_CODE,
                roster=None, cases: Optional[List] = None) -> List[str]:
    """Spawn background learning workers for the given patterns.
    Returns the ids spawned. NEVER blocks the caller.

    `mode=proposal` is the `--oM` path: no LLM and no lab are required
    (the artifact is a deterministic dossier), and it spends the PROPOSAL
    budget instead of the authored-capability budget.
    """
    state = state or EvolutionState()
    if mode not in MODES:
        mode = MODE_CODE
    proposal_mode = mode == MODE_PROPOSAL
    spawned: List[str] = []
    for pat in patterns:
        h = _sig_hash(pat)
        if _already_authoring(h, state):
            continue
        if not proposal_mode and not lab_ok:
            _emit_note(emit, "evolution skipped: lab unreachable "
                             "(no proof, no PR)")
            continue
        # P1-4: claim the slot ATOMICALLY before spawning — the old
        # can_gate()-check + count_gate()-after-run window let concurrent
        # workers over-admit past the daily budget
        budget_ok = (state.reserve_proposal_slot() if proposal_mode
                     else state.reserve_gate_slot())
        if not budget_ok:
            _emit_note(emit, ("evolution daily proposal budget exhausted"
                              if proposal_mode else
                              "evolution daily gate budget exhausted"))
            break
        pid = f"{datetime.now(timezone.utc).strftime('%Y%m%d')}-{h}"
        # reserve BEFORE spawning: two runs in the same session must never
        # author the same gap (the worker releases on failure)
        state.mark_authored(h, pid)
        th = threading.Thread(
            target=_worker,
            args=(pid, pat, advisor, state, emit),
            kwargs={"mode": mode, "roster": roster, "case": (cases or {}) and
                    next((c for c in (cases or [])
                          if getattr(c, "sig_hash", "") == h), None)},
            daemon=True, name=f"evolution-{h}")
        th.start()
        spawned.append(pid)
        _emit_note(emit, (f"evolution proposal drafted for pattern {h} "
                          f"({pid})" if proposal_mode else
                          f"evolution sub-agent spawned for pattern {h} "
                          f"(proposal {pid})"))
    return spawned


def _worker(pid: str, pat: Dict, advisor, state: EvolutionState,
            emit: Optional[Callable], mode: str = MODE_CODE,
            roster=None, case=None) -> None:
    from phantom.automation.evolution import publish as publish_mod

    h = pat.get("sig_hash") or _sig_hash(pat)
    if mode == MODE_PROPOSAL:
        _worker_proposal(pid, pat, state, emit, roster=roster, case=case)
        return

    from phantom.automation.evolution import author as author_mod
    from phantom.automation.evolution.sandbox import Sandbox

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

    # the gate slot was already reserved (and counted) at spawn time
    pub = publish_mod.publish(pid, result, state)
    if pub.ok:
        _emit_note(emit, f"evolution {pid}: {pub.detail}")
    else:
        _emit_note(emit, f"evolution {pid}: publish deferred — {pub.detail}")


def _worker_proposal(pid: str, pat: Dict, state: EvolutionState,
                     emit: Optional[Callable], roster=None, case=None) -> None:
    """`--oM`: write the dossier and offer it as a markdown-only PR.

    No LLM, no sandbox, no lab — the triage verdict already decided this is
    a capability-shaped gap, and the artifact is a document for a human.
    """
    from phantom.automation.evolution import publish as publish_mod
    from phantom.automation.evolution import proposal as proposal_mod
    from phantom.automation.brain.triage import Triage

    if case is None:
        try:
            triage = Triage(registry=_default_registry())
            case = triage.package(pat, case_id=pid, roster=roster,
                                  stall_class=str(pat.get("stall_class", "")))
        except Exception as exc:                 # noqa: BLE001
            state.clear_authored(pat.get("sig_hash", "") or pid)
            _emit_note(emit, f"evolution {pid}: triage failed ({exc})")
            return
    if not getattr(case, "proposes_code", False):
        # the triage verdict says this is NOT a capability gap: releasing
        # the reservation is the right outcome, and the reason is recorded
        state.clear_authored(case.sig_hash or pid)
        _emit_note(emit, f"evolution {pid}: no proposal — {case.verdict} "
                         f"({case.verdict_reason})")
        return
    res = proposal_mod.write_proposal(pid, case, emit=emit)
    if not res.ok:
        state.clear_authored(case.sig_hash or pid)
        _emit_note(emit, f"evolution {pid}: proposal not written ({res.error})")
        return
    pub = publish_mod.publish(pid, proposal_mod.as_author_result(res), state)
    if pub.ok:
        _emit_note(emit, f"evolution {pid}: {pub.detail}")
    else:
        _emit_note(emit, f"evolution {pid}: proposal kept local — "
                         f"{res.relpath} ({pub.detail})")


def _default_registry():
    """The capability registry, or None when the kit cannot be imported."""
    try:
        from phantom.automation.guidance.commands import make_registry
        return make_registry()
    except Exception:
        return None


def _emit_note(emit: Optional[Callable], detail: str) -> None:
    if emit is None:
        return
    try:
        emit("note", capability="evolution", detail=detail)
    except Exception:
        pass
