"""llm_proposals.py — the model may PROPOSE commands; only the operator decides.

The advisor was deliberately non-gating for *capability preferences*: it picked
ids, the planner ranked them, no harm done. Concrete COMMANDS are a different
kind of object. A command is executed, so the model must never be able to reach
the executor on its own. The contract this module enforces is exactly the one
the design asked for:

    the model proposes  ->  a human accepts or refuses
                        ->  ONLY an accepted proposal is executed,
                            and it is executed through the SAME gated path
                            as any operator command (scope, safe target,
                            tool availability).

Nothing here executes anything by itself. `propose()` only queues, `accept()`
only changes a state, and `execute()` refuses anything that is not accepted and
then delegates to the project's executor (`phantom.core.executor.run_command`),
which is where scope/stealth actually live. A test pins that delegation, so the
queue can never grow a private execution path that skips the gate.

`static_reject()` is HYGIENE, not security: it drops an empty proposal, one with
embedded newlines (a proposal is ONE command) and an absurdly long one. The
security boundary is the executor, and pretending otherwise would be worse than
not checking at all — so the check is narrow and documented as such.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

MAX_PROPOSALS = 100
MAX_COMMAND_LEN = 500

# best-effort host extraction for the scope pre-check (see `out_of_scope_hosts`)
_HOST_TOKEN = re.compile(
    r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,24})\b")
# tokens that LOOK like hosts but are file names in practice: checked anyway
# (fail-closed), listed here so the exclusion is a decision, not an accident
_FILE_EXT = ("txt", "json", "log", "csv", "xml", "yaml", "yml", "html",
             "list", "conf", "ini", "md", "c", "cpp", "h", "py", "sh",
             "ps1", "exe", "bin", "gguf", "db", "sqlite", "pem", "key",
             "crt", "zip", "gz", "tar", "png", "jpg", "pdf", "docx",
             "xlsx", "pcap", "sh", "service", "local", "internal")

PENDING = "pending"
ACCEPTED = "accepted"
REFUSED = "refused"
STATES = (PENDING, ACCEPTED, REFUSED)


def static_reject(command: str) -> str:
    """Return the reason a proposal is not even worth queueing, or ''.

    Hygiene only (see the module docstring): emptiness, newlines, length.
    """
    cmd = (command or "").strip()
    if not cmd:
        return "empty"
    if "\n" in cmd or "\r" in cmd:
        return "multi-line"
    if len(cmd) > MAX_COMMAND_LEN:
        return "too-long"
    return ""


def hosts_in_command(command: str) -> List[str]:
    """Every token in the command that looks like a host or an IP.

    Deliberately naive and over-inclusive: a false positive makes the gate
    refuse a proposal (fail-closed, the right direction for an authorization
    check). Tokens whose last label is a well-known file extension are skipped,
    because `.txt` is not a TLD however much it looks like one.
    """
    out: List[str] = []
    for match in _HOST_TOKEN.finditer(command or ""):
        token = match.group(0)
        if "." in token:
            last = token.rsplit(".", 1)[-1].lower()
            if last in _FILE_EXT:
                continue
        if token not in out:
            out.append(token)
    return out


def out_of_scope_hosts(command: str, scope_list, *, check=None) -> List[str]:
    """Hosts named INSIDE a proposed command that are not in scope.

    The executor gates on the SESSION target, so a proposed command whose own
    arguments name a different host would be checked only against that session
    target and could name anything. This closes that gap on the model surface:
    the proposal's own arguments are verified before it runs. Returns [] when no
    scope is declared (nothing to check against) or when everything is in
    scope.
    """
    if not scope_list:
        return []
    if check is None:
        from phantom.core.scope import is_in_scope as check  # type: ignore
    bad: List[str] = []
    for host in hosts_in_command(command):
        try:
            ok = bool(check(host, list(scope_list)))
        except Exception:
            ok = False  # an unresolvable host is not an authorization
        if not ok:
            bad.append(host)
    return bad


@dataclass
class Proposal:
    """One command the model suggested, and its operator verdict."""

    id: int
    ts: str
    command: str
    why: str = ""
    source: str = "llm"
    agent: str = ""
    state: str = PENDING
    decided_by: str = ""
    decision_reason: str = ""
    executed: bool = False
    result_ok: Optional[bool] = None
    result_excerpt: str = ""

    # -------------------------------------------------------------- helpers

    @property
    def pending(self) -> bool:
        return self.state == PENDING

    @property
    def accepted(self) -> bool:
        return self.state == ACCEPTED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "ts": self.ts, "command": self.command,
            "why": self.why, "source": self.source, "agent": self.agent,
            "state": self.state, "decided_by": self.decided_by,
            "decision_reason": self.decision_reason,
            "executed": self.executed, "result_ok": self.result_ok,
            "result_excerpt": self.result_excerpt,
        }


class ProposalQueue:
    """Bounded, thread-free queue of model command proposals.

    Thread-free on purpose: the accept decision is an operator action, and the
    whole point is that exactly one human reads each proposal. Keeping it free
    of locks also keeps it trivially testable.
    """

    def __init__(self, max_proposals: int = MAX_PROPOSALS) -> None:
        self.max_proposals = max_proposals
        self._items: List[Proposal] = []
        self._next_id = 1
        self.proposed = 0
        self.rejected_static = 0

    # ------------------------------------------------------------- propose

    def propose(self, *, command: str, why: str = "", source: str = "llm",
                agent: str = "") -> Optional[Proposal]:
        """Queue ONE proposal. Returns None when hygiene drops it."""
        cmd = (command or "").strip()
        reason = static_reject(cmd)
        if reason:
            self.rejected_static += 1
            return None
        prop = Proposal(
            id=self._next_id,
            ts=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
            command=cmd,
            why=(why or "").strip()[:400],
            source=source,
            agent=agent,
        )
        self._next_id += 1
        self.proposed += 1
        self._items.append(prop)
        if len(self._items) > self.max_proposals:
            # capacity pressure evicts the OLDEST DECIDED proposal first (its
            # verdict is already in the journal) and only then the oldest
            # pending one: the queue is the operator's action list, and an
            # undecided item silently disappearing is the thing to avoid.
            pending = [p for p in self._items if p.pending]
            decided = [p for p in self._items if not p.pending]
            room = max(self.max_proposals - len(pending), 0)
            keep = pending + (decided[-room:] if room else [])
            self._items = sorted(keep[-self.max_proposals:], key=lambda p: p.id)
        return prop

    # ---------------------------------------------------------------- views

    def all(self) -> List[Proposal]:
        return list(self._items)

    def pending(self) -> List[Proposal]:
        return [p for p in self._items if p.pending]

    def get(self, proposal_id: int) -> Optional[Proposal]:
        for prop in self._items:
            if prop.id == proposal_id:
                return prop
        return None

    def stats(self) -> Dict[str, int]:
        return {
            "proposed": self.proposed,
            "pending": len(self.pending()),
            "accepted": sum(1 for p in self._items if p.state == ACCEPTED),
            "refused": sum(1 for p in self._items if p.state == REFUSED),
            "executed": sum(1 for p in self._items if p.executed),
            "static_rejected": self.rejected_static,
        }

    # ------------------------------------------------------------- decide

    def accept(self, proposal_id: int, *, decided_by: str = "operator"
               ) -> Tuple[bool, str]:
        """Move a proposal to ACCEPTED. Does NOT execute (see `execute`)."""
        prop = self.get(proposal_id)
        if prop is None:
            return False, f"unknown proposal #{proposal_id}"
        if not prop.pending:
            return False, (f"proposal #{proposal_id} is already {prop.state} "
                           f"({prop.decided_by or 'operator'})")
        prop.state = ACCEPTED
        prop.decided_by = decided_by
        prop.decision_reason = ""
        return True, f"accepted #{proposal_id}: {prop.command}"

    def refuse(self, proposal_id: int, reason: str = "",
               *, decided_by: str = "operator") -> Tuple[bool, str]:
        """Move a proposal to REFUSED, with the operator's reason."""
        prop = self.get(proposal_id)
        if prop is None:
            return False, f"unknown proposal #{proposal_id}"
        if not prop.pending:
            return False, (f"proposal #{proposal_id} is already {prop.state} "
                           f"({prop.decided_by or 'operator'})")
        prop.state = REFUSED
        prop.decided_by = decided_by
        prop.decision_reason = (reason or "").strip()[:200]
        return True, f"refused #{proposal_id}: {prop.command}"

    def record_result(self, proposal_id: int, *, ok: bool,
                      excerpt: str = "") -> None:
        prop = self.get(proposal_id)
        if prop is None:
            return
        prop.executed = True
        prop.result_ok = bool(ok)
        prop.result_excerpt = (excerpt or "")[:400]

    def clear(self) -> int:
        """Empty the queue AND its counters (a full reset, as `llm clear`)."""
        n = len(self._items)
        self._items = []
        self._next_id = 1
        self.proposed = 0
        self.rejected_static = 0
        return n

    # -------------------------------------------------------------- render

    def render(self, limit: int = 20) -> str:
        """Plain-text operator view: what the model wanted, and the verdict."""
        if not self._items:
            return "no model command proposals"
        rows = self._items[-limit:] if limit else self._items
        lines = [f"llm proposals: {len(rows)} of {len(self._items)}"
                 f"   (pending: {len(self.pending())})"]
        for prop in rows:
            mark = {"pending": "PENDING ", "accepted": "ACCEPTED",
                    "refused": "REFUSED "}.get(prop.state, prop.state.upper())
            lines.append(f"  #{prop.id} [{mark}] $ {prop.command}")
            if prop.why:
                lines.append(f"      model: {prop.why}")
            if prop.state == REFUSED and prop.decision_reason:
                lines.append(f"      operator: {prop.decision_reason}")
            if prop.executed:
                verdict = "ok" if prop.result_ok else "failed/refused"
                lines.append(f"      executed: {verdict}")
                for line in (prop.result_excerpt or "").splitlines()[:3]:
                    lines.append(f"        | {line[:160]}")
        return "\n".join(lines)


def execute(prop: Proposal, *, target: str = "", runner=None,
            status=None, scope=None) -> str:
    """Run an ACCEPTED proposal through the project's gated executor.

    Returns the command output ('' when refused). A proposal that was not
    accepted is never run: this is the single place that could bypass the
    operator, so it checks the state itself and does not trust its callers.

    `scope`, when given, is the engagement scope: hosts named inside the
    command that are not in it abort the run BEFORE the executor is reached
    (see `out_of_scope_hosts`).
    """
    if prop is None or prop.state != ACCEPTED:
        return ""
    if scope and out_of_scope_hosts(prop.command, scope):
        return ""
    if runner is None:
        from phantom.core import executor as _executor
        runner = _executor.run_command
    try:
        return runner(prop.command, target, status=status) or ""
    except Exception:
        return ""


queue = ProposalQueue()


def render(limit: int = 20) -> str:
    return queue.render(limit)


def pending_as_dicts() -> List[Dict[str, Any]]:
    return [p.to_dict() for p in queue.all()]
