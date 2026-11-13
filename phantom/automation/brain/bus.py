"""
phantom.automation.brain.bus — cell-to-cell request/response (C2).

`ShareContext` BROADCASTS: a cell publishes a high-value finding and every
peer sees it sooner or later. That is enough for "the exploit cell learns
that SSH is open". It cannot express "the exploit cell ASKS the recon cell
which version is behind 8080 and needs the answer NOW", and without that a
team is just N agents reading the same noticeboard.

The bus adds the missing direction and — more importantly — it keeps the
KNOWLEDGE SCOPE enforceable while doing it: a cell answers only inside the
kinds it is allowed to see. The recon cell therefore cannot leak an
exploitation fact it does not have, and a cell cannot launder another
cell's knowledge by asking for it.

Design notes:
  * questions are explicit (`ask(cell, role, kind, key)`), answers are
    batched (`answer_all`), so the caller decides the cadence and nothing
    spins;
  * a denied answer is a RESULT, not an error: it is recorded with the
    reason ("out of the answering cell's scope"), which is exactly what the
    operator needs to read when the team stops making progress;
  * the transcript is bounded — a bus that grows forever is a leak.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from phantom.automation.brain.cells import Cell

MAX_TRANSCRIPT = 500


@dataclass
class Query:
    """One question from one cell to a role."""

    qid: str
    from_cell: str
    to_role: str
    kind: str
    key: str = ""
    note: str = ""


@dataclass
class Answer:
    """What came back. `answered=False` always carries `reason`."""

    qid: str
    from_cell: str
    to_role: str
    kind: str
    key: str = ""
    answered: bool = False
    value: Any = None
    reason: str = ""

    def to_dict(self) -> dict:
        return {"qid": self.qid, "from": self.from_cell, "to": self.to_role,
                "kind": self.kind, "key": self.key,
                "answered": self.answered, "reason": self.reason,
                "value": self.value if self.answered else None}


class CellBus:
    """Scoped request/response between the cells of one team."""

    def __init__(self, cells: Sequence[Cell] = ()) -> None:
        self._cells: List[Cell] = list(cells)
        self._pending: List[Query] = []
        self._transcript: List[Answer] = []
        self._seq = 0

    # ── membership ─────────────────────────────────────────────────────
    def register(self, cell: Cell) -> None:
        if cell not in self._cells:
            self._cells.append(cell)

    def cells(self) -> List[Cell]:
        return list(self._cells)

    def role(self, name: str) -> List[Cell]:
        return [c for c in self._cells if c.spec.role == name]

    # ── ask ────────────────────────────────────────────────────────────
    def ask(self, from_cell: str, to_role: str, kind: str, key: str = "",
            note: str = "") -> str:
        """Queue a question and return its id (the caller correlates)."""
        self._seq += 1
        qid = f"q{self._seq}"
        self._pending.append(Query(qid=qid, from_cell=from_cell,
                                   to_role=to_role, kind=kind, key=key,
                                   note=note))
        return qid

    def pending(self) -> List[Query]:
        return list(self._pending)

    # ── answer ─────────────────────────────────────────────────────────
    def answer_all(self, findings: Iterable[Any]) -> List[Answer]:
        """Resolve every pending question against the shared map.

        A question is answered by the FIRST cell of the target role that is
        ALLOWED to see the kind; if no cell of that role may see it, the
        answer is denied with the reason (never silently dropped).
        """
        pool = list(findings)
        out: List[Answer] = []
        still: List[Query] = []
        for q in self._pending:
            candidates = self.role(q.to_role)
            if not candidates:
                out.append(Answer(q.qid, q.from_cell, q.to_role, q.kind, q.key,
                                  False, None,
                                  f"no cell with role '{q.to_role}' in the roster"))
                continue
            allowed = [c for c in candidates if c.sees(q.kind)]
            if not allowed:
                out.append(Answer(
                    q.qid, candidates[0].cell_id, q.to_role, q.kind, q.key,
                    False, None,
                    f"role '{q.to_role}' may not see kind '{q.kind}'"))
                continue
            hit = self._lookup(pool, allowed[0], q.kind, q.key)
            out.append(Answer(q.qid, allowed[0].cell_id, q.to_role, q.kind,
                              q.key, hit is not None, hit,
                              "" if hit is not None else "not in the shared map"))
        for a in out:
            self._transcript.append(a)
        self._pending = still
        self._trim()
        return out

    @staticmethod
    def _lookup(pool: List[Any], cell: Cell, kind: str, key: str):
        """The cell looks at the SHARED map through its own eyes."""
        for f in cell.view_of(pool):
            if str(getattr(f, "kind", "")) != kind:
                continue
            if key and str(getattr(f, "key", "")) != key:
                continue
            value = getattr(f, "value", None)
            return value if isinstance(value, (dict, list, str, int, float,
                                               bool, type(None))) else str(value)
        return None

    def transcript(self) -> List[dict]:
        return [a.to_dict() for a in self._transcript]

    def answered_count(self) -> int:
        return sum(1 for a in self._transcript if a.answered)

    def denied_count(self) -> int:
        return sum(1 for a in self._transcript if not a.answered)

    def _trim(self) -> None:
        if len(self._transcript) > MAX_TRANSCRIPT:
            self._transcript = self._transcript[-MAX_TRANSCRIPT:]

    def stats(self) -> dict:
        return {"cells": len(self._cells), "pending": len(self._pending),
                "answered": self.answered_count(),
                "denied": self.denied_count()}
