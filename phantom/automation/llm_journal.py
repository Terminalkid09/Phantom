"""llm_journal.py — what the model proposed, and what the algorithm did with it.

The LLM advisor is deliberately non-gating: it proposes, the deterministic layer
decides. That is the right architecture and it hid a question the operator could
not answer — WHEN THE PLANNER IGNORED THE MODEL, WHY? A dropped proposal left no
trace at all, so nobody could tell "the model hallucinated a capability that does
not exist" from "the model pointed at the exact move this engagement needed and a
gate refused it for a reason that no longer applied".

This module is that trace, and nothing else. It records, per model call:

  * the REQUEST digest (never the full prompt: target text is already redacted
    on the wire and the journal is written to disk, so it keeps a digest),
  * the RAW model output,
  * every proposal with its own VERDICT and the reason the deterministic layer
    gave (`accepted`, or dropped as `not-whitelisted` / `unknown-capability` /
    `paranoid-aggressive` / `parse-error`),
  * and the run/agent it belongs to.

`refusals()` is the operator view the design asked for: the proposals that were
DROPPED, with reasons, so a human can review the model's judgement against the
algorithm's — and notice when the algorithm was the one that was wrong.

Storage is a bounded in-memory ring plus a best-effort JSONL append (same shape
as the audit log, but it is diagnostic data, not chain-of-custody: a failed
write is reported in the entry, never raised, and never blocks a run).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

MAX_ENTRIES = 500


def _digest(text: str) -> str:
    """Short, stable fingerprint of a request (never the request itself)."""
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class Entry:
    """One model call and the fate of every proposal it made."""

    seq: int
    ts: str
    kind: str                                  # suggest | dossier | classify | ...
    request_digest: str = ""
    raw: str = ""
    proposals: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""
    agent: str = ""
    wrote: bool = True

    # -------------------------------------------------------------- helpers

    @property
    def accepted(self) -> List[str]:
        return [p.get("capability_id", "") for p in self.proposals
                if p.get("verdict") == "accepted"]

    @property
    def dropped(self) -> List[Dict[str, Any]]:
        return [p for p in self.proposals if p.get("verdict") == "dropped"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq, "ts": self.ts, "kind": self.kind,
            "request_digest": self.request_digest, "raw": self.raw,
            "proposals": [dict(p) for p in self.proposals],
            "error": self.error, "agent": self.agent,
            "accepted": self.accepted,
            "dropped": [p.get("capability_id", "") for p in self.dropped],
        }


class Journal:
    """Bounded, thread-safe, file-backed record of model proposals."""

    def __init__(self, path: Optional[str] = None,
                 max_entries: int = MAX_ENTRIES) -> None:
        if path is None:
            from phantom.utils.paths import data_dir
            path = os.path.join(data_dir(), "llm_journal.jsonl")
        self.path = path
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._entries: List[Entry] = []

    # ------------------------------------------------------------- record

    def record(self, kind: str, *, request: str = "", raw: str = "",
               proposals: Optional[List[Dict[str, Any]]] = None,
               error: str = "", agent: str = "") -> Entry:
        """Append one call. NEVER raises: this is diagnostic data, and a
        journal that can break a run is worse than no journal at all."""
        with self._lock:
            entry = Entry(
                seq=len(self._entries) + 1,
                ts=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
                kind=kind,
                request_digest=_digest(request),
                raw=(raw or "")[:8000],
                proposals=[dict(p) for p in (proposals or [])],
                error=error, agent=agent,
            )
            self._entries.append(entry)
            if len(self._entries) > self.max_entries:
                self._entries = self._entries[-self.max_entries:]
            entry.wrote = self._append(entry)
            return entry

    def _append(self, entry: Entry) -> bool:
        """Best-effort JSONL append next to the other run artifacts."""
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry.to_dict(), default=str) + "\n")
            return True
        except Exception:
            return False

    # -------------------------------------------------------------- views

    def entries(self, kind: str = "", limit: int = 0) -> List[Entry]:
        with self._lock:
            out = [e for e in self._entries if not kind or e.kind == kind]
        return out[-limit:] if limit else list(out)

    def refusals(self, limit: int = 0) -> List[Entry]:
        """Calls where the DETERMINISTIC layer dropped something the model
        proposed — the review surface for "did we refuse a good idea?"."""
        with self._lock:
            out = [e for e in self._entries if e.dropped or e.error]
        return out[-limit:] if limit else list(out)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            entries = list(self._entries)
        dropped = sum(len(e.dropped) for e in entries)
        return {
            "calls": len(entries),
            "proposals": sum(len(e.proposals) for e in entries),
            "accepted": sum(len(e.accepted) for e in entries),
            "dropped": dropped,
            "errors": sum(1 for e in entries if e.error),
            "refusals": len(self.refusals()),
        }

    def clear(self) -> int:
        with self._lock:
            n = len(self._entries)
            self._entries = []
        return n

    def render(self, limit: int = 20, refused_only: bool = False) -> str:
        """Plain-text view for the CLI: what was proposed, and what happened."""
        rows = self.refusals(limit) if refused_only else self.entries(limit=limit)
        if not rows:
            return ("no model proposals recorded yet"
                    + (" (no refusals)" if refused_only else ""))
        lines = [f"llm journal: {len(rows)} call(s)"
                 + (" (refusals only)" if refused_only else "")]
        for entry in rows:
            lines.append(f"  #{entry.seq} {entry.ts} {entry.kind}"
                         + (f" agent={entry.agent}" if entry.agent else ""))
            if entry.error:
                lines.append(f"      error: {entry.error}")
            if not entry.proposals:
                lines.append("      (no valid proposal in the output)")
            for prop in entry.proposals:
                cid = prop.get("capability_id", "?")
                verdict = prop.get("verdict", "?")
                why = prop.get("reason", "")
                drop = prop.get("drop_reason", "")
                mark = "ACCEPTED" if verdict == "accepted" else "DROPPED"
                lines.append(f"      [{mark}] {cid}"
                             + (f" - {drop}" if drop else "")
                             + (f" | model said: {why}" if why else ""))
        return "\n".join(lines)


journal = Journal()
