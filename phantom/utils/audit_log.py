"""audit_log.py — hash-chained, append-only audit log.

Every C2 security-relevant event (beacon registration, task queueing,
task results, auth failures, operator logins) is appended to a JSONL
file where each record carries:

  * seq   — monotonic sequence number
  * prev  — the hash of the previous record (genesis: 64 zeros)
  * hash  — SHA-256 over the canonical JSON of the record WITHOUT `hash`

Tampering with ANY record breaks the chain: every hash after the edited
record no longer verifies, and `verify()` pinpoints the first bad record.
The log is the operator-facing "chain of custody" that professional
engagements require — it can be shown to the client as proof the activity
timeline was not rewritten post-hoc.

Design notes:
  * append-only: records are never updated or deleted in place
  * file lock: a threading.Lock guards concurrent appends (C2 listener
    thread, shell threads, agent workers)
  * bounded read cost: `verify()` streams the file once
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

_GENESIS = "0" * 64


def _canonical(record: Dict[str, Any]) -> str:
    """Stable JSON serialization used for hashing (sorted keys, no spaces)."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      default=str)


class AuditLog:
    """Append-only, hash-chained JSONL audit log."""

    def __init__(self, path: Optional[str] = None) -> None:
        if path is None:
            from phantom.utils.paths import data_dir
            path = os.path.join(data_dir(), "c2_audit.log")
        self.path = path
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ append

    def append(self, event: str, **fields: Any) -> Dict[str, Any]:
        """Append one event; returns the record as written."""
        with self._lock:
            prev = self._last_hash()
            record: Dict[str, Any] = {
                "seq": self._count() + 1,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event": event,
            }
            record.update(fields)
            record["prev"] = prev
            record["hash"] = hashlib.sha256(
                _canonical(record).encode("utf-8")).hexdigest()
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(_canonical(record) + "\n")
            return record

    # ------------------------------------------------------------------ reads

    def _iter(self):
        if not os.path.isfile(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    yield {"_corrupt": line}

    def _count(self) -> int:
        n = 0
        for _ in self._iter():
            n += 1
        return n

    def _last_hash(self) -> str:
        last = _GENESIS
        for rec in self._iter():
            if isinstance(rec, dict) and rec.get("hash"):
                last = rec["hash"]
        return last

    def tail(self, n: int = 20) -> List[Dict[str, Any]]:
        """Last `n` records (oldest first)."""
        records = [r for r in self._iter()]
        return records[-n:]

    # ----------------------------------------------------------------- verify

    def verify(self) -> Tuple[bool, int, Optional[Dict[str, Any]]]:
        """Verify the hash chain.

        Returns (ok, records_checked, first_bad_record_or_None).
        ok is True when every record's hash recomputes and every `prev`
        links to the previous record's hash.
        """
        prev = _GENESIS
        seq = 0
        for rec in self._iter():
            seq += 1
            if "_corrupt" in rec:
                return False, seq, rec
            stored_hash = rec.get("hash", "")
            body = {k: v for k, v in rec.items() if k != "hash"}
            expect = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
            if rec.get("prev") != prev or stored_hash != expect:
                return False, seq, rec
            prev = stored_hash
            if rec.get("seq") != seq:
                return False, seq, rec
        return True, seq, None


audit_log = AuditLog()
