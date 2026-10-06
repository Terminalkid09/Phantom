"""capability_registry.py — capability trust state machine + provenance store.

AutoModeBrief §5/§6/§13: a discovered tool must not be one boolean away from
execution. It should cross explicit states — ``discovered`` → ``candidate``
→ ``reviewed`` → ``approved`` → ``enabled`` → ``executed`` → ``validated`` —
and carry provenance (version, path, sha256, source, platform, privileges)
that a change to the BINARY can invalidate.

The registry keeps one :class:`CapabilityRecord` per capability id and:

  * enforces the state machine: a transition to a state that does not follow
    the current one is refused (``can_transition`` / ``transition``);
  * records provenance and the manifest hash at approval time;
  * :meth:`verify_integrity` re-hashes the binary and, on a mismatch,
    DEMOTES the record back to ``discovered`` and clears the approval — a
    tool that changed under us must be re-approved (§6);
  * persists atomically, and answers ``enabled_ids()`` — the ONLY ids the
    planner may load.

The store is best-effort: a missing/broken file is an empty registry, never
a crash.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

# The capability lifecycle, in order. ``validated`` is terminal; a demotion
# (integrity change) always returns to ``discovered``.
STATES: Tuple[str, ...] = (
    "discovered", "candidate", "reviewed", "approved", "enabled",
    "executed", "validated",
)
_ORDER = {state: i for i, state in enumerate(STATES)}

# Legal forward edges (plus the terminal executed<->validated loop). Anything
# else — including a jump over review — is refused.
_EDGES: Dict[str, Tuple[str, ...]] = {
    "discovered": ("candidate",),
    "candidate": ("reviewed",),
    "reviewed": ("approved",),
    "approved": ("enabled",),
    "enabled": ("executed",),
    "executed": ("validated",),
    "validated": (),
}


def _default_path() -> str:
    try:
        from phantom.utils.paths import data_dir
        return os.path.join(data_dir(), "capability_registry.json")
    except Exception:
        return "capability_registry.json"


def sha256_file(path: str) -> str:
    """sha256 of a file, or '' when unreadable (never raises)."""
    import hashlib
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


@dataclass
class CapabilityRecord:
    """One capability's provenance and trust state."""

    capability: str
    tool: str = ""
    state: str = "discovered"
    version: str = ""
    path: str = ""
    sha256: str = ""
    source: str = "operator-local"   # operator-local | learned | unknown
    platforms: Tuple[str, ...] = ()
    required_privileges: str = "user"
    manifest_digest: str = ""        # sha256 of the declarative manifest
    status_history: List[str] = field(default_factory=list)
    discovered_at: float = 0.0
    approved_at: float = 0.0
    approved_by: str = ""
    note: str = ""

    @property
    def approved(self) -> bool:
        return _ORDER.get(self.state, -1) >= _ORDER["approved"]

    @property
    def enabled(self) -> bool:
        return _ORDER.get(self.state, -1) >= _ORDER["enabled"]

    def can_transition(self, to_state: str) -> bool:
        return to_state in _EDGES.get(self.state, ())

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["platforms"] = list(self.platforms)
        data["approved"] = self.approved
        data["enabled"] = self.enabled
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapabilityRecord":
        data = data or {}
        return cls(
            capability=str(data.get("capability") or ""),
            tool=str(data.get("tool") or ""),
            state=str(data.get("state") or "discovered"),
            version=str(data.get("version") or ""),
            path=str(data.get("path") or ""),
            sha256=str(data.get("sha256") or ""),
            source=str(data.get("source") or "operator-local"),
            platforms=tuple(data.get("platforms") or ()),
            required_privileges=str(data.get("required_privileges") or "user"),
            manifest_digest=str(data.get("manifest_digest") or ""),
            status_history=list(data.get("status_history") or []),
            discovered_at=float(data.get("discovered_at") or 0.0),
            approved_at=float(data.get("approved_at") or 0.0),
            approved_by=str(data.get("approved_by") or ""),
            note=str(data.get("note") or ""),
        )


class CapabilityRegistry:
    """Persisted capability trust state + provenance (thread-safe)."""

    def __init__(self, path: Optional[str] = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.path = path if path is not None else _default_path()
        self._clock = clock
        self._lock = threading.Lock()
        self._rows: Dict[str, CapabilityRecord] = {}
        self._loaded = False

    # ------------------------------------------------------------- persist

    def load(self) -> "CapabilityRegistry":
        with self._lock:
            if self._loaded:
                return self
            self._loaded = True
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                return self
            rows = (data or {}).get("capabilities") or {}
            if isinstance(rows, dict):
                for cap, row in rows.items():
                    try:
                        self._rows[str(cap)] = CapabilityRecord.from_dict(
                            {**row, "capability": cap})
                    except Exception:
                        continue
        return self

    def save(self) -> bool:
        self._ensure_loaded()
        with self._lock:
            payload = {"version": 1, "capabilities":
                       {c: r.to_dict() for c, r in self._rows.items()}}
        try:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            tmp = f"{self.path}.tmp{os.getpid()}"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True, default=str)
            os.replace(tmp, self.path)
            return True
        except OSError:
            return False

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    # ----------------------------------------------------------- discovery

    def discover(self, record: CapabilityRecord) -> CapabilityRecord:
        """Register/refresh a DISCOVERED capability (never auto-enables).

        A re-discovery that changes the binary hash DEMOTES an approved record
        back to ``discovered`` and clears its approval, exactly like an
        explicit :meth:`verify_integrity` mismatch (§6).
        """
        self._ensure_loaded()
        cap = record.capability
        with self._lock:
            existing = self._rows.get(cap)
            now = self._clock()
            if existing is None:
                record.discovered_at = record.discovered_at or now
                record.status_history = [record.state]
                self._rows[cap] = record
                return record
            changed = (record.sha256 and existing.sha256
                       and record.sha256 != existing.sha256)
            record.discovered_at = existing.discovered_at or now
            record.status_history = list(existing.status_history)
            if changed:
                record.state = "discovered"
                record.approved_at = 0.0
                record.approved_by = ""
                record.note = "binary changed: approval invalidated"
                record.status_history.append("discovered")
            else:
                # keep the further state; only refresh provenance fields
                record.state = existing.state
                record.approved_at = existing.approved_at
                record.approved_by = existing.approved_by
            self._rows[cap] = record
            return record

    # --------------------------------------------------------- transitions

    def transition(self, capability: str, to_state: str, actor: str = "",
                   reason: str = "") -> bool:
        """Move a capability one legal step forward. False when refused."""
        self._ensure_loaded()
        with self._lock:
            row = self._rows.get(capability)
            if row is None or not row.can_transition(to_state):
                return False
            row.state = to_state
            row.status_history.append(to_state)
            if to_state == "approved":
                row.approved_at = self._clock()
                row.approved_by = actor or "operator"
            if reason:
                row.note = reason[:200]
            return True

    def approve(self, capability: str, actor: str = "operator",
                reason: str = "") -> bool:
        """Walk a candidate to ``approved`` through every required state.

        A candidate cannot jump straight to approved: review then approve, so
        the audit trail shows the review really happened.
        """
        row = self.of(capability)
        if row is None:
            return False
        while row.state in ("discovered", "candidate", "reviewed"):
            nxt = _EDGES[row.state][0]
            if not self.transition(capability, nxt, actor=actor, reason=reason):
                return False
            row = self.of(capability)
        return row.state in ("approved", "enabled", "executed", "validated")

    def enable(self, capability: str, actor: str = "operator") -> bool:
        """Approve if needed, then enable (approved -> enabled)."""
        if not self.approve(capability, actor=actor):
            return False
        row = self.of(capability)
        if row is not None and row.state == "approved":
            return self.transition(capability, "enabled", actor=actor)
        return row is not None and row.enabled

    # ---------------------------------------------------------- integrity

    def verify_integrity(self, capability: str, actual_sha: str) -> bool:
        """True when the binary still matches the approved hash.

        On a mismatch the record is DEMOTED to ``discovered`` and its approval
        cleared, so a changed binary must be re-reviewed before it can run
        again (§6). Returns False on mismatch (and when the record is unknown).
        """
        self._ensure_loaded()
        with self._lock:
            row = self._rows.get(capability)
            if row is None or not row.sha256 or not actual_sha:
                return False
            if row.sha256 == actual_sha:
                return True
            row.state = "discovered"
            row.approved_at = 0.0
            row.approved_by = ""
            row.status_history.append("discovered")
            row.note = "integrity mismatch: approval invalidated"
            return False

    def demote(self, capability: str, reason: str = "") -> bool:
        """Send a capability back to ``discovered`` and clear its approval.

        The operator's revoke: an enabled capability stops being loadable
        until it is reviewed and approved again. False when unknown or
        already discovered.
        """
        self._ensure_loaded()
        with self._lock:
            row = self._rows.get(capability)
            if row is None or row.state == "discovered":
                return False
            row.state = "discovered"
            row.approved_at = 0.0
            row.approved_by = ""
            row.status_history.append("discovered")
            if reason:
                row.note = reason[:200]
            return True

    # -------------------------------------------------------------- reads

    def of(self, capability: str) -> Optional[CapabilityRecord]:
        self._ensure_loaded()
        with self._lock:
            return self._rows.get(str(capability))

    def all(self) -> List[CapabilityRecord]:
        self._ensure_loaded()
        with self._lock:
            return [self._rows[k] for k in sorted(self._rows)]

    def enabled_ids(self) -> set:
        """The ONLY ids the planner may load (state >= enabled)."""
        return {r.capability for r in self.all() if r.enabled}

    def report(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.all()]
