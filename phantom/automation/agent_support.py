"""agent_support.py — small, self-contained pieces of the autonomous agent.

`agent.py` is the orchestrator of the whole autonomy stack; over time it also
accumulated a handful of leaf helpers and tiny value objects that have nothing
to do with orchestration (scope checks, stream formatting, HTTP header
parsing, the campaign share bus and the beacon session wrapper). They are
pure/independent — no `AutonomousAgent` state and no orchestration — so they
live here, keeping `agent.py` focused on the kill-chain loop.

Every name defined here is RE-EXPORTED from `phantom.automation.agent` (the
existing import surface), so nothing that imported `from
phantom.automation.agent import ShareContext` had to change.
"""

from __future__ import annotations

import re
import threading
import time
from typing import Any, Dict, List, Optional


# ── pure helpers ────────────────────────────────────────────────────────────

def _in_scope(target: str, scope_list: List[str]) -> bool:
    """Scope enforcement: empty scope list = everything allowed."""
    if not scope_list:
        return True
    from phantom.core.scope import is_in_scope
    return is_in_scope(target, scope_list)


def _safe_stream_value(f) -> str:
    """Operator-visible value summary for `found` events.

    The policy (cookie jars stay local; everything else renders as the
    first values joined) lives in `stream_contract.safe_value` so the
    agent and the swarm share it. Called from `_emit_found` so every
    `found` site shares one policy.
    """
    from phantom.core.stream_contract import safe_value
    return safe_value(getattr(f, "kind", ""), getattr(f, "value", ""))


def _is_ip(value: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", (value or "").strip()))


def _headers_from_raw(raw: str) -> Dict[str, str]:
    """`Name: value` pairs of a raw HTTP response, lower-cased keys."""
    out: Dict[str, str] = {}
    for line in (raw or "").splitlines():
        if ":" not in line or line.lstrip().startswith("<"):
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        if not name or len(name) > 40 or " " in name:
            continue
        out.setdefault(name.lower(), value.strip())
    return out


def _best_origin(wm):
    """The credible origin behind an edge, or None (see kit.best_origin)."""
    try:
        from phantom.automation.guidance.kit import best_origin
        return best_origin(wm)
    except Exception:
        return None


# ── campaign share bus ──────────────────────────────────────────────────────

class ShareContext:
    """Cross-sub-agent shared knowledge inside a campaign.

    Credentials discovered by one sub-agent become immediately available
    to the others (reuse across the network), and the peer targets are the
    lateral-movement candidates. Thread-safe: sub-agents run concurrently.
    """

    # findings worth broadcasting to peers: the firehose of every service /
    # header finding would drown them and duplicate their own scans
    SHARED_KINDS = {
        "victim_ip", "ad_domain", "os", "environment", "beacon",
        "cloud_creds", "rce_foothold", "follow_accepted",
    }

    def __init__(self, peers: Optional[List[str]] = None) -> None:
        self.peers: List[str] = list(peers or [])
        self._lock = threading.Lock()
        self._creds: List[tuple] = []  # (service, username, password, source)
        # (kind, key) -> {"value": dict, "target": source_target}
        self._findings: Dict[tuple, dict] = {}
        # (entity, capability) -> already probed by SOME worker in this
        # campaign: prevents two sub-agents re-running the same single-shot
        # probe against the same entity
        self._tried: set = set()

    def add_creds(self, service: str, username: str, password: str,
                  source_target: str) -> None:
        entry = (service, username, password, source_target)
        with self._lock:
            for c in self._creds:
                if c[:3] == entry[:3]:
                    return
            self._creds.append(entry)

    def find(self, service: Optional[str] = None) -> Optional[tuple]:
        """First matching credential pair (any service if service is None)."""
        with self._lock:
            for c in self._creds:
                if service is None or c[0] == service:
                    return (c[1], c[2])
        return None

    def first_peer(self, exclude: Optional[str] = None) -> Optional[str]:
        for p in self.peers:
            if p != exclude:
                return p
        return None

    def publish_finding(self, kind: str, key: str, value: dict,
                        source_target: str) -> None:
        """Broadcast a high-value finding to the other sub-agents.

        Only SHARED_KINDS are published — the firehose of every service/
        header finding would drown the peers and duplicate their own scans.
        """
        if kind not in self.SHARED_KINDS:
            return
        with self._lock:
            self._findings[(kind, key)] = {
                "value": value, "target": source_target,
            }

    def shared_finding(self, kind: str,
                       key: Optional[str] = None) -> Optional[tuple]:
        """A peer's high-value finding: (value_dict, source_target) or None."""
        with self._lock:
            for (k, kk), entry in self._findings.items():
                if k != kind:
                    continue
                if key is None or kk == key:
                    return (entry["value"], entry["target"])
        return None

    def shared_findings(self, kind: str) -> List[tuple]:
        """All peers' findings of a kind: [(value_dict, source_target), ...]."""
        with self._lock:
            return [(e["value"], e["target"])
                    for (k, _kk), e in self._findings.items() if k == kind]

    def mark_tried(self, entity: str, capability: str) -> None:
        with self._lock:
            self._tried.add((entity, capability))

    def was_tried(self, entity: str, capability: str) -> bool:
        with self._lock:
            return (entity, capability) in self._tried

    def tried_count(self) -> int:
        with self._lock:
            return len(self._tried)


# ── event stream ────────────────────────────────────────────────────────────

class EventSink:
    """Collector of decision events (console stream / tests)."""

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    def emit(self, kind: str, **data) -> None:
        self.events.append({"kind": kind, **data})

    def by_kind(self, kind: str) -> List[Dict[str, Any]]:
        return [e for e in self.events if e["kind"] == kind]


# ── beacon channel ──────────────────────────────────────────────────────────

class _BeaconSession:
    """A session over OUR C2 stack for one registered C++ beacon.

    Post-exploitation is queued as C2 tasks and the output is collected
    from the C2 state — the exact same channel the C2 shell uses. This is
    the ONLY path for post-exploitation: commands run inside the beacon,
    never from a wrapper listener.
    """

    def __init__(self, beacon_id: str) -> None:
        self.beacon_id = beacon_id

    def task(self, command: str) -> Optional[str]:
        from phantom.core.c2_server import c2_state
        try:
            return c2_state.queue_task(self.beacon_id, command)
        except Exception:
            # P1-1 legacy adapter: OS command lines (persistence cron/unit,
            # recon one-liners) are not beacon verbs — the beacon executes
            # them through its OS-shell verb, exactly like the C2 shell's
            # interact mode does for free-form input.
            try:
                return c2_state.queue_task(self.beacon_id,
                                           f"shell {command}")
            except Exception:
                return None

    def wait_result(self, task_id: str, timeout: float = 30.0) -> Optional[str]:
        from phantom.core.c2_server import c2_state
        deadline = time.time() + timeout
        while time.time() < deadline:
            for r in c2_state.get_results(self.beacon_id):
                if r.get("task_id") == task_id:
                    return r.get("output", "")
            time.sleep(0.1)
        return None
