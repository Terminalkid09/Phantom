"""
experience.cases — the episode store.

An EPISODE is one closed loop the agent lived through:

    situation (signature) + phase + technique -> outcome (+ cause)
    ...and, when it failed, the technique that ACTUALLY succeeded after it
    (the repair).

That last field is what turns a pile of statistics into transferable
knowledge: not "sqli is 60% effective" but "on a PHP app behind a WAF,
the upload-RCE was blocked — the SQLi on /export is what worked".

Storage is a single bounded JSON file under `data/` (gitignored). Two
modes, matching the agreed policy:

    * engagement-scoped (default) — episodes live in memory for the run
      only; nothing is read from or written to disk, so no client's data
      ever contaminates another engagement.
    * global (opt-in) — the store loads and persists across engagements.

The store never grows without bound: oldest episodes are dropped past
`max_episodes`, and consolidation prunes by age before saving.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from phantom.utils.paths import data_dir

from . import causes as C


def experience_path() -> str:
    return os.path.join(data_dir(), "experience_cases.json")


@dataclass
class Episode:
    """One recorded attempt with its situation, outcome and repair.

    `eid` is the episode IDENTITY. It exists because timestamps are not
    unique (two moves often land in the same clock tick, especially on
    Windows where the timer is coarse) — deduplication must therefore key
    on identity, never on a timestamp, or genuinely distinct attempts
    collapse into one and the statistics lie.
    """

    sig: Dict[str, Any] = field(default_factory=dict)
    phase: str = ""
    technique: str = ""
    ok: bool = False
    cause: str = ""
    repair: str = ""
    detail: str = ""
    ts: float = field(default_factory=time.time)
    eid: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Episode":
        data = data or {}
        eid = str(data.get("eid", "") or "") or uuid.uuid4().hex[:12]
        return cls(
            eid=eid,
            sig=dict(data.get("sig") or {}),
            phase=str(data.get("phase", "")),
            technique=str(data.get("technique", "")),
            ok=bool(data.get("ok", False)),
            cause=str(data.get("cause", "")),
            repair=str(data.get("repair", "")),
            detail=str(data.get("detail", ""))[:400],
            ts=float(data.get("ts", 0.0) or 0.0),
        )

    def learnable(self) -> bool:
        """A success always teaches; a failure teaches only when the cause
        was the technique's fault (not a missing tool / scope / flag)."""
        if self.ok:
            return True
        return C.is_learnable(self.cause)


DEFAULT_MAX_EPISODES = 2000
DEFAULT_MAX_AGE_DAYS = 365.0


class CaseStore:
    """Bounded, thread-safe episode store with optional persistence."""

    def __init__(self, path: Optional[str] = None, enabled: bool = False,
                 max_episodes: int = DEFAULT_MAX_EPISODES) -> None:
        self.path = path or experience_path()
        self.enabled = bool(enabled)
        self.max_episodes = int(max_episodes)
        self._lock = threading.Lock()
        self._episodes: List[Episode] = []
        if self.enabled:
            self.load()

    # ── access ────────────────────────────────────────────────────────
    @property
    def episodes(self) -> List[Episode]:
        with self._lock:
            return list(self._episodes)

    def record(self, ep: Episode) -> None:
        with self._lock:
            self._episodes.append(ep)
            self._trim_locked()

    def extend(self, eps: Iterable[Episode]) -> int:
        n = 0
        with self._lock:
            for ep in eps:
                self._episodes.append(ep)
                n += 1
            self._trim_locked()
        return n

    def _trim_locked(self) -> None:
        if len(self._episodes) > self.max_episodes:
            # drop the oldest: recency is what transfers
            self._episodes.sort(key=lambda e: e.ts)
            self._episodes = self._episodes[-self.max_episodes:]

    def clear(self) -> None:
        with self._lock:
            self._episodes = []
        if self.enabled:
            self.save()

    # ── persistence ───────────────────────────────────────────────────
    def load(self) -> int:
        if not self.enabled:
            return 0
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            return 0
        eps = [Episode.from_dict(e) for e in (raw.get("episodes") or [])
               if isinstance(e, dict)]
        with self._lock:
            self._episodes = eps[-self.max_episodes:]
        return len(eps)

    def save(self) -> bool:
        if not self.enabled:
            return False
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with self._lock:
                payload = {
                    "version": 1,
                    "saved": time.time(),
                    "episodes": [e.to_dict() for e in self._episodes],
                }
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=1)
            os.replace(tmp, self.path)      # atomic swap
            return True
        except OSError:
            return False

    # ── introspection ─────────────────────────────────────────────────
    def stats(self) -> Dict[str, Any]:
        eps = self.episodes
        by_cause: Dict[str, int] = {}
        by_phase: Dict[str, int] = {}
        wins = 0
        learnable = 0
        repairs: Dict[str, int] = {}
        for e in eps:
            by_phase[e.phase] = by_phase.get(e.phase, 0) + 1
            if e.ok:
                wins += 1
            else:
                by_cause[e.cause] = by_cause.get(e.cause, 0) + 1
            if e.learnable():
                learnable += 1
            if e.repair:
                repairs[e.repair] = repairs.get(e.repair, 0) + 1
        return {
            "enabled": self.enabled,
            "path": self.path if self.enabled else "(engagement-scoped)",
            "episodes": len(eps),
            "learnable": learnable,
            "successes": wins,
            "failures": len(eps) - wins,
            "by_cause": dict(sorted(by_cause.items(),
                                    key=lambda kv: -kv[1])),
            "by_phase": dict(sorted(by_phase.items())),
            "top_repairs": dict(sorted(repairs.items(),
                                       key=lambda kv: -kv[1])[:10]),
        }
