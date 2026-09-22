"""Board: the swarm blackboard.

One committed WorldModel per target, guarded by a single lock. The
contract that makes multi-agent reasoning safe:

* workers READ committed facts any time (shared reads);
* workers NEVER write the board — they run on a snapshot and return
  staged findings (private scratch by construction);
* the orchestrator COMMITS staged findings under the lock,
  first-writer-wins per (kind, key), every decision counted.

A second worker on the same task therefore reasons over the same
committed truth WITHOUT seeing its sibling's in-flight hypotheses —
diversity survives parallelism.
"""
from __future__ import annotations

import re
import threading
from typing import Any, Dict, List, Tuple

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


class Board:
    """Committed WorldModels per target + mediated commit."""

    def __init__(self, targets) -> None:
        from phantom.automation.belief import WorldModel
        try:
            from phantom.automation.guidance.targets import classify_target
        except Exception:
            classify_target = None  # type: ignore
        self._lock = threading.Lock()
        self._wms: Dict[str, Any] = {}
        for target in targets or []:
            ttype = "ip"
            if classify_target is not None:
                try:
                    ttype = classify_target(target) or "ip"
                except Exception:
                    ttype = "ip"
            self._wms[target] = WorldModel(target=target, target_type=ttype)
        self.added = 0
        self.skipped = 0

    # ------------------------------------------------------------- reads

    def targets(self) -> List[str]:
        return list(self._wms.keys())

    def ensure(self, target: str):
        """Lazily create the committed model for a dynamically resolved
        target (victim IPs...): every target owns its board slice before
        any worker touches it."""
        with self._lock:
            if target not in self._wms:
                from phantom.automation.belief import WorldModel
                try:
                    from phantom.automation.guidance.targets import \
                        classify_target
                    ttype = classify_target(target) or "ip"
                except Exception:
                    ttype = "ip"
                self._wms[target] = WorldModel(target=target,
                                               target_type=ttype)
            return self._wms[target]

    def has(self, target: str, kind: str) -> bool:
        """Is any finding of this kind committed for the target?"""
        wm = self._wms.get(target)
        if wm is None:
            return False
        try:
            return bool(wm.find(kind))
        except Exception:
            return False

    def count(self, target: str, kind: str) -> int:
        """How many findings of this kind are committed for the target?"""
        wm = self._wms.get(target)
        if wm is None:
            return 0
        try:
            return len(wm.find(kind))
        except Exception:
            return 0

    def kinds(self, target: str) -> List[str]:
        try:
            data = self._wms[target].to_dict()
        except KeyError:
            return []
        return sorted({f.get("kind", "") for f in data.get("findings", [])})

    def target_values(self, target: str, kind: str, limit: int = 5) -> List[str]:
        """Committed scalar values of a fact kind (victim IPs, hosts...).

        Values may be strings or small dicts ({"ip": ...}); only
        plausible target tokens are returned, bounded and deterministic."""
        wm = self._wms.get(target)
        if wm is None:
            return []
        out: List[str] = []
        try:
            findings = wm.find(kind)
        except Exception:
            return []
        for f in findings:
            value = getattr(f, "value", None)
            candidates = []
            if isinstance(value, str):
                candidates = [value]
            elif isinstance(value, dict):
                for k in ("ip", "host", "target", "address"):
                    if isinstance(value.get(k), str):
                        candidates.append(value[k])
            for c in candidates:
                c = c.strip()
                if c and c not in out and (_IPV4.match(c) or "." in c or c.startswith("http")):
                    out.append(c)
            if len(out) >= limit:
                break
        return out[:limit]

    def snapshot(self, target: str):
        """A private WorldModel copy for one worker (deep via dict)."""
        from phantom.automation.belief import WorldModel
        with self._lock:
            data = self._wms[target].to_dict()
        return WorldModel.from_dict(data)

    def worldmodel(self, target: str):
        """The COMMITTED model (read-only use: fingerprinting, reporting).
        Never mutate it — workers run on snapshots, the board on commit."""
        return self._wms.get(target)

    def snapshot_keys(self, target: str) -> set:
        wm = self._wms.get(target)
        if wm is None:
            return set()
        with self._lock:
            data = wm.to_dict()
        return {(f.get("kind", ""), f.get("key", ""))
                for f in data.get("findings", [])}

    # ------------------------------------------------------------ commit

    def commit(self, task_id: str, target: str,
               staged: List[dict]) -> Tuple[int, int]:
        """Merge staged findings: new (kind, key) pairs are added,
        duplicates are skipped. Returns (added, skipped)."""
        wm = self._wms.get(target)
        if wm is None or not staged:
            return 0, 0
        added = skipped = 0
        with self._lock:
            known = {(f.get("kind", ""), f.get("key", ""))
                     for f in wm.to_dict().get("findings", [])}
            for s in staged:
                kind = s.get("kind", "")
                key = s.get("key", "")
                if not kind or not key or (kind, key) in known:
                    skipped += 1
                    continue
                try:
                    wm.add_finding(kind, key, s.get("value", {}),
                                   confidence=s.get("confidence", 0.5),
                                   source=s.get("source") or task_id)
                except Exception:
                    skipped += 1
                    continue
                known.add((kind, key))
                added += 1
        self.added += added
        self.skipped += skipped
        return added, skipped

    def summary(self) -> Dict[str, List[str]]:
        return {t: self.kinds(t) for t in self.targets()}
