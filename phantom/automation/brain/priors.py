"""
phantom.automation.brain.priors — per-fingerprint success priors.

The agent must not be amnesiac across engagements: "SQLi dump worked on
every nginx/PHP e-commerce so far" and "kerberoast never worked without
SPNs" are COST SIGNALS for the composition and capability ordering.
Priors persist per (technique, fingerprint-class) in data/
(gitignored), are read at planning time, and update from live outcomes.

Learning rule (regret-bounded, like the calibrated weights):
    multiplier = clamp(0.5, 1.5, 0.8 + 0.4 * success_rate)
  where success_rate blends the historical rate with a neutral prior so
  a single failure never kills a technique.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Dict, Optional, Tuple

from phantom.utils.paths import data_dir


def priors_path() -> str:
    return os.path.join(data_dir(), "technique_priors.json")


def _fingerprint_class(wm) -> str:
    """The coarse fingerprint class of the current target (the prior
    bucket): first known service product or OS, else 'generic'."""
    for kind in ("fingerprint", "web_header", "banner"):
        for f in wm.find(kind):
            v = f.value if isinstance(f.value, dict) else {}
            product = str(v.get("product") or v.get("server") or "").lower()
            if product:
                return product.split("_")[0].split("/")[0][:24]
    for f in wm.find("os"):
        v = f.value if isinstance(f.value, dict) else {}
        name = str(v.get("name", "")).lower()
        if name:
            return name.split()[0][:24]
    return "generic"


class TechniquePriors:
    """Persistent per-(technique, fingerprint-class) success memory."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or priors_path()
        self._lock = threading.Lock()
        self._data: Dict[str, Dict[str, Dict[str, float]]] = {}
        self._load()

    # ── persistence ────────────────────────────────────────────────────
    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                self._data = json.load(fh)
        except (OSError, ValueError):
            self._data = {}

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=1)
        os.replace(tmp, self.path)          # atomic swap

    # ── query ──────────────────────────────────────────────────────────
    def multiplier(self, technique: str, fingerprint_class: str,
                   neutral: float = 1.0) -> float:
        """Planning-time cost multiplier for a technique on a class."""
        with self._lock:
            rec = self._data.get(technique, {}).get(fingerprint_class)
        if not rec:
            return neutral
        wins = float(rec.get("wins", 0))
        runs = float(rec.get("runs", 0))
        if runs <= 0:
            return neutral
        # blend with a neutral prior of 2 pseudo-observations at 50%
        rate = (wins + 1.0) / (runs + 2.0)
        return max(0.5, min(1.5, 0.8 + 0.4 * (1.0 - rate) * 2.0))

    def multiplier_for(self, wm, technique: str) -> float:
        return self.multiplier(technique, _fingerprint_class(wm))

    # ── recording ──────────────────────────────────────────────────────
    def record(self, technique: str, fingerprint_class: str,
               ok: bool) -> None:
        with self._lock:
            bucket = self._data.setdefault(technique, {}) \
                               .setdefault(fingerprint_class,
                                           {"runs": 0.0, "wins": 0.0})
            bucket["runs"] = float(bucket.get("runs", 0)) + 1.0
            if ok:
                bucket["wins"] = float(bucket.get("wins", 0)) + 1.0
        self.save()

    def record_from_worldmodel(self, wm, technique: str, ok: bool) -> None:
        self.record(technique, _fingerprint_class(wm), ok)

    # ── introspection ──────────────────────────────────────────────────
    def summary(self, technique: Optional[str] = None) -> dict:
        with self._lock:
            if technique:
                return json.loads(json.dumps(
                    self._data.get(technique, {})))
            return json.loads(json.dumps(self._data))
