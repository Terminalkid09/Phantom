"""
fallback.py — intelligent fallback strategy chain + historical self-learning.

Phase 6: When one approach fails, this engine determines the NEXT best action
based on what was learned from the failure, not a fixed linear sequence.

Phase 7: Historical self-learning — every engagement's outcome is persisted
and used as a prior for future engagements (same target class, same services).

Design:
  - Fallback is informed: "brute failed but account 'admin' exists" → phish admin
  - Fallback is bounded: never retry a permanently failed path
  - Learning is cumulative: Beta-Binomial posteriors over technique success
"""

from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from phantom.automation.belief import WorldModel, Finding


# ── data model ─────────────────────────────────────────────────────────

@dataclass
class StrategyAttempt:
    """Record of one attempted strategy with outcome."""
    strategy: str                    # network_footprint | exploit_chain | ...
    capability: str                  # scan_tcp | service_exploit | ...
    target: str
    ok: bool
    reason: str = ""                 # failure reason if not ok
    learned: Dict[str, Any] = field(default_factory=dict)  # e.g. {"valid_accounts": ["admin"]}
    elapsed: float = 0.0
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "strategy": self.strategy, "capability": self.capability,
            "target": self.target, "ok": self.ok, "reason": self.reason,
            "learned": self.learned, "elapsed": self.elapsed, "ts": self.ts,
        }


@dataclass
class TechniqueStats:
    """Accumulated success/failure stats for one technique."""
    successes: int = 0
    failures: int = 0
    last_used: float = 0.0
    target_os_breakdown: Dict[str, Tuple[int, int]] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return self.successes + self.failures

    @property
    def rate(self) -> float:
        if self.total == 0:
            return 0.5  # uninformed prior
        return self.successes / self.total

    @property
    def beta_alpha(self) -> float:
        return self.successes + 1.0  # Beta(1,1) prior

    @property
    def beta_beta(self) -> float:
        return self.failures + 1.0

    @property
    def posterior_mean(self) -> float:
        return self.beta_alpha / (self.beta_alpha + self.beta_beta)


# ── fallback decision tree ─────────────────────────────────────────────

# Ordered fallback chains for each starting strategy
# Each entry: (strategy_name, precondition_check, weight_boost)
FALLBACK_CHAINS: Dict[str, List[str]] = {
    "network_footprint": [
        "network_footprint",   # scan deeper (UDP, specific ports)
        "exploit_chain",       # try version-matched exploits
        "network_creds",       # try credential testing
        "network_beacon",      # deploy beacon if creds found
    ],
    "exploit_chain": [
        "exploit_chain",       # try another CVE
        "network_creds",       # fall back to credential testing
        "network_beacon",      # deploy with any creds found
        "network_footprint",   # re-scan, maybe missed something
    ],
    "network_creds": [
        "network_creds",       # try another service
        "exploit_chain",       # exploit might bypass auth
        "network_beacon",      # deploy if any creds found
        "network_footprint",   # re-scan for more services
    ],
    "network_beacon": [
        "network_beacon",      # try different payload
        "network_creds",       # find more creds
        "exploit_chain",       # exploit to get shell
    ],
    "identity_breach": [
        "identity_breach",     # try another breach source
        "identity_phish",      # phish the target
        "identity_osint",      # gather more OSINT
    ],
    "identity_phish": [
        "identity_phish",      # try another channel (SMS vs email)
        "identity_breach",     # re-check breach data
        "identity_osint",      # more OSINT might reveal new targets
    ],
}


class FallbackEngine:
    """Determines the next strategy when the current one fails."""

    def __init__(self, history: Optional[HistoricalLearner] = None) -> None:
        self.history = history
        self.attempts: List[StrategyAttempt] = []

    def record(self, strategy: str, capability: str, target: str,
               ok: bool, reason: str = "", learned: Dict[str, Any] = None,
               elapsed: float = 0.0) -> None:
        """Record outcome of a strategy attempt."""
        attempt = StrategyAttempt(
            strategy=strategy, capability=capability,
            target=target, ok=ok, reason=reason,
            learned=dict(learned or {}), elapsed=elapsed,
        )
        self.attempts.append(attempt)
        if self.history:
            self.history.record(strategy, capability, target, ok)

    def failed_strategies(self) -> Set[str]:
        """Set of strategies that have been tried and failed."""
        return {a.strategy for a in self.attempts if not a.ok}

    def next_strategy(self, current: str, wm: WorldModel) -> Optional[str]:
        """Pick the next strategy to try after `current` failed.

        Returns None if no viable fallback exists.
        """
        chain = FALLBACK_CHAINS.get(current, [])
        failed = self.failed_strategies()

        for candidate in chain:
            if candidate not in failed:
                # Check if candidate makes sense given what we learned
                if self._viable(candidate, wm):
                    return candidate

        # All fallbacks exhausted — try gap analysis
        return self._gap_analysis(wm)

    def _viable(self, strategy: str, wm: WorldModel) -> bool:
        """Is this strategy viable given current WorldModel state?"""
        if strategy == "network_footprint":
            return bool(wm.target)
        if strategy == "exploit_chain":
            return bool(wm.find("service"))
        if strategy == "network_creds":
            return bool(wm.find("service"))
        if strategy == "network_beacon":
            return bool(wm.find("creds")) or bool(wm.find("rce"))
        if strategy == "identity_breach":
            return bool(wm.find("identity"))
        if strategy == "identity_phish":
            return bool(wm.find("identity")) and bool(wm.find("contact"))
        if strategy == "identity_osint":
            return bool(wm.find("identity"))
        return True

    def _gap_analysis(self, wm: WorldModel) -> Optional[str]:
        """When all fallbacks are exhausted: what's missing?"""
        # What do we have?
        has_creds = bool(wm.find("creds"))
        has_exploit = bool(wm.find("exploit_plan")) or bool(wm.find("hunt_anomaly"))
        has_beacon = bool(wm.find("beacon"))
        has_vuln = bool(wm.find("vuln"))

        # Path to beacon
        if has_beacon:
            return None  # Already achieved

        if has_creds:
            return "network_beacon"

        if has_exploit:
            return "exploit_chain"

        if has_vuln:
            return "network_creds"

        # Last resort: manual operator guidance
        return None  # Nothing more the engine can do automatically

    def learned_accounts(self) -> List[str]:
        """Extract valid account names from failed login attempts."""
        accounts = set()
        for a in self.attempts:
            if not a.ok and a.learned.get("valid_accounts"):
                accounts.update(a.learned["valid_accounts"])
        return list(accounts)


# ── historical self-learning ───────────────────────────────────────────

class HistoricalLearner:
    """Cumulative technique success tracking with temporal decay.

    Persists to data/engagement_history.json — Beta-Binomial posteriors
    over time with configurable decay for recency weighting.
    """

    def __init__(self, store_path: str = "",
                 decay_days: float = 90.0) -> None:
        self.store_path = store_path or self._default_path()
        self.decay_days = decay_days
        self.stats: Dict[str, TechniqueStats] = defaultdict(TechniqueStats)
        self._load()

    @staticmethod
    def _default_path() -> str:
        from phantom.utils.paths import data_dir
        return os.path.join(data_dir(), "engagement_history.json")

    def _load(self) -> None:
        try:
            with open(self.store_path, "r") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return

        # Robust against both current (dict of techniques) and legacy
        # (flat list of {technique, success, ...} records) formats, and
        # against any corrupt/foreign payload — never crash on load.
        if isinstance(data, dict):
            techniques = data.get("techniques", {})
            if not isinstance(techniques, dict):
                return
            for key, val in techniques.items():
                if not isinstance(val, dict):
                    continue
                s = TechniqueStats(
                    successes=val.get("successes", 0),
                    failures=val.get("failures", 0),
                    last_used=val.get("last_used", 0.0),
                    target_os_breakdown=val.get("os_breakdown", {})
                    if isinstance(val.get("os_breakdown"), dict) else {},
                )
                self.stats[key] = s
            return
        if isinstance(data, list):
            # legacy flat-record format: fold records into the stats
            for rec in data:
                if not isinstance(rec, dict):
                    continue
                key = rec.get("technique") or rec.get("capability")
                if not key:
                    continue
                s = self.stats[key]
                if rec.get("success"):
                    s.successes += 1
                else:
                    s.failures += 1
                ts = rec.get("timestamp")
                if ts:
                    try:
                        from datetime import datetime
                        s.last_used = max(
                            s.last_used,
                            datetime.fromisoformat(str(ts)).timestamp(),
                        )
                    except (ValueError, TypeError):
                        pass

    def _save(self) -> None:
        import atexit
        os.makedirs(os.path.dirname(self.store_path), exist_ok=True)
        try:
            data = {
                "techniques": {
                    k: {
                        "successes": v.successes,
                        "failures": v.failures,
                        "last_used": v.last_used,
                        "os_breakdown": v.target_os_breakdown,
                    } for k, v in self.stats.items()
                },
                "updated": time.time(),
            }
            with open(self.store_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def record(self, strategy: str, capability: str, target: str,
               ok: bool, os_hint: str = "") -> None:
        """Record a technique outcome."""
        key = capability or strategy
        s = self.stats[key]
        s.last_used = time.time()
        if ok:
            s.successes += 1
        else:
            s.failures += 1

        if os_hint:
            os_key = os_hint.lower()
            wins, total = s.target_os_breakdown.get(os_key, (0, 0))
            s.target_os_breakdown[os_key] = (
                wins + (1 if ok else 0),
                total + 1,
            )

        # Save every 10 records
        if (s.total % 10) == 0:
            self._save()

    def prior(self, capability: str, os_hint: str = "") -> float:
        """Posterior mean success rate for this capability.

        With os_hint: narrow to the OS-specific breakdown if enough samples.
        Fall back to the global posterior.
        """
        s = self.stats.get(capability, TechniqueStats())

        if os_hint:
            os_key = os_hint.lower()
            wins, total = s.target_os_breakdown.get(os_key, (0, 0))
            if total >= 3:  # enough samples for OS-specific prior
                alpha = wins + 1.0
                beta = (total - wins) + 1.0
                return alpha / (alpha + beta)

        if s.total == 0:
            return 0.5  # uniformed Beta(1,1)
        return s.posterior_mean

    def best_alternative(self, capability: str,
                         candidates: List[str]) -> Optional[str]:
        """Among candidates, pick the one with best historical success."""
        best = None
        best_rate = -1.0
        current_rate = self.prior(capability)
        for c in candidates:
            rate = self.prior(c)
            if rate > best_rate and rate > current_rate:
                best_rate = rate
                best = c
        return best

    def summary(self) -> Dict[str, Any]:
        """One-line stats for each technique."""
        items = {}
        for k, v in sorted(self.stats.items()):
            items[k] = {
                "total": v.total,
                "successes": v.successes,
                "failures": v.failures,
                "rate": round(v.posterior_mean, 3),
                "last_used_days": round((time.time() - v.last_used) / 86400, 1) if v.last_used else 0,
            }
        return items

    def to_dict(self) -> dict:
        return {"techniques": self.stats, "updated": time.time()}

    def persist(self) -> None:
        """Force save to disk (called at end of engagement)."""
        self._save()


# ── unified entry point ────────────────────────────────────────────────

def init_historical_learner(store_path: str = "") -> HistoricalLearner:
    """Create or load the cumulative history store."""
    return HistoricalLearner(store_path=store_path)


def engine_summary(fallback: FallbackEngine, history: HistoricalLearner) -> Dict[str, Any]:
    """Combined summary for operator reports."""
    return {
        "attempts": len(fallback.attempts),
        "successful": sum(1 for a in fallback.attempts if a.ok),
        "failed_strategies": list(fallback.failed_strategies()),
        "learned_accounts": fallback.learned_accounts(),
        "technique_stats": history.summary(),
    }