"""
calibration.py - Phantom Calibration Engine

Uses Bayesian updating to calibrate scoring weights
based on historical engagement success/failure rates.
"""

import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from math import sqrt

from phantom.utils.notifier import notifier

WEIGHTS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "calibrated_weights.json"
)

INITIAL_WEIGHTS = {
    "services_found": 2.0,
    "cve_exploitability": 3.0,
    "cve_high_risk": 5.0,
    "cred_harvested": 5.0,
    "domain_admin": 20.0,
    "critical_asset": 15.0,
    "network_segmentation": 8.0,
    "lateral_movement_vector": 10.0,
    "waf_detected": 12.0,
    "breach_correlated": 15.0,
    "os_accuracy": 0.5,
    "web_endpoint": 4.0,
    "social_profile": 3.0,
    "recent_exploit_in_wild": 25.0,
}


class CalibrationEngine:
    """
    Calibrates scoring weights using Bayesian-inspired updating.

    Weights are points-per-evidence values (e.g. 3.0 pts per CVE). The
    update is RELATIVE and BOUNDED: a success rate above the global
    baseline moves the weight up (max +100% per observation batch),
    below the baseline moves it down (min -50%). A pseudo-count `alpha`
    controls how much trust to place in the new observation (more
    observations -> more trust).

    Success rates per technique are tracked with a Beta-style posterior
    and exposed through `confidence_interval()` (Wilson score interval).
    """

    def __init__(self, weights_file: Optional[str] = None):
        self.weights_file = weights_file or WEIGHTS_FILE
        self.weights = dict(INITIAL_WEIGHTS)
        self.observations: Dict[str, Dict[str, int]] = {}
        self.alpha = 10.0
        self._load_state()

    def _load_state(self) -> None:
        if not os.path.exists(self.weights_file):
            return
        try:
            with open(self.weights_file, "r") as f:
                data = json.load(f)
            self.weights = data.get("weights", self.weights)
            self.observations = data.get("observations", {})
            notifier.info(f"Loaded {len(self.weights)} calibrated weights")
        except Exception as e:
            notifier.warn(f"Failed to load calibration state: {e}")

    def _save_state(self) -> None:
        data = {
            "weights": self.weights,
            "observations": self.observations,
            "last_updated": datetime.now().isoformat(),
        }
        try:
            os.makedirs(os.path.dirname(self.weights_file), exist_ok=True)
            with open(self.weights_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            notifier.warn(f"Failed to save calibration state: {e}")

    def get_weight(self, key: str) -> float:
        return self.weights.get(key, 1.0)

    def _global_baseline(self, exclude: Optional[str] = None) -> float:
        """Overall success rate across all observed techniques (excluding one)."""
        total_s = 0
        total_f = 0
        for key, o in self.observations.items():
            if exclude is not None and key == exclude:
                continue
            total_s += o["successes"]
            total_f += o["failures"]
        total = total_s + total_f
        return (total_s / total) if total > 0 else 0.5

    def _update_weight(self, key: str, successes: int, failures: int,
                       obs_key: Optional[str] = None) -> float:
        """Apply the bounded relative update to a weight and return it."""
        total = successes + failures
        current = self.weights.get(key, 1.0)
        if total == 0:
            return current

        rate = successes / total
        baseline = max(self._global_baseline(exclude=obs_key or key), 0.01)
        adjustment = max(-1.0, min(1.0, (rate - baseline) / baseline))

        # Trust grows with the number of observations (alpha pseudo-count).
        trust = self.alpha / (self.alpha + total)
        new = current * (1.0 + trust * adjustment * 0.2)

        # Absolute bounds: never drift beyond [50%, 200%] of the initial weight.
        initial = INITIAL_WEIGHTS.get(key, 1.0)
        new = min(max(new, initial * 0.5), initial * 2.0)
        return round(new, 3)

    def observe(self, technique: str, success: bool) -> None:
        if technique not in self.observations:
            self.observations[technique] = {"successes": 0, "failures": 0}

        if success:
            self.observations[technique]["successes"] += 1
        else:
            self.observations[technique]["failures"] += 1

        obs = self.observations[technique]
        self.weights[technique] = self._update_weight(
            technique, obs["successes"], obs["failures"]
        )
        self._save_state()

    def observe_weight(self, weight_key: str, success: bool) -> None:
        """Calibrate a scoring weight directly from an engagement outcome.

        Used by the workflow engine to feed phase results back into the
        evidence weights (e.g. 'services_found', 'cve_exploitability').
        """
        obs = self.observations.get(f"__w__:{weight_key}")
        if obs is None:
            obs = {"successes": 0, "failures": 0}
            self.observations[f"__w__:{weight_key}"] = obs

        if success:
            obs["successes"] += 1
        else:
            obs["failures"] += 1

        self.weights[weight_key] = self._update_weight(
            weight_key, obs["successes"], obs["failures"],
            obs_key=f"__w__:{weight_key}",
        )
        self._save_state()

    def confidence_interval(self, technique: str, confidence: float = 0.95) -> tuple:
        """
        Calculate confidence interval for a technique's success rate.
        Uses Wilson score interval (valid for small samples).
        Returns (lower_bound, upper_bound)
        """
        import math
        obs = self.observations.get(technique, {"successes": 0, "failures": 0})
        total = obs["successes"] + obs["failures"]

        if total == 0:
            return (0.0, 1.0)

        z = {0.90: 1.645, 0.95: 1.96, 0.99: 2.576}.get(confidence, 1.96)
        p = obs["successes"] / total
        n = total

        denominator = 1 + z * z / n
        centre = (p + z * z / (2 * n)) / denominator
        spread = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / denominator

        lower = max(0.0, centre - spread)
        upper = min(1.0, centre + spread)
        return (round(lower, 3), round(upper, 3))

    def recalibrate(self, engagement_results: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Bulk recalibrate from a set of engagement results.
        Each result: {"technique": str, "success": bool, "confidence": float}
        """
        for result in engagement_results:
            technique = result.get("technique", "")
            success = result.get("success", False)
            self.observe(technique, success)

        notifier.success(f"Calibration complete: {len(self.observations)} techniques recalibrated")
        return self.weights

    def get_recommendation(self, technique: str) -> Dict[str, Any]:
        """
        Get a recommendation for whether to use a technique based on calibration data.
        Returns: {"use": bool, "confidence": float, "reason": str}
        """
        obs = self.observations.get(technique)
        if not obs:
            return {
                "use": True,
                "confidence": 0.0,
                "reason": "No historical data, using default scoring",
            }

        total = obs["successes"] + obs["failures"]
        if total == 0:
            return {"use": True, "confidence": 0.0, "reason": "No observations"}

        success_rate = obs["successes"] / total
        ci_lower, ci_upper = self.confidence_interval(technique)

        should_use = success_rate > 0.15  # At least 15% success threshold
        # Narrower interval (more data / less uncertainty) -> higher confidence.
        confidence = round(100.0 * (1.0 - (ci_upper - ci_lower)), 1)

        reason = f"Historical success rate: {success_rate:.1%} ({obs['successes']}/{total})"
        if ci_upper - ci_lower > 0.4:
            reason += ", but low confidence (small sample)"

        return {
            "use": should_use,
            "confidence": confidence,
            "reason": reason,
        }


# Global instance
calibration_engine = CalibrationEngine()
