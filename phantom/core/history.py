"""
history.py — Phantom Historical Learning System

Tracks engagement results and provides:
- Technique success/fail statistics
- Alternative technique suggestions
- Temporal decay for old results
"""

import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from phantom.utils.notifier import notifier

HISTORY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "engagement_history.json"
)

# Techniques that are similar - used for suggestion engine
SIMILAR_TECHNIQUES = {
    "exploit_cve_public": ["exploit_default_creds", "exploit_known_vuln"],
    "exploit_default_creds": ["brute_force_passwords", "exploit_cve_public"],
    "brute_force_passwords": ["exploit_default_creds", "exploit_ldap_bind"],
    "kerberoasting": ["asrm_rogue", "ntlm_relay"],
    "ntlm_relay": ["kerberoasting", "smb_relay"],
    "smb_relay": ["ntlm_relay", "kerberoasting"],
    "phishing_spear": ["watering_hole", "supply_chain"],
    "watering_hole": ["phishing_spear", "malvertising"],
    "malvertising": ["watering_hole", "phishing_spear"],
    "powershell_remoting": ["wmi_exec", "winrs"],
    "wmi_exec": ["powershell_remoting", "winrs"],
    "winrs": ["powershell_remoting", "wmi_exec"],
}


class HistoricalAnalyzer:
    """Analyzes historical engagement data to inform future decisions."""

    def __init__(self, history_file: Optional[str] = None):
        self.history_file = history_file or HISTORY_FILE
        self.records: List[Dict[str, Any]] = []
        self._load_history()

    def _load_history(self) -> None:
        if not os.path.exists(self.history_file):
            self.records = []
            return
        try:
            with open(self.history_file, "r") as f:
                data = json.load(f)
        except Exception as e:
            notifier.warn(f"Failed to load engagement history: {e}")
            self.records = []
            return
        # Normalise both formats: flat list of records (ours) and the
        # dict-of-techniques shape written by automations.fallback.
        if isinstance(data, list):
            self.records = [r for r in data if isinstance(r, dict)]
        elif isinstance(data, dict) and isinstance(data.get("techniques"), dict):
            self.records = []
            for technique, val in data["techniques"].items():
                if not isinstance(val, dict):
                    continue
                wins = int(val.get("successes", 0))
                losses = int(val.get("failures", 0))
                for _ in range(wins):
                    self.records.append({"technique": technique,
                                         "target_profile": "",
                                         "success": True})
                for _ in range(losses):
                    self.records.append({"technique": technique,
                                         "target_profile": "",
                                         "success": False})
        else:
            self.records = []

    def _save_history(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
            with open(self.history_file, "w") as f:
                json.dump(self.records, f, indent=2)
        except Exception as e:
            notifier.warn(f"Failed to save engagement history: {e}")

    def record_attempt(self, technique: str, target_profile: str,
                       success: bool, metadata: Optional[Dict] = None) -> None:
        """Record a technique attempt outcome."""
        entry = {
            "technique": technique,
            "target_profile": target_profile,
            "success": success,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {},
        }
        self.records.append(entry)
        self._save_history()
        notifier.info(f"Recorded attempt: {technique} on {target_profile} = {'success' if success else 'fail'}")

    def should_avoid(self, technique: str, target_profile: str,
                     failure_threshold: int = 3) -> bool:
        """
        Determine if a technique should be avoided based on failure history.
        Returns True if failed >= failure_threshold times on similar profiles.
        """
        failures = 0
        recent_window = datetime.now() - timedelta(days=90)

        for record in self.records:
            if (record["technique"] == technique and
                record["target_profile"] == target_profile and
                not record["success"]):
                try:
                    ts = datetime.fromisoformat(record["timestamp"])
                    if ts >= recent_window:
                        failures += 1
                except Exception:
                    failures += 1

        return failures >= failure_threshold

    def suggest_alternative(self, failed_technique: str,
                            target_profile: str) -> Optional[str]:
        """
        Suggest an alternative technique based on similar techniques
        that have succeeded on this target profile.
        """
        similar = SIMILAR_TECHNIQUES.get(failed_technique, [])
        best_alternative = None
        best_success_rate = 0.0

        recent_window = datetime.now() - timedelta(days=180)

        for alt in similar:
            successes = 0
            total = 0
            for record in self.records:
                if (record["technique"] == alt and
                    record["target_profile"] == target_profile):
                    try:
                        ts = datetime.fromisoformat(record["timestamp"])
                        if ts >= recent_window:
                            total += 1
                            if record["success"]:
                                successes += 1
                    except Exception:
                        total += 1
                        if record["success"]:
                            successes += 1

            if total > 0:
                rate = successes / total
                if rate > best_success_rate:
                    best_success_rate = rate
                    best_alternative = alt

        return best_alternative

    def suggest_alternative_phase(self, failed_phase: str, target_profile: str) -> Optional[str]:
        """
        Suggest an alternative phase based on successful phases that ran
        after similar failures in previous engagements.
        """
        # Phases that could be alternatives based on kill chain flow
        phase_fallbacks = {
            "cve_correlate": ["test_creds", "web_recon", "social_recon"],
            "test_creds": ["social_recon", "breach_check", "web_recon"],
            "deploy_beacon": ["persistence", "osint", "scan"],
            "persistence": ["deploy_beacon", "scan", "web_recon"],
            "web_recon": ["social_recon", "osint", "cve_correlate"],
            "scan": ["osint", "social_recon"],
        }

        alternatives = phase_fallbacks.get(failed_phase, [])
        best_alt = None
        best_rate = 0.0

        recent_window = datetime.now() - timedelta(days=180)

        for alt in alternatives:
            relevant = [
                r for r in self.records
                if r.get("metadata", {}).get("phase") == alt
                and r.get("target_profile") == target_profile
            ]
            if not relevant:
                continue

            recent = []
            for r in relevant:
                try:
                    ts = datetime.fromisoformat(r["timestamp"])
                    if ts >= recent_window:
                        recent.append(r)
                except Exception:
                    recent.append(r)

            if not recent:
                continue

            successes = sum(1 for r in recent if r["success"])
            rate = successes / len(recent)

            if rate > best_rate:
                best_rate = rate
                best_alt = alt

        return best_alt

    def get_statistics(self, target_profile: Optional[str] = None,
                       days: int = 90) -> Dict[str, Any]:
        """Get engagement statistics for a target profile or all targets."""
        cutoff = datetime.now() - timedelta(days=days)
        relevant = []

        for record in self.records:
            try:
                ts = datetime.fromisoformat(record["timestamp"])
                if ts >= cutoff:
                    if target_profile is None or record["target_profile"] == target_profile:
                        relevant.append(record)
            except Exception:
                relevant.append(record)

        if not relevant:
            return {"total": 0, "successes": 0, "failures": 0, "success_rate": 0.0}

        successes = sum(1 for r in relevant if r["success"])
        total = len(relevant)

        return {
            "total": total,
            "successes": successes,
            "failures": total - successes,
            "success_rate": round(successes / total, 3) if total > 0 else 0.0,
        }

    def get_technique_stats(self, technique: str) -> Dict[str, Any]:
        """Get detailed statistics for a specific technique."""
        relevant = [r for r in self.records if r["technique"] == technique]
        total = len(relevant)
        successes = sum(1 for r in relevant if r["success"])

        return {
            "technique": technique,
            "total_attempts": total,
            "successes": successes,
            "failures": total - successes,
            "success_rate": round(successes / total, 3) if total > 0 else 0.0,
        }

    def get_recommendation_for_phase(self, phase: str, target_profile: str) -> Dict[str, Any]:
        """
        Get recommendation for whether to execute a phase based on
        historical success rates for that phase on similar target profiles.

        Returns: {"use": bool, "reason": str, "success_rate": float}
        """
        relevant = [
            r for r in self.records
            if r.get("metadata", {}).get("phase") == phase
            and r.get("target_profile") == target_profile
        ]

        if not relevant:
            return {"use": True, "reason": "No historical data", "success_rate": None}

        total = len(relevant)
        successes = sum(1 for r in relevant if r["success"])
        rate = successes / total if total > 0 else 0.0

        # If less than 10% success rate with > 3 attempts, skip
        if total >= 3 and rate < 0.10:
            return {"use": False, "reason": f"Low historical success rate ({rate:.1%})", "success_rate": rate}

        return {"use": True, "reason": f"Historical success rate: {rate:.1%}", "success_rate": rate}


# Global instance
history_analyzer = HistoricalAnalyzer()
