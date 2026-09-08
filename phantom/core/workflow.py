"""
workflow.py — Phantom Modular Kill Chain Workflow Manager
┌────────────────────────────────────────────────────────
Encapsulates the auto-mode kill chain as a configurable
workflow of phases. Each phase is a callable that returns
bool indicating success/failure.
"""

import os
import json
from datetime import datetime
from typing import Optional, Dict, List, Any, Callable
from dataclasses import dataclass, field

from phantom.core.session import session, KB_STATUS_DEFAULT
from phantom.utils.notifier import notifier
from phantom.core.attack_mapping import attack_mapper, AttackTechnique
from phantom.core.risk_engine import risk_engine, RiskProfile
from phantom.core.history import history_analyzer
from phantom.core.calibration import calibration_engine
from phantom.core.threatintel import threat_intel


@dataclass
class WorkflowResult:
    name: str
    success: bool
    error: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# Default workflow phases
DEFAULT_PHASES = {
    "ip": [
        "classify",
        "scan",
        "os_detect",
        "osint",
        "web_recon",
        "cve_correlate",
        "test_creds",
        "deploy_beacon",
        "persistence",
    ],
    "domain": [
        "classify",
        "scan",
        "os_detect",
        "osint",
        "web_recon",
        "cve_correlate",
        "test_creds",
        "deploy_beacon",
        "persistence",
    ],
    "url": [
        "classify",
        "scan",
        "web_recon",
        "osint",
        "cve_correlate",
        "test_creds",
        "deploy_beacon",
        "persistence",
    ],
    "email": [
        "classify",
        "breach_check",
        "social_recon",
        "osint",
    ],
    "username": [
        "classify",
        "social_recon",
        "breach_check",
        "osint",
    ],
}

# Status key mapping
STATUS_KEY_MAP = {
    "classify": "classified",
    "scan": "scan_done",
    "os_detect": "os_detected",
    "osint": "osint_done",
    "web_recon": "web_recon_done",
    "social_recon": "social_recon_done",
    "breach_check": "breach_check_done",
    "cve_correlate": "cve_correlate_done",
    "test_creds": "default_creds_tested",
    "deploy_beacon": "rce_attempted",
    "persistence": "persistence_set",
}

# Adaptive scoring weights
SCORING_CONFIG = {
    "scan": 2.0,          # pts per service found
    "os_detect": 0.5,     # pts per accuracy %
    "cve_correlate": 3.0, # pts per CVE + 5 for high-risk
    "test_creds": 5.0,    # pts per credential
    "web_recon": 4.0,     # pts per endpoint
    "social_recon": 3.0,  # pts per profile
    "breach_check": 10.0, # pts per breach
}


class WorkflowManager:
    """
    Manages the execution of a modular kill chain workflow.
    
    Features:
    - Configurable phase sequences per target type
    - Adaptive priority scoring based on findings
    - Failure handling with configurable retry/skipping
    - Result tracking and reporting
    """

    def __init__(self, phases: Optional[Dict[str, List[str]]] = None):
        self.phases = phases or dict(DEFAULT_PHASES)
        self.results: List[WorkflowResult] = []
        self._executors: Dict[str, Callable] = {}

    def register_executor(self, phase: str, fn: Callable) -> None:
        """Register an executor function for a phase."""
        self._executors[phase] = fn

    def get_phases(self, target_type: str) -> List[str]:
        """Get the phase sequence for a target type."""
        return self.phases.get(target_type, self.phases.get("ip", []))

    def execute_phase(self, phase: str) -> WorkflowResult:
        """Execute a single phase by name."""
        notifier.status(f"[workflow] Executing phase: {phase}")

        kb = session.knowledge_base
        status = kb.get("status", {})
        status_key = STATUS_KEY_MAP.get(phase)

        executor = self._executors.get(phase)
        if not executor:
            if status_key:
                status[status_key] = True

            return WorkflowResult(
                name=phase,
                success=False,
                error=f"No executor registered for phase '{phase}'",
            )

        try:
            result = executor()
            outcome = WorkflowResult(
                name=phase,
                success=bool(result),
            )
        except Exception as e:
            outcome = WorkflowResult(
                name=phase,
                success=False,
                error=str(e),
            )

        # Mark the phase as attempted (success or not) so decide_next
        # makes progress and cannot loop forever on a failing phase.
        if status_key:
            status[status_key] = True

        return outcome

    def _score_adaptive(self, kb: Dict) -> Dict[str, float]:
        """Compute adaptive priority scores for pending phases using
        threat intel, historical data, ATT&CK mapping, and risk engine."""
        scores: Dict[str, float] = {}

        services = kb.get("services", [])
        os_info = kb.get("os_info", {})
        cves = kb.get("cves", [])
        creds = kb.get("creds_found", [])
        endpoints = kb.get("web_endpoints", [])
        social = kb.get("social_profiles", [])
        breaches = kb.get("breaches_found", [])
        target_profile = kb.get("target_type", "ip")

        # ── Base scoring (calibrated weights) ────────────────────────────────
        w = calibration_engine.get_weight

        scores["scan"] = min(len(services) * w("services_found"), 20.0)
        accuracy = os_info.get("accuracy", 0)
        scores["os_detect"] = min(float(accuracy) * w("os_accuracy"), 20.0)

        # CVE scoring with threat intel
        cve_score = 0.0
        for cve in cves:
            base_score = cve.get("score", cve.get("cvss", 0))
            cve_score += base_score * w("cve_exploitability")

            # Check if CVE is recently exploited in the wild
            ti_result = self._check_ti_exploited(cve.get("id", ""))
            if ti_result.get("exploited"):
                cve_score += ti_result.get("confidence", 0) * 0.3

            # High-risk bonus
            if base_score >= 70:
                cve_score += w("cve_high_risk")

            # Active exploitation in wild
            if cve.get("recent_exploit"):
                cve_score += w("recent_exploit_in_wild")

        scores["cve_correlate"] = min(cve_score, 40.0)

        scores["test_creds"] = min(
            len(creds) * w("cred_harvested"),
            w("domain_admin") if any(c.get("domain_admin") for c in creds) else 20.0,
        )
        scores["web_recon"] = min(len(endpoints) * w("web_endpoint"), 15.0)
        scores["social_recon"] = min(len(social) * w("social_profile"), 15.0)
        scores["breach_check"] = min(len(breaches) * w("breach_correlated"), 20.0)

        # ── ATT&CK phase priority boost ──────────────────────────────────────
        if services:
            techniques = attack_mapper.map_services_to_techniques(services)
            phase_priority = attack_mapper.calculate_phase_priority(techniques)

            # Boost phases aligned with high-priority attack techniques
            kill_chain_map = {
                "initial_access": ["cve_correlate", "test_creds", "web_recon"],
                "lateral_movement": ["deploy_beacon", "persistence"],
                "privilege_escalation": ["os_detect", "cve_correlate"],
                "credential_access": ["test_creds", "social_recon", "breach_check"],
                "discovery": ["scan", "osint"],
            }

            for phase, techniques_in_phase in phase_priority.items():
                if phase in kill_chain_map:
                    boost = techniques_in_phase * 0.3
                    for mapped_phase in kill_chain_map[phase]:
                        scores[mapped_phase] = scores.get(mapped_phase, 0) + boost

        # ── Historical learning adjustments ──────────────────────────────────
        # Apply historical success rates to adjust scores
        for phase in list(scores.keys()):
            recommendation = history_analyzer.get_recommendation_for_phase(phase, target_profile)
            if not recommendation.get("use", True):
                scores[phase] -= 50.0  # Strongly deprioritize

        return scores

    def _check_ti_exploited(self, cve_id: str) -> Dict[str, Any]:
        """Check threat intel for recent CVE exploitation."""
        try:
            return threat_intel.is_recently_exploited(cve_id)
        except Exception:
            return {"exploited": False, "confidence": 0.0}

    def decide_next(self, target_type: str) -> Optional[str]:
        """Determine the next phase to execute based on KB and adaptive scoring."""
        phases = self.get_phases(target_type)
        kb = session.knowledge_base
        status = kb.get("status", {})

        # Find pending phases
        pending = []
        for phase in phases:
            status_key = STATUS_KEY_MAP.get(phase)
            if status_key and not status.get(status_key, False):
                pending.append(phase)

        if not pending:
            return None

        # Sort by adaptive score (higher = more important)
        scores = self._score_adaptive(kb)
        services = kb.get("services", [])
        creds = kb.get("creds_found", [])

        def _priority(phase: str) -> tuple:
            base = scores.get(phase, 0.0)

            # ── Enterprise Threat Intelligence Scoring ──────────────────────
            cves = kb.get("cves", [])
            if phase == "cve_correlate":
                # Check for CVEs with recent exploit activity (7d window)
                from datetime import datetime, timedelta
                recent_cves = [
                    c for c in cves
                    if (c.get("score", 0) >= 70)
                    and c.get("recent_exploit", False)
                ]
                if recent_cves:
                    base += 25.0  # High priority: active exploitation in the wild
                # Critical infrastructure boost
                if kb.get("critical_infrastructure", False):
                    base += 15.0

            if phase == "deploy_beacon":
                # Enterprise context: check network segmentation
                if kb.get("network_segmentation"):
                    seg_info = kb.get("network_segmentation", {})
                    if seg_info.get("isolated_network"):
                        base += 10.0  # Harder to reach, prioritize persistence first
                # Active Directory environment
                if kb.get("domain_environment"):
                    base += 10.0
                # High-value asset detection
                critical_assets = kb.get("critical_assets", [])
                if critical_assets:
                    base += 5.0 * len(critical_assets)

            if phase == "persistence":
                # Skip persistence if beacon not yet deployed
                if not kb.get("beacon_deployed", False) and not creds:
                    base -= 50.0
                # Enterprise: multi-persistence for high-value targets
                if kb.get("critical_infrastructure") or kb.get("domain_environment"):
                    base += 15.0

            if phase == "test_creds":
                # Enterprise password policy indicators
                if kb.get("password_policy"):
                    policy = kb.get("password_policy", {})
                    if policy.get("min_length", 0) < 10:
                        base += 5.0  # Weak policy = higher cred success chance
                    if not policy.get("multi_factor", True):
                        base += 10.0  # No MFA = critical
                # Check for known default creds in scope
                if kb.get("known_defaults"):
                    base += 10.0

            if phase == "web_recon":
                # Enterprise: check for WAF/WAF bypass needed
                web_services = [
                    s for s in services
                    if s.get("service") in ("http", "https", "http-proxy")
                    or s.get("port") in ("80", "443", "8080", "8443")
                ]
                if web_services:
                    base += 5.0 * len(web_services)
                else:
                    base -= 15.0
                # WAF detected increases priority
                if kb.get("waf_detected"):
                    base += 20.0

            if phase == "osint":
                # Enterprise: subprocessor/integrated tool OSINT priority
                if kb.get("domain_enumerated"):
                    base += 10.0
                subdomains = kb.get("subdomains_found", [])
                if subdomains:
                    base += 3.0 * len(subdomains)

            if phase == "social_recon":
                emails = kb.get("emails_found", [])
                if emails:
                    base += 5.0 * len(emails)
                social = kb.get("social_profiles", [])
                if social:
                    base += 3.0 * len(social)

            if phase == "breach_check":
                # Correlate with known breach patterns
                breaches = kb.get("breaches_found", [])
                if breaches:
                    base += 15.0 * len(breaches)  # Credential spill = escalate

            # ── Dependency Chain ────────────────────────────────────────────
            # Some phases require results from others
            if phase == "cve_correlate" and not services:
                base -= 30.0  # Need services first
            if phase == "deploy_beacon" and not kb.get("status", {}).get("os_detected") and not creds:
                base -= 40.0  # Need OS or creds

            return (-base, phases.index(phase))

        pending.sort(key=_priority)
        return pending[0]

    def _record_feedback(self, phase: str, success: bool) -> None:
        """Feed engagement outcomes into calibration and history engines."""
        target_profile = session.knowledge_base.get("target_type", "ip")
        history_analyzer.record_attempt(
            technique=phase,
            target_profile=target_profile,
            success=success,
            metadata={"phase": phase},
        )
        calibration_engine.observe(phase, success)
        for weight_key in self._feedback_weight_map(phase):
            calibration_engine.observe_weight(weight_key, success)

    @staticmethod
    def _feedback_weight_map(phase: str) -> List[str]:
        """Map a phase to the calibration weight keys it provides evidence for."""
        mapping = {
            "scan": ["services_found"],
            "os_detect": ["os_accuracy"],
            "cve_correlate": ["cve_exploitability", "cve_high_risk"],
            "test_creds": ["cred_harvested", "domain_admin"],
            "web_recon": ["web_endpoint"],
            "social_recon": ["social_profile"],
            "breach_check": ["breach_correlated"],
        }
        return mapping.get(phase, [])

    def run_workflow(
        self,
        target: str,
        stealth: bool = True,
        aggressive: bool = False,
        stop_on_failure: bool = False,
    ) -> List[WorkflowResult]:
        """Execute the full workflow for a target."""
        session.target = target
        kb = session.knowledge_base
        kb["target"] = target
        kb["stealth"] = stealth
        kb["aggressive"] = aggressive
        kb["started_at"] = datetime.now().isoformat()

        notifier.success("=== PHANTOM WORKFLOW EXECUTION ===")
        notifier.info(f"Target: {target}")

        start_time = datetime.now()
        self.results = []

        # Safety cap: at most 3 attempts per phase in the sequence, so a
        # misbehaving executor can never stall the workflow indefinitely.
        phases = self.get_phases(kb.get("target_type", "ip"))
        max_steps = max(len(phases) * 3, 10)

        while max_steps > 0:
            max_steps -= 1
            phase = self.decide_next(kb.get("target_type", "ip"))
            if phase is None:
                break

            result = self.execute_phase(phase)
            self.results.append(result)
            self._record_feedback(phase, result.success)

            if not result.success:
                if stop_on_failure:
                    notifier.error(f"Workflow stopped at phase: {phase}")
                    break
                notifier.warn(f"Phase '{phase}' failed, continuing...")
        else:
            notifier.warn("Workflow safety cap reached; aborting to avoid an infinite loop.")

        elapsed = (datetime.now() - start_time).total_seconds()
        notifier.success(f"=== WORKFLOW COMPLETE in {elapsed:.0f}s ===")
        return self.results

    def export_results(self) -> Dict[str, Any]:
        """Export workflow results as structured data."""
        return {
            "target": session.target,
            "results": [r.__dict__ for r in self.results],
            "kb": session.knowledge_base,
        }


# Global instance
workflow_manager = WorkflowManager()
