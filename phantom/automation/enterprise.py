"""
enterprise.py — enterprise scoring wired into the autonomous agent.

Bridges the core enterprise modules (risk engine, MITRE ATT&CK mapping)
into the agent's decision loop:

  * assessment  — maps discovered services to ATT&CK techniques and target
                  risk, registered as findings for the report (MITRE mapping
                  + composite risk score). Offline-safe: the threat-intel
                  prevalence behind the mapper is a static heuristic table.
  * learning    — a bounded success-rate prior per capability that blends
                  TWO sources and stays regret-bounded in a [0.5x, 1.5x]
                  band around the base priority:
                    (1) the in-run rate of THIS engagement (calibration-
                        lite, memory only), and
                    (2) the disk-persisted Bayesian calibration written by
                        PREVIOUS engagements (data/calibrated_weights.json,
                        technique-level). The read path is lazy + cached and
                        never writes — the hot loop must not touch disk;
                        persist() flushes this run's outcomes once at the
                        end. Together this closes the learning loop: what
                        worked on past campaigns tilts the next planner.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from phantom.automation.belief import WorldModel


class EnterpriseBrain:
    """Enterprise scoring for one agent run (no disk, no console noise)."""

    def __init__(self, profile: str = "enterprise",
                 threat_intel=None) -> None:
        self.profile = profile
        self._stats: Dict[str, List[int]] = {}  # capability id -> [ok, fail]
        # lazy imports keep agent startup light; the modules are offline-safe
        self._risk = None
        self._mapper = None
        # disk-prior cache: capability id -> calibration multiplier (lazy,
        # loaded once from the previous engagements' calibrated weights)
        self._disk_mult: Dict[str, float] = {}
        self._calibration = None  # lazy CalibrationEngine ref (or False)
        # Optional ThreatIntelFeed (NVD/OTX/CISA KEV): enriches the report
        # with "exploited in the wild" and boosts recently-exploited CVEs.
        self._threat_intel_feed = threat_intel

    def cve_threat(self, cve_id: str) -> Dict[str, Any]:
        """Exploitation-in-the-wild status for a CVE. Returns a safe
        "not exploited" verdict when no threat-intel feed was wired in
        (so the agent never hits the network in tests/default runs)."""
        if self._threat_intel_feed is None or not cve_id:
            return {"exploited": False, "confidence": 0.0, "source": ""}
        try:
            info = self._threat_intel_feed.is_recently_exploited(cve_id)
            return {
                "exploited": bool(info.get("exploited")),
                "confidence": round(float(info.get("confidence", 0.0)), 1),
                "source": info.get("source", ""),
            }
        except Exception:
            return {"exploited": False, "confidence": 0.0, "source": ""}

    def assess_services(self, services: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Map discovered services to ATT&CK techniques + composite risk,
        without a WorldModel (used by the MANUAL modules so operator-driven
        engagements get the same enterprise scoring as the agent).

        ``services``: list of dicts with at least ``service`` (and optionally
        ``port``/``product``). Returns {"techniques": [...], "risk": float}.
        """
        techniques: List[Any] = []
        try:
            if services:
                techniques = self._attack_mapper().map_services_to_techniques(services)
        except Exception:
            techniques = []
        risk = 0.0
        for s in services:
            name = s.get("service") or s.get("product") or ""
            try:
                crit = self._risk_engine().get_service_criticality(name)
            except Exception:
                crit = 0.0
            risk = max(risk, crit)
        return {
            "techniques": [
                {"id": t.id, "name": t.name, "tactic": t.tactic,
                 "phase": t.kill_chain_phase,
                 "prevalence": t.prevalence_score,
                 "detection_rate": t.detection_rate}
                for t in techniques
            ],
            "risk": round(risk, 1),
        }

    # ------------------------------------------------------------- internals

    def _risk_engine(self):
        if self._risk is None:
            from phantom.core.risk_engine import RiskEngine
            self._risk = RiskEngine()
        return self._risk

    def _attack_mapper(self):
        if self._mapper is None:
            from phantom.core.attack_mapping import AttackMapper
            self._mapper = AttackMapper()
        return self._mapper

    # ------------------------------------------------------------- learning

    def record(self, capability_id: str, ok: bool) -> None:
        """Record one real attempt of a capability (called only after the
        capability actually ran — never for deferrals/blocks)."""
        s, f = self._stats.get(capability_id, (0, 0))
        if ok:
            s += 1
        else:
            f += 1
        # cap growth: decay old observations so the prior tracks recency
        if s + f > 100:
            s, f = s // 2, f // 2
        self._stats[capability_id] = [s, f]

    def _calibration_engine(self):
        """Lazy handle to the disk-persisted calibration engine (module
        singleton). Read-only in the hot path: load once, then cache the
        per-capability multipliers in memory."""
        if self._calibration is None:
            try:
                from phantom.core.calibration import calibration_engine
                self._calibration = calibration_engine
            except Exception:
                self._calibration = False
        return self._calibration or None

    def _disk_multiplier(self, capability_id: str) -> float:
        """Cross-engagement multiplier from calibrated weights (written by
        previous runs via persist()). Default 1.0 = neutral; clamped to the
        same [0.5x, 1.5x] band as the in-run prior so a single historic
        outlier can never dominate a fresh engagement."""
        m = self._disk_mult.get(capability_id)
        if m is not None:
            return m
        eng = self._calibration_engine()
        m = 1.0
        if eng is not None:
            try:
                w = float(eng.get_weight(self._technique_for(capability_id)))
                if w > 0:
                    m = min(1.5, max(0.5, w))
            except Exception:
                m = 1.0
        self._disk_mult[capability_id] = m
        return m

    def prior(self, capability_id: str, category: str, base: float) -> float:
        """Adjust a base priority with the blended success-rate prior.

        Combines the in-run success rate (this engagement) with the
        calibrated weights of PREVIOUS engagements; the product is bounded
        to [0.5x, 1.5x] and untouched until the capability has been
        attempted at least once (in-run). Post-exploitation capabilities
        keep their own ordering (the caller applies the post penalty AFTER
        this)."""
        s, f = self._stats.get(capability_id, (0, 0))
        total = s + f
        if total == 0:
            # never attempted in this run: only the historic prior applies
            return base * self._disk_multiplier(capability_id)
        rate = s / total
        m = (0.5 + rate) * self._disk_multiplier(capability_id)
        return base * min(1.5, max(0.5, m))

    def success_rate(self, capability_id: str) -> Optional[float]:
        s, f = self._stats.get(capability_id, (0, 0))
        total = s + f
        return round(s / total, 3) if total else None

    # ----------------------------------------------------------- assessment

    def assess(self, wm: WorldModel) -> Dict[str, Any]:
        """Map open services to MITRE ATT&CK techniques and compute the
        composite target risk; register both as findings (idempotent)."""
        services = [f.value for f in wm.find("service")
                    if isinstance(f.value, dict)]
        techniques: List[Any] = []
        phase_priorities: Dict[str, float] = {}
        try:
            if services:
                mapper = self._attack_mapper()
                techniques = mapper.map_services_to_techniques(services)
                phase_priorities = mapper.calculate_phase_priority(techniques)
        except Exception:
            techniques = []
            phase_priorities = {}

        for t in techniques:
            wm.add_finding(
                "attack_technique", t.id,
                {"id": t.id, "name": t.name, "tactic": t.tactic,
                 "phase": t.kill_chain_phase,
                 "prevalence": t.prevalence_score,
                 "detection_rate": t.detection_rate},
                confidence=0.7, source="attack_mapping")

        # threat intel: mark known-CVE findings as exploited-in-the-wild so
        # the report can rank them by live priority (KEV/OTX/NVD heuristics)
        self._enrich_cve_findings(wm)

        risk = self._target_risk(wm, services)
        wm.add_finding(
            "target_risk", "overall",
            {"score": risk, "service_count": len(services),
             "ad": bool(wm.find("ad_domain") or wm.find("ad_hint"))},
            confidence=0.7, source="risk_engine")

        return {"techniques": techniques,
                "phase_priorities": phase_priorities,
                "risk": risk}

    def _enrich_cve_findings(self, wm: WorldModel) -> None:
        """Annotate exploit_plan / vuln findings with threat-intel status."""
        if self._threat_intel_feed is None:
            return
        for kind in ("exploit_plan", "vuln"):
            for f in wm.find(kind):
                if not isinstance(f.value, dict):
                    continue
                cve = f.value.get("cve") or f.value.get("cve_id")
                if not cve:
                    continue
                status = self.cve_threat(str(cve))
                f.value["recently_exploited"] = status["exploited"]
                f.value["exploit_confidence"] = status["confidence"]
                f.value["exploit_source"] = status["source"]

    def persist(self, calibration=None, history=None) -> Dict[str, Any]:
        """Flush this run's per-capability outcomes to the DISK-persisted
        learning engines (Bayesian calibration + historical analyzer).

        Called once at the END of a run — never in the hot loop. The
        calibration/history engines are injected (or the module globals) so
        tests can point them at temp files.
        """
        from phantom.core.calibration import CalibrationEngine, calibration_engine
        from phantom.core.history import HistoricalAnalyzer, history_analyzer
        cal = calibration or calibration_engine
        hist = history or history_analyzer
        recorded = 0
        for cap_id, (s, f) in self._stats.items():
            if s + f == 0:
                continue
            technique = self._technique_for(cap_id)
            # Bayesian weight calibration: one observation per attempt
            try:
                for _ in range(s):
                    cal.observe(technique, True)
                for _ in range(f):
                    cal.observe(technique, False)
            except Exception:
                pass
            # historical record: aggregate outcome for the profile
            try:
                hist.record_attempt(technique, self.profile, s > f)
            except Exception:
                pass
            recorded += 1
        return {"techniques_recorded": recorded}

    @staticmethod
    def _technique_for(capability_id: str) -> str:
        """Canonical MITRE-ish technique label for a capability (stable keys
        so calibration/history aggregate across runs)."""
        return {
            "scan_tcp": "network_service_scanning",
            "version_detect": "service_fingerprinting",
            "os_detect": "os_fingerprinting",
            "service_exploit": "exploit_cve_public",
            "hunt_web": "bug_class_hunting",
            "ssh_login": "brute_force_passwords",
            "beacon_deploy": "beacon_deploy",
            "persistence_install": "persistence",
            "privesc_system": "privesc",
            "privesc_sudo": "privesc",
            "privesc_service_perms": "privesc",
            "inject_beacon": "process_injection",
            "ad_enum": "ad_enumeration",
            "kerberoast": "kerberoasting",
            "as_rep_roast": "as_rep_roasting",
            "dc_sync": "dc_sync",
            "hash_crack": "hash_cracking",
            "lateral_pivot": "lateral_movement",
            "smb_pivot": "lateral_movement",
            "winrm_pivot": "lateral_movement",
            "phish_identity": "phishing_spear",
            "breach_check": "breach_correlation",
        }.get(capability_id, capability_id)

    def _target_risk(self, wm: WorldModel,
                     services: List[Dict[str, Any]]) -> float:
        """Composite exposure risk from the most business-critical service,
        boosted when a domain controller is present (crown-jewel posture)."""
        crit = 0.0
        for s in services:
            name = s.get("service") or s.get("product") or ""
            crit = max(crit, self._risk_engine().get_service_criticality(name))
        score = crit
        if wm.find("ad_domain") or wm.find("ad_hint"):
            score = min(100.0, score + 15.0)
        return round(score, 1)
