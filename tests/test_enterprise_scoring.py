"""Tests for enterprise-grade decision engine scoring."""
import tempfile
import unittest

from phantom.core.workflow import WorkflowManager
from phantom.core.session import session, KB_STATUS_DEFAULT
from phantom.core.calibration import INITIAL_WEIGHTS


def _isolate_calibration():
    """Point the calibration + history singletons at empty state so scoring
    uses INITIAL_WEIGHTS and no accumulated engagement history instead of the
    operator's real runtime data (which exists only on machines where
    Phantom has been used and would skew every assertion here)."""
    import os as _os
    from phantom.core.calibration import calibration_engine
    from phantom.core.history import history_analyzer
    tmp = tempfile.mkdtemp()
    cal_orig = (calibration_engine.weights_file,
                calibration_engine.weights,
                calibration_engine.observations)
    calibration_engine.weights_file = _os.path.join(tmp, "w.json")
    calibration_engine.weights = dict(INITIAL_WEIGHTS)
    calibration_engine.observations = {}
    hist_orig = (history_analyzer.history_file, history_analyzer.records)
    history_analyzer.history_file = _os.path.join(tmp, "h.json")
    history_analyzer.records = []

    def restore():
        (calibration_engine.weights_file,
         calibration_engine.weights,
         calibration_engine.observations) = cal_orig
        (history_analyzer.history_file, history_analyzer.records) = hist_orig
    return restore


class TestEnterpriseScoring(unittest.TestCase):

    def _reset_session(self):
        session.knowledge_base = {
            "target": "",
            "target_type": "ip",
            "stealth": True,
            "aggressive": False,
            "started_at": None,
            "status": dict(KB_STATUS_DEFAULT),
            "services": [],
            "os_info": {},
            "creds_found": [],
            "rce_vectors": [],
            "cves": [],
            "web_endpoints": [],
            "social_profiles": [],
            "emails_found": [],
            "subdomains_found": [],
            "breaches_found": [],
            "beacon_deployed": False,
            "persistence_set": False,
            "current_step": None,
            "errors": [],
            "next_targets": [],
            "last_output": {},
            "critical_infrastructure": False,
            "domain_environment": False,
            "network_segmentation": {},
            "critical_assets": [],
            "password_policy": {},
            "waf_detected": False,
            "domain_enumerated": False,
            "known_defaults": False,
        }
        return session

    def setUp(self):
        self._restore = _isolate_calibration()
        self.addCleanup(self._restore)
        self.wm = WorkflowManager()

    def test_critical_infrastructure_boost(self):
        session = self._reset_session()
        session.knowledge_base["critical_infrastructure"] = True
        session.knowledge_base["cves"] = [{"score": 90, "recent_exploit": True}]

        scores = self.wm._score_adaptive(session.knowledge_base)
        self.assertGreater(scores["cve_correlate"], 0)

    def test_domain_environment_beacon_boost(self):
        session = self._reset_session()
        session.knowledge_base["domain_environment"] = True

        phases = self.wm.get_phases("ip")
        # Mark all but deploy_beacon as done
        for phase in phases:
            status_key = {"classify": "classified", "scan": "scan_done",
                          "os_detect": "os_detected", "osint": "osint_done",
                          "web_recon": "web_recon_done", "cve_correlate": "cve_correlate_done",
                          "test_creds": "default_creds_tested",
                          "deploy_beacon": "rce_attempted", "persistence": "persistence_set"}
            key = status_key.get(phase)
            if key and phase != "deploy_beacon":
                session.knowledge_base["status"][key] = True

        phase = self.wm.decide_next("ip")
        self.assertEqual(phase, "deploy_beacon")

    def test_waf_detection_web_recon_boost(self):
        session = self._reset_session()
        session.knowledge_base["waf_detected"] = True
        session.knowledge_base["services"] = [{"port": "80", "service": "http"}]
        session.knowledge_base["status"]["classified"] = True
        session.knowledge_base["status"]["scan_done"] = True
        session.knowledge_base["status"]["os_detected"] = True
        session.knowledge_base["status"]["osint_done"] = True

        # web_recon should be prioritized due to WAF detection
        phase = self.wm.decide_next("ip")
        self.assertEqual(phase, "web_recon")

    def test_breach_check_credential_spill_boost(self):
        session = self._reset_session()
        session.knowledge_base["breaches_found"] = [{"email": "test@test.com"}]
        session.knowledge_base["target_type"] = "email"
        session.knowledge_base["status"]["classified"] = True

        phase = self.wm.decide_next("email")
        scores = self.wm._score_adaptive(session.knowledge_base)
        self.assertGreater(scores["breach_check"], 0.0)

    def test_cve_with_recent_exploit_high_priority(self):
        session = self._reset_session()
        session.knowledge_base["cves"] = [{"score": 95, "recent_exploit": True}]
        session.knowledge_base["services"] = [{"port": "443", "service": "https"}]
        session.knowledge_base["status"]["classified"] = True
        session.knowledge_base["status"]["scan_done"] = True
        session.knowledge_base["status"]["os_detected"] = True
        session.knowledge_base["status"]["osint_done"] = True
        session.knowledge_base["status"]["web_recon_done"] = True

        # CVE correlation should be prioritized with recent exploit
        phase = self.wm.decide_next("ip")
        self.assertEqual(phase, "cve_correlate")

    def test_multi_factor_disabled_boost(self):
        session = self._reset_session()
        session.knowledge_base["password_policy"] = {"multi_factor": False, "min_length": 8}
        session.knowledge_base["services"] = [{"port": "22", "service": "ssh"}]
        session.knowledge_base["status"]["classified"] = True
        session.knowledge_base["status"]["scan_done"] = True

        phase = self.wm.decide_next("ip")
        # test_creds should be prioritized with weak password policy
        self.assertEqual(phase, "test_creds")

    def test_persistence_deprioritized_without_beacon(self):
        session = self._reset_session()
        session.knowledge_base["beacon_deployed"] = False
        session.knowledge_base["creds_found"] = []
        session.knowledge_base["target_type"] = "ip"

        # Set all phases done EXCEPT deploy_beacon and persistence
        status_map = {"classify": "classified", "scan": "scan_done",
                      "os_detect": "os_detected", "osint": "osint_done",
                      "web_recon": "web_recon_done", "cve_correlate": "cve_correlate_done",
                      "test_creds": "default_creds_tested",
                      "persistence": "persistence_set"}
        # Note: DON'T set rce_attempted=True so deploy_beacon remains pending
        for phase, key in status_map.items():
            session.knowledge_base["status"][key] = True

        phase = self.wm.decide_next("ip")
        # deploy_beacon should be tried before persistence
        self.assertEqual(phase, "deploy_beacon")

    def test_network_segmentation_boost(self):
        session = self._reset_session()
        session.knowledge_base["network_segmentation"] = {"isolated_network": True}
        session.knowledge_base["status"]["classified"] = True
        session.knowledge_base["status"]["scan_done"] = True
        session.knowledge_base["status"]["os_detected"] = True
        session.knowledge_base["status"]["osint_done"] = True
        session.knowledge_base["status"]["web_recon_done"] = True
        session.knowledge_base["status"]["cve_correlate_done"] = True
        session.knowledge_base["status"]["default_creds_tested"] = True

        phase = self.wm.decide_next("ip")
        # Deploy beacon should be prioritized due to isolated network
        self.assertEqual(phase, "deploy_beacon")


class TestDependencyChainAwareness(unittest.TestCase):

    def _reset_session(self):
        session.knowledge_base = {
            "target": "",
            "target_type": "ip",
            "stealth": True,
            "aggressive": False,
            "started_at": None,
            "status": dict(KB_STATUS_DEFAULT),
            "services": [],
            "os_info": {},
            "creds_found": [],
            "rce_vectors": [],
            "cves": [],
            "web_endpoints": [],
            "social_profiles": [],
            "emails_found": [],
            "subdomains_found": [],
            "breaches_found": [],
            "beacon_deployed": False,
            "persistence_set": False,
            "current_step": None,
            "errors": [],
            "next_targets": [],
            "last_output": {},
            "critical_infrastructure": False,
            "domain_environment": False,
            "network_segmentation": {},
            "critical_assets": [],
            "password_policy": {},
            "waf_detected": False,
            "domain_enumerated": False,
            "known_defaults": False,
        }
        return session

    def setUp(self):
        self._restore = _isolate_calibration()
        self.addCleanup(self._restore)
        self.wm = WorkflowManager()

    def test_cve_correlate_requires_services(self):
        """CVE correlation should be deprioritized without services."""
        session = self._reset_session()
        session.knowledge_base["status"]["classified"] = True

        phase = self.wm.decide_next("ip")
        # Should not return cve_correlate as first priority without services
        self.assertNotEqual(phase, "cve_correlate")

    def test_beacon_requires_os_or_creds(self):
        """Beacon deployment should be deprioritized without OS detection or creds."""
        session = self._reset_session()
        session.knowledge_base["status"]["classified"] = True
        session.knowledge_base["status"]["scan_done"] = True
        # No OS detection, no creds
        phase = self.wm.decide_next("ip")
        # Should prioritize os_detect before deploy_beacon
        self.assertNotEqual(phase, "deploy_beacon")


if __name__ == "__main__":
    unittest.main()
