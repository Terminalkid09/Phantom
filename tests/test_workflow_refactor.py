"""Tests for the WorkflowManager and refactored persistence module."""
import os
import unittest
from unittest.mock import patch, MagicMock

from phantom.core.workflow import (
    WorkflowManager,
    WorkflowResult,
    DEFAULT_PHASES,
    STATUS_KEY_MAP,
    SCORING_CONFIG,
)
from phantom.core.persistence import PersistenceManager, PersistenceRule, create_default_rules_file


def _isolate_history():
    """Redirect the global history analyzer to a temp file and return
    a restore callback. run_workflow feeds feedback into the global
    history_analyzer and calibration_engine, which would otherwise
    pollute the real on-disk data files."""
    import tempfile
    from phantom.core.history import history_analyzer
    from phantom.core.calibration import calibration_engine

    orig_file = history_analyzer.history_file
    orig_records = history_analyzer.records
    history_analyzer.history_file = os.path.join(tempfile.mkdtemp(), "hist.json")
    history_analyzer.records = []

    orig_wfile = calibration_engine.weights_file
    orig_weights = calibration_engine.weights
    orig_observations = calibration_engine.observations
    calibration_engine.weights_file = os.path.join(tempfile.mkdtemp(), "weights.json")
    calibration_engine.weights = dict(orig_weights)
    calibration_engine.observations = dict(orig_observations)

    def restore():
        history_analyzer.history_file = orig_file
        history_analyzer.records = orig_records
        calibration_engine.weights_file = orig_wfile
        calibration_engine.weights = orig_weights
        calibration_engine.observations = orig_observations

    return restore


class TestWorkflowManagerInit(unittest.TestCase):

    def test_default_phases_loaded(self):
        wm = WorkflowManager()
        self.assertIn("ip", wm.phases)
        self.assertIn("domain", wm.phases)
        self.assertIn("email", wm.phases)
        self.assertIn("username", wm.phases)

    def test_get_phases_returns_list(self):
        wm = WorkflowManager()
        phases = wm.get_phases("ip")
        self.assertIsInstance(phases, list)
        self.assertIn("classify", phases)
        self.assertIn("scan", phases)

    def test_register_executor(self):
        wm = WorkflowManager()
        mock_fn = MagicMock(return_value=True)
        wm.register_executor("test_phase", mock_fn)
        self.assertIn("test_phase", wm._executors)


class TestWorkflowPhaseExecution(unittest.TestCase):

    def test_execute_phase_without_executor(self):
        wm = WorkflowManager()
        result = wm.execute_phase("classify")
        self.assertFalse(result.success)
        self.assertIn("No executor", result.error)

    def test_execute_phase_with_executor(self):
        wm = WorkflowManager()
        mock_fn = MagicMock(return_value=True)
        wm.register_executor("scan", mock_fn)
        result = wm.execute_phase("scan")
        self.assertTrue(result.success)
        mock_fn.assert_called_once()

    def test_execute_phase_handles_exception(self):
        wm = WorkflowManager()
        wm.register_executor("os_detect", lambda: (_ for _ in ()).throw(ValueError("Test error")))
        result = wm.execute_phase("os_detect")
        self.assertFalse(result.success)
        self.assertEqual(result.error, "Test error")

    def test_failed_phase_marked_attempted(self):
        """Regression: a failing executor used to leave the phase pending,
        causing run_workflow to loop on it forever."""
        from phantom.core.session import session, KB_STATUS_DEFAULT
        original = session.knowledge_base
        session.knowledge_base = {
            "target": "", "target_type": "ip", "stealth": True,
            "aggressive": False, "started_at": None,
            "status": dict(KB_STATUS_DEFAULT),
            "services": [], "os_info": {}, "creds_found": [], "cves": [],
            "web_endpoints": [], "errors": [], "next_targets": [], "last_output": {},
        }
        try:
            wm = WorkflowManager()
            wm.register_executor("os_detect", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
            wm.execute_phase("os_detect")
            self.assertTrue(session.knowledge_base["status"]["os_detected"],
                            "failed phase must be marked as attempted")
        finally:
            session.knowledge_base = original

    def test_run_workflow_terminates_with_failing_executor(self):
        """Regression: a persistently failing phase used to hang run_workflow."""
        from phantom.core.session import session, KB_STATUS_DEFAULT
        original = session.knowledge_base
        session.knowledge_base = {
            "target": "", "target_type": "ip", "stealth": True,
            "aggressive": False, "started_at": None,
            "status": dict(KB_STATUS_DEFAULT),
            "services": [], "os_info": {}, "creds_found": [], "cves": [],
            "web_endpoints": [], "errors": [], "next_targets": [], "last_output": {},
        }
        try:
            wm = WorkflowManager()
            wm.register_executor("scan", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
            wm.register_executor("classify", lambda: True)
            restore_history = _isolate_history()
            try:
                results = wm.run_workflow("10.0.0.1")
            finally:
                restore_history()
            self.assertGreater(len(results), 0)
        finally:
            session.knowledge_base = original

    def test_workflow_feedback_recorded(self):
        """Successful phases must feed calibration and history engines."""
        from phantom.core.session import session, KB_STATUS_DEFAULT
        from phantom.core.history import history_analyzer
        from phantom.core.calibration import calibration_engine

        restore_history = _isolate_history()
        original_kb = session.knowledge_base

        session.knowledge_base = {
            "target": "", "target_type": "ip", "stealth": True,
            "aggressive": False, "started_at": None,
            "status": dict(KB_STATUS_DEFAULT),
            "services": [], "os_info": {}, "creds_found": [], "cves": [],
            "web_endpoints": [], "errors": [], "next_targets": [], "last_output": {},
        }
        try:
            wm = WorkflowManager()
            wm.register_executor("classify", lambda: True)
            wm.run_workflow("10.0.0.1")
            self.assertGreater(len(history_analyzer.records), 0)
            self.assertTrue(any(r["technique"] == "classify" for r in history_analyzer.records))
        finally:
            session.knowledge_base = original_kb
            restore_history()


class TestWorkflowDecisionEngine(unittest.TestCase):

    def setUp(self):
        # Deterministic scoring: the real operator's calibrated weights (if
        # present on disk) would leak into _score_adaptive and make these
        # assertions depend on prior real usage instead of INITIAL_WEIGHTS.
        self._restore = _isolate_history()
        self.addCleanup(self._restore)

    def _reset_session(self):
        from phantom.core.session import session, KB_STATUS_DEFAULT
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
            # Enterprise context fields
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

    def test_decide_next_first_uncompleted(self):
        from phantom.core.workflow import workflow_manager
        session = self._reset_session()

        phase = workflow_manager.decide_next("ip")
        self.assertEqual(phase, "classify")

    def test_decide_next_skips_completed(self):
        from phantom.core.workflow import workflow_manager
        session = self._reset_session()
        session.knowledge_base["status"]["classified"] = True

        phase = workflow_manager.decide_next("ip")
        self.assertEqual(phase, "scan")

    def test_decide_next_returns_none_when_all_done(self):
        from phantom.core.workflow import workflow_manager
        from phantom.core.session import KB_STATUS_DEFAULT
        session = self._reset_session()
        for key in KB_STATUS_DEFAULT:
            session.knowledge_base["status"][key] = True

        phase = workflow_manager.decide_next("ip")
        self.assertIsNone(phase)

    def test_adaptive_scoring_empty_kb(self):
        from phantom.core.workflow import workflow_manager
        session = self._reset_session()
        scores = workflow_manager._score_adaptive(session.knowledge_base)
        self.assertTrue(all(v == 0.0 for v in scores.values()))

    def test_adaptive_scoring_with_services(self):
        from phantom.core.workflow import workflow_manager
        session = self._reset_session()
        session.knowledge_base["services"] = [
            {"port": "80"},
            {"port": "443"},
            {"port": "22"},
        ]
        scores = workflow_manager._score_adaptive(session.knowledge_base)
        self.assertGreater(scores["scan"], 0.0)


class TestWorkflowResult(unittest.TestCase):

    def test_result_default_error_none(self):
        result = WorkflowResult(name="test", success=True)
        self.assertIsNone(result.error)

    def test_result_with_error(self):
        result = WorkflowResult(name="test", success=False, error="Failed")
        self.assertEqual(result.error, "Failed")

    def test_result_has_timestamp(self):
        result = WorkflowResult(name="test", success=True)
        self.assertIsNotNone(result.timestamp)


class TestPersistenceManagerBuiltinRules(unittest.TestCase):

    def test_built_in_rules_count(self):
        pm = PersistenceManager()
        self.assertEqual(len(pm.rules), 5)

    def test_get_windows_runkey(self):
        pm = PersistenceManager()
        cmd = pm.get_windows_runkey("C:\\beacon.exe")
        self.assertIn("reg add", cmd)
        self.assertIn("PhantomBeacon", cmd)

    def test_get_windows_schtask(self):
        pm = PersistenceManager()
        cmd = pm.get_windows_schtask("C:\\beacon.exe")
        self.assertIn("schtasks", cmd)

    def test_get_linux_cron(self):
        pm = PersistenceManager()
        cmd = pm.get_linux_cron("/tmp/beacon")
        self.assertIn("crontab", cmd)

    def test_get_linux_systemd(self):
        pm = PersistenceManager()
        cmd = pm.get_linux_systemd("/tmp/beacon", "phantom")
        self.assertIn("systemctl", cmd)

    def test_list_rules(self):
        pm = PersistenceManager()
        rules = pm.list_rules()
        self.assertEqual(len(rules), 5)

    def test_list_rules_filter_platform(self):
        pm = PersistenceManager()
        rules = pm.list_rules("windows")
        for r in rules:
            self.assertIn("windows", r["platforms"])


class TestPersistenceRule(unittest.TestCase):

    def test_rule_generation(self):
        rule = PersistenceRule({
            "name": "test_rule",
            "platforms": ["linux"],
            "command_template": "echo '{binary_path}' >> /tmp/persist.sh",
        })
        result = rule.generate("/tmp/beacon")
        self.assertIn("/tmp/beacon", result)

    def test_rule_with_kwargs(self):
        rule = PersistenceRule({
            "name": "test_rule",
            "platforms": ["windows"],
            "command_template": 'reg add "{key}" /v {name} /d "{binary_path}" /f',
        })
        result = rule.generate("C:\\beacon.exe", key="HKCU\\Run", name="MyBeacon")
        self.assertIn("C:\\beacon.exe", result)
        self.assertIn("MyBeacon", result)

    def test_rule_missing_param_returns_none(self):
        rule = PersistenceRule({
            "name": "test_rule",
            "platforms": ["linux"],
            "command_template": "echo '{binary_path}' >> {missing_file}",
        })
        result = rule.generate("/tmp/beacon")
        self.assertIsNone(result)


class TestPlatformMapping(unittest.TestCase):

    def test_windows_detection(self):
        pm = PersistenceManager()
        self.assertEqual(pm._get_platform("Windows Server 2019"), "windows")
        self.assertEqual(pm._get_platform("win10"), "windows")

    def test_linux_detection(self):
        pm = PersistenceManager()
        self.assertEqual(pm._get_platform("Ubuntu 20.04"), "linux")
        self.assertEqual(pm._get_platform("centos 7"), "linux")

    def test_macos_detection(self):
        pm = PersistenceManager()
        self.assertEqual(pm._get_platform("macOS Monterey"), "macos")
        self.assertEqual(pm._get_platform("Darwin 21.0"), "macos")


class TestDefaultRulesFile(unittest.TestCase):

    def test_create_default_rules_file(self, ):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            test_path = os.path.join(tmpdir, "persistence_rules.json")
            create_default_rules_file(test_path)
            self.assertTrue(os.path.isfile(test_path))
            import json
            with open(test_path) as f:
                data = json.load(f)
            self.assertIn("rules", data)
            self.assertEqual(len(data["rules"]), 2)


class TestEnterpriseIntegration(unittest.TestCase):

    def setUp(self):
        # same determinism guard as TestWorkflowDecisionEngine
        self._restore = _isolate_history()
        self.addCleanup(self._restore)

    def test_score_adaptive_with_enterprise_context(self):
        from phantom.core.workflow import WorkflowManager
        wm = WorkflowManager()
        kb = {
            "target_type": "ip",
            "os_info": {"accuracy": 95, "os": "windows"},
            "services": [{"port": "445", "service": "microsoft-ds"}],
            "cves": [{"id": "CVE-2021-34527", "score": 88}],
            "creds_found": [{"username": "admin", "domain_admin": True}],
            "web_endpoints": ["/admin"],
            "breaches_found": ["domain"],
        }
        scores = wm._score_adaptive(kb)
        self.assertIn("scan", scores)
        self.assertIn("cve_correlate", scores)
        self.assertGreater(scores["cve_correlate"], 30.0)

    def test_decide_next_returns_phase_or_none(self):
        wm = WorkflowManager()
        result = wm.decide_next("ip")
        self.assertTrue(result is None or isinstance(result, str))

    def test_enterprise_kb_fields_accessible(self):
        from phantom.core.session import session
        # knowledge_base is the single source of truth for enterprise context
        kb = session.knowledge_base
        for field in ("critical_infrastructure", "domain_environment",
                      "network_segmentation", "critical_assets", "password_policy",
                      "waf_detected", "domain_enumerated", "known_defaults"):
            self.assertIn(field, kb)


if __name__ == "__main__":
    unittest.main()
