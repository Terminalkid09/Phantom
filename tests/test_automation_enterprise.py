"""Tests for the enterprise scoring bridge (EnterpriseBrain) + wiring."""
import os
import unittest
from unittest.mock import Mock

from phantom.automation.belief import WorldModel
from phantom.automation.enterprise import EnterpriseBrain


class _FakeFeed:
    """Threat-intel stub: maps CVE -> exploited-in-the-wild status."""

    def __init__(self, exploited_map=None):
        self.exploited_map = exploited_map or {}
        self.calls = []

    def is_recently_exploited(self, cve):
        self.calls.append(cve)
        exploited = self.exploited_map.get(cve, False)
        return {"exploited": exploited,
                "confidence": 95.0 if exploited else 0.0,
                "source": "test" if exploited else "unknown"}


def _wm(services=()):
    wm = WorldModel(target="10.0.0.5", target_type="ip")
    for port, svc in services:
        wm.add_finding("service", f"tcp/{port}",
                       {"port": str(port), "service": svc, "product": svc},
                       confidence=0.9, source="nmap")
    return wm


class TestEnterpriseBrain(unittest.TestCase):

    def test_prior_untouched_without_observations(self):
        brain = EnterpriseBrain()
        self.assertEqual(brain.prior("ssh_login", "creds", 2.0), 2.0)

    def test_prior_bounded_and_learned(self):
        brain = EnterpriseBrain()
        brain.record("ssh_login", True)
        brain.record("ssh_login", True)
        brain.record("ssh_login", False)  # 2/3 success
        self.assertAlmostEqual(brain.prior("ssh_login", "creds", 2.0),
                               2.0 * (0.5 + 2 / 3), places=3)

    def test_success_rate(self):
        brain = EnterpriseBrain()
        self.assertIsNone(brain.success_rate("x"))
        brain.record("x", True)
        self.assertEqual(brain.success_rate("x"), 1.0)

    def test_assess_maps_mitre_and_risk(self):
        wm = _wm([(445, "microsoft-ds"), (389, "ldap")])
        result = EnterpriseBrain().assess(wm)
        self.assertTrue(wm.find("attack_technique"))
        self.assertTrue(result["techniques"])
        risk = wm.find("target_risk")[0].value
        self.assertGreater(risk["score"], 0)

    def test_assess_ad_boosts_risk(self):
        wm = _wm([(22, "ssh")])
        brain = EnterpriseBrain()
        plain = wm.find("target_risk")
        brain.assess(wm)
        no_ad = wm.find("target_risk")[0].value["score"]
        wm.add_finding("ad_hint", "domain", {"domain": ""}, confidence=0.7)
        brain.assess(wm)
        with_ad = wm.find("target_risk")[0].value["score"]
        self.assertGreater(with_ad, no_ad)


class TestEnterprisePersistenceAndThreatIntel(unittest.TestCase):

    def test_persist_flushes_to_calibration_and_history(self):
        brain = EnterpriseBrain()
        brain.record("ssh_login", True)
        brain.record("ssh_login", True)
        brain.record("ssh_login", False)  # 2/3
        brain.record("kerberoast", True)

        cal = Mock()
        hist = Mock()
        result = brain.persist(calibration=cal, history=hist)

        self.assertEqual(result["techniques_recorded"], 2)
        # ssh_login -> brute_force_passwords (2 ok, 1 fail); kerberoast -> kerberoasting
        ok_calls = [c for c in cal.observe.call_args_list if c.args[1] is True]
        fail_calls = [c for c in cal.observe.call_args_list if c.args[1] is False]
        self.assertEqual(len(ok_calls), 3)
        self.assertEqual(len(fail_calls), 1)
        self.assertEqual(
            set(c.args[0] for c in cal.observe.call_args_list),
            {"brute_force_passwords", "kerberoasting"})
        self.assertEqual(hist.record_attempt.call_count, 2)

    def test_persist_skips_empty_stats(self):
        brain = EnterpriseBrain()
        cal, hist = Mock(), Mock()
        result = brain.persist(calibration=cal, history=hist)
        self.assertEqual(result["techniques_recorded"], 0)
        cal.observe.assert_not_called()
        hist.record_attempt.assert_not_called()

    def test_cve_threat_with_feed(self):
        brain = EnterpriseBrain(threat_intel=_FakeFeed({"CVE-2021-44228": True}))
        info = brain.cve_threat("CVE-2021-44228")
        self.assertTrue(info["exploited"])
        self.assertEqual(info["source"], "test")
        self.assertFalse(brain.cve_threat("CVE-1999-0001")["exploited"])

    def test_cve_threat_no_feed_is_safe(self):
        # no feed injected -> no enrichment, never raises
        brain = EnterpriseBrain()
        self.assertEqual(brain.cve_threat("CVE-2021-44228"),
                         {"exploited": False, "confidence": 0.0, "source": ""})

    def test_assess_enriches_exploit_plan(self):
        wm = _wm([(80, "http")])
        wm.add_finding("exploit_plan", "CVE-2021-41773",
                       {"cve": "CVE-2021-41773", "software": "apache"},
                       confidence=0.9, source="service_exploit")
        feed = _FakeFeed({"CVE-2021-41773": True})
        EnterpriseBrain(threat_intel=feed).assess(wm)
        plan = wm.find("exploit_plan")[0].value
        self.assertTrue(plan["recently_exploited"])
        self.assertEqual(plan["exploit_source"], "test")

    def test_technique_mapping_stable(self):
        self.assertEqual(EnterpriseBrain._technique_for("ssh_login"),
                         "brute_force_passwords")
        self.assertEqual(EnterpriseBrain._technique_for("kerberoast"),
                         "kerberoasting")
        self.assertEqual(EnterpriseBrain._technique_for("custom_cap"),
                         "custom_cap")


class TestAgentEnterpriseWiring(unittest.TestCase):

    def _runner(self):
        def runner(cmd, timeout=None):
            res = Mock()
            res.ok = True
            res.stdout = ""
            res.stderr = ""
            if "nmap" in cmd:
                res.stdout = ("22/tcp open ssh OpenSSH 7.9p1\\n"
                              "445/tcp open microsoft-ds Samba 4.13")
            return res
        return runner

    def test_run_records_learning_and_assesses(self):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.runtime.stealth_runtime import (
            StealthRuntime, TimingGovernor)
        from phantom.automation.runtime.toolchain import ToolRegistry
        from phantom.automation.guidance.stealth import StealthConfig, StealthEngine

        agent = AutonomousAgent(
            target="10.0.0.5", target_type="ip", profile="enterprise",
            on_event=lambda k, d: None,
            runtime=StealthRuntime(
                StealthEngine(WorldModel(target="10.0.0.5"), StealthConfig()),
                runner=self._runner(), cost_per_action=0.5,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0)),
            toolchain=ToolRegistry(installed={"nmap", "curl", "nc"}))
        agent.run(goal="footprint", max_iterations=3)
        # learning: scan_tcp actually ran and learned new services
        self.assertEqual(agent.enterprise.success_rate("scan_tcp"), 1.0)
        # assessment: MITRE + risk registered as findings
        self.assertTrue(agent.wm.find("attack_technique"))
        self.assertTrue(agent.wm.find("target_risk"))


class TestCrossEngagementPrior(unittest.TestCase):
    """The learning loop read path: disk-persisted calibrated weights from
    PREVIOUS engagements must tilt the planner before this run has any
    in-run observations (regret-bounded to [0.5x, 1.5x])."""

    @staticmethod
    def _brain_with_weight(weight):
        import os
        import tempfile
        from phantom.core.calibration import CalibrationEngine
        path = tempfile.mktemp(suffix=".json")
        cal = CalibrationEngine(weights_file=path)
        cal.weights["kerberoasting"] = weight
        brain = EnterpriseBrain()
        brain._calibration = cal
        return brain, path

    @staticmethod
    def _rm(path):
        try:
            os.unlink(path)
        except OSError:
            pass

    def test_untouched_capability_uses_disk_prior(self):
        brain, path = self._brain_with_weight(0.6)
        try:
            # never attempted in this run: the historic prior alone applies
            self.assertAlmostEqual(brain.prior("kerberoast", "ad", 100.0),
                                   60.0, places=5)
        finally:
            self._rm(path)

    def test_disk_prior_boost_and_clamp(self):
        brain, path = self._brain_with_weight(1.4)
        try:
            self.assertAlmostEqual(brain.prior("kerberoast", "ad", 100.0),
                                   140.0, places=5)
        finally:
            self._rm(path)
        brain2, path2 = self._brain_with_weight(9.0)
        try:
            self.assertAlmostEqual(brain2.prior("kerberoast", "ad", 100.0),
                                   150.0, places=5)
        finally:
            self._rm(path2)

    def test_in_run_success_blends_and_stays_bounded(self):
        brain, path = self._brain_with_weight(1.4)
        try:
            brain.record("kerberoast", True)  # in-run success on top
            prior = brain.prior("kerberoast", "ad", 100.0)
            self.assertGreater(prior, 100.0)
            self.assertLessEqual(prior, 150.0)
        finally:
            self._rm(path)

    def test_neutral_when_no_calibration_file(self):
        import os
        import tempfile
        from phantom.core.calibration import CalibrationEngine
        path = tempfile.mktemp(suffix=".json")
        brain = EnterpriseBrain()
        try:
            brain._calibration = CalibrationEngine(weights_file=path)
            self.assertEqual(brain.prior("ssh_login", "creds", 2.0), 2.0)
        finally:
            self._rm(path)


if __name__ == "__main__":
    unittest.main()
