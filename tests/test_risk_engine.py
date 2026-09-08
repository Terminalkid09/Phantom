"""Tests for the Risk-Based Prioritization Engine."""
import unittest

from phantom.core.risk_engine import (
    RiskEngine, RiskProfile, risk_engine,
    BUSINESS_CRITICALITY, NETWORK_POSITION, ASSET_CLASSIFICATIONS,
)


class TestBusinessCriticality(unittest.TestCase):

    def test_service_criticality_values(self):
        self.assertEqual(BUSINESS_CRITICALITY["ldap"], 100)
        self.assertEqual(BUSINESS_CRITICALITY["dns"], 95)
        self.assertEqual(BUSINESS_CRITICALITY["ssh"], 85)

    def test_get_service_criticality_known(self):
        engine = RiskEngine()
        score = engine.get_service_criticality("ldap")
        self.assertEqual(score, 100)

    def test_get_service_criticality_unknown(self):
        engine = RiskEngine()
        score = engine.get_service_criticality("unknown_service")
        self.assertEqual(score, 25.0)


class TestNetworkPosition(unittest.TestCase):

    def test_network_position_values(self):
        self.assertEqual(NETWORK_POSITION["dmz"], 30)
        self.assertEqual(NETWORK_POSITION["core_infrastructure"], 95)
        self.assertEqual(NETWORK_POSITION["isolated_management"], 10)

    def test_get_network_position_no_info(self):
        engine = RiskEngine()
        score = engine.get_network_position_score({})
        self.assertEqual(score, NETWORK_POSITION["unknown"])

    def test_get_network_position_with_segment(self):
        engine = RiskEngine()
        score = engine.get_network_position_score({"segment": "dmz"})
        self.assertEqual(score, 30)

    def test_get_network_position_isolated(self):
        engine = RiskEngine()
        score = engine.get_network_position_score({"isolated_network": True})
        self.assertEqual(score, NETWORK_POSITION["isolated_management"])  # 10


class TestRiskCalculation(unittest.TestCase):

    def test_calculate_exposure_risk_basic(self):
        engine = RiskEngine()
        profile = engine.calculate_exposure_risk(
            target="192.168.1.1",
            service="ssh",
            port=22,
        )
        self.assertIsInstance(profile, RiskProfile)
        self.assertGreater(profile.overall_risk, 0)

    def test_calculate_exposure_risk_critical_asset(self):
        engine = RiskEngine()
        profile = engine.calculate_exposure_risk(
            target="192.168.1.10",
            service="kerberos",
            port=88,
            asset_classification="authentication_server",
        )
        # kerberos=100*0.3=30, network unknown=50*0.25=12.5, asset=100/10=10*0.1=1, port=0
        self.assertGreater(profile.overall_risk, 30)
        self.assertLessEqual(profile.overall_risk, 60)

    def test_calculate_exposure_risk_low_value(self):
        engine = RiskEngine()
        profile = engine.calculate_exposure_risk(
            target="192.168.1.50",
            service="printer",
            port=9100,
        )
        self.assertLess(profile.overall_risk, 40)

    def test_risk_profile_has_factors(self):
        engine = RiskEngine()
        profile = engine.calculate_exposure_risk(
            "10.0.0.1", "http", 80,
            vulnerability_age_days=200,
            asset_classification="customer_data",
        )
        self.assertIn("business_criticality", profile.factors)
        self.assertIn("network_position", profile.factors)
        self.assertIn("vulnerability_age", profile.factors)
        self.assertIn("asset_classification", profile.factors)
        self.assertIn("port_exposure", profile.factors)

    def test_vulnerability_age_factor(self):
        engine = RiskEngine()
        # 200 days old => > 180 but <= 365, so should be 30.0
        profile = engine.calculate_exposure_risk("10.0.0.1", "http", 80, vulnerability_age_days=200)
        self.assertGreaterEqual(profile.factors["vulnerability_age"], 30)

        # 5 days old => <= 7, so should be 10.0
        profile_new = engine.calculate_exposure_risk("10.0.0.1", "http", 80, vulnerability_age_days=5)
        self.assertEqual(profile_new.factors["vulnerability_age"], 10.0)


class TestTargetRanking(unittest.TestCase):

    def test_rank_targets_by_risk(self):
        engine = RiskEngine()
        targets = [
            engine.calculate_exposure_risk("10.0.0.1", "printer", 9100),
            engine.calculate_exposure_risk("10.0.0.2", "ldap", 389),
            engine.calculate_exposure_risk("10.0.0.3", "ssh", 22),
        ]
        ranked = engine.rank_targets(targets)
        self.assertEqual(ranked[0].service, "ldap")
        self.assertEqual(ranked[-1].service, "printer")


class TestRecommendedPhase(unittest.TestCase):

    def test_high_risk_aggressive(self):
        engine = RiskEngine()
        phase = engine.get_recommended_phase(85)
        self.assertEqual(phase, "initial_access_aggressive")

    def test_medium_risk_balanced(self):
        engine = RiskEngine()
        phase = engine.get_recommended_phase(65)
        self.assertEqual(phase, "initial_access_balanced")

    def test_low_risk_stealth(self):
        engine = RiskEngine()
        phase = engine.get_recommended_phase(20)
        self.assertEqual(phase, "recon_stealth")


class TestExploitTimingRisk(unittest.TestCase):

    def test_recent_vulnerability(self):
        engine = RiskEngine()
        result = engine.get_exploit_timing_risk(5)
        self.assertEqual(result["exploit_complexity"], "high")
        self.assertEqual(result["detection_risk"], "high")

    def test_old_vulnerability(self):
        engine = RiskEngine()
        result = engine.get_exploit_timing_risk(400)
        self.assertEqual(result["exploit_complexity"], "low")
        self.assertEqual(result["detection_risk"], "high")

    def test_medium_vulnerability(self):
        engine = RiskEngine()
        result = engine.get_exploit_timing_risk(100)
        self.assertEqual(result["exploit_complexity"], "medium")


if __name__ == "__main__":
    unittest.main()
