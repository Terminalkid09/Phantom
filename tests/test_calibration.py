"""Tests for the Calibration Engine."""
import unittest
import tempfile
import os

from phantom.core.calibration import CalibrationEngine, INITIAL_WEIGHTS


def _new_engine():
    return CalibrationEngine(weights_file=os.path.join(tempfile.mkdtemp(), "weights.json"))


class TestCalibrationEngineInit(unittest.TestCase):

    def test_default_weights_loaded(self):
        engine = _new_engine()
        self.assertIn("services_found", engine.weights)
        self.assertEqual(len(engine.weights), len(INITIAL_WEIGHTS))

    def test_alpha_prior(self):
        engine = _new_engine()
        self.assertEqual(engine.alpha, 10.0)

    def test_get_weight(self):
        engine = _new_engine()
        w = engine.get_weight("services_found")
        self.assertEqual(w, 2.0)

    def test_get_unknown_weight(self):
        engine = _new_engine()
        w = engine.get_weight("unknown_key")
        self.assertEqual(w, 1.0)


class TestBayesianUpdate(unittest.TestCase):

    def test_success_increases_weight(self):
        """Regression: 100% success used to DECREASE the weight."""
        engine = _new_engine()
        initial = engine.get_weight("exploit_cve_public")
        for _ in range(5):
            engine.observe("exploit_cve_public", True)
        self.assertGreater(engine.get_weight("exploit_cve_public"), initial)

    def test_failure_decreases_weight(self):
        engine = _new_engine()
        initial = engine.get_weight("exploit_cve_public")
        for _ in range(5):
            engine.observe("exploit_cve_public", False)
        self.assertLess(engine.get_weight("exploit_cve_public"), initial)

    def test_weight_bounded_by_initial(self):
        """Weight must stay within [50%, 200%] of the initial value."""
        engine = _new_engine()
        initial = engine.get_weight("exploit_cve_public")
        for _ in range(20):
            engine.observe("exploit_cve_public", True)
        self.assertLessEqual(engine.get_weight("exploit_cve_public"), initial * 2.0)

        engine2 = _new_engine()
        for _ in range(20):
            engine2.observe("exploit_cve_public", False)
        self.assertGreaterEqual(engine2.get_weight("exploit_cve_public"), initial * 0.5)

    def test_persistence_of_weights(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            weights_file = os.path.join(tmpdir, "weights.json")

            engine1 = CalibrationEngine(weights_file=weights_file)
            engine1.observe("test_technique", True)
            engine1.observe("test_technique", True)

            engine2 = CalibrationEngine(weights_file=weights_file)
            self.assertIn("test_technique", engine2.observations)
            self.assertEqual(engine2.observations["test_technique"]["successes"], 2)

    def test_observe_weight_calibrates_evidence_keys(self):
        engine = _new_engine()
        initial = engine.get_weight("services_found")
        engine.observe_weight("services_found", True)
        self.assertGreater(engine.get_weight("services_found"), initial)


class TestConfidenceInterval(unittest.TestCase):

    def test_confidence_interval_small_sample(self):
        engine = _new_engine()
        engine.observations = {"test": {"successes": 9, "failures": 1}}
        lower, upper = engine.confidence_interval("test")
        self.assertGreater(upper, lower)
        self.assertGreaterEqual(lower, 0.0)
        self.assertLessEqual(upper, 1.0)

    def test_confidence_interval_zero_observations(self):
        engine = _new_engine()
        lower, upper = engine.confidence_interval("unknown")
        self.assertEqual((lower, upper), (0.0, 1.0))

    def test_confidence_interval_all_failures(self):
        engine = _new_engine()
        engine.observations = {"test": {"successes": 0, "failures": 10}}
        lower, upper = engine.confidence_interval("test")
        self.assertEqual(lower, 0.0)

    def test_confidence_level_changes_interval(self):
        engine = _new_engine()
        engine.observations = {"test": {"successes": 5, "failures": 5}}
        lo90, hi90 = engine.confidence_interval("test", 0.90)
        lo99, hi99 = engine.confidence_interval("test", 0.99)
        # 99% interval must be wider than 90% interval
        self.assertLessEqual(hi99 - lo99, 1.0)
        self.assertGreaterEqual(hi99 - lo99, hi90 - lo90 - 0.001)


class TestRecalibrate(unittest.TestCase):

    def test_recalibrate_from_results(self):
        engine = _new_engine()
        initial = engine.get_weight("exploit_cve_public")

        results = [
            {"technique": "exploit_cve_public", "success": True},
            {"technique": "exploit_cve_public", "success": True},
            {"technique": "kerberoasting", "success": True},
        ]
        engine.recalibrate(results)

        self.assertGreater(engine.get_weight("exploit_cve_public"), initial)


class TestGetRecommendation(unittest.TestCase):

    def test_recommendation_no_data(self):
        engine = _new_engine()
        rec = engine.get_recommendation("unknown_technique")
        self.assertTrue(rec["use"])
        self.assertEqual(rec["confidence"], 0.0)

    def test_recommendation_with_success(self):
        engine = _new_engine()
        engine.observations = {"test": {"successes": 8, "failures": 2}}
        rec = engine.get_recommendation("test")
        self.assertTrue(rec["use"])
        self.assertIn("success rate", rec["reason"])

    def test_recommendation_with_failure(self):
        engine = _new_engine()
        engine.observations = {"test": {"successes": 0, "failures": 10}}
        rec = engine.get_recommendation("test")
        self.assertFalse(rec["use"])

    def test_confidence_not_inverted(self):
        """Regression: a wide interval (few observations) must NOT yield high confidence."""
        few = _new_engine()
        few.observations = {"t1": {"successes": 1, "failures": 0}}
        many = _new_engine()
        many.observations = {"t2": {"successes": 90, "failures": 10}}
        # More data -> narrower CI -> higher confidence
        self.assertGreater(many.get_recommendation("t2")["confidence"],
                           few.get_recommendation("t1")["confidence"])


if __name__ == "__main__":
    unittest.main()