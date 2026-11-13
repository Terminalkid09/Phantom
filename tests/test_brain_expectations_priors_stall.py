"""Fase 3 gate tests: predictive expectations, cross-session priors,
stall classification."""
import os
import tempfile
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.brain.expectations import ExpectationEngine
from phantom.automation.brain.priors import TechniquePriors
from phantom.automation.brain.stall import StallClassifier


class TestExpectations(unittest.TestCase):
    def test_met_expectation_on_coherent_target(self):
        eng = ExpectationEngine()
        wm = WorldModel(target="10.0.0.9")
        wm.add_finding("fingerprint", "http/80", {"product": "nginx"})
        wm.add_finding("web_header", "server", {"server": "nginx/1.18.0"})
        diffs = eng.evaluate(wm)
        self.assertTrue(any(d.status == "met" and d.exp_id ==
                            "nginx-server-header" for d in diffs))
        self.assertEqual(eng.signals(wm), [])

    def test_violation_is_a_signal(self):
        eng = ExpectationEngine()
        wm = WorldModel(target="10.0.0.10")
        wm.add_finding("fingerprint", "http/80", {"product": "nginx"})
        wm.add_finding("web_header", "server", {"server": "Microsoft-IIS/10"})
        sig = eng.signals(wm)
        self.assertTrue(any(d.exp_id == "nginx-server-header" for d in sig))

    def test_visibility_gaps_are_unknowns(self):
        eng = ExpectationEngine()
        wm = WorldModel(target="10.0.0.9")
        wm.add_finding("fingerprint", "http/80", {"product": "nginx"})
        gaps = eng.visibility_gaps(wm)
        self.assertTrue(any(g.exp_id == "nginx-alias-traversal" for g in gaps))

    def test_condition_filtering(self):
        eng = ExpectationEngine()
        wm = WorldModel(target="10.0.0.9")   # no fingerprint: no conditions
        active = eng.active(wm)
        self.assertFalse(any(e.exp_id.startswith("nginx-") for e in active))

    def test_web_config_leak_detection(self):
        eng = ExpectationEngine()
        wm = WorldModel(target="10.0.0.9")
        wm.add_finding("fingerprint", "http/80", {"product": "Microsoft-IIS"})
        wm.add_finding("hunt_anomaly", "leak",
                       {"path": "/web.config", "status": 200})
        sig = eng.signals(wm)
        self.assertTrue(any(d.exp_id == "iis-webconfig" for d in sig),
                        "a 200 on /web.config MUST be a violation signal")


class TestPriors(unittest.TestCase):
    def _wm(self, product="nginx"):
        wm = WorldModel(target="10.0.0.9")
        wm.add_finding("fingerprint", "http/80", {"product": product})
        return wm

    def test_failures_raise_cost(self):
        p = TechniquePriors(path=tempfile.mktemp(suffix=".json"))
        wm = self._wm()
        for _ in range(3):
            p.record_from_worldmodel(wm, "web_sqli_dump", ok=False)
        self.assertGreater(p.multiplier_for(wm, "web_sqli_dump"), 1.2)

    def test_never_tried_is_neutral(self):
        p = TechniquePriors(path=tempfile.mktemp(suffix=".json"))
        self.assertEqual(p.multiplier_for(self._wm(), "kerberoast"), 1.0)

    def test_regret_bounds(self):
        p = TechniquePriors(path=tempfile.mktemp(suffix=".json"))
        wm = self._wm()
        for _ in range(20):
            p.record_from_worldmodel(wm, "web_sqli_dump", ok=False)
        m = p.multiplier_for(wm, "web_sqli_dump")
        self.assertLessEqual(m, 1.5)   # never more than 1.5x
        self.assertGreaterEqual(m, 0.5)

    def test_persists_across_instances(self):
        path = tempfile.mktemp(suffix=".json")
        p = TechniquePriors(path=path)
        wm = self._wm()
        p.record_from_worldmodel(wm, "web_sqli_dump", ok=True)
        p2 = TechniquePriors(path=path)
        self.assertEqual(p.multiplier_for(wm, "web_sqli_dump"),
                         p2.multiplier_for(wm, "web_sqli_dump"))
        os.remove(path)

    def test_buckets_are_per_fingerprint_class(self):
        path = tempfile.mktemp(suffix=".json")
        p = TechniquePriors(path=path)
        for _ in range(5):
            p.record_from_worldmodel(self._wm("nginx"), "web_sqli_dump",
                                     ok=False)
        # same technique on apache is untouched
        self.assertEqual(p.multiplier_for(self._wm("apache"),
                                          "web_sqli_dump"), 1.0)
        os.remove(path)


class TestStallClassifier(unittest.TestCase):
    def test_no_visibility_on_blind_perimeter(self):
        wm = WorldModel(target="corp.com")
        v = StallClassifier().classify(wm)
        self.assertEqual(v.stall_class, "no_visibility")
        self.assertIn("surface_map", v.strategies)

    def test_blocked_on_refusals(self):
        wm = WorldModel(target="10.0.0.9")
        for _ in range(4):
            wm.record_failure("web_rce", "403 forbidden by WAF")
        v = StallClassifier().classify(wm)
        self.assertEqual(v.stall_class, "blocked")
        self.assertIn("evasion_change", v.strategies)

    def test_blocked_on_noise_breaker(self):
        wm = WorldModel(target="10.0.0.9")
        wm.add_finding("service", "tcp/80", {"service": "http", "port": 80})
        v = StallClassifier(noise_breaker_tripped=True).classify(wm)
        self.assertEqual(v.stall_class, "blocked")

    def test_wrong_model_on_mismatch(self):
        wm = WorldModel(target="10.0.0.9")
        wm.record_failure("http_probe",
                          "fingerprint mismatch: banner says nginx, headers say IIS")
        self.assertEqual(StallClassifier().classify(wm).stall_class,
                         "wrong_model")

    def test_wrong_altitude_when_surface_exhausted(self):
        wm = WorldModel(target="10.0.0.9")
        wm.add_finding("service", "tcp/80", {"service": "http", "port": 80})
        wm.add_finding("service", "tcp/22", {"service": "ssh", "port": 22})
        for reason in ("auth failed", "no dump", "no upload", "timeout"):
            wm.record_failure("x", reason)
        v = StallClassifier().classify(wm)
        self.assertEqual(v.stall_class, "wrong_altitude")
        self.assertIn("social_pivot", v.strategies)

    def test_transient_default(self):
        wm = WorldModel(target="10.0.0.9")
        wm.add_finding("service", "tcp/22", {"service": "ssh", "port": 22})
        wm.record_failure("ssh_banner", "timeout")
        self.assertEqual(StallClassifier().classify(wm).stall_class,
                         "transient")

    def test_priority_order_wrong_model_beats_blocked(self):
        wm = WorldModel(target="10.0.0.9")
        wm.fingerprint_mismatch = True
        for _ in range(5):
            wm.record_failure("x", "403 forbidden")
        # wrong_model outranks blocked: re-probing is the senior move
        self.assertEqual(StallClassifier().classify(wm).stall_class,
                         "wrong_model")


if __name__ == "__main__":
    unittest.main()
