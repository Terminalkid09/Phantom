"""Tests for fallback strategies and historical self-learning engine."""
import unittest
import tempfile
import os
from phantom.automation.belief import WorldModel
from phantom.automation.fallback import (
    FallbackEngine, HistoricalLearner, StrategyAttempt,
    TechniqueStats, FALLBACK_CHAINS, engine_summary,
)



class TestTechniqueStats(unittest.TestCase):
    """Test Bayesian posterior calculations."""

    def test_default_prior(self):
        """With no data, posterior is Beta(1,1) → 0.5."""
        s = TechniqueStats()
        self.assertEqual(s.rate, 0.5)
        self.assertAlmostEqual(s.posterior_mean, 0.5)

    def test_one_success(self):
        """Beta(2,1) → 0.667 posterior mean."""
        s = TechniqueStats(successes=1, failures=0)
        self.assertAlmostEqual(s.posterior_mean, 2.0 / 3.0, places=2)

    def test_mixed(self):
        """3 successes, 2 failures → Beta(4,3) → 0.571."""
        s = TechniqueStats(successes=3, failures=2)
        self.assertAlmostEqual(s.posterior_mean, 4.0 / 7.0, places=2)


class TestFallbackEngine(unittest.TestCase):
    """Test fallback decision logic."""

    def setUp(self):
        self.engine = FallbackEngine()

    def test_record_and_failed(self):
        """Recording a failure adds to failed_strategies."""
        self.engine.record("network_footprint", "scan_tcp",
                           "10.0.0.5", ok=False, reason="timeout")
        self.assertIn("network_footprint", self.engine.failed_strategies())

    def test_record_success_not_failed(self):
        """Recording a success does NOT add to failed_strategies."""
        self.engine.record("network_footprint", "scan_tcp",
                           "10.0.0.5", ok=True)
        self.assertNotIn("network_footprint", self.engine.failed_strategies())

    def test_next_strategy_skips_failed(self):
        """Failed strategy is skipped, next viable one chosen."""
        wm = WorldModel("10.0.0.5", "ip")
        wm.add_finding("service", "tcp/22", {"service": "ssh", "port": "22"},
                       confidence=0.9, source="scan")

        self.engine.record("network_footprint", "scan_tcp",
                           "10.0.0.5", ok=False, reason="no ports open")
        next_s = self.engine.next_strategy("network_footprint", wm)
        self.assertIsNotNone(next_s)
        self.assertNotEqual(next_s, "network_footprint")

    def test_next_strategy_respects_viability(self):
        """Without services, exploit_chain is not viable."""
        wm = WorldModel("10.0.0.5", "ip")
        self.engine.record("network_footprint", "scan_tcp",
                           "10.0.0.5", ok=False)
        # Should not pick exploit_chain (no services)
        next_s = self.engine.next_strategy("network_footprint", wm)
        if next_s:
            self.assertNotEqual(next_s, "exploit_chain")

    def test_gap_analysis_beacon_already(self):
        """When beacon is deployed, gap_analysis returns None."""
        wm = WorldModel("10.0.0.5", "ip")
        wm.add_finding("beacon", "established", {"session": "abc"}, confidence=0.9)
        result = self.engine._gap_analysis(wm)
        self.assertIsNone(result)

    def test_gap_analysis_with_creds(self):
        """With credentials but no beacon, gap_analysis recommends beacon."""
        wm = WorldModel("10.0.0.5", "ip")
        wm.add_finding("creds", "ssh:10.0.0.5",
                       {"username": "root", "password": "x"}, confidence=0.9)
        result = self.engine._gap_analysis(wm)
        self.assertEqual(result, "network_beacon")

    def test_learned_accounts(self):
        """Failed login attempts reveal valid accounts."""
        self.engine.record("network_creds", "ssh_login", "10.0.0.5",
                           ok=False, reason="auth failed",
                           learned={"valid_accounts": ["admin", "root"]})
        accounts = self.engine.learned_accounts()
        self.assertIn("admin", accounts)
        self.assertIn("root", accounts)

    def test_strategy_attempt_to_dict(self):
        """StrategyAttempt serialization works."""
        a = StrategyAttempt(strategy="network_footprint",
                            capability="scan_tcp", target="10.0.0.5",
                            ok=True, learned={"ports": [22, 80]})
        d = a.to_dict()
        self.assertEqual(d["strategy"], "network_footprint")
        self.assertEqual(d["ok"], True)
        self.assertEqual(d["learned"]["ports"], [22, 80])


class TestHistoricalLearner(unittest.TestCase):
    """Test self-learning persistence."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = os.path.join(self.tmpdir, "test_history.json")

    def tearDown(self):
        try:
            os.remove(self.store)
            os.rmdir(self.tmpdir)
        except Exception:
            pass

    def test_new_learner_uninformed(self):
        """Fresh learner starts with Beta(1,1) prior."""
        learner = HistoricalLearner(store_path=self.store, decay_days=90)
        self.assertAlmostEqual(learner.prior("unknown_cap"), 0.5)

    def test_load_legacy_list_format(self):
        """A legacy flat-list history file must load (migrated), not crash.

        Regression: the shared engagement_history.json used to be written as
        a flat list by core.history while automations.fallback expected a
        dict-of-techniques — HistoricalLearner crashed on every init.
        """
        import json
        legacy = [
            {"technique": "classify", "target_profile": "ip", "success": True,
             "timestamp": "2026-08-21T16:45:30"},
            {"technique": "scan", "target_profile": "ip", "success": False,
             "timestamp": "2026-08-21T16:45:31"},
            {"technique": "scan", "target_profile": "ip", "success": False,
             "timestamp": "2026-08-21T16:45:32"},
            "not-a-record",  # junk must be skipped, not crash
        ]
        with open(self.store, "w") as f:
            json.dump(legacy, f)
        learner = HistoricalLearner(store_path=self.store, decay_days=90)
        self.assertEqual(learner.stats["classify"].successes, 1)
        self.assertEqual(learner.stats["scan"].failures, 2)
        # 1 win / 3 samples -> posterior > 0.5
        self.assertGreater(learner.prior("classify"), 0.5)
        self.assertLess(learner.prior("scan"), 0.5)

    def test_load_corrupt_file_never_crashes(self):
        """A corrupt/foreign payload must be ignored, not raise."""
        import json
        with open(self.store, "w") as f:
            json.dump({"techniques": ["oops", "list-not-dict"]}, f)
        learner = HistoricalLearner(store_path=self.store, decay_days=90)
        self.assertEqual(len(learner.stats), 0)
        with open(self.store, "w") as f:
            f.write("{not json at all")
        learner = HistoricalLearner(store_path=self.store, decay_days=90)
        self.assertEqual(len(learner.stats), 0)

    def test_record_and_prior(self):
        """Recording successes improves the posterior."""
        learner = HistoricalLearner(store_path=self.store, decay_days=90)
        for _ in range(5):
            learner.record("exploit", "service_exploit", "10.0.0.5", ok=True)
        prior = learner.prior("service_exploit")
        self.assertGreater(prior, 0.5)

    def test_record_failure_lowers_prior(self):
        """Failures lower the posterior."""
        learner = HistoricalLearner(store_path=self.store, decay_days=90)
        learner.record("exploit", "service_exploit", "10.0.0.5", ok=True)
        learner.record("exploit", "service_exploit", "10.0.0.5", ok=False)
        learner.record("exploit", "service_exploit", "10.0.0.5", ok=False)
        prior = learner.prior("service_exploit")
        self.assertLess(prior, 0.5)

    def test_os_hint_prior(self):
        """OS-specific breakdown returns narrow prior when enough samples."""
        learner = HistoricalLearner(store_path=self.store, decay_days=90)
        # 5 Windows successes
        for _ in range(5):
            learner.record("exploit", "service_exploit", "10.0.0.5",
                          ok=True, os_hint="windows")
        # 5 Linux failures
        for _ in range(5):
            learner.record("exploit", "service_exploit", "10.0.0.5",
                          ok=False, os_hint="linux")
        win_prior = learner.prior("service_exploit", os_hint="windows")
        lin_prior = learner.prior("service_exploit", os_hint="linux")
        self.assertGreater(win_prior, lin_prior)

    def test_summary_returns_dict(self):
        """Summary returns structured stats."""
        learner = HistoricalLearner(store_path=self.store, decay_days=90)
        learner.record("exploit", "service_exploit", "10.0.0.5", ok=True)
        summary = learner.summary()
        self.assertIn("service_exploit", summary)

    def test_persist_and_reload(self):
        """Saved history survives reload."""
        learner = HistoricalLearner(store_path=self.store, decay_days=90)
        learner.record("exploit", "service_exploit", "10.0.0.5", ok=True)
        learner.persist()

        learner2 = HistoricalLearner(store_path=self.store, decay_days=90)
        prior = learner2.prior("service_exploit")
        self.assertGreater(prior, 0.5)

    def test_best_alternative(self):
        """Picks the candidate with highest historical success."""
        learner = HistoricalLearner(store_path=self.store, decay_days=90)
        for _ in range(5):
            learner.record("foo", "capa", "10.0.0.5", ok=True)
        for _ in range(5):
            learner.record("bar", "capb", "10.0.0.5", ok=False)
        best = learner.best_alternative("capb", ["capa", "capb"])
        self.assertEqual(best, "capa")

    def test_engine_summary(self):
        """Combined summary works."""
        engine = FallbackEngine()
        engine.record("network_footprint", "scan_tcp", "10.0.0.5", ok=True)
        learner = HistoricalLearner(store_path=self.store, decay_days=90)
        learner.record("exploit", "service_exploit", "10.0.0.5", ok=False)
        summary = engine_summary(engine, learner)
        self.assertEqual(summary["attempts"], 1)
        self.assertEqual(summary["successful"], 1)


if __name__ == "__main__":
    unittest.main()