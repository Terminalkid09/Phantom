"""Persisted capability health (AutoModeBrief §16 P2.8).

Pins the ledger arithmetic (streak, Laplace-smoothed health, bounded
multiplier), the worst-first report, persistence, and the agent hook that
records one real attempt.
"""
import os
import tempfile
import unittest
from unittest import mock

from phantom.automation import capability_health as ch
from phantom.automation.capability_health import CapHealth, CapabilityHealth


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        self.now += 1.0
        return self.now


class TestCapHealth(unittest.TestCase):
    def test_new_capability_is_neutral(self):
        row = CapHealth("x")
        self.assertEqual(row.health(), 0.5)
        self.assertAlmostEqual(row.multiplier(), 1.0, places=2)
        self.assertIsNone(row.success_rate())

    def test_streak_tracks_consecutive(self):
        row = CapHealth("x")
        row.streak = 0
        # simulate via CapabilityHealth.record semantics
        led = CapabilityHealth(path=os.devnull)
        r = led.record("x", False)
        self.assertEqual(r.streak, -1)
        r = led.record("x", False)
        self.assertEqual(r.streak, -2)
        r = led.record("x", True)
        self.assertEqual(r.streak, 1)
        r = led.record("x", True)
        self.assertEqual(r.streak, 2)

    def test_health_and_multiplier_move_with_results(self):
        good = CapHealth("g", ok=10, fail=0)
        self.assertGreater(good.health(), 0.5)
        self.assertGreater(good.multiplier(), 1.0)
        bad = CapHealth("b", ok=0, fail=10)
        self.assertLess(bad.health(), 0.5)
        self.assertLess(bad.multiplier(), 1.0)
        # bounded
        self.assertLessEqual(CapHealth("m", ok=1000).multiplier(), 1.5)
        self.assertGreaterEqual(CapHealth("m", fail=1000).multiplier(), 0.5)


class TestCapabilityHealthStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "health.json")
        self.led = CapabilityHealth(path=self.path, clock=_Clock())

    def test_record_and_report_worst_first(self):
        self.led.record("a", True)
        self.led.record("b", False)
        self.led.record("b", False)
        rep = self.led.report()
        self.assertEqual(rep[0]["capability"], "b")   # worst first
        self.assertEqual(rep[0]["fail"], 2)

    def test_persistence_round_trip(self):
        self.led.record("scan_tcp", True)
        self.led.record("scan_tcp", False, reason="timeout")
        self.assertTrue(self.led.save())
        revived = CapabilityHealth(path=self.path)
        revived.load()
        row = revived.of("scan_tcp")
        self.assertIsNotNone(row)
        self.assertEqual(row.ok, 1)
        self.assertEqual(row.fail, 1)
        self.assertEqual(row.last_reason, "timeout")

    def test_broken_store_is_empty_not_fatal(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{ not json")
        led = CapabilityHealth(path=self.path)
        led.load()
        self.assertTrue(led.record("x", True).ok == 1)

    def test_unknown_capability_multiplier_is_neutral(self):
        self.assertEqual(self.led.multiplier("never_seen"), 1.0)

    def test_eviction_is_bounded(self):
        led = CapabilityHealth(path=os.devnull, clock=_Clock(),
                               max_capabilities=3)
        for i in range(6):
            led.record(f"cap{i}", True)
        self.assertLessEqual(len(led.report()), 3)

    def test_decay_above_max_attempts(self):
        led = CapabilityHealth(path=os.devnull, clock=_Clock())
        for _ in range(205):
            led.record("c", True)
        row = led.of("c")
        self.assertLess(row.attempts(), 205)


class TestAgentWiring(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.led = CapabilityHealth(path=os.path.join(self.tmp, "h.json"),
                                    clock=_Clock())
        ch.set_instance(self.led)

    def tearDown(self):
        ch.set_instance(None)

    def test_record_health_respects_config_and_records(self):
        from phantom.automation import agent
        with mock.patch.dict(os.environ, {"PHANTOM_CAPABILITY_HEALTH": "1"}):
            agent._record_health("scan_tcp", True)
        self.assertIsNotNone(self.led.of("scan_tcp"))
        with mock.patch.dict(os.environ, {"PHANTOM_CAPABILITY_HEALTH": "0"}):
            agent._record_health("scan_tcp", False)
        # disabled: the failed attempt was NOT folded in
        self.assertEqual(self.led.of("scan_tcp").fail, 0)


if __name__ == "__main__":
    unittest.main()
