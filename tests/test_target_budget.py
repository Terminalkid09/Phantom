"""Per-target budgets (ManusReview §4.2).

Pins that a budget keyed by TARGET (separate from the run-wide budget) can
refuse a spend atomically, reports a typed reason, and that the swarm skips
an exhausted target while charging the targets it did run.
"""
import unittest

from phantom.automation.budget import (
    KIND_ACTIONS,
    KIND_NOISE,
    BudgetLedger,
    TargetBudget,
    ledger_from_config,
)


class _FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class TestTargetBudget(unittest.TestCase):
    def test_unlimited_by_default_never_refuses(self):
        row = TargetBudget(target="10.0.0.1")
        self.assertFalse(row.exhausted())
        self.assertEqual(row.reason(), "")
        self.assertTrue(row.max_actions == 0)

    def test_action_limit_is_reported_and_bounded(self):
        row = TargetBudget(target="h", max_actions=2)
        row.actions = 2
        self.assertTrue(row.exhausted())
        self.assertIn("action budget exhausted", row.reason())
        self.assertEqual(row.remaining()[KIND_ACTIONS], 0)


class TestBudgetLedger(unittest.TestCase):
    def setUp(self):
        self.clock = _FakeClock()
        self.led = BudgetLedger(default_actions=3, clock=self.clock)

    def test_spend_charges_and_refuses_atomic(self):
        self.assertTrue(self.led.spend("a", actions=2))
        # a 2-more spend would cross the limit of 3 -> refused, nothing charged
        self.assertFalse(self.led.spend("a", actions=2))
        self.assertEqual(self.led.budget_for("a").actions, 2)
        self.assertTrue(self.led.spend("a", actions=1))
        self.assertTrue(self.led.exhausted("a"))
        self.assertEqual(self.led.refused, 1)
        self.assertEqual(self.led.charged, 2)

    def test_targets_are_isolated(self):
        self.assertTrue(self.led.spend("a", actions=3))
        self.assertTrue(self.led.exhausted("a"))
        self.assertFalse(self.led.exhausted("b"))
        self.assertTrue(self.led.spend("b", actions=1))

    def test_limit_override_zero_means_unlimited(self):
        self.led.set_limit("a", max_actions=0)
        for _ in range(10):
            self.assertTrue(self.led.spend("a", actions=5))

    def test_noise_kind_and_remaining(self):
        led = BudgetLedger(default_noise=1.0, clock=self.clock)
        self.assertTrue(led.spend("t", noise=0.6))
        self.assertFalse(led.spend("t", noise=0.6))
        self.assertAlmostEqual(led.remaining("t")[KIND_NOISE], 0.4, places=3)

    def test_snapshot_is_plain_data(self):
        self.led.spend("a", actions=1)
        snap = self.led.snapshot()
        self.assertIn("a", snap["targets"])
        self.assertTrue(snap["targets"]["a"]["actions"] == 1)
        self.assertIn("reason", snap["targets"]["a"])

    def test_from_config_reads_limits(self):
        def getter(key, default=None):
            return {"budget.per_target_actions": 5}.get(key, default)
        led = ledger_from_config(getter)
        self.assertEqual(led.budget_for("x").max_actions, 5)
        self.assertFalse(led.exhausted("x"))

    def test_broken_config_reader_is_unlimited(self):
        def getter(key, default=None):
            raise RuntimeError("boom")
        led = ledger_from_config(getter)
        self.assertTrue(led.spend("x", actions=1000))


class TestSwarmBudgetIntegration(unittest.TestCase):
    def _run(self, ledger):
        from phantom.automation.swarm import run_swarm

        def runner(cap, wm, slots=None):
            return ""

        events = []
        summary = run_swarm(
            ["10.0.0.1", "10.0.0.2"], chain="footprint",
            runner=runner, budget=2, seed=1,
            on_event=lambda k, d: events.append((k, d)),
            budgets=ledger)
        return summary, events

    def test_exhausted_target_is_skipped(self):
        led = BudgetLedger(default_actions=1)
        led.spend("10.0.0.1", actions=1)      # pre-spend target 1 to its cap
        summary, events = self._run(led)
        reasons = [d for k, d in events if k == "budget_exhausted"]
        self.assertTrue(any(d["target"] == "10.0.0.1" for d in reasons))
        # target 2 is never skipped
        self.assertFalse(any(d["target"] == "10.0.0.2" for d in reasons))
        self.assertIn("budgets", summary)
        self.assertTrue(summary["budgets"]["targets"])

    def test_unlimited_ledger_skips_nothing(self):
        led = BudgetLedger()          # unlimited
        _, events = self._run(led)
        self.assertFalse(any(k == "budget_exhausted" for k, _ in events))


if __name__ == "__main__":
    unittest.main()
