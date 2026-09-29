"""Shared-activity between swarm pools.

A pool whose own run returned can leave a worker in flight (drain timeout).
Without a cross-pool view, the scheduler declared a queued task whose
producer was running in ANOTHER pool as "never released" — a false dead end
for a fact that was about to be committed. These tests pin the shared view,
the bounded wait, and the honest summary note.
"""
import unittest

from phantom.automation.swarm import scheduler


class _FakeOrch:
    def __init__(self, active=0, seq=None):
        self.active = active
        self.seq = list(seq or [])
        self.campaign = []

    def _agents_active(self):
        if self.seq:
            return self.seq.pop(0)
        return self.active


class _Task:
    def __init__(self, status="queued", needs=("creds",)):
        self.id = "t1"
        self.goal = "deliver"
        self.status = status
        self.attempts = 0
        self.profile = ""
        self.failure_kind = ""
        self.note = ""
        self.done_targets = set()
        self.needs = needs


class _Board:
    added = 0
    skipped = 0

    def summary(self):
        return {}


class TestActiveAcross(unittest.TestCase):
    def test_it_sums_every_pool(self):
        orchs = {"a": _FakeOrch(2), "b": _FakeOrch(3), "c": _FakeOrch(0)}
        self.assertEqual(scheduler._active_across(orchs), 5)

    def test_a_pool_without_the_hook_is_ignored(self):
        class _Bare:
            def _agents_active(self):
                raise RuntimeError("no hook")

        self.assertEqual(scheduler._active_across({"x": _Bare()}), 0)


class TestWaitForActivity(unittest.TestCase):
    def test_it_returns_once_every_pool_is_quiet(self):
        o = _FakeOrch(seq=[2, 1, 0])
        self.assertEqual(scheduler._wait_for_activity({"t": o}, grace=2.0), 0)

    def test_it_gives_up_after_the_grace(self):
        o = _FakeOrch(active=3)
        self.assertGreaterEqual(
            scheduler._wait_for_activity({"t": o}, grace=0.2), 1)


class TestSummaryHonesty(unittest.TestCase):
    def _summarize(self, active):
        return scheduler._summarize(
            [_Task()], _Board(), {"t": _FakeOrch(active)},
            {"failures": [], "cases": []})

    def test_a_queued_task_with_active_producers_is_pending(self):
        s = self._summarize(active=2)
        self.assertEqual(s["shared_activity"]["active_at_summary"], 2)
        self.assertIn("pending producer", s["tasks"][0]["note"])
        self.assertNotIn("never released", s["tasks"][0]["note"])

    def test_a_queued_task_with_nothing_in_flight_is_never_released(self):
        s = self._summarize(active=0)
        self.assertEqual(s["shared_activity"]["active_at_summary"], 0)
        self.assertIn("never released", s["tasks"][0]["note"])


if __name__ == "__main__":
    unittest.main()
