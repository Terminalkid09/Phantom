"""Task lifecycle: cancellation + idempotency (ManusReview §4.2, §12.7).

Pins that an operator stop cascades through the token tree, that a repeated
(task, target) re-dispatch reuses the prior result instead of re-running, and
that the dispatcher honours both.
"""
import unittest
from types import SimpleNamespace

from phantom.automation.budget import BudgetLedger
from phantom.automation.swarm.cancellation import (
    Cancelled,
    CancellationToken,
    NullToken,
)
from phantom.automation.swarm.idempotency import IdempotencyRegistry
from phantom.automation.swarm.leases import LeaseTable


class TestCancellationToken(unittest.TestCase):
    def test_starts_live(self):
        token = CancellationToken()
        self.assertFalse(token.cancelled)
        self.assertEqual(token.reason, "")

    def test_cancel_sets_reason_and_is_idempotent(self):
        token = CancellationToken()
        self.assertTrue(token.cancel("operator stop"))
        self.assertFalse(token.cancel("a later reason"))
        self.assertTrue(token.cancelled)
        self.assertEqual(token.reason, "operator stop")

    def test_cancel_cascades_to_children(self):
        root = CancellationToken()
        a = root.child()
        b = root.child()
        c = a.child()
        root.cancel("stop all")
        self.assertTrue(all(t.cancelled for t in (a, b, c)))
        self.assertTrue(c.reason == "stop all")

    def test_child_of_cancelled_parent_is_born_cancelled(self):
        root = CancellationToken()
        root.cancel("gone")
        child = root.child()
        self.assertTrue(child.cancelled)
        self.assertEqual(child.reason, "gone")

    def test_cancelling_one_child_leaves_sibling_live(self):
        root = CancellationToken()
        a = root.child()
        b = root.child()
        a.cancel("just a")
        self.assertTrue(a.cancelled)
        self.assertFalse(b.cancelled)
        self.assertFalse(root.cancelled)

    def test_raise_if_cancelled(self):
        token = CancellationToken()
        token.raise_if_cancelled()          # no-op while live
        token.cancel("nope")
        with self.assertRaises(Cancelled) as ctx:
            token.raise_if_cancelled()
        self.assertEqual(ctx.exception.reason, "nope")

    def test_null_token_is_a_plain_token(self):
        token = NullToken()
        self.assertFalse(token.cancelled)


class TestIdempotencyRegistry(unittest.TestCase):
    def test_first_begin_runs_repeat_skips(self):
        reg = IdempotencyRegistry()
        self.assertTrue(reg.begin("k"))
        reg.complete("k", "result")
        self.assertFalse(reg.begin("k"))
        self.assertEqual(reg.outcome("k"), "result")
        self.assertEqual(reg.ran, 1)
        self.assertEqual(reg.skipped, 1)

    def test_in_flight_key_is_not_double_run(self):
        reg = IdempotencyRegistry()
        self.assertTrue(reg.begin("k"))
        self.assertTrue(reg.in_flight("k"))
        self.assertFalse(reg.begin("k"))    # concurrent duplicate
        self.assertFalse(reg.completed("k"))

    def test_fail_releases_for_retry(self):
        reg = IdempotencyRegistry()
        reg.begin("k")
        reg.fail("k")
        self.assertFalse(reg.in_flight("k"))
        self.assertTrue(reg.begin("k"))     # retry allowed

    def test_bounded(self):
        reg = IdempotencyRegistry(max_entries=2)
        for i in range(5):
            reg.begin(f"k{i}")
            reg.complete(f"k{i}", i)
        self.assertIsNone(reg.outcome("k0"))
        self.assertEqual(reg.outcome("k4"), 4)

    def test_key_for_is_stable(self):
        self.assertEqual(IdempotencyRegistry.key_for("t1", "10.0.0.1"),
                         "t1:10.0.0.1")


class _FakeBoard:
    def __init__(self):
        self.leases = LeaseTable()
        self.budgets = BudgetLedger()
        self.wm = SimpleNamespace()

    def worldmodel(self, target):
        return self.wm

    def ensure(self, target):
        return None


class TestDispatchLifecycle(unittest.TestCase):
    def _action(self, task_id="t1", cap="cap#1", target="10.0.0.1"):
        task = SimpleNamespace(id=task_id, profile="",
                               avoid_caps=frozenset())
        return SimpleNamespace(task=task, targets=[target],
                               capability_id=cap, worker_profile=None,
                               worker_avoid=None, worker_seed=None)

    def _patch(self, swarm, result, calls):
        from phantom.automation.swarm import scheduler

        def worker(*a, **k):
            calls.append(1)
            return result

        saved = (swarm.run_swarm_task, scheduler.commit_result)
        swarm.run_swarm_task = worker
        scheduler.commit_result = lambda *a, **k: None
        return saved

    def _unpatch(self, swarm, saved):
        from phantom.automation.swarm import scheduler
        swarm.run_swarm_task, scheduler.commit_result = saved

    def test_cancel_before_dispatch_stops_the_worker(self):
        from phantom.automation import swarm
        board = _FakeBoard()
        action = self._action()
        token = CancellationToken()
        token.cancel("operator stop")
        calls, events = [], []
        saved = self._patch(swarm, SimpleNamespace(ok=True, staged=[],
                                                   actions_taken=0,
                                                   stall="", note=""), calls)
        try:
            swarm._dispatch(action, board, cancel=token,
                            on_event=lambda k, d: events.append(k))
        finally:
            self._unpatch(swarm, saved)
        self.assertEqual(calls, [])
        self.assertIn("cancelled", events)

    def test_second_dispatch_is_idempotent(self):
        from phantom.automation import swarm
        board = _FakeBoard()
        action = self._action()
        reg = IdempotencyRegistry()
        calls, events = [], []
        result = SimpleNamespace(ok=True, staged=[], actions_taken=1,
                                 stall="", note="")
        saved = self._patch(swarm, result, calls)
        try:
            swarm._dispatch(action, board, idempotency=reg,
                            on_event=lambda k, d: events.append(k))
            swarm._dispatch(action, board, idempotency=reg,
                            on_event=lambda k, d: events.append(k))
        finally:
            self._unpatch(swarm, saved)
        self.assertEqual(len(calls), 1)               # ran exactly once
        self.assertIn("idempotent_skip", events)
        self.assertTrue(reg.completed(IdempotencyRegistry.key_for(
            "t1", "10.0.0.1")))


if __name__ == "__main__":
    unittest.main()
