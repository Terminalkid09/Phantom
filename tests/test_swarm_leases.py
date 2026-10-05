"""Swarm task leases: (task, target) RUN ownership with a TTL.

Pins the primitive (grant/release/expiry/idempotency/denial) with an
injectable clock, and the dispatcher integration: a lease held by another
owner makes the worker SKIP the slot, and a completed worker always frees
its own.
"""
import unittest
from types import SimpleNamespace

from phantom.automation.swarm.leases import Lease, LeaseTable
from phantom.automation.swarm.board import Board


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


class TestLeaseTable(unittest.TestCase):
    def test_first_claim_wins_and_same_owner_is_idempotent(self):
        table = LeaseTable(ttl=10, clock=FakeClock())
        self.assertTrue(table.claim("t1", "10.0.0.1", "w1"))
        self.assertEqual(table.owner_of("t1", "10.0.0.1"), "w1")
        # same owner re-claiming is a grant, not a denial
        self.assertTrue(table.claim("t1", "10.0.0.1", "w1"))
        self.assertEqual(table.denied, 0)
        self.assertEqual(table.active(), 1)

    def test_other_owner_is_denied_while_live(self):
        table = LeaseTable(ttl=10, clock=FakeClock())
        table.claim("t1", "10.0.0.1", "w1")
        self.assertFalse(table.claim("t1", "10.0.0.1", "w2"))
        self.assertEqual(table.owner_of("t1", "10.0.0.1"), "w1")
        self.assertEqual(table.denied, 1)

    def test_expired_lease_is_reclaimable(self):
        clock = FakeClock()
        table = LeaseTable(ttl=10, clock=clock)
        table.claim("t1", "10.0.0.1", "w1")
        clock.now += 11
        self.assertIsNone(table.owner_of("t1", "10.0.0.1"))
        self.assertTrue(table.claim("t1", "10.0.0.1", "w2"))
        self.assertEqual(table.owner_of("t1", "10.0.0.1"), "w2")
        self.assertEqual(table.reclaimed, 1)

    def test_release_is_owner_checked(self):
        table = LeaseTable(ttl=10, clock=FakeClock())
        table.claim("t1", "10.0.0.1", "w1")
        self.assertFalse(table.release("t1", "10.0.0.1", "w2"))  # stale owner
        self.assertEqual(table.owner_of("t1", "10.0.0.1"), "w1")
        self.assertTrue(table.release("t1", "10.0.0.1", "w1"))
        self.assertIsNone(table.owner_of("t1", "10.0.0.1"))
        self.assertEqual(table.released, 1)

    def test_renew_extends_and_rejects_foreign_owner(self):
        clock = FakeClock()
        table = LeaseTable(ttl=10, clock=clock)
        table.claim("t1", "10.0.0.1", "w1")
        clock.now += 8
        self.assertTrue(table.renew("t1", "10.0.0.1", "w1"))
        clock.now += 8          # 16s total, but renewed 8s ago -> still live
        self.assertEqual(table.owner_of("t1", "10.0.0.1"), "w1")
        self.assertFalse(table.renew("t1", "10.0.0.1", "w2"))

    def test_sweep_drops_only_expired(self):
        clock = FakeClock()
        table = LeaseTable(ttl=10, clock=clock)
        table.claim("t1", "a", "w1")
        clock.now += 5
        table.claim("t2", "b", "w2")
        clock.now += 6          # t1 expired (11s), t2 live (6s)
        dead = table.sweep()
        self.assertEqual(dead, [("t1", "a")])
        self.assertEqual(table.active(), 1)


class TestBoardExposesLeases(unittest.TestCase):
    def test_board_has_a_lease_table(self):
        board = Board(["10.0.0.1", "10.0.0.2"])
        self.assertIsInstance(board.leases, LeaseTable)
        self.assertTrue(board.leases.claim("t1", "10.0.0.1", "w1"))


class _FakeBoard:
    def __init__(self):
        self.leases = LeaseTable()
        self.wm = SimpleNamespace()

    def worldmodel(self, target):
        return self.wm

    def ensure(self, target):
        return None


class TestDispatchIntegration(unittest.TestCase):
    def _action(self, task_id="t1", cap="cap#1", target="10.0.0.1"):
        task = SimpleNamespace(id=task_id, profile="",
                               avoid_caps=frozenset())
        return SimpleNamespace(task=task, targets=[target],
                               capability_id=cap, worker_profile=None,
                               worker_avoid=None, worker_seed=None)

    def test_a_held_lease_makes_the_worker_skip(self):
        from phantom.automation import swarm
        board = _FakeBoard()
        action = self._action()
        # someone else already owns the slot
        board.leases.claim("t1", "10.0.0.1", "other-owner")
        called = {"n": 0}
        events = []

        def never(*a, **k):
            called["n"] += 1
            raise AssertionError("worker ran under a foreign lease")

        saved = swarm.run_swarm_task
        swarm.run_swarm_task = never
        try:
            swarm._dispatch(action, board, on_event=lambda k, d: events.append(k))
        finally:
            swarm.run_swarm_task = saved
        self.assertEqual(called["n"], 0)
        self.assertIn("lease_denied", events)

    def test_a_completed_worker_releases_its_lease(self):
        from phantom.automation import swarm
        from phantom.automation.swarm import scheduler
        board = _FakeBoard()
        action = self._action()
        result = SimpleNamespace(ok=True, staged=[], actions_taken=1,
                                 stall="", note="")

        saved_worker = swarm.run_swarm_task
        saved_commit = scheduler.commit_result
        swarm.run_swarm_task = lambda *a, **k: result
        scheduler.commit_result = lambda *a, **k: None
        try:
            swarm._dispatch(action, board)
        finally:
            swarm.run_swarm_task = saved_worker
            scheduler.commit_result = saved_commit
        # the slot is free again after the worker finishes
        self.assertIsNone(board.leases.owner_of("t1", "10.0.0.1"))
        self.assertEqual(board.leases.active(), 0)


if __name__ == "__main__":
    unittest.main()
