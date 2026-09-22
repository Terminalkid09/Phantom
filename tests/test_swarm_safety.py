"""Tests: swarm safety rails (pre-live-fire audit).

* out-of-scope network targets are REFUSED upfront (no threads);
* identity targets always pass (scope gates machines, never people);
* workers inherit scope_list (execution-level enforcement);
* session seeds apply PER TARGET (never cross-contaminate).
"""
import unittest
from unittest.mock import Mock, patch

T1 = "10.0.0.5"
T2 = "10.0.0.9"


class TestScopeRefusal(unittest.TestCase):
    def test_out_of_scope_refused_before_any_worker(self):
        from phantom.automation.swarm import run_swarm
        events = []
        summary = run_swarm(
            [T1], chain="footprint", budget=2,
            scope_list=["192.168.0.0/16"],
            on_event=lambda k, d: events.append(k))
        self.assertFalse(summary["ok"])
        self.assertIn("out of scope", summary["reason"])
        self.assertIn(T1, summary["reason"])
        self.assertEqual(summary["tasks"], [])
        self.assertEqual(events, [])  # zero worker activity

    def test_identity_targets_ignore_scope(self):
        from phantom.automation.swarm import _refuse_out_of_scope
        self.assertEqual(
            _refuse_out_of_scope(["bob@example.com"], ["10.0.0.0/8"]), [])

    def test_in_scope_targets_pass(self):
        from phantom.automation.swarm import _refuse_out_of_scope
        self.assertEqual(_refuse_out_of_scope([T1], ["10.0.0.0/8"]), [])
        self.assertEqual(_refuse_out_of_scope([T1], []), [])


class TestWorkerScopePlumbing(unittest.TestCase):
    def test_worker_agent_receives_scope_list(self):
        import phantom.automation.swarm.worker as worker_mod
        from phantom.automation.swarm.board import Board
        from phantom.automation.swarm.tasks import build_tasks
        board = Board([T1])
        task = build_tasks("footprint", [T1], budget=2)[0]
        seen = {}

        class _FakeAgent:
            def __init__(self, **kwargs):
                seen.update(kwargs)
                self.stealth_engine = Mock()
                self.wm = board.snapshot(T1)
                self._last_stall = ""

            def run(self, goal=None, max_iterations=None):
                return {"actions_taken": 0}

        with patch("phantom.automation.agent.AutonomousAgent",
                     _FakeAgent):
            with patch("phantom.automation.runtime.stealth_runtime.StealthRuntime"):
                worker_mod.run_swarm_task(
                    task, T1, board, runner=Mock(),
                    scope_list=["10.0.0.0/8"])
        self.assertEqual(seen.get("scope_list"), ["10.0.0.0/8"])


class TestSeedPerTarget(unittest.TestCase):
    def test_seed_never_crosses_targets(self):
        import phantom.core.automode as am
        seed_calls = []

        def _seed(target):
            seed_calls.append(target)
            if target == T1:
                return [{"kind": "service", "key": "tcp/80",
                         "value": {"port": "80", "service": "http"},
                         "confidence": 0.9, "source": "manual"}]
            return []

        captured = {}

        def _fake_run_swarm(targets, **kwargs):
            captured["seed_facts"] = kwargs.get("seed_facts")
            captured["scope"] = kwargs.get("scope_list")
            board = Mock()
            board.count = Mock(return_value=0)
            board.targets = Mock(return_value=[])
            return {"ok": False, "tasks": [], "board": {},
                    "added": 0, "skipped": 0, "actions_taken": 0,
                    "trail": [], "failures": [], "evolution_cases": [],
                    "board_ref": board}

        with patch.object(am, "seed_findings_from_session",
                           side_effect=_seed):
            with patch("phantom.automation.swarm.run_swarm",
                       side_effect=_fake_run_swarm):
                am._run_swarm_operation([T1, T2], "footprint", "enterprise",
                                        False, False, 0, False, None, False)
        self.assertEqual(sorted(seed_calls), [T1, T2])
        seeds = captured["seed_facts"]
        self.assertIn(T1, seeds)  # T1's manual service stays on T1
        self.assertNotIn(T2, seeds)  # T2 gets NOTHING from T1


if __name__ == "__main__":
    unittest.main()
