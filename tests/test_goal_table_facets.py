"""Tests: the ONE goal table (goals.GOALS: facts + chain + engine).

A policy fix must be made once: these tests pin that the derived views
(GOAL_FACTS / SWARM_CHAIN / GOAL_ENGINES) all agree with the declaration,
that `engine_for` encodes the fallback policy, and that the swarm path
announces its ignored flags exactly once, in _run_swarm_operation.
"""
import unittest
from unittest.mock import Mock, patch


class TestGoalTable(unittest.TestCase):
    def test_views_agree_with_the_declaration(self):
        from phantom.automation.goals import (GOALS, GOAL_ENGINES,
                                              GOAL_FACTS, SWARM_CHAIN)
        for goal, spec in GOALS.items():
            with self.subTest(goal=goal):
                if spec.facts:
                    self.assertIs(GOAL_FACTS[goal], spec.facts)
                else:
                    self.assertNotIn(goal, GOAL_FACTS)  # "deep" stays out
                if spec.chain:
                    self.assertEqual(SWARM_CHAIN[goal], spec.chain)
                else:
                    self.assertNotIn(goal, SWARM_CHAIN)
                self.assertEqual(GOAL_ENGINES[goal], spec.engine)

    def test_engine_facet_tracks_the_chain(self):
        from phantom.automation.goals import GOALS
        for goal, spec in GOALS.items():
            with self.subTest(goal=goal):
                self.assertEqual(spec.engine == "swarm", bool(spec.chain))

    def test_every_swarm_engine_goal_is_a_swarm_goal(self):
        from phantom.automation.goals import GOAL_ENGINES, SWARM_CHAIN
        swarm = {g for g, e in GOAL_ENGINES.items() if e == "swarm"}
        self.assertEqual(swarm, set(SWARM_CHAIN))


class TestEngineFor(unittest.TestCase):
    def test_swarm_is_honored_for_swarm_goals(self):
        from phantom.automation.goals import engine_for
        self.assertEqual(engine_for("deliver", "swarm"), ("swarm", ""))
        self.assertEqual(engine_for("deep", "swarm"), ("swarm", ""))

    def test_swarm_falls_back_to_agent_with_a_note(self):
        from phantom.automation.goals import engine_for
        engine, note = engine_for("cleanup", "swarm")
        self.assertEqual(engine, "agent")
        self.assertIn("Swarm has no chain for goal 'cleanup'", note)

    def test_agent_request_is_unchanged(self):
        from phantom.automation.goals import engine_for
        self.assertEqual(engine_for("cleanup", "agent"), ("agent", ""))
        self.assertEqual(engine_for("deliver", ""), ("agent", ""))


class TestSwarmIgnoredFlags(unittest.TestCase):
    def _run(self, **flags):
        import phantom.core.automode as am

        def _fake_run_swarm(targets, **kwargs):
            board = Mock()
            board.targets.return_value = []
            board.count.return_value = 0
            return {"ok": True, "tasks": [], "board": {}, "added": 0,
                    "skipped": 0, "actions_taken": 0, "trail": [],
                    "failures": [], "evolution_cases": [],
                    "board_ref": board}

        with patch("phantom.automation.swarm.run_swarm",
                   side_effect=_fake_run_swarm), \
                patch.object(am, "seed_findings_from_session",
                             return_value=[]), \
                patch.object(am.notifier, "success"), \
                patch.object(am.notifier, "info"), \
                patch.object(am.notifier, "warn") as m_warn:
            am._run_swarm_operation(["10.0.0.5"], "footprint", "enterprise",
                                    False, False, 0, False, None, False,
                                    **flags)
        return [str(c.args[0]) for c in m_warn.call_args_list]

    def test_each_ignored_flag_is_announced(self):
        texts = self._run(resume="cp.json", experience=True, evolution=True)
        self.assertEqual(len(texts), 3)
        for flag in ("--resume", "--experience", "--evolution"):
            self.assertTrue(any(flag in t and "ignorato" in t for t in texts),
                            flag)

    def test_silent_when_no_flag_is_given(self):
        self.assertEqual(self._run(), [])


class TestSwarmBranchMergePrint(unittest.TestCase):
    def test_merge_is_printed_per_target(self):
        import phantom.core.automode as am
        merged = {"10.0.0.5": {"service": 3}, "10.0.0.6": {}}
        result = {"beacon_established": False}
        summary = {"tasks": []}
        with patch.object(am, "_run_swarm_operation",
                          return_value=(result, summary, merged)), \
                patch.object(am, "_write_swarm_summary", return_value={}), \
                patch.object(am, "_print_swarm_tail"), \
                patch.object(am.notifier, "success"), \
                patch.object(am.notifier, "info") as m_info, \
                patch.object(am.notifier, "warn"):
            am._run_swarm_branch(
                ["10.0.0.5", "10.0.0.6"], "footprint", "enterprise",
                False, False, 0, False, None, False, "/out", 0.0,
                False, True, "", False, False)
        texts = [str(c.args[0]) for c in m_info.call_args_list]
        self.assertTrue(any("Core sync [10.0.0.5]: service=3" in t
                            for t in texts), texts)
        self.assertFalse(any("10.0.0.6" in t for t in texts))  # empty target


if __name__ == "__main__":
    unittest.main()
