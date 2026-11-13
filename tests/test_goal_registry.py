"""Invariants for the single goal registry (phantom/automation/goals.py).

The agent planner and the swarm engine used to keep two parallel goal
tables by hand. They now read ONE registry; these tests fail if the two
views drift or if a goal points at a swarm chain template that no longer
exists.
"""
import unittest


class TestGoalRegistry(unittest.TestCase):
    def test_planner_reexports_the_single_source(self):
        from phantom.automation import goals
        from phantom.automation import planner
        self.assertIs(planner.GOAL_FACTS, goals.GOAL_FACTS)

    def test_automode_uses_the_single_source(self):
        from phantom.automation import goals
        from phantom.core import automode
        self.assertIs(automode._GOAL_CHAIN, goals.SWARM_CHAIN)

    def test_every_swarm_goal_is_a_known_goal(self):
        from phantom.automation.goals import GOAL_FACTS, SWARM_CHAIN
        # "deep" is a meta-goal the planner handles specially, so it has a
        # swarm chain without a GOAL_FACTS entry of its own.
        unknown = set(SWARM_CHAIN) - set(GOAL_FACTS) - {"deep"}
        self.assertEqual(unknown, set(),
                         f"swarm goals with no goal definition: {unknown}")

    def test_every_swarm_goal_maps_to_a_real_chain(self):
        from phantom.automation.goals import SWARM_CHAIN
        from phantom.automation.swarm.tasks import CHAIN_TEMPLATES
        missing = {g: c for g, c in SWARM_CHAIN.items()
                   if c not in CHAIN_TEMPLATES}
        self.assertEqual(missing, {},
                         f"swarm goals pointing at unknown chains: {missing}")

    def test_goal_facts_are_non_empty_lists(self):
        from phantom.automation.goals import GOAL_FACTS
        for goal, facts in GOAL_FACTS.items():
            self.assertTrue(facts, f"{goal} has no terminal facts")
            self.assertTrue(all(isinstance(f, str) and f for f in facts),
                            goal)


if __name__ == "__main__":
    unittest.main()
