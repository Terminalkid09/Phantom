"""Coverage contract: every goal/profile the operator can pick must be
plannable. A goal naming an unsourceable fact (or a profile missing
from the defender stack) can never complete — this test pins the full
matrix so dead options cannot creep back in."""
import unittest


class TestGoalCoverage(unittest.TestCase):
    def test_every_goal_fact_has_a_source_capability(self):
        from phantom.automation.guidance.commands import make_registry
        from phantom.automation.planner import GOAL_FACTS, _FACT_SOURCES
        ids = {c.id for c in make_registry().all()}
        dead = {}
        for goal, facts in GOAL_FACTS.items():
            for fact in facts:
                srcs = [s for s in _FACT_SOURCES.get(fact, []) if s in ids]
                if not srcs:
                    dead.setdefault(goal, []).append(fact)
        self.assertEqual(dead, {}, f"unsourceable goal facts: {dead}")

    def test_cli_goals_are_plannable(self):
        from phantom.automation.planner import GOAL_FACTS
        # auto --goal choices + agent --goal choices (deep is a meta-goal
        # run by the stage ladder, not a fact set — hence the exemption)
        cli_goals = {"deep", "deliver", "complete_kill_chain", "footprint",
                     "beacon", "creds", "identity", "post_exploit", "ad",
                     "crack", "lateral", "cleanup"}
        for goal in cli_goals:
            if goal == "deep":
                continue
            self.assertIn(goal, GOAL_FACTS, goal)

    def test_swarm_chains_map_to_real_goals(self):
        from phantom.automation.planner import GOAL_FACTS
        from phantom.automation.swarm.tasks import build_tasks
        for chain in ("footprint", "identity", "full", "deep",
                        "web", "creds"):
            for task in build_tasks(chain, ["10.0.0.5"]):
                self.assertIn(task.goal, GOAL_FACTS,
                              f"{chain}:{task.goal}")

    def test_all_defender_profiles_exist_and_score(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.guidance.threatmodel import (
            _DEFAULT_STACK, BlueTeamModel)
        for profile in ("enterprise", "smb", "cloud", "financial",
                        "government", "mobile"):
            self.assertIn(profile, _DEFAULT_STACK, profile)
            model = BlueTeamModel.for_profile(profile)
            wm = WorldModel(target="10.0.0.5", target_type="ip")
            risk = model.risk("exploit", "aggressive", 4.0)
            self.assertGreaterEqual(risk, 0.0, profile)


if __name__ == "__main__":
    unittest.main()
