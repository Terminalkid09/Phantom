"""The capability coverage audit: every declared path must still resolve.

These are the invariants that keep a declarative plan from silently
degrading into "no affordable path to goal". They are cheap and read-only,
so they run on every suite — a rename that breaks a table fails here
instead of at an operator's engagement.
"""
import unittest

from phantom.automation.goals import GOAL_FACTS, SWARM_CHAIN
from phantom.automation.guidance.kit import CAPABILITIES
from phantom.automation.planner import _FACT_SOURCES
from phantom.automation.swarm import coverage
from phantom.automation.swarm.tasks import _CHAINS


class TestAuditIsGreen(unittest.TestCase):
    def setUp(self):
        self.report = coverage.audit()

    def test_the_whole_audit_passes(self):
        self.assertTrue(
            self.report.ok,
            "\n".join(str(g) for g in self.report.gaps))

    def test_no_unknown_capability_ids(self):
        self.assertEqual(self.report.by_kind().get("unknown_id"), None)

    def test_no_unreachable_goals(self):
        self.assertEqual(self.report.by_kind().get("unreachable_goal"), None)

    def test_no_unproduced_chain_facts(self):
        self.assertEqual(self.report.by_kind().get("unproduced_fact"), None)

    def test_no_effect_drift(self):
        self.assertEqual(self.report.by_kind().get("effect_drift"), None)

    def test_every_profile_row_is_ok(self):
        for row in self.report.profiles:
            self.assertTrue(row.ok, f"{row.profile}: {row}")


class TestEffectDriftIsActuallyReconciled(unittest.TestCase):
    """The audit found three capabilities declaring fewer effects than
    their interpreter emits. The declared list is what the planner's
    completeness check reads, so an omission makes a SUCCESSFUL final
    step look incomplete."""

    def _effects(self, cid):
        for cap in CAPABILITIES:
            if cap.id == cid:
                return set(cap.effects)
        self.fail(f"{cid} not in the registry")

    def test_breach_check_declares_breach_exposure(self):
        self.assertIn("breach_exposure", self._effects("breach_check"))

    def test_rce_foothold_declares_cloud_creds(self):
        self.assertIn("cloud_creds", self._effects("rce_foothold"))

    def test_dm_launch_declares_the_stage_facts(self):
        effects = self._effects("dm_launch")
        self.assertIn("dm_stage", effects)
        self.assertIn("dm_plan", effects)

    def test_the_drifted_facts_are_now_indexed_and_produced(self):
        producers = coverage._producers()
        for fact in ("breach_exposure", "cloud_creds", "dm_stage"):
            self.assertIn(fact, producers, fact)
            self.assertIn(fact, _FACT_SOURCES, fact)


class TestProfilePhases(unittest.TestCase):
    def test_an_undeclared_phase_is_not_reachable(self):
        # the guard that keeps a label from passing as a plan
        self.assertFalse(coverage._phase_reachable(
            "no-such-phase", GOAL_FACTS, coverage._producers()))

    def test_declared_phases_are_reachable(self):
        producers = coverage._producers()
        for profile, phases in coverage.PROFILE_PHASES.items():
            for phase in phases:
                self.assertTrue(
                    coverage._phase_reachable(phase, GOAL_FACTS, producers),
                    f"{profile}: phase '{phase}' unreachable")

    def test_every_profile_chain_template_exists(self):
        from phantom.automation.swarm.profile_policy import POLICY
        for name, policy in POLICY.items():
            self.assertIn(policy.chain, _CHAINS, name)

    def test_every_swarm_chain_goal_is_known(self):
        for goal, chain in SWARM_CHAIN.items():
            self.assertIn(chain, _CHAINS, goal)
            self.assertTrue(goal in GOAL_FACTS or goal == "deep", goal)


class TestProfileLookup(unittest.TestCase):
    def test_known_profile(self):
        row = coverage.coverage_for_profile("mobile")
        self.assertEqual(row.chain, "footprint")
        self.assertTrue(row.ok)

    def test_unknown_profile_has_no_chain(self):
        row = coverage.coverage_for_profile("not-a-profile")
        self.assertEqual(row.chain, "")

    def test_report_names_every_profile(self):
        text = coverage.format_report()
        for profile in ("smb", "enterprise", "cloud", "financial",
                        "government", "mobile"):
            self.assertIn(profile, text)


class TestShellCommand(unittest.TestCase):
    def test_coverage_command_is_registered(self):
        from phantom.core.shell.registry import command_names
        self.assertIn("coverage", command_names())

    def test_coverage_command_has_help(self):
        from phantom.core.shell.commands.system import cmd_coverage
        self.assertTrue((cmd_coverage.__doc__ or "").strip())

    def test_coverage_command_renders_without_raising(self):
        from phantom.core.shell.commands.system import cmd_coverage
        from phantom.core.session import session

        class _Shell:
            pass

        cmd_coverage(_Shell(), "")
        cmd_coverage(_Shell(), "mobile")
        cmd_coverage(_Shell(), "not-a-profile")
        self.assertIsNotNone(session)


if __name__ == "__main__":
    unittest.main()
