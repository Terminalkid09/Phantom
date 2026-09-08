"""Tests for the deep-mode engagement ladder (deliver -> post_exploit ->
ad -> crack -> lateral) and its wiring into the auto-mode entry points."""
import os
import unittest

from phantom.automation.agent import AutonomousAgent, DEEP_GOAL, DEEP_STAGES
from phantom.automation.belief import WorldModel
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.runtime.stealth_runtime import StealthRuntime, TimingGovernor
from phantom.automation.runtime.toolchain import ToolRegistry


def _full_wm():
    """A world where every deep-stage goal is already satisfied: the run must
    complete each stage instantly WITHOUT ever invoking a tool."""
    wm = WorldModel(target="dc.corp.local", target_type="domain")
    wm.add_finding("beacon", "b1", {"id": "b1"}, source="beacon_deploy")
    wm.add_finding("persistence", "p1", {"kind": "cron"}, source="persistence_install")
    wm.add_finding("system_privilege", "sp", {"level": "system"}, source="privesc_system")
    wm.add_finding("injection", "inj", {"pid": 1234}, source="inject_beacon")
    wm.add_finding("ad_domain", "corp.local", {"domain": "corp.local"}, source="ad_enum")
    wm.add_finding("ad_creds", "svc", {"username": "svc", "hash": "h"}, source="kerberoast")
    wm.add_finding("cracked", "svc:pw", {"username": "svc", "password": "pw"}, source="hash_crack")
    wm.add_finding("pivot", "peer1", {"host": "10.0.0.9"}, source="lateral_pivot")
    return wm


def _exploding_runner(_cmd, _timeout=20.0):
    raise AssertionError("deep stage already satisfied: no tool should run")


class TestDeepLadderConstants(unittest.TestCase):

    def test_stages_order_and_terminal(self):
        self.assertEqual(DEEP_GOAL, "deep")
        self.assertEqual(DEEP_STAGES,
                         ("deliver", "post_exploit", "ad", "crack", "lateral"))
        # the last stage is lateral movement — impact/cleanup stay manual
        self.assertNotIn("cleanup", DEEP_STAGES)
        self.assertNotIn("impact", DEEP_STAGES)

    def test_goal_exposed_everywhere(self):
        from phantom.core.auto_shell import _GOALS
        self.assertIn("deep", _GOALS)
        # the two CLI argparsers list deep too
        from phantom.core import shell as _shell
        import inspect
        src = inspect.getsource(_shell.PhantomShell.do_agent) + \
              inspect.getsource(_shell.PhantomShell.do_auto)
        self.assertIn('"deep"', src)


class TestDeepModeRun(unittest.TestCase):

    def _agent(self, wm):
        return AutonomousAgent(
            target="dc.corp.local", target_type="domain", shared_wm=wm,
            runtime=StealthRuntime(
                StealthEngine(wm, StealthConfig(profile="enterprise")),
                runner=_exploding_runner, cost_per_action=0.5,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0)),
            toolchain=ToolRegistry(
                installed={"nmap", "curl", "nc", "sshpass", "impacket-secretsdump"}))

    def test_deep_run_walks_all_stages_and_reports_them(self):
        events = []
        agent = self._agent(_full_wm())
        agent._on_event = lambda k, d: events.append(k)
        result = agent.run(goal="deep", max_iterations=4)
        self.assertEqual(result["goal"], "deep")
        self.assertEqual(
            result["stages"],
            {"deliver": True, "post_exploit": True, "ad": True,
             "crack": True, "lateral": True})
        # every stage surfaced as an event + exactly ONE terminal done
        self.assertEqual(sum(1 for k in events if k == "stage"), 5)
        self.assertEqual(sum(1 for k in events if k == "done"), 1)

    def test_single_goal_run_has_no_stage_ladder(self):
        events = []
        agent = self._agent(_full_wm())
        agent._on_event = lambda k, d: events.append(k)
        result = agent.run(goal="deliver", max_iterations=4)
        self.assertEqual(result["stages"], {})
        self.assertEqual(sum(1 for k in events if k == "stage"), 0)
        self.assertEqual(result["beacon_established"], True)


class TestDeepDryRun(unittest.TestCase):

    def test_automode_dry_run_plans_every_stage(self):
        from phantom.core.automode import _dry_run_plan
        plan, tt, chain, goal_facts = _dry_run_plan(
            "10.0.0.5", "deep", "enterprise", False, False, False)
        self.assertEqual(plan.goal, "deep")
        self.assertTrue(plan.steps)
        reasons = [s.reason for s in plan.steps]
        # every step is tagged with the stage it belongs to
        self.assertTrue(all(any(
            f"[{st}]" in r for st in DEEP_STAGES) for r in reasons),
            reasons)


if __name__ == "__main__":
    unittest.main()
