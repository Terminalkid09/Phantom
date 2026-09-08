"""Strategic planning: target profiling, declarative strategy library and
Planner.plan_strategic (per-target stage selection + fallback)."""
import os
import tempfile
import threading
import unittest
from unittest.mock import Mock


def _temp_beacon(platform=None, host=None, port=None):
    """Fake compile-on-demand: produces a real file (the deploy path
    checks the binary exists on disk)."""
    fd, path = tempfile.mkstemp(prefix="fake_beacon_", suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(b"PHANTOM-FAKE-BEACON")
    return path

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthEngine, StealthConfig
from phantom.automation.guidance.strategy import (
    ProfileDetector,
    TargetModel,
    STRATEGIES,
    applicable_strategies,
)
from phantom.automation.planner import Planner, GOAL_FACTS

VICTIM_IP = "10.0.0.5"


def _planner() -> Planner:
    wm = WorldModel(target=VICTIM_IP)
    return Planner(make_registry(), StealthEngine(wm, StealthConfig()))


def _approving_sandbox():
    from phantom.automation.sandbox.sandbox import (SandboxEngine,
                                                    SandboxVerdict,
                                                    SandboxResult)

    class _Approve(SandboxEngine):
        def preflight(self, sample_path):
            return SandboxVerdict(approved=True,
                                  results=[SandboxResult(backend="docker",
                                                         ok=True)])
    return _Approve()


class TestProfileDetector(unittest.TestCase):

    def test_identity_target(self):
        wm = WorldModel(target="jdoe@corp.com", target_type="email")
        model = ProfileDetector.detect(wm)
        self.assertTrue(model.is_identity)
        self.assertFalse(model.is_network)
        self.assertEqual(model.profile, "identity")

    def test_network_target(self):
        wm = WorldModel(target=VICTIM_IP, target_type="ip")
        wm.add_finding("service", "tcp/22", {"port": "22"},
                       confidence=0.9)
        wm.add_finding("os", "linux", {"os": "Linux"}, confidence=0.9)
        model = ProfileDetector.detect(wm)
        self.assertTrue(model.is_network)
        self.assertEqual(model.open_services, ["tcp/22"])
        self.assertTrue(model.has_os)
        self.assertEqual(model.profile, "network")

    def test_compromised_and_ad(self):
        wm = WorldModel(target=VICTIM_IP, target_type="ip")
        wm.add_finding("beacon", "established", {"payload": "true"},
                       confidence=0.95)
        wm.add_finding("ad_domain", "corp.local", {"domain": "corp.local"},
                       confidence=0.9)
        model = ProfileDetector.detect(wm)
        self.assertTrue(model.has_beacon)
        self.assertTrue(model.has_ad)
        self.assertEqual(model.profile, "ad-domain")


class TestStrategyLibrary(unittest.TestCase):

    def test_library_covers_all_goals(self):
        goals = {s.goal for s in STRATEGIES}
        self.assertIn("identity", goals)
        self.assertIn("creds", goals)
        self.assertIn("beacon", goals)
        self.assertIn("footprint", goals)
        self.assertIn("ad", goals)
        self.assertIn("crack", goals)
        self.assertIn("harvest", goals)
        self.assertIn("trojan", goals)
        self.assertIn("impact", goals)
        self.assertIn("lateral", goals)
        self.assertIn("cleanup", goals)
        self.assertEqual(len(STRATEGIES), len({s.id for s in STRATEGIES}))

    def test_applicable_identity_vs_network(self):
        identity = TargetModel(target_type="email", is_identity=True)
        network = TargetModel(target_type="ip", is_network=True)
        ids = {s.id for s in applicable_strategies(identity)}
        self.assertIn("identity_osint", ids)
        self.assertNotIn("network_footprint", ids)
        nids = {s.id for s in applicable_strategies(network)}
        self.assertIn("network_footprint", nids)
        self.assertNotIn("identity_osint", nids)

    def test_ordering_is_weight_aware(self):
        identity = TargetModel(target_type="email", is_identity=True)
        stages = applicable_strategies(identity)
        self.assertEqual(stages[0].id, "identity_osint")
        self.assertEqual(stages[1].id, "identity_breach")
        self.assertEqual(stages[2].id, "identity_beacon")
        network = TargetModel(target_type="ip", is_network=True)
        stages = applicable_strategies(network)
        self.assertEqual(stages[0].id, "network_footprint")
        self.assertEqual(stages[1].id, "network_creds")
        self.assertEqual(stages[2].id, "network_beacon")

    def test_beacon_stages_appear_only_with_foothold(self):
        bare = TargetModel(target_type="ip", is_network=True)
        comp = TargetModel(target_type="ip", is_network=True,
                           has_beacon=True)
        bare_ids = {s.id for s in applicable_strategies(bare)}
        comp_ids = {s.id for s in applicable_strategies(comp)}
        self.assertNotIn("harvest_intel", bare_ids)
        self.assertNotIn("supply_chain", bare_ids)
        self.assertIn("harvest_intel", comp_ids)
        self.assertIn("supply_chain", comp_ids)
        self.assertIn("impact_sim", comp_ids)


class TestPlanStrategic(unittest.TestCase):

    def test_fresh_network_target_starts_with_footprint(self):
        wm = WorldModel(target=VICTIM_IP, target_type="ip")
        plan = _planner().plan_strategic(wm)
        self.assertTrue(plan.complete)
        self.assertTrue(plan.strategic)
        self.assertEqual(plan.strategy, "network_footprint")
        self.assertIn("scan_tcp", [s.capability.id for s in plan.steps])
        self.assertIn("network_footprint", plan.strategy_chain)
        self.assertIn("network_creds", plan.strategy_chain)
        self.assertIn("network_beacon", plan.strategy_chain)

    def test_advances_stages_as_facts_arrive(self):
        planner = _planner()
        wm = WorldModel(target=VICTIM_IP, target_type="ip")
        wm.add_finding("service", "tcp/22", {"port": "22", "service": "ssh"},
                       confidence=0.9)
        wm.add_finding("creds", "ssh:root", {"username": "root",
                                             "password": "toor",
                                             "valid": True},
                       confidence=0.9)
        plan = planner.plan_strategic(wm)
        self.assertEqual(plan.strategy, "network_beacon")
        self.assertIn("beacon_deploy", [s.capability.id for s in plan.steps])
        self.assertTrue(plan.complete)

    def test_identity_target_uses_identity_stages(self):
        wm = WorldModel(target="jdoe@corp.com", target_type="email")
        plan = _planner().plan_strategic(wm)
        self.assertEqual(plan.strategy, "identity_osint")
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("osint_identity", ids)
        self.assertTrue(plan.complete)

    def test_identity_advances_to_breach_after_osint(self):
        wm = WorldModel(target="jdoe@corp.com", target_type="email")
        wm.add_finding("identity", "identity:jdoe",
                       {"username": "jdoe", "email": "jdoe@corp.com"},
                       confidence=0.7)
        plan = _planner().plan_strategic(wm)
        self.assertEqual(plan.strategy, "identity_breach")
        self.assertIn("breach_check",
                      [s.capability.id for s in plan.steps])

    def test_goal_filter_picks_matching_stage(self):
        wm = WorldModel(target=VICTIM_IP, target_type="ip")
        wm.add_finding("beacon", "established", {"payload": "true"},
                       confidence=0.95)
        for goal, stage, cap in (
                ("harvest", "harvest_intel", "cookie_stealer"),
                ("impact", "impact_sim", "ransom_sim"),
                ("trojan", "supply_chain", "trojan_deliver")):
            plan = _planner().plan_strategic(wm, goal=goal)
            self.assertTrue(plan.strategic, goal)
            self.assertEqual(plan.strategy, stage, goal)
            self.assertIn(cap, [s.capability.id for s in plan.steps], goal)

    def test_fallback_when_no_strategy_matches(self):
        wm = WorldModel(target=VICTIM_IP, target_type="ip")
        # "deliver" has no strategy stage -> generic planning
        plan = _planner().plan_strategic(wm, goal="deliver")
        self.assertFalse(plan.strategic)
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("beacon_deploy", ids)
        self.assertIn("persistence_install", ids)
        self.assertTrue(plan.complete)

    def test_everything_satisfied_returns_empty(self):
        wm = WorldModel(target=VICTIM_IP, target_type="ip")
        for kind, key, val in (
                ("service", "tcp/22", {"port": "22"}),
                ("creds", "ssh:root", {"username": "root", "valid": True}),
                ("beacon", "established", {"payload": "true"})):
            wm.add_finding(kind, key, val, confidence=0.95)
        plan = _planner().plan_strategic(wm)
        self.assertTrue(plan.complete)
        self.assertTrue(plan.strategic)
        self.assertEqual(plan.steps, [])


class TestAgentStrategicIntegration(unittest.TestCase):
    """The auto-mode runs the strategic layer end-to-end."""

    def setUp(self):
        from phantom.core.c2_server import c2_state
        c2_state.beacons.clear()
        c2_state.tasks.clear()
        c2_state.results.clear()
        self.events = []

    def test_run_emits_strategic_plan_events(self):
        from phantom.automation.agent import run_autonomous
        from phantom.automation.runtime.toolchain import ToolRegistry
        from phantom.core.c2_server import c2_state

        def runner(cmd, timeout=None):
            res = Mock()
            res.ok = True
            res.stdout = ""
            res.stderr = ""
            if "api/v1/payload" in cmd:
                c2_state.update_beacon("beacon-s1", {"ip": VICTIM_IP,
                                                     "os": "Linux"})
                res.stdout = "PHANTOM"
            elif "sshpass" in cmd and "scp" in cmd:
                # beacon deploy (scp + setsid): beacon starts on target
                c2_state.update_beacon("beacon-s1", {"ip": VICTIM_IP,
                                                     "os": "Linux"})
                res.stdout = "PHANTOM"
            elif "nmap" in cmd:
                res.stdout = "22/tcp open ssh OpenSSH 7.9p1"
            elif "nc -w" in cmd:
                res.stdout = "SSH-2.0-OpenSSH_7.9p1 Debian-10"
            elif "sshpass" in cmd:
                res.stdout = "uid=0(root) gid=0(root)"
            else:
                res.stdout = "PHANTOM"
            return res

        stop = threading.Event()

        def sim():
            import time
            while not stop.is_set():
                for bid in list(c2_state.get_beacons().keys()):
                    for task in c2_state.get_pending_tasks(bid):
                        res = runner(task["command"])
                        c2_state.add_result(bid, task["task_id"], res.stdout)
                time.sleep(0.05)

        t = threading.Thread(target=sim, daemon=True)
        t.start()
        try:
            result = run_autonomous(
                target=VICTIM_IP, goal="complete_kill_chain",
                max_iterations=20, runner=runner,
                cred_discoverer=lambda s: ("root", "toor"),
                sandbox=_approving_sandbox(),
                toolchain=ToolRegistry(
                    installed={"nmap", "sshpass", "curl", "nc"}),
                beacon_builder=_temp_beacon,
                on_event=lambda k, d: self.events.append((k, d)))
        finally:
            stop.set()
            t.join(timeout=3)

        self.assertTrue(result["beacon_established"], result)
        plans = [d for k, d in self.events if k == "plan"]
        self.assertGreaterEqual(len(plans), 1)
        self.assertTrue(all(d.get("strategic") for d in plans), plans)
        stages = [d.get("strategy") for d in plans]
        self.assertEqual(stages[0], "network_footprint", stages)
        self.assertIn("network_creds", stages, stages)
        self.assertIn("network_beacon", stages, stages)


if __name__ == "__main__":
    unittest.main()
