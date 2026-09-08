"""Tests for the planner and the orchestrator."""
import threading
import time
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthEngine, StealthConfig
from phantom.automation.planner import Planner, GOAL_FACTS
from phantom.automation.orchestrator import (
    Orchestrator,
    PrioritizedAction,
    ActionStatus,
)


class TestPlanner(unittest.TestCase):

    def setUp(self):
        self.registry = make_registry()
        self.wm = WorldModel(target="10.0.0.5", target_type="ip")
        self.stealth = StealthEngine(self.wm, StealthConfig())
        self.planner = Planner(self.registry, self.stealth)

    def test_empty_wm_plans_to_footprint(self):
        plan = self.planner.plan(self.wm, goal="footprint")
        self.assertGreater(len(plan.steps), 0)
        kinds = [s.capability.effects for s in plan.steps]
        self.assertTrue(any("service" in e for e in kinds))

    def test_beacon_goal_needs_creds_chain(self):
        plan = self.planner.plan(self.wm, goal="beacon")
        ids = [s.capability.id for s in plan.steps]
        # full backward chain: scanner -> ssh_login -> beacon_deploy
        self.assertIn("scan_tcp", ids)
        self.assertIn("ssh_login", ids)
        self.assertIn("beacon_deploy", ids)
        # execution order is the reverse of the backward chain: scan first,
        # then login, then deploy — ssh_login requires an open SSH service
        exec_order = [s.capability.id for s in reversed(plan.steps)]
        self.assertEqual(exec_order, ["scan_tcp", "ssh_login", "beacon_deploy"])

    def test_goal_reached_is_complete(self):
        self.wm.add_finding("beacon", "established", {"ok": True})
        plan = self.planner.plan(self.wm, goal="beacon")
        self.assertTrue(plan.complete)
        self.assertEqual(plan.steps, [])

    def test_cold_crack_goal_still_plans_creds_chain(self):
        """Regression: goal 'crack' planned from scratch must NOT trust
        hash_crack's conditional 'creds' effect and drop the real credential
        acquisition chain (ssh_login -> beacon_deploy). A cold crack run
        bootstraps the beacon exactly like goal 'ad' does."""
        plan = self.planner.plan_strategic(self.wm, goal="crack")
        self.assertTrue(plan.complete)
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("scan_tcp", ids)
        self.assertIn("ssh_login", ids)
        self.assertIn("beacon_deploy", ids)
        self.assertIn("ad_enum", ids)
        self.assertIn("kerberoast", ids)
        self.assertIn("hash_crack", ids)

    def test_first_ready_steps(self):
        plan = self.planner.plan(self.wm, goal="beacon")
        ready = plan.first_ready(self.registry, self.wm)
        self.assertIsNotNone(ready)
        self.assertEqual(ready.capability.id, "scan_tcp")

    def test_cost_is_signal_never_blocks(self):
        wm = WorldModel(target="10.0.0.5")
        stealth = StealthEngine(wm, StealthConfig())
        planner = Planner(self.registry, stealth)
        plan = planner.plan(wm, goal="beacon")
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("beacon_deploy", ids)  # cost 5.0 — no budget can stop it

    def test_suggest_next_cheapest(self):
        step = self.planner.suggest_next(self.wm, goal="footprint")
        self.assertIsNotNone(step)
        self.assertIn(step.capability.id, ("ssh_banner", "http_probe", "scan_tcp"))

    def test_identity_goal_on_network_target_degrades_to_footprint(self):
        # "identity" on an IP/domain used to produce an empty plan -> the
        # agent halted instantly without doing anything. It must instead
        # degrade to footprint recon (scan first) — the operator expects
        # the scan to run even on an IP.
        plan = self.planner.plan_strategic(self.wm, goal="identity")
        self.assertTrue(plan.steps, "identity goal on an IP must not be empty")
        self.assertTrue(plan.complete)
        self.assertTrue(plan.strategy.startswith("fallback:identity"),
                        plan.strategy)

    def test_kill_chain_goal_on_identity_target_degrades_to_identity(self):
        # complete_kill_chain / deliver on a username/phone/email used to
        # halt instantly (no plan): it must degrade to the identity chain
        # (osint -> phish -> poll) instead of doing nothing.
        from phantom.automation.guidance.targets import is_identity_target
        self.assertTrue(is_identity_target("username"))
        wm = WorldModel(target="jdoe", target_type="username")
        stealth = StealthEngine(wm, StealthConfig())
        planner = Planner(self.registry, stealth)
        plan = planner.plan_strategic(wm, goal="complete_kill_chain")
        self.assertTrue(plan.steps, "kill chain on a username must not be empty")
        self.assertTrue(plan.complete)

    def test_aggressive_unlocks_beacon_path(self):
        wm = WorldModel(target="10.0.0.5")
        wm.add_finding("creds", "ssh:root", {"username": "root", "password": "r",
                                             "valid": True})
        stealth = StealthEngine(wm, StealthConfig(aggressive=True))
        plan = Planner(self.registry, stealth).plan(wm, goal="beacon")
        self.assertTrue(plan.complete)
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("beacon_deploy", ids)

    def test_ready_capability_preferred_over_chain(self):
        """When an RCE foothold already exists, the planner should prefer the
        direct beacon_via_rce path (preconditions already satisfied) over
        forcing a creds chain via beacon_deploy."""
        wm = WorldModel(target="10.0.0.5")
        wm.add_finding("rce_foothold", "web_upload", {"kind": "upload",
                                                      "url": "http://t/u"})
        stealth = StealthEngine(wm, StealthConfig())
        plan = Planner(self.registry, stealth).plan(wm, goal="beacon")
        ids = [s.capability.id for s in plan.steps]
        # The ready path must be selected, not require new cred el not findable
        self.assertIn("beacon_via_rce", ids)

    def test_cloud_and_mobile_capabilities_registered(self):
        """New cloud/IAM + mobile capabilities must be in the registry and
        plan once a beacon/foothold exists."""
        ids = {c.id for c in self.registry.all()}
        for cap in ("cloud_creds_harvest", "cloud_s3_enum", "mobile_probe",
                    "k8s_escape"):
            self.assertIn(cap, ids)

    def test_cloud_plan_after_beacon(self):
        wm = WorldModel(target="10.0.0.5")
        wm.add_finding("beacon", "established", {"ok": True})
        wm.add_finding("environment", "box",
                       {"kinds": [{"kind": "container"}]})
        stealth = StealthEngine(wm, StealthConfig())
        plan = Planner(self.registry, stealth).plan(wm, goal="cloud")
        ids = [s.capability.id for s in plan.steps]
        # harvest is the ready step (produces cloud_creds for the cloud goal)
        self.assertIn("cloud_creds_harvest", ids)

    def test_cloud_s3_plans_once_creds_present(self):
        wm = WorldModel(target="10.0.0.5")
        wm.add_finding("beacon", "established", {"ok": True})
        wm.add_finding("cloud_creds", "iam_aws",
                       {"provider": "aws", "via": "metadata"})
        stealth = StealthEngine(wm, StealthConfig())
        plan = Planner(self.registry, stealth).plan(wm, goal="cloud")
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("cloud_s3_enum", ids)


class TestOrchestrator(unittest.TestCase):

    def _make(self, max_agents=4):
        wm = WorldModel(target="10.0.0.5")
        stealth = StealthEngine(wm, StealthConfig())
        return Orchestrator(wm, stealth, worker=lambda a, ctx: True, max_agents=max_agents)

    def test_priority_order(self):
        orch = self._make()
        orch.submit("http_probe", "h1", 0.2)
        orch.submit("scan_tcp", "h2", 0.9)
        orch.submit("ssh_banner", "h3", 0.5)
        self.assertEqual(orch._pop().capability_id, "scan_tcp")
        self.assertEqual(orch._pop().capability_id, "ssh_banner")
        self.assertEqual(orch._pop().capability_id, "http_probe")

    def test_drains_and_records_trail(self):
        orch = self._make()
        for i in range(6):
            orch.submit(f"cap{i}", "10.0.0.5", 0.5)
        orch.run()
        self.assertEqual(orch.stats()["done"], 6)
        self.assertEqual(len(orch.campaign), 6)
        self.assertEqual(orch.stats()["queued"], 0)

    def test_entity_lock_serializes_same_target(self):
        """Two actions on the same entity must never run concurrently."""
        active = []
        guard = threading.Lock()
        peak = [0]

        def worker(action, ctx):
            with guard:
                active.append(action.entity)
                peak[0] = max(peak[0], len(active))
            time.sleep(0.05)
            with guard:
                active.remove(action.entity)
            return True

        orch = Orchestrator(WorldModel(target="t"), StealthEngine(WorldModel()),
                            worker=worker, max_agents=4)
        for _ in range(8):
            orch.submit("cap", "target-1", 0.5)
        orch.run()
        self.assertEqual(peak[0], 1)

    def test_parallel_entities(self):
        """Different entities should run concurrently up to pool size."""
        running = [0]
        peak = [0]
        guard = threading.Lock()

        def worker(action, ctx):
            with guard:
                running[0] += 1
                peak[0] = max(peak[0], running[0])
            time.sleep(0.05)
            with guard:
                running[0] -= 1
            return True

        orch = Orchestrator(WorldModel(target="t"), StealthEngine(WorldModel()),
                            worker=worker, max_agents=4)
        for i in range(6):
            orch.submit("cap", f"host-{i}", 0.5)
        orch.run()
        self.assertGreater(peak[0], 1)

    def test_stop_halts_early(self):
        orch = self._make()

        def slow_worker(action, ctx):
            time.sleep(1.0)
            return True
        orch.worker = slow_worker
        for i in range(10):
            orch.submit("cap", f"host-{i}", 0.5)
        t = threading.Thread(target=orch.run, daemon=True)
        t.start()
        time.sleep(0.2)
        orch.stop()
        t.join(timeout=2)
        self.assertLess(orch.stats()["done"], 10)

    def test_pause_resume(self):
        orch = self._make()
        orch.submit("cap", "host-1", 0.5)
        orch.pause()
        t = threading.Thread(target=orch.run, daemon=True)
        t.start()
        time.sleep(0.3)
        self.assertEqual(orch.stats()["done"], 0)  # paused: nothing ran
        orch.resume()
        t.join(timeout=3)
        self.assertEqual(orch.stats()["done"], 1)

    def test_failed_worker_reports_failure(self):
        def boom(action, ctx):
            raise RuntimeError("boom")
        orch = Orchestrator(WorldModel(target="t"), StealthEngine(WorldModel()),
                            worker=boom)
        a = orch.submit("cap", "host-1", 0.5)
        orch.run()
        self.assertEqual(a.status, ActionStatus.FAILED)
        self.assertIn("boom", a.detail)
        self.assertEqual(orch.stats()["done"], 1)


if __name__ == "__main__":
    unittest.main()
