"""Tests for the cross-session technique priors wiring (brain/priors.py):
multiplier math, fingerprint-class bucketing, and the planner using earned
success rates to reorder equally-ready moves."""
import os
import tempfile
import unittest

from phantom.automation.belief import Finding, WorldModel
from phantom.automation.brain.priors import (
    TechniquePriors,
    _fingerprint_class,
    priors_path,
)


def _priors(tmpdir, name="priors.json"):
    return TechniquePriors(path=os.path.join(tmpdir, name))


class TestPriorMath(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.pr = _priors(self.tmp)

    def test_unknown_technique_is_neutral(self):
        self.assertEqual(self.pr.multiplier("web_creds", "nginx"), 1.0)

    def test_wins_make_technique_cheaper(self):
        for _ in range(3):
            self.pr.record("web_creds", "nginx", True)
        self.assertLess(self.pr.multiplier("web_creds", "nginx"), 1.0)

    def test_losses_make_technique_costlier(self):
        for _ in range(3):
            self.pr.record("ssh_login", "nginx", False)
        self.assertGreater(self.pr.multiplier("ssh_login", "nginx"), 1.0)

    def test_multiplier_bounded(self):
        # extreme record: never explodes beyond [0.5, 1.5]
        for _ in range(50):
            self.pr.record("brute_ssh", "openssh", False)
        self.assertGreaterEqual(self.pr.multiplier("brute_ssh", "openssh"), 0.5)
        self.assertLessEqual(self.pr.multiplier("brute_ssh", "openssh"), 1.5)
        pr2 = _priors(self.tmp, "p2.json")
        for _ in range(50):
            pr2.record("web_creds", "openssh", True)
        self.assertLessEqual(pr2.multiplier("web_creds", "openssh"), 1.5)

    def test_persistence_across_instances(self):
        self.pr.record("web_creds", "nginx", True)
        pr2 = TechniquePriors(path=self.pr.path)
        self.assertEqual(pr2.multiplier("web_creds", "nginx"),
                         self.pr.multiplier("web_creds", "nginx"))

    def test_classes_are_independent(self):
        self.pr.record("web_creds", "nginx", True)
        self.assertEqual(self.pr.multiplier("web_creds", "apache"), 1.0)


class TestFingerprintClass(unittest.TestCase):
    def test_product_bucket(self):
        wm = WorldModel("10.0.0.9")
        wm.add_finding(kind="fingerprint", key="p",
                       value={"product": "OpenSSH_9.6p1"}, source="t")
        self.assertEqual(_fingerprint_class(wm), "openssh")

    def test_os_bucket(self):
        wm = WorldModel("10.0.0.9")
        wm.add_finding(kind="os", key="os",
                       value={"name": "Linux 5.15"}, source="t")
        self.assertEqual(_fingerprint_class(wm), "linux")

    def test_generic_when_nothing_known(self):
        self.assertEqual(_fingerprint_class(WorldModel("10.0.0.9")), "generic")


class TestPlannerPriorsOrdering(unittest.TestCase):
    def _planner(self, priors):
        from phantom.automation.guidance.commands import make_registry
        from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
        from phantom.automation.planner import Planner
        wm = WorldModel("10.0.0.9")
        se = StealthEngine(wm, StealthConfig())
        pl = Planner(make_registry(), se)
        pl.priors = priors
        return pl

    def test_planner_attribute_exists(self):
        pl = self._planner(None)
        self.assertIsNone(pl.priors)

    def test_ready_moves_reordered_by_priors(self):
        """With priors saying web_creds wins and ssh_login loses against
        nginx, a plan needing creds tries web_creds before ssh_login."""
        self.tmp = tempfile.mkdtemp()
        pr = _priors(self.tmp, "order.json")
        pr.record("web_creds", "nginx", True)
        pr.record("web_creds", "nginx", True)
        pr.record("ssh_login", "nginx", False)
        pl = self._planner(pr)
        wm = WorldModel("10.0.0.9")
        wm.add_finding(kind="service", key="tcp/80",
                       value={"port": 80, "service": "http"}, source="t")
        wm.add_finding(kind="service", key="tcp/22",
                       value={"port": 22, "service": "ssh"}, source="t")
        wm.add_finding(kind="fingerprint", key="p",
                       value={"product": "nginx/1.18"}, source="t")
        plan = pl.plan(wm, goal="creds")
        ids = [s.capability.id for s in plan.steps]
        self.assertTrue(ids, "plan should not be empty")
        if "ssh_login" in ids and "web_creds" in ids:
            self.assertLess(ids.index("web_creds"), ids.index("ssh_login"))


class TestAgentWiring(unittest.TestCase):
    def test_agent_has_priors_when_persisting(self):
        """persist_learning=True wires TechniquePriors into agent+planner."""
        import inspect
        from phantom.automation import agent as agent_mod
        src = inspect.getsource(agent_mod.AutonomousAgent.__init__)
        self.assertIn("TechniquePriors", src)
        self.assertIn("self.planner.priors = self._priors", src)
        # outcomes are flushed at run end
        run_src = inspect.getsource(agent_mod.AutonomousAgent.run)
        self.assertIn("record_from_worldmodel", run_src)

    def test_planner_reorders_via_priors_multiplier(self):
        """Direct: the ready-list sort key uses multiplier_for."""
        import inspect
        from phantom.automation.planner import Planner
        src = inspect.getsource(Planner._pick_source)
        self.assertIn("multiplier_for", src)
        self.assertIn("self.priors is not None", src)


if __name__ == "__main__":
    unittest.main()
