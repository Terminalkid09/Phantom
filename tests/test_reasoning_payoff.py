"""Tests: the reasoning -> action payoff bonus.

A confirmed bug is worth nothing until the move that discharges it runs.
These tests pin that a confirmed code-execution / session primitive
promotes its payoff move, and that the bonus does NOT become a loop (it
disappears once the payoff finding exists).
"""
import unittest

from phantom.automation.agent import AutonomousAgent
from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.planner import PlanStep

TARGET = "10.0.0.5"


def _agent(wm):
    return AutonomousAgent(target=TARGET, on_event=None, shared_wm=wm)


def _step(reg, cap_id):
    return PlanStep(capability=reg.get(cap_id))


class TestPayoffBonus(unittest.TestCase):

    def setUp(self):
        self.reg = make_registry()

    def _wm_with(self, cls, confirmed=True):
        wm = WorldModel(target=TARGET, target_type="ip")
        wm.add_finding("service", "tcp/80", {"port": "80", "service": "http"})
        wm.add_finding("hunt_anomaly", f"{cls}:80:p",
                       {"cls": cls, "confirmed": confirmed, "score": 2.5,
                        "endpoint": "/?q=1", "port": "80"})
        return wm

    def test_confirmed_cmdi_promotes_the_rce_foothold(self):
        agent = _agent(self._wm_with("cmdi"))
        self.assertGreater(agent._payoff_bonus(_step(self.reg, "rce_foothold")),
                           0.0)

    def test_unconfirmed_cmdi_gets_no_bonus(self):
        agent = _agent(self._wm_with("cmdi", confirmed=False))
        self.assertEqual(agent._payoff_bonus(_step(self.reg, "rce_foothold")),
                         0.0)

    def test_no_bonus_once_the_payoff_exists(self):
        wm = self._wm_with("cmdi")
        wm.add_finding("rce_foothold", "cmdi", {"channel": "cmdi"})
        agent = _agent(wm)
        self.assertEqual(agent._payoff_bonus(_step(self.reg, "rce_foothold")),
                         0.0)

    def test_unrelated_capability_gets_no_bonus(self):
        agent = _agent(self._wm_with("cmdi"))
        self.assertEqual(agent._payoff_bonus(_step(self.reg, "scan_tcp")), 0.0)

    def test_confirmed_xss_promotes_the_weaponizer(self):
        agent = _agent(self._wm_with("xss"))
        self.assertGreater(
            agent._payoff_bonus(_step(self.reg, "xss_weaponize")), 0.0)

    def test_confirmed_ssrf_promotes_the_cloud_creds_harvest(self):
        agent = _agent(self._wm_with("ssrf"))
        self.assertGreater(
            agent._payoff_bonus(_step(self.reg, "cloud_creds_harvest")), 0.0)


if __name__ == "__main__":
    unittest.main()
