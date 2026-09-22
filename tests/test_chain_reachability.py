"""Chain reachability regression (structural, optimistic execution).

For every (target_type x toolset x goal) that must work, simulate the
drive loop faithfully: per wave execute ALL plan steps whose
preconditions hold NOW, refuse tool-missing moves (dead), assume
designed-success with minimal-plausible values. Success = every goal
fact satisfied.

This pins the graph bridges (http-derived service, curl_probe,
web goal): removing one re-opens the URL deadlock and fails here.
It does NOT prove a live target falls — the lab does that.
"""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.guidance.threatmodel import BlueTeamModel
from phantom.automation.planner import GOAL_FACTS, Planner, _fact_satisfied

SAMPLE = {"ip": "10.0.0.5", "domain": "example.com",
          "url": "http://example.com/"}
LEAK_SOURCES = {"breach_check"}  # leak knowledge, never access


def _optimistic(kind, cap_id=""):
    if kind == "service":
        return {"port": "80", "service": "http"}
    if kind == "creds":
        if cap_id in LEAK_SOURCES:
            return {"username": "u", "password": "p", "valid": False}
        return {"username": "u", "password": "p", "valid": True}
    if kind == "os":
        return {"name": "Linux"}
    if kind == "beacon":
        return {"beacon_id": "B-1"}
    return {}


def walk(ttype, toolset, goal, max_rounds=25):
    """(reached, rounds, refusals, tried). toolset None = everything."""
    wm = WorldModel(target=SAMPLE[ttype], target_type=ttype)
    stealth = StealthEngine(wm, StealthConfig(),
                            BlueTeamModel.for_profile("enterprise"))
    planner = Planner(make_registry(), stealth)
    dead = set()
    executed = set()
    last_facts = -1
    refusals = 0
    tried = []
    empty_waves = 0
    for _ in range(max_rounds):
        if all(_fact_satisfied(wm, g) for g in GOAL_FACTS[goal]):
            return True, len(tried), refusals, tried
        if len(wm.to_dict().get("findings", [])) != last_facts:
            executed.clear()
            last_facts = len(wm.to_dict().get("findings", []))
        plan = planner.plan(wm, goal=goal, dead=frozenset(dead))
        if not plan.steps:
            return False, len(tried), refusals, tried
        progressed = False
        for step in plan.steps:
            cap = step.capability
            if cap.id in executed:
                continue
            try:
                if not all(p(wm) for p in cap.preconditions):
                    continue  # deferred
            except Exception:
                continue
            if toolset is not None and getattr(cap, "tools", None) \
                    and not any(t in toolset for t in cap.tools):
                dead.add(cap.id)
                refusals += 1
                continue
            tried.append(cap.id)
            executed.add(cap.id)
            for effect in (cap.effects or []):
                if not wm.find(effect):
                    wm.add_finding(effect, "audit",
                                   _optimistic(effect, cap.id),
                                   confidence=0.5, source="audit")
            progressed = True
        empty_waves = 0 if progressed else empty_waves + 1
        if empty_waves >= 3:
            return False, len(tried), refusals, tried
    return False, len(tried), refusals, tried


class TestChainReachability(unittest.TestCase):
    def _plan(self, ttype, goal):
        wm = WorldModel(target=SAMPLE[ttype], target_type=ttype)
        stealth = StealthEngine(wm, StealthConfig(),
                                BlueTeamModel.for_profile("enterprise"))
        return Planner(make_registry(), stealth).plan(wm, goal=goal), wm

    def test_full_toolset_plans_footprint_everywhere(self):
        # pure graph property: a path covering every footprint fact
        # exists on all network types (no target truth required)
        for ttype in SAMPLE:
            plan, _ = self._plan(ttype, "footprint")
            self.assertTrue(plan.complete, ttype)
            self.assertTrue(plan.steps, ttype)

    def test_url_curl_only_reaches_web_goal(self):
        reached, _, _, tried = walk("url", {"curl"}, "web")
        self.assertTrue(reached, tried)

    def test_ip_curl_only_grows_service_without_nmap(self):
        # the curl_probe bridge: service facts with no scanner installed.
        # Assumption (documented): the walk target answers on ssh/http —
        # the test pins the GRAPH path, the lab proves live targets.
        reached, _, _, tried = walk("ip", {"curl"}, "footprint")
        self.assertIn("curl_probe", tried)
        self.assertTrue(reached, tried)

    def test_identity_chain_reachable(self):
        for ttype, sample in (("email", "a@example.com"),
                              ("username", "john_doe"),
                              ("phone", "+39123456789")):
            wm = WorldModel(target=sample, target_type=ttype)
            stealth = StealthEngine(wm, StealthConfig(),
                                    BlueTeamModel.for_profile("enterprise"))
            planner = Planner(make_registry(), stealth)
            plan = planner.plan(wm, goal="identity")
            self.assertTrue(plan.steps or plan.complete, ttype)


if __name__ == "__main__":
    unittest.main()
