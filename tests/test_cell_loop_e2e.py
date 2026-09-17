"""C4 end-to-end acceptance — the strict cell loop must not starve a run.

The unit tests prove that a migrated goal ROUTES every legitimate capability
and REFUSES the ones its coverage does not own. This file proves the other
half of the migration contract, which is the one that matters in production:

    switching the strict cell loop on must not change the run's OUTCOME,
    and must not change the SEQUENCE of capabilities it involves.

Both chains are exercised with the real agent loop (fake runner, fake sandbox,
fake beacon builder — no network). The identity chain is the interesting one:
its doctrine chain forbids `footprint`, yet it still has to scan the address
it harvested, which is exactly the starvation case this file exists to pin.
"""

import threading
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.runtime.stealth_runtime import (
    StealthRuntime,
    TimingGovernor,
)
from phantom.automation.agent import AutonomousAgent

from tests.test_automation_deliver import (
    _FakeSocialEngine,
    _approving_sandbox,
    _c2_simulator,
    _fake_builder,
    _fake_runner,
    _reset_c2,
)

NET_TARGET = "10.0.0.5"
ID_TARGET = "bob@corp.com"


def _agent(target, target_type, events, *, runner, social=None,
           cell_loop=False, cell_stages=None):
    from phantom.automation.runtime.toolchain import ToolRegistry
    return AutonomousAgent(
        target=target, target_type=target_type, profile="enterprise",
        on_event=lambda k, d: events.append((k, d)),
        runtime=StealthRuntime(
            StealthEngine(WorldModel(target=target), StealthConfig()),
            runner=runner, cost_per_action=0.5,
            governor=TimingGovernor(base_delay=0.0, jitter=0.0),
        ),
        cred_discoverer=lambda service: ("root", "toor"),
        sandbox=_approving_sandbox(),
        toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc",
                                          "redis-cli", "smbmap"}),
        beacon_builder=_fake_builder,
        social_engine=social or _FakeSocialEngine(),
        cell_loop=cell_loop, cell_stages=list(cell_stages or []),
    )


def _run(agent, goal="deliver", max_iterations=15):
    stop = threading.Event()
    sim = threading.Thread(target=_c2_simulator,
                           args=(agent.runtime.runner, stop), daemon=True)
    sim.start()
    try:
        return agent.run(goal=goal, max_iterations=max_iterations)
    finally:
        stop.set()
        sim.join(timeout=3)


def _sequence(events):
    return [d.get("capability") for k, d in events if k == "run"]


class TestStrictLoopDoesNotStarveTheChain(unittest.TestCase):

    def setUp(self):
        _reset_c2()

    def test_the_network_chain_reaches_its_goals_with_the_strict_loop_on(self):
        events = []
        agent = _agent(NET_TARGET, "ip", events, runner=_fake_runner(),
                       cell_loop=True, cell_stages=("deliver",))
        result = _run(agent)
        self.assertTrue(result["beacon_established"], result)
        self.assertTrue(result["persistence_installed"], result)
        self.assertTrue(agent.cells.strict)
        self.assertEqual(agent.cells.refused, 0)
        self.assertGreater(agent.cells.routed, 0)

    def test_the_identity_chain_reaches_its_goals_with_the_strict_loop_on(self):
        social = _FakeSocialEngine()
        agent = _agent(ID_TARGET, "auto", [], runner=_fake_runner(),
                       social=social, cell_loop=True,
                       cell_stages=("deliver",))
        result = _run(agent)
        self.assertTrue(result["beacon_established"], result)
        self.assertTrue(result["persistence_installed"], result)
        self.assertEqual(agent.cells.refused, 0)
        # the social chain still ran: strictness narrows the ROSTER that may
        # act, it does not narrow the chain
        kinds = [c[0] for c in social.calls]
        self.assertIn("osint", kinds)
        self.assertIn("phish", kinds)

    def test_the_migration_is_behaviour_preserving(self):
        """Same target, same flags: strict vs lenient must produce the same
        capability SEQUENCE and the same terminal outcome. Anything else
        means the roster is silently changing the plan."""
        for target, ttype in ((NET_TARGET, "ip"), (ID_TARGET, "auto")):
            events_a, events_b = [], []
            lenient = _agent(target, ttype, events_a, runner=_fake_runner(),
                             social=_FakeSocialEngine())
            strict = _agent(target, ttype, events_b, runner=_fake_runner(),
                            social=_FakeSocialEngine(), cell_loop=True,
                            cell_stages=("deliver",))
            result_a = _run(lenient)
            result_b = _run(strict)
            self.assertEqual(result_a["beacon_established"],
                             result_b["beacon_established"], target)
            self.assertEqual(result_a["persistence_installed"],
                             result_b["persistence_installed"], target)
            self.assertEqual(_sequence(events_a), _sequence(events_b), target)

    def test_an_unowned_category_is_blocked_with_a_reason_not_silently(self):
        """Whatever the strict loop refuses must be AUDITABLE: a `blocked`
        event naming the stage and the category, never a silent skip."""
        events = []
        agent = _agent(NET_TARGET, "ip", events, runner=_fake_runner(),
                       cell_loop=True, cell_stages=("deliver",))
        agent._ensure_cells("deliver")
        agent._current_stage = "deliver"
        from phantom.automation.planner import PlanStep
        cap = agent.registry.get("osint_identity")
        self.assertIsNotNone(cap)
        before = agent.cells.refused
        ran = []
        agent._execute_capability = lambda step: ran.append(1) or True
        self.assertFalse(agent._exec_with_permit(
            PlanStep(capability=cap, slot_values={})))
        self.assertEqual(ran, [])
        self.assertEqual(agent.cells.refused, before + 1)
        reasons = [str(d.get("reason", "")) for k, d in events
                   if k == "blocked"]
        self.assertTrue(any("cell-scoped" in r for r in reasons), reasons)


if __name__ == "__main__":
    unittest.main()
