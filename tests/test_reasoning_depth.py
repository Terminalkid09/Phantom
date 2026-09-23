"""Reasoning depth: a version check must be exact, and a dead lens must talk.

Two bugs, both of which made the AUTOMATION look smarter than it was:

* `"2.4.49" in version` is a SUBSTRING test: `Apache httpd 2.4.490` and any
  banner that merely contained those digits were flagged as vulnerable, and
  the planner acts on a vuln hypothesis (it spends real moves on it).
* `_decision_for` wrapped the arbiter in `except Exception: return base`.
  When the lens/tribunal layer broke, the move still happened and the
  EXPLANATION silently disappeared — indistinguishable from competence.
"""
import pytest

from phantom.automation.belief import WorldModel
from phantom.automation.reasoning import ReasoningEngine


def _wm(version, product="Apache"):
    wm = WorldModel(target="10.0.0.5", target_type="ip")
    wm.add_finding(
        "service", "tcp/80",
        {"port": "80", "protocol": "tcp", "service": product.lower(),
         "product": product, "version": version},
        confidence=0.9, source="nmap")
    return wm


class TestVersionMatchIsExact:
    @pytest.mark.parametrize("banner", [
        "Apache httpd 2.4.49",
        "Apache/2.4.49 (Unix)",
    ])
    def test_the_vulnerable_build_is_flagged(self, banner):
        wm = _wm(banner)
        ReasoningEngine().run(wm)
        assert wm.find("vuln_class", software="apache"), banner

    @pytest.mark.parametrize("banner", [
        "Apache httpd 2.4.490",   # substring of 2.4.49
        "Apache httpd 2.4.449",   # substring of 2.4.49
        "Apache httpd 2.4.59",    # patched line
        "Apache httpd 2.4.62",    # current
        "Apache httpd 12.4.49",   # different major
    ])
    def test_a_patched_build_is_not_flagged(self, banner):
        wm = _wm(banner)
        ReasoningEngine().run(wm)
        assert not wm.find("vuln_class", software="apache"), banner

    def test_the_incomplete_fix_build_is_flagged_separately(self):
        wm = _wm("Apache httpd 2.4.50")
        ReasoningEngine().run(wm)
        found = wm.find("vuln_class", software="apache")
        assert found
        assert "2.4.50" in found[0].value["detail"]


class TestArbiterDegradationIsVisible:
    """`except: return base` used to swallow the whole reasoning layer."""

    def _agent(self, events):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.guidance.stealth import (
            StealthConfig, StealthEngine)
        from phantom.automation.runtime.stealth_runtime import (
            StealthRuntime, TimingGovernor)
        from phantom.automation.runtime.toolchain import ToolRegistry

        return AutonomousAgent(
            target="10.0.0.5", target_type="ip", profile="enterprise",
            on_event=lambda k, d: events.append((k, d)),
            runtime=StealthRuntime(
                StealthEngine(WorldModel(target="10.0.0.5"),
                              StealthConfig()),
                runner=lambda cmd, timeout=60: None,
                cost_per_action=0.0,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0)),
            toolchain=ToolRegistry(installed={"nmap"}),
            scope_list=["10.0.0.0/8"])

    def _step(self):
        from phantom.automation.guidance.commands import make_registry
        from phantom.automation.planner import PlanStep
        return PlanStep(capability=make_registry().get("scan_tcp"),
                        slot_values={})

    class _BrokenArbiter:
        def evaluate(self, *a, **k):
            raise RuntimeError("tribunal exploded")

        def search_policy(self, *a, **k):
            raise RuntimeError("tribunal exploded")

    def test_broken_arbiter_falls_back_but_says_so(self):
        events = []
        agent = self._agent(events)
        agent.arbiter = self._BrokenArbiter()
        assert agent._decision_for(self._step(), 0.42) == 0.42
        degraded = [d for k, d in events if k == "degraded"]
        assert degraded, events
        assert degraded[0]["layer"] == "arbiter"
        assert "RuntimeError" in degraded[0]["detail"]

    def test_degradation_is_announced_once_per_layer(self):
        events = []
        agent = self._agent(events)
        agent.arbiter = self._BrokenArbiter()
        for _ in range(5):
            agent._decision_for(self._step(), 0.42)
        assert len([1 for k, _ in events if k == "degraded"]) == 1

    def test_broken_search_policy_says_so_too(self):
        events = []
        agent = self._agent(events)
        agent.arbiter = self._BrokenArbiter()
        assert agent.search_policy() == "adaptive"
        layers = [d["layer"] for k, d in events if k == "degraded"]
        assert "search_policy" in layers
