"""Centralized execution broker (AutoModeBrief §13.5)."""
import os
import unittest

from phantom.automation.runtime.broker import ExecutionBroker
from phantom.automation.runtime.drivers import parse_driver
from phantom.automation.runtime.capability_registry import (
    CapabilityRecord,
    CapabilityRegistry,
)


def _driver(**over):
    base = {
        "id": "probe", "tool": "probe", "category": "recon",
        "command": "",
        "argv": ["probe", "-t", "{target}"],
        "effects": ["service"], "stealth_level": "passive",
        "detection_risk": 0.1, "timeout": 30,
        "requires": ["target"],
    }
    base.update(over)
    return parse_driver(base)


class _Toolchain:
    def __init__(self, present=("probe",)):
        self.present = set(present)

    def has(self, name):
        return name in self.present


class _Cancel:
    def __init__(self, cancelled=False, reason="stop"):
        self.cancelled = cancelled
        self.reason = reason


def _enabled_registry(cap="probe"):
    reg = CapabilityRegistry(path=os.devnull)
    reg.discover(CapabilityRecord(capability=cap, tool=cap, sha256="h"))
    reg.enable(cap)
    return reg


class TestPreflight(unittest.TestCase):
    def test_allowed_builds_the_command(self):
        broker = ExecutionBroker(toolchain=_Toolchain())
        decision = broker.preflight(_driver(), target="10.0.0.5")
        self.assertTrue(decision.allowed, decision.explain())
        self.assertIn("10.0.0.5", decision.command)

    def test_registry_not_enabled_is_refused(self):
        reg = CapabilityRegistry(path=os.devnull)
        reg.discover(CapabilityRecord(capability="probe", tool="probe",
                                      sha256="h"))     # stuck at discovered
        broker = ExecutionBroker(registry=reg, toolchain=_Toolchain())
        d = broker.preflight(_driver(), target="10.0.0.5")
        self.assertFalse(d.allowed)
        self.assertTrue(any("not enabled" in r for r in d.reasons))

    def test_enabled_registry_allows(self):
        broker = ExecutionBroker(registry=_enabled_registry(),
                                 toolchain=_Toolchain())
        self.assertTrue(broker.preflight(_driver(),
                                         target="10.0.0.5").allowed)

    def test_scope_refuses_out_of_scope_target(self):
        broker = ExecutionBroker(toolchain=_Toolchain(),
                                 scope_list=["10.0.0.0/24"])
        d = broker.preflight(_driver(), target="10.9.9.9")
        self.assertFalse(d.allowed)
        self.assertTrue(any("scope" in r for r in d.reasons))

    def test_missing_tool_is_refused(self):
        broker = ExecutionBroker(toolchain=_Toolchain(present=()))
        d = broker.preflight(_driver(), target="10.0.0.5")
        self.assertFalse(d.allowed)
        self.assertTrue(any("unavailable" in r for r in d.reasons))

    def test_missing_required_input_is_refused(self):
        drv = _driver(command="", argv=["probe", "--user", "{user}", "{target}"],
                      inputs=[{"name": "user", "type": "str", "required": True}],
                      requires=["target"])
        broker = ExecutionBroker(toolchain=_Toolchain())
        d = broker.preflight(drv, target="10.0.0.5")
        self.assertFalse(d.allowed)
        self.assertTrue(any("required input" in r for r in d.reasons))

    def test_cancellation_refuses(self):
        broker = ExecutionBroker(toolchain=_Toolchain(),
                                 cancel=_Cancel(cancelled=True))
        d = broker.preflight(_driver(), target="10.0.0.5")
        self.assertFalse(d.allowed)
        self.assertTrue(any("cancelled" in r for r in d.reasons))


class TestRun(unittest.TestCase):
    def test_run_with_runner_is_ok(self):
        broker = ExecutionBroker(toolchain=_Toolchain())
        seen = {}

        def runner(cmd, timeout):
            seen["cmd"] = cmd
            seen["timeout"] = timeout
            return True, "open"

        res = broker.run(_driver(), target="10.0.0.5", runner=runner)
        self.assertTrue(res.ok)
        self.assertEqual(res.output, "open")
        self.assertIn("10.0.0.5", seen["cmd"])
        self.assertEqual(seen["timeout"], 30)

    def test_refused_run_does_not_call_runner(self):
        broker = ExecutionBroker(toolchain=_Toolchain(present=()))
        called = {"n": 0}

        def runner(cmd, timeout):
            called["n"] += 1
            return True, ""

        res = broker.run(_driver(), target="10.0.0.5", runner=runner)
        self.assertFalse(res.ok)
        self.assertEqual(called["n"], 0)

    def test_no_runner_is_refused_not_shelled(self):
        broker = ExecutionBroker(toolchain=_Toolchain())
        res = broker.run(_driver(), target="10.0.0.5")
        self.assertFalse(res.ok)
        self.assertIn("runner", res.error)

    def test_audit_event_emitted(self):
        events = []

        class _Audit:
            def record(self, kind, **fields):
                events.append((kind, fields))

        broker = ExecutionBroker(toolchain=_Toolchain(), audit=_Audit())
        broker.run(_driver(), target="10.0.0.5",
                   runner=lambda c, t: (True, "x"))
        self.assertTrue(any(k == "capability_executed" for k, _ in events))


if __name__ == "__main__":
    unittest.main()
