"""Broker gate for runtime drivers in the agent (AutoModeBrief §13.5).

Pins that `_authorize_driver` refuses a driver whose registry record is not
enabled and allows (with the broker-built command) one that is.
"""
import os
import tempfile
import unittest
from unittest import mock

from phantom.automation import agent as agent_mod
from phantom.automation.runtime import capability_registry as reg_mod
from phantom.automation.runtime.capability_registry import (
    CapabilityRecord,
    CapabilityRegistry,
)
from phantom.automation.runtime.drivers import driver_capability, parse_driver

_MANIFEST = {
    "id": "my_scanner", "tool": "my_scanner", "category": "recon",
    "command": "my_scanner --target {target}", "effects": ["service"],
    "requires": ["target"], "stealth_level": "passive", "detection_risk": 0.1,
}


class _Toolchain:
    def __init__(self, present=("my_scanner",)):
        self.present = set(present)

    def has(self, name):
        return name in self.present

    def resolve(self, tools):
        for t in tools:
            if t in self.present:
                return t
        return None


class _FakeSelf:
    target = "10.0.0.5"
    scope_list = []
    aggressive = False

    def __init__(self, toolchain):
        self.toolchain = toolchain


class TestAgentBrokerGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.reg_path = os.path.join(self.tmp, "reg.json")
        self._patch = mock.patch.object(reg_mod, "_default_path",
                                        lambda: self.reg_path)
        self._patch.start()
        self.addCleanup(self._patch.stop)
        self.cap = driver_capability(parse_driver(_MANIFEST))

    def _registry(self, enable):
        reg = CapabilityRegistry(path=self.reg_path)
        reg.discover(CapabilityRecord(capability="my_scanner",
                                      tool="my_scanner", sha256="h"))
        if enable:
            reg.enable("my_scanner")
        reg.save()

    def test_driver_carries_its_manifest(self):
        self.assertIsNotNone(getattr(self.cap, "driver", None))

    def test_not_enabled_driver_is_refused(self):
        self._registry(enable=False)
        holder = _FakeSelf(_Toolchain())
        decision = agent_mod.AutonomousAgent._authorize_driver(
            holder, self.cap, {"target": "10.0.0.5"})
        self.assertFalse(decision.allowed)
        self.assertTrue(any("not enabled" in r for r in decision.reasons))

    def test_enabled_driver_is_allowed_with_a_command(self):
        self._registry(enable=True)
        holder = _FakeSelf(_Toolchain())
        decision = agent_mod.AutonomousAgent._authorize_driver(
            holder, self.cap, {"target": "10.0.0.5"})
        self.assertTrue(decision.allowed, decision.explain())
        self.assertIn("10.0.0.5", decision.command)

    def test_missing_tool_is_refused(self):
        self._registry(enable=True)
        holder = _FakeSelf(_Toolchain(present=()))
        decision = agent_mod.AutonomousAgent._authorize_driver(
            holder, self.cap, {"target": "10.0.0.5"})
        self.assertFalse(decision.allowed)

    def test_scope_refusal(self):
        self._registry(enable=True)
        holder = _FakeSelf(_Toolchain())
        holder.target = "10.9.9.9"            # out of the declared scope
        holder.scope_list = ["10.0.0.0/24"]
        decision = agent_mod.AutonomousAgent._authorize_driver(
            holder, self.cap, {"target": "10.9.9.9"})
        self.assertFalse(decision.allowed)
        self.assertTrue(any("scope" in r for r in decision.reasons))


if __name__ == "__main__":
    unittest.main()
