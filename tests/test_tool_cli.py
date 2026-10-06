"""The `tool` shell command (AutoModeBrief §4.3 / §13)."""
import os
import tempfile
import unittest
from unittest import mock

from phantom.automation.runtime import capability_registry as reg_mod
from phantom.automation.runtime import import_tool
from phantom.core.shell.commands import system as sys_cmd


class _Runner:
    def __call__(self, argv, timeout):
        return (0, "myprobe 9.9") if argv[-1] == "--version" \
            else (0, "usage: myprobe TARGET")


class TestToolCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.reg_path = os.path.join(self.tmp, "reg.json")
        self.drivers_dir = os.path.join(self.tmp, "drivers")
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as fh:
            self.binary = fh.name
        self.addCleanup(lambda: os.path.exists(self.binary)
                        and os.unlink(self.binary))
        self._patches = [
            mock.patch.object(reg_mod, "_default_path",
                              lambda: self.reg_path),
            mock.patch.object(import_tool, "_default_runner", _Runner()),
            mock.patch("phantom.utils.paths.data_dir", lambda: self.tmp),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def test_import_creates_a_disabled_candidate(self):
        sys_cmd.cmd_tool(None, f"import {self.binary}")
        reg = reg_mod.CapabilityRegistry(path=self.reg_path)
        reg.load()
        rows = reg.all()
        self.assertTrue(rows)
        self.assertEqual(rows[0].state, "candidate")
        self.assertFalse(rows[0].enabled)
        # the manifest skeleton was written, but it is not runnable
        written = [f for f in os.listdir(self.drivers_dir)
                   if f.endswith(".candidate.json")]
        self.assertTrue(written)

    def test_approve_then_enable_then_disable(self):
        sys_cmd.cmd_tool(None, f"import {self.binary}")
        reg = reg_mod.CapabilityRegistry(path=self.reg_path)
        reg.load()
        cap = reg.all()[0].capability
        sys_cmd.cmd_tool(None, f"approve {cap}")
        sys_cmd.cmd_tool(None, f"enable {cap}")
        reg2 = reg_mod.CapabilityRegistry(path=self.reg_path)
        reg2.load()
        self.assertTrue(reg2.of(cap).enabled)
        self.assertIn(cap, reg2.enabled_ids())
        sys_cmd.cmd_tool(None, f"disable {cap}")
        reg3 = reg_mod.CapabilityRegistry(path=self.reg_path)
        reg3.load()
        self.assertFalse(reg3.of(cap).enabled)

    def test_list_on_empty_registry_is_safe(self):
        sys_cmd.cmd_tool(None, "list")     # must not raise

    def test_unknown_subcommand_is_reported(self):
        sys_cmd.cmd_tool(None, "frobnicate")   # must not raise


if __name__ == "__main__":
    unittest.main()
