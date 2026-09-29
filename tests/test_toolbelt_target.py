"""Tests: target-aware tool selection.

The belt used to rank tools by what is installed on the OPERATOR box
("best tool on MY machine"). That answers the wrong question: a perfectly
installed SMB tool is worthless against a host with no SMB, and that is how
a plan ends up grinding a tool against a surface that is not there. These
tests pin the target fit.
"""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.brain.toolbelt import TargetSurface, Toolbelt
from phantom.automation.runtime.toolchain import ToolRegistry

TARGET = "10.0.0.5"


def _wm(services):
    wm = WorldModel(target=TARGET, target_type="ip")
    for i, svc in enumerate(services):
        wm.add_finding("service", f"tcp/{i}",
                       {"port": str(20 + i), "service": svc})
    return wm


class TestTargetSurface(unittest.TestCase):

    def test_derives_services_from_findings(self):
        surface = Toolbelt.surface_from_wm(_wm(["http", "ssh", "smb"]))
        self.assertTrue(surface.has("http"))
        self.assertTrue(surface.has("ssh"))
        self.assertTrue(surface.has("smb"))
        self.assertTrue(surface.has_web)

    def test_smb_alias_matches(self):
        surface = Toolbelt.surface_from_wm(_wm(["microsoft-ds"]))
        self.assertTrue(surface.has("smb"))

    def test_no_web_service_means_no_web(self):
        surface = Toolbelt.surface_from_wm(_wm(["ssh"]))
        self.assertFalse(surface.has_web)

    def test_empty_world_model_is_an_empty_surface(self):
        surface = Toolbelt.surface_from_wm(
            WorldModel(target=TARGET, target_type="ip"))
        self.assertEqual(len(surface.services), 0)


class TestTargetAwarePick(unittest.TestCase):

    def setUp(self):
        reg = ToolRegistry(installed={"smbmap", "curl", "nc", "hydra", "nmap"})
        self.belt = Toolbelt(reg)

    def test_smb_tool_refused_without_an_smb_surface(self):
        surface = TargetSurface(services=frozenset({"http"}))
        choice = self.belt.pick("smb_enum", target=surface)
        self.assertIsNone(choice.tool)
        self.assertIn("smb", choice.reason)

    def test_smb_tool_chosen_when_the_surface_is_there(self):
        surface = TargetSurface(services=frozenset({"smb"}))
        choice = self.belt.pick("smb_enum", target=surface)
        self.assertEqual(choice.tool, "smbmap")

    def test_http_tool_refused_without_a_web_surface(self):
        surface = TargetSurface(services=frozenset({"smb"}), has_web=False)
        choice = self.belt.pick("http_probe", target=surface)
        self.assertIsNone(choice.tool)

    def test_ssh_banner_prefers_the_internal_engine_on_an_ssh_target(self):
        surface = TargetSurface(services=frozenset({"ssh"}))
        choice = self.belt.pick("ssh_banner", target=surface)
        self.assertEqual(choice.tool, "__internal__")

    def test_without_a_target_the_legacy_behaviour_is_kept(self):
        choice = self.belt.pick("smb_enum")
        self.assertEqual(choice.tool, "smbmap")

    def test_choice_is_cached_per_target(self):
        web = TargetSurface(services=frozenset({"http"}), has_web=True)
        smb = TargetSurface(services=frozenset({"smb"}))
        self.assertIsNone(self.belt.pick("smb_enum", target=web).tool)
        self.assertEqual(self.belt.pick("smb_enum", target=smb).tool, "smbmap")


if __name__ == "__main__":
    unittest.main()
