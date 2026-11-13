"""Strong manifest validation with typed errors (AutoModeBrief §13.3)."""
import unittest

from phantom.automation.runtime.manifest import validate_manifest


def _valid(**over):
    base = {
        "id": "my_scanner", "tool": "my-scanner", "category": "recon",
        "description": "d", "command": "my-scanner --target {target}",
        "effects": ["service"], "requires": ["target"],
        "opsec_cost": 0.2, "detection_risk": 0.05,
        "stealth_level": "passive", "timeout": 60,
    }
    base.update(over)
    return base


class TestValidManifest(unittest.TestCase):
    def test_accepts_a_wellformed_manifest(self):
        res = validate_manifest(_valid())
        self.assertTrue(res.ok, res.explain())
        self.assertEqual(res.driver.id, "my_scanner")
        self.assertEqual(res.errors, [])

    def test_accepts_an_argv_manifest(self):
        res = validate_manifest(_valid(command="",
                                       argv=["my-scanner", "-u", "{target}"]))
        self.assertTrue(res.ok, res.explain())


class TestTypedErrors(unittest.TestCase):
    def _errors(self, data):
        res = validate_manifest(data)
        self.assertFalse(res.ok)
        return {e.field for e in res.errors}

    def test_non_dict_root(self):
        self.assertIn("<root>", self._errors(["nope"]))

    def test_missing_required_fields(self):
        fields = self._errors({"description": "x"})
        self.assertIn("id", fields)
        self.assertIn("tool", fields)
        self.assertIn("category", fields)
        self.assertIn("effects", fields)

    def test_unknown_category(self):
        self.assertIn("category", self._errors(_valid(category="nonsense")))

    def test_empty_effects(self):
        self.assertIn("effects", self._errors(_valid(effects=[])))

    def test_unknown_placeholder(self):
        fields = self._errors(_valid(command="my-scanner {evil} {target}"))
        self.assertIn("inputs", fields)

    def test_declared_placeholder_is_allowed(self):
        res = validate_manifest(_valid(
            command="my-scanner --user {user} {target}",
            inputs=[{"name": "user", "type": "str", "required": True}]))
        self.assertTrue(res.ok, res.explain())

    def test_constant_command_is_rejected(self):
        self.assertIn("command",
                      self._errors(_valid(command="my-scanner --all")))

    def test_timeout_out_of_range(self):
        self.assertIn("timeout", self._errors(_valid(timeout=10 ** 9)))
        self.assertIn("timeout", self._errors(_valid(timeout=0)))

    def test_risk_out_of_range(self):
        self.assertIn("detection_risk",
                      self._errors(_valid(detection_risk=99.0)))

    def test_stealth_level_unknown(self):
        self.assertIn("stealth_level",
                      self._errors(_valid(stealth_level="invisible")))

    def test_executable_must_match_tool(self):
        self.assertIn("tool",
                      self._errors(_valid(command="something-else {target}")))


if __name__ == "__main__":
    unittest.main()
