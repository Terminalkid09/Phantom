"""Approval policy: auto / operator / deny (AutoModeBrief §13.4)."""
import unittest

from phantom.automation.runtime.approval import (
    ACTION_AUTO,
    ACTION_DENY,
    ACTION_OPERATOR,
    decide,
    mode_of,
    needs_approval,
)
from phantom.automation.runtime.drivers import parse_driver


def _driver(**over):
    base = {
        "id": "probe", "tool": "probe", "category": "recon",
        "command": "probe --target {target}", "effects": ["service"],
        "stealth_level": "passive", "detection_risk": 0.1, "timeout": 30,
    }
    base.update(over)
    return parse_driver(base)


class TestApprovalPolicy(unittest.TestCase):
    def test_passive_argv_in_lab_is_auto(self):
        drv = _driver(command="", argv=["probe", "-t", "{target}"])
        d = decide(drv, source="operator-local", lab=True)
        self.assertEqual(d.action, ACTION_AUTO)
        self.assertTrue(d.auto)
        self.assertFalse(needs_approval(drv, lab=True))

    def test_passive_outside_lab_requires_operator(self):
        drv = _driver(command="", argv=["probe", "-t", "{target}"])
        d = decide(drv, source="operator-local", lab=False)
        self.assertEqual(d.action, ACTION_OPERATOR)

    def test_shell_pipeline_requires_operator(self):
        drv = _driver(command="probe --target {target} | tee out")
        self.assertEqual(decide(drv, lab=True).action, ACTION_OPERATOR)

    def test_state_changing_category_requires_operator(self):
        drv = _driver(id="boom", tool="boom", category="exploit",
                      command="boom {target}")
        self.assertEqual(decide(drv, lab=True).action, ACTION_OPERATOR)

    def test_high_detection_risk_requires_operator(self):
        drv = _driver(command="", argv=["probe", "{target}"],
                      detection_risk=0.9)
        self.assertEqual(decide(drv, lab=True).action, ACTION_OPERATOR)

    def test_learned_source_is_denied(self):
        drv = _driver(command="", argv=["probe", "{target}"])
        d = decide(drv, source="learned", lab=True)
        self.assertEqual(d.action, ACTION_DENY)
        self.assertTrue(d.denied)

    def test_unknown_source_is_denied(self):
        drv = _driver(command="", argv=["probe", "{target}"])
        self.assertEqual(decide(drv, source="unknown").action, ACTION_DENY)

    def test_mode_of(self):
        self.assertEqual(mode_of(_driver(command="",
                                         argv=["probe", "{target}"])),
                         "argv")
        self.assertEqual(mode_of(_driver()), "shell")

    def test_decisions_are_serializable(self):
        drv = _driver(command="", argv=["probe", "{target}"])
        d = decide(drv, lab=True)
        self.assertEqual(d.to_dict()["action"], ACTION_AUTO)


if __name__ == "__main__":
    unittest.main()
