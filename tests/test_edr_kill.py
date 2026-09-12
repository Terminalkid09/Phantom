"""Tests for the EDR/AV killer: `edr-kill` beacon command, the
`edr_disable` post capability (aggressive-only + SYSTEM gate) and its
interpreter (a run that stops nothing must not produce a success)."""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.kit import CAPABILITIES


class TestEdrDisableCapability(unittest.TestCase):

    def _cap(self):
        return [c for c in CAPABILITIES if c.id == "edr_disable"][0]

    def test_registered_as_post_forceful(self):
        c = self._cap()
        self.assertEqual(c.category, "post")
        self.assertTrue(c.forceful)          # refused in paranoid mode
        self.assertEqual(c.stealth_level, "aggressive")
        self.assertIn("defensive_gap", c.effects)

    def test_adapter_issues_edr_kill(self):
        wm = WorldModel("10.0.0.9")
        self.assertEqual(self._cap().adapter(wm, {}), "edr-kill")

    def test_interpreter_confirms_stopped_services(self):
        wm = WorldModel("10.0.0.9")
        findings = self._cap().interpret(
            "stopped WinDefend\nstopped Sense\ndefender_realtime=disabled\n",
            wm, {})
        self.assertTrue(findings)
        self.assertEqual(findings[0].kind, "defensive_gap")
        self.assertIn("WinDefend", findings[0].value["stopped"])

    def test_interpreter_no_success_when_nothing_stopped(self):
        wm = WorldModel("10.0.0.9")
        findings = self._cap().interpret(
            "no known AV service stopped (or insufficient privileges)\n",
            wm, {})
        self.assertEqual(findings, [])


class TestEdrKillBeaconSurface(unittest.TestCase):

    def test_in_beacon_command_list(self):
        from phantom.utils.c2_helpers import BEACON_COMMAND_LIST
        names = [c for c, _, _ in BEACON_COMMAND_LIST]
        self.assertIn("edr-kill", names)
        self.assertIn("edrcheck", names)

    def test_edrkill_module_present_in_evasion_header(self):
        """The C++ module must exist, DETECT before acting, and be wired
        into the dispatcher. Detection is keyword-based (not a fixed product
        list) so unknown AV/EDR products are still found."""
        import os
        ev = os.path.join(os.path.dirname(__file__), "..", "phantom",
                          "payloads", "beacon", "src", "evasion.h")
        with open(ev, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read()
        self.assertIn("namespace edrkill", src)
        self.assertIn("disable_defender", src)
        # detect-first design
        self.assertIn("detect_defensive_services", src)
        self.assertIn("DEFENSIVE_KEYWORDS", src)
        # generic keywords catch products nobody hard-coded
        for kw in ("\"edr\"", "\"endpoint\"", "\"antivirus\"",
                   "\"protection\""):
            self.assertIn(kw, src)

    def test_edrkill_wired_into_beacon_dispatcher(self):
        import os
        main = os.path.join(os.path.dirname(__file__), "..", "phantom",
                            "payloads", "beacon", "src", "main.cpp")
        with open(main, "r", encoding="utf-8", errors="replace") as fh:
            main_src = fh.read()
        self.assertIn("edr-kill", main_src)
        self.assertIn("edrkill::kill_av", main_src)

    def test_interpreter_counts_killed_linux_daemons(self):
        cap = [c for c in CAPABILITIES if c.id == "edr_disable"][0]
        wm = WorldModel("10.0.0.9")
        findings = cap.interpret(
            "detected_defensive_services=1\n  found clamav-daemon\n"
            "killed clamav-daemon\nservices_stopped=1 failed=0\n", wm, {})
        self.assertTrue(findings)
        self.assertIn("clamav-daemon", findings[0].value["stopped"])


if __name__ == "__main__":
    unittest.main()