"""brute_smb / brute_rdp: the creds source a Windows-only box needs.

A host whose only surface is SMB or RDP (no web, no ssh) used to have NO
creds source, so the planner produced NO plan at all (see
``scripts/coverage_matrix_sim.py``, ``bare_windows_device`` / ``ad_host``).
These two loud, ``--aggressive``-gated sources close that hole; these tests
pin their command shape, their service gate and their interpreter.
"""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.kit import _brute_rdp_interp, _brute_smb_interp


def _service_wm(port, service):
    wm = WorldModel(target="10.0.0.1", target_type="ip")
    wm.add_finding("service", f"tcp/{port}",
                   {"port": str(port), "protocol": "tcp", "service": service,
                    "product": "", "version": ""},
                   confidence=0.9, source="scan_tcp")
    return wm


class TestBruteSmbCommand(unittest.TestCase):
    def test_hydra_command_targets_smb(self):
        cap = make_registry().get("brute_smb")
        self.assertIsNotNone(cap)
        cmd = cap.make_command(_service_wm(445, "microsoft-ds"), {})
        self.assertIn("hydra", cmd)
        self.assertIn("smb://10.0.0.1", cmd)
        self.assertIn("-f", cmd)          # stop-on-first-hit, bounded noise

    def test_netbios_label_also_builds_the_command(self):
        cap = make_registry().get("brute_smb")
        cmd = cap.make_command(_service_wm(139, "netbios-ssn"), {})
        self.assertIn("smb://10.0.0.1", cmd)


class TestBruteRdpCommand(unittest.TestCase):
    def test_hydra_command_targets_rdp(self):
        cap = make_registry().get("brute_rdp")
        self.assertIsNotNone(cap)
        cmd = cap.make_command(_service_wm(3389, "ms-wbt-server"), {})
        self.assertIn("hydra", cmd)
        self.assertIn("rdp://10.0.0.1", cmd)
        self.assertIn("-f", cmd)


class TestInterpreters(unittest.TestCase):
    def test_hydra_smb_success_line_becomes_creds(self):
        wm = _service_wm(445, "microsoft-ds")
        out = ("[445][smb] host: 10.0.0.1   login: Administrator   "
               "password: P@ssw0rd")
        findings = _brute_smb_interp(out, wm, {})
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.kind, "creds")
        self.assertEqual(finding.key, "smb:Administrator")
        self.assertEqual(finding.value["password"], "P@ssw0rd")
        self.assertEqual(finding.value["service"], "smb")
        self.assertTrue(finding.value["valid"])

    def test_hydra_rdp_success_line_becomes_creds(self):
        wm = _service_wm(3389, "ms-wbt-server")
        out = "[3389][rdp] host: 10.0.0.1   login: admin   password: admin"
        findings = _brute_rdp_interp(out, wm, {})
        self.assertEqual([f.key for f in findings], ["rdp:admin"])

    def test_no_success_line_is_no_creds(self):
        wm = _service_wm(445, "microsoft-ds")
        self.assertEqual(_brute_smb_interp("[445][smb] host: 10.0.0.1\n",
                                           wm, {}), [])


if __name__ == "__main__":
    unittest.main()
