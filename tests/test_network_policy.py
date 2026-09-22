"""Tests: network-range policy + sane scan defaults (safety audit).

* a CIDR/range input authorizes discovery (-sn + ranking) ONLY;
  full engagement needs explicit --force-network (disclaimer + confirm
  at the CLI, explicit flag on API);
* default scan is top-1000 (not a 65k sweep), -sV runs at reduced
  version intensity (firmware-safe); full range stays available via
  explicit slot (deep-scan escalation) and --stealth.
"""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch


class TestRangePolicy(unittest.TestCase):
    @staticmethod
    def _quiet(am):
        return (
            patch.object(am.notifier, "success"),
            patch.object(am.notifier, "info"),
            patch.object(am.notifier, "warn"),
            patch.object(am.notifier, "error"),
        )

    def _run(self, **kwargs):
        import phantom.core.automode as am
        from phantom.core.session import session
        session.target = ""
        session.scope = []
        tri = {"ranked": [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}],
               "hosts": [{}, {}]}
        n = self._quiet(am)
        with n[0], n[1], n[2], n[3], \
                patch("phantom.core.netmap.triage_networks",
                      return_value=tri), \
                patch.object(am, "_run_agent_single") as m_single, \
                patch.object(am, "_ensure_c2_listener",
                             return_value=True):
            am.run_auto_mode(targets=["10.0.0.99/30"], **kwargs)
        return m_single

    def test_range_defaults_to_discovery_only(self):
        import phantom.core.automode as am
        from phantom.core.session import session
        session.target = ""
        session.scope = []
        tri = {"ranked": [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}],
               "hosts": [{}, {}]}
        n = self._quiet(am)
        with n[0], n[1], n[2], n[3], \
                patch("phantom.core.netmap.triage_networks",
                      return_value=tri), \
                patch.object(am, "_run_agent_single") as m_single, \
                patch.object(am, "_ensure_c2_listener",
                             return_value=True):
            am.run_auto_mode(targets=["10.0.0.99/30"])
        m_single.assert_not_called()

    def test_force_network_engages(self):
        import phantom.core.automode as am
        from phantom.core.session import session
        session.target = ""
        session.scope = []
        tri = {"ranked": [{"ip": "10.0.0.1"}], "hosts": [{}]}
        n = self._quiet(am)
        agent = Mock()
        result = {"beacon_established": False, "beacon_id": "",
                  "persistence_installed": False, "creds_found": 0,
                  "victim_ips": 0, "hypotheses": 0,
                  "hypotheses_confirmed": 0, "actions_taken": 0}
        with n[0], n[1], n[2], n[3], \
                patch("phantom.core.netmap.triage_networks",
                      return_value=tri), \
                patch.object(am, "_run_agent_single",
                             return_value=(result, agent)) as m_single, \
                patch.object(am, "_ensure_c2_listener",
                             return_value=True), \
                patch.object(am, "_report_out_dir",
                             return_value="/tmp"), \
                patch.object(am, "_write_agent_reports",
                             return_value=("/tmp/t", {})), \
                patch.object(am, "_merge_results_to_session",
                             return_value={}):
            am.run_auto_mode(targets=["10.0.0.99/30"], force_network=True)
        m_single.assert_called_once()

    def test_single_ip_unaffected_by_policy(self):
        import phantom.core.automode as am
        from phantom.core.session import session
        session.target = ""
        session.scope = []
        n = self._quiet(am)
        agent = Mock()
        result = {"beacon_established": False, "beacon_id": "",
                  "persistence_installed": False, "creds_found": 0,
                  "victim_ips": 0, "hypotheses": 0,
                  "hypotheses_confirmed": 0, "actions_taken": 0}
        with n[0], n[1], n[2], n[3], \
                patch.object(am, "_run_agent_single",
                             return_value=(result, agent)) as m_single, \
                patch.object(am, "_ensure_c2_listener",
                             return_value=True), \
                patch.object(am, "_report_out_dir",
                             return_value="/tmp"), \
                patch.object(am, "_write_agent_reports",
                             return_value=("/tmp/t", {})), \
                patch.object(am, "_merge_results_to_session",
                             return_value={}):
            am.run_auto_mode(targets=["10.0.0.5"])
        m_single.assert_called_once()


class TestScanDefaults(unittest.TestCase):
    def test_default_is_top1000_not_full_sweep(self):
        from phantom.automation.guidance.kit import _scan_port_spec
        spec = _scan_port_spec(SimpleNamespace(scan_style="balanced"))
        self.assertIn("--top-ports 1000", spec)
        self.assertNotIn("65535", spec)

    def test_agent_default_style_balanced(self):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.guidance.kit import _scan_port_spec
        agent = AutonomousAgent(target="10.0.0.5")
        self.assertEqual(agent.wm.scan_style, "balanced")
        self.assertEqual(_scan_port_spec(agent.wm),
                         "--top-ports 1000 --min-rate 300")

    def test_stealth_keeps_full_range_slow(self):
        from phantom.automation.guidance.kit import _scan_port_spec
        spec = _scan_port_spec(SimpleNamespace(scan_style="full_stealth"))
        self.assertIn("1-65535", spec)
        self.assertIn("-T2", spec)

    def test_version_intensity_is_firmware_safe(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.guidance.kit import _version_adapter
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        wm.add_finding("service", "tcp/22",
                       {"port": "22", "service": "ssh"},
                       confidence=0.9, source="scan_tcp")
        cmd = _version_adapter(wm, {})
        self.assertIn("--version-intensity 2", cmd)
        self.assertIn("-p 22", cmd)


if __name__ == "__main__":
    unittest.main()
