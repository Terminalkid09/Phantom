"""Tests for the auto-mode network triage: CIDR input gets host discovery
+ surface ranking so the agent pool assaults the richest hosts first. The
engine is unified: automode delegates to netmap.triage_networks (the same
one the `map` command and Electron use)."""
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from phantom.core import automode


class TestExtractNetworks(unittest.TestCase):
    def test_extracts_cidr(self):
        self.assertEqual(automode._extract_networks(["10.0.0.0/24"]),
                         ["10.0.0.0/24"])

    def test_ignores_single_hosts_and_urls(self):
        self.assertEqual(automode._extract_networks(
            ["10.0.0.5", "example.com", "https://x/"]), [])

    def test_mixed_input(self):
        self.assertEqual(automode._extract_networks(
            ["10.0.0.5", "172.16.0.0/16"]), ["172.16.0.0/16"])


class TestTriageIntegration(unittest.TestCase):
    """The triage runs inside run_auto_mode BEFORE the campaign: when a
    CIDR is given, discovered+ranked hosts become the targets and the
    campaign receives them (never the raw CIDR expansion)."""

    # run_auto_mode auto-starts the C2 listener and builds reports;
    # mock those side effects so the test only exercises the triage path
    def _patched(self):
        return ExitStack()

    def _run(self, targets, **extra):
        with self._patched() as stack:
            camp = stack.enter_context(
                patch.object(automode, "_run_agent_campaign"))
            # single-resolved-target runs take _run_agent_single (a REAL
            # agent run): mock it too so tests never touch the network
            single = stack.enter_context(
                patch.object(automode, "_run_agent_single",
                            return_value=({}, None)))
            stack.enter_context(
                patch("phantom.core.c2_server.server_instance"))
            stack.enter_context(
                patch("phantom.core.automode._write_agent_reports",
                      return_value=("d", {})))
            session = stack.enter_context(patch.object(automode, "session"))
            for target, value in extra.items():
                stack.enter_context(patch.object(automode, target, value))
            session.scope = []
            session.target = None
            automode.run_auto_mode(targets, goal="deliver")
            return camp, single, session

    def _tri(self, ranked_ips, alive_ips=None):
        alive_ips = alive_ips if alive_ips is not None else ranked_ips
        return {"hosts": [{"ip": ip, "alive": True} for ip in alive_ips],
                "ranked": [{"ip": ip} for ip in ranked_ips],
                "method": "nmap -sn", "elapsed": 1.0}

    @patch("phantom.core.netmap.triage_networks",
           return_value={"hosts": [{"ip": "10.0.0.9", "alive": True},
                                   {"ip": "10.0.0.50", "alive": True}],
                         "ranked": [{"ip": "10.0.0.50"},
                                     {"ip": "10.0.0.9"}],
                         "method": "nmap -sn", "elapsed": 1.0})
    def test_cidr_uses_discovered_ranked_hosts(self, _t):
        camp, _single, _s = self._run(["10.0.0.0/24"])
        self.assertEqual(camp.call_args[0][0],
                         ["10.0.0.50", "10.0.0.9"])

    @patch("phantom.core.netmap.triage_networks",
           return_value={"hosts": [], "ranked": [],
                         "method": "none", "elapsed": 1.0})
    def test_no_alive_hosts_keeps_explicit_targets(self, _t):
        # single explicit host: no triage needed, the single-agent path
        # receives the host itself (never the raw CIDR expansion)
        camp, single, _s = self._run(["10.0.0.5"])
        self.assertIsNone(camp.call_args)  # campaign not used for 1 target
        self.assertEqual(single.call_args[0][0], "10.0.0.5")

    @patch("phantom.core.netmap.triage_networks",
           return_value={"hosts": [{"ip": "10.0.0.9", "alive": True},
                                   {"ip": "10.0.0.50", "alive": True}],
                         "ranked": [{"ip": "10.0.0.50"},
                                     {"ip": "10.0.0.9"}],
                         "method": "nmap -sn", "elapsed": 1.0})
    def test_explicit_host_precedes_discovered(self, _t):
        camp, _single, _s = self._run(["10.0.0.5", "10.0.0.0/30"])
        targets = camp.call_args[0][0]
        # explicit host first (operator intent), then discovered+ranked
        self.assertEqual(targets[0], "10.0.0.5")
        self.assertIn("10.0.0.50", targets)
        self.assertIn("10.0.0.9", targets)
        # and the CIDR expansion never leaks into the assault pool
        self.assertEqual(len(targets), 3)


if __name__ == "__main__":
    unittest.main()