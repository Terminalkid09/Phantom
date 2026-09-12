"""Tests for the unified network triage engine (netmap.triage_networks)
and the liveness probe (check_hosts_alive): one engine for the auto-mode
assault pool, the `map` command and the Electron map, with dead hosts
never ranked as targets."""
import unittest
from unittest.mock import patch

from phantom.core import netmap


class TestTriageNetworks(unittest.TestCase):
    @patch.object(netmap, "_quick_probe_hosts")
    @patch.object(netmap, "_enrich_hosts")
    @patch.object(netmap, "rank_hosts_exposure",
                  side_effect=lambda hosts, timeout=40.0:
                  [{"ip": h["ip"], "score": 9, "risk": "HIGH",
                    "open_ports": [{"port": 445, "service": "smb",
                                    "weight": 4}], "port_count": 1,
                    "banner": ""} for h in hosts])
    @patch.object(netmap, "_parse_nmap_sn",
                  return_value=[{"ip": "10.0.0.1"},
                                {"ip": "10.0.0.9"},
                                {"ip": "10.0.0.50"}])
    @patch.object(netmap, "_run", return_value="Nmap scan report for 10.0.0.1\n")
    @patch.object(netmap, "save_discovered_hosts")
    @patch("shutil.which", return_value="/usr/bin/nmap")
    def test_discovers_enriches_and_ranks(self, *_):
        tri = netmap.triage_networks(["10.0.0.0/24"])
        self.assertEqual(len(tri["hosts"]), 3)
        # every freshly discovered host is alive by definition
        self.assertTrue(all(h["alive"] for h in tri["hosts"]))
        self.assertTrue(all(h.get("last_seen") for h in tri["hosts"]))
        self.assertEqual(len(tri["ranked"]), 3)
        self.assertEqual(tri["method"], "nmap -sn")

    @patch.object(netmap, "_run", return_value="")
    @patch.object(netmap, "save_discovered_hosts")
    @patch("shutil.which", return_value=None)
    def test_no_hosts_returns_empty(self, *_):
        tri = netmap.triage_networks(["10.0.0.0/24"])
        self.assertEqual(tri["hosts"], [])
        self.assertEqual(tri["ranked"], [])

    @patch.object(netmap, "_quick_probe_hosts")
    @patch.object(netmap, "_enrich_hosts")
    @patch.object(netmap, "rank_hosts_exposure", return_value=[])
    @patch.object(netmap, "_parse_nmap_sn",
                  return_value=[{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}])
    @patch.object(netmap, "_run", return_value="Nmap scan report for 10.0.0.1\n")
    @patch.object(netmap, "save_discovered_hosts")
    @patch("shutil.which", return_value="/usr/bin/nmap")
    def test_empty_networks_input(self, *_):
        tri = netmap.triage_networks([])
        self.assertEqual(tri["hosts"], [])
        self.assertEqual(tri["ranked"], [])


class TestCheckHostsAlive(unittest.TestCase):
    @patch("shutil.which", return_value="/bin/ping")
    def test_marks_alive_and_dead(self, *_):
        hosts = [{"ip": "10.0.0.1"}, {"ip": "10.0.0.9"}]

        def fake_run(cmd, capture_output=True, timeout=2):
            class R:
                returncode = 0 if cmd[-1] == "10.0.0.1" else 1
            return R()

        with patch("subprocess.run", side_effect=fake_run), \
                patch.object(netmap, "_LIVENESS_CACHE", {}):
            status = netmap.check_hosts_alive(hosts, force=True)
        self.assertEqual(status, {"10.0.0.1": True, "10.0.0.9": False})
        self.assertTrue(hosts[0]["alive"])
        self.assertFalse(hosts[1]["alive"])
        self.assertTrue(hosts[0].get("last_seen"))

    @patch("shutil.which", return_value=None)
    def test_degrades_optimistic_without_ping(self, *_):
        hosts = [{"ip": "10.0.0.1"}]
        status = netmap.check_hosts_alive(hosts, force=True)
        self.assertEqual(status, {"10.0.0.1": True})
        self.assertTrue(hosts[0]["alive"])

    def test_empty(self):
        self.assertEqual(netmap.check_hosts_alive([]), {})


class TestRankExcludesDead(unittest.TestCase):
    @patch.object(netmap, "_probe_ports", return_value=[445, 80])
    def test_dead_host_never_ranked(self, *_):
        hosts = [
            {"ip": "10.0.0.1", "alive": True},
            {"ip": "10.0.0.9", "alive": False},  # powered off
        ]
        ranked = netmap.rank_hosts_exposure(hosts)
        ips = [r["ip"] for r in ranked]
        self.assertIn("10.0.0.1", ips)
        self.assertNotIn("10.0.0.9", ips)


if __name__ == "__main__":
    unittest.main()