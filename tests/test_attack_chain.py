"""Tests for cross-service attack graph chaining engine."""
import unittest
from phantom.automation.belief import WorldModel
from phantom.automation.attack_chain import (
    AttackGraph, AttackNode, AttackEdge, AttackPath,
    CHAIN_RULES, build_attack_summary,
)


class TestAttackGraph(unittest.TestCase):
    """Test attack graph construction and path finding."""

    @classmethod
    def setUpClass(cls):
        """Register the attack_chain module so its capabilities appear in tests."""
        import phantom.automation.attack_chain  # noqa: F401

    def setUp(self):
        self.wm = WorldModel("10.0.0.5", "ip")

    def test_empty_graph(self):
        """Graph with no findings has no nodes and no paths."""
        graph = AttackGraph(self.wm)
        graph.build()
        self.assertEqual(len(graph.nodes), 0)
        self.assertEqual(len(graph.edges), 0)
        self.assertEqual(len(graph.find_paths("beacon")), 0)

    def test_service_node_only(self):
        """A single service creates one node but no paths (no creds)."""
        self.wm.add_finding("service", "tcp/22", {"service": "ssh", "port": "22"},
                            confidence=0.9, source="scan")
        graph = AttackGraph(self.wm)
        graph.build()
        self.assertEqual(len(graph.nodes), 1)
        self.assertEqual(len(graph.edges), 0)

    def test_creds_to_ssh_path(self):
        """Credentials + SSH service creates a path to beacon."""
        self.wm.add_finding("service", "tcp/22", {"service": "ssh", "port": "22"},
                            confidence=0.9, source="scan")
        self.wm.add_finding("creds", "ssh:10.0.0.5",
                            {"username": "root", "password": "toor", "service": "ssh"},
                            confidence=0.9, source="brute")
        # Beacon finding as actual goal
        self.wm.add_finding("beacon", "established",
                            {"session": "abc123"},
                            confidence=0.9, source="beacon_deploy")

        graph = AttackGraph(self.wm)
        graph.build()
        paths = graph.find_paths("beacon")
        self.assertGreater(len(paths), 0, "Should find path from creds to beacon")

    def test_smb_anon_chain(self):
        """SMB service enabling anonymous access."""
        self.wm.add_finding("service", "tcp/445",
                            {"service": "smb", "port": "445", "anonymous": True, "null_session": True},
                            confidence=0.9, source="fingerprint")
        self.wm.add_finding("smb_anon", "tcp/445",
                            {"anonymous": True},
                            confidence=0.9, source="fingerprint")

        graph = AttackGraph(self.wm)
        graph.build()
        # SMB → SMB anon edge should exist
        self.assertGreater(len(graph.edges), 0)

    def test_ssrf_to_cloud_creds(self):
        """SSRF finding → cloud credentials path."""
        self.wm.add_finding("hunt_anomaly", "ssrf:tcp/443",
                            {"cls": "ssrf", "confirmed": True, "endpoint": "/redirect"},
                            confidence=0.8, source="hunt_web")
        self.wm.add_finding("cloud_creds", "aws:iam",
                            {"access_key": "AKIA...", "secret": "xxx"},
                            confidence=0.7, source="ssrf_probe")
        self.wm.add_finding("beacon", "established",
                            {"session": "def456"},
                            confidence=0.9, source="beacon_deploy")

        graph = AttackGraph(self.wm)
        graph.build()
        paths = graph.find_paths("beacon")
        self.assertGreater(len(paths), 0)

    def test_missing_for_goal(self):
        """When only services exist, missing_for_goal reports gaps."""
        self.wm.add_finding("service", "tcp/22", {"service": "ssh", "port": "22"},
                            confidence=0.9, source="scan")
        graph = AttackGraph(self.wm)
        graph.build()
        missing = graph.missing_for_goal("beacon")
        self.assertIn("creds", missing)
        self.assertIn("rce", missing)

    def test_redis_no_auth_chain(self):
        """Redis no-auth → credential acquisition potential."""
        self.wm.add_finding("service", "tcp/6379",
                            {"service": "redis", "port": "6379", "auth_required": False},
                            confidence=0.9, source="fingerprint")
        self.wm.add_finding("beacon", "established",
                            {"session": "ghi789"},
                            confidence=0.9, source="beacon_deploy")

        graph = AttackGraph(self.wm)
        graph.build()
        # Redis with no-auth is an entry point (service node), the
        # chain rule self-links it but self-edges are skipped — the
        # node is still reachable and appears in entry_points
        redis_node = graph.nodes.get("service:tcp/6379")
        self.assertIsNotNone(redis_node)
        self.assertTrue(redis_node.reachable)
        summary = build_attack_summary(self.wm)
        self.assertIn("redis", str(summary["entry_points"]).lower())

    def test_ssti_rce_path(self):
        """SSTI confirmed → RCE → beacon chain."""
        self.wm.add_finding("hunt_anomaly", "ssti:tcp/443",
                            {"cls": "ssti", "confirmed": True, "severity": "critical",
                             "endpoint": "/profile"},
                            confidence=0.9, source="hunt_web")
        self.wm.add_finding("rce", "ssti:tcp/443",
                            {"confirmed": True, "severity": "critical"},
                            confidence=0.8, source="hunt_web")
        self.wm.add_finding("beacon", "established",
                            {"session": "jkl012"},
                            confidence=0.9, source="beacon_deploy")

        graph = AttackGraph(self.wm)
        graph.build()
        paths = graph.find_paths("beacon")
        self.assertGreater(len(paths), 0)

    def test_build_attack_summary(self):
        """build_attack_summary returns structured dict."""
        self.wm.add_finding("service", "tcp/22", {"service": "ssh", "port": "22"},
                            confidence=0.9, source="scan")
        self.wm.add_finding("creds", "ssh:10.0.0.5",
                            {"username": "admin", "password": "pass",
                             "service": "ssh"},
                            confidence=0.9, source="brute")
        self.wm.add_finding("beacon", "established",
                            {"session": "mno345"},
                            confidence=0.9, source="beacon_deploy")

        summary = build_attack_summary(self.wm)
        self.assertIn("nodes", summary)
        self.assertIn("edges", summary)
        self.assertIn("paths_to_beacon", summary)
        self.assertIn("best_path", summary)
        self.assertIn("missing_for_beacon", summary)
        self.assertGreater(summary["paths_to_beacon"], 0)

    def test_attack_path_properties(self):
        """AttackPath dataclass properties work."""
        path = AttackPath(
            nodes=["svc/22", "creds/ssh", "beacon"],
            total_cost=2.0, total_confidence=0.6, goal="beacon",
        )
        self.assertEqual(path.length, 3)
        self.assertIn("svc/22", path.summary)
        self.assertIn("beacon", path.summary)

    def test_chain_rules_registered(self):
        """All chain rules are valid tuples."""
        for rule in CHAIN_RULES:
            self.assertEqual(len(rule), 7)
            from_kind, from_cond, to_kind, to_cond, label, conf, tech = rule
            self.assertIsInstance(from_kind, str)
            self.assertIsInstance(to_kind, str)
            self.assertIsInstance(label, str)
            self.assertGreater(conf, 0)
            self.assertLessEqual(conf, 1.0)

    def test_multiple_entry_points(self):
        """Graph with multiple services picks best path."""
        self.wm.add_finding("service", "tcp/22", {"service": "ssh", "port": "22"},
                            confidence=0.9, source="scan")
        self.wm.add_finding("service", "tcp/445", {"service": "smb", "port": "445"},
                            confidence=0.9, source="scan")
        self.wm.add_finding("creds", "ssh:10.0.0.5",
                            {"username": "root", "password": "god",
                             "service": "ssh"},
                            confidence=0.9, source="brute")
        self.wm.add_finding("beacon", "established",
                            {"session": "pqr678"},
                            confidence=0.9, source="beacon_deploy")

        graph = AttackGraph(self.wm)
        graph.build()
        summary = build_attack_summary(self.wm)
        self.assertGreater(len(summary["entry_points"]), 0)

    def test_hash_to_creds_edge(self):
        """Hash finding enables creds via cracking edge."""
        self.wm.add_finding("hash", "ntlm:DC01",
                            {"hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                             "username": "Administrator"},
                            confidence=0.9, source="dc_sync")
        self.wm.add_finding("creds", "ssh:10.0.0.5",
                            {"username": "admin", "password": "cracked",
                             "service": "ssh"},
                            confidence=0.5, source="hash_crack")
        self.wm.add_finding("beacon", "established",
                            {"session": "stu901"},
                            confidence=0.9, source="beacon_deploy")

        graph = AttackGraph(self.wm)
        graph.build()
        # Should have hash → creds edge
        has_hash_edge = any("hash" in e.label.lower() for e in graph.edges)
        self.assertTrue(has_hash_edge)


if __name__ == "__main__":
    unittest.main()