"""Sub-agent coordination tests: the campaign ShareContext now pools
high-value findings (not just creds) and a move ledger prevents two
workers from re-running the same single-shot probe on one entity."""
import unittest

from phantom.automation.agent import ShareContext


class TestShareContextFindings(unittest.TestCase):
    def test_publish_shared_kind(self):
        s = ShareContext(peers=["10.0.0.5", "10.0.0.9"])
        s.publish_finding("victim_ip", "1.2.3.4", {"ip": "1.2.3.4"}, "t-user")
        self.assertEqual(s.shared_finding("victim_ip"),
                         ({"ip": "1.2.3.4"}, "t-user"))

    def test_non_shared_kind_not_broadcast(self):
        s = ShareContext()
        s.publish_finding("service", "tcp/22", {"port": "22"}, "t1")
        self.assertIsNone(s.shared_finding("service"))

    def test_shared_findings_lists_all(self):
        s = ShareContext()
        s.publish_finding("ad_domain", "corp.local", {"domain": "corp.local"}, "t1")
        s.publish_finding("ad_domain", "corp2.local", {"domain": "corp2.local"}, "t2")
        self.assertEqual(len(s.shared_findings("ad_domain")), 2)

    def test_creds_still_work(self):
        s = ShareContext()
        s.add_creds("ssh", "root", "toor", "t1")
        self.assertEqual(s.find("ssh"), ("root", "toor"))
        self.assertEqual(s.find(None), ("root", "toor"))


class TestShareContextLedger(unittest.TestCase):
    def test_mark_and_was_tried(self):
        s = ShareContext()
        self.assertFalse(s.was_tried("10.0.0.9", "ssh_banner"))
        s.mark_tried("10.0.0.9", "ssh_banner")
        self.assertTrue(s.was_tried("10.0.0.9", "ssh_banner"))

    def test_entity_scoped(self):
        s = ShareContext()
        s.mark_tried("10.0.0.9", "scan_tcp")
        self.assertFalse(s.was_tried("10.0.0.5", "scan_tcp"))
        self.assertFalse(s.was_tried("10.0.0.9", "http_probe"))

    def test_tried_count(self):
        s = ShareContext()
        s.mark_tried("a", "x")
        s.mark_tried("a", "x")  # idempotent set
        s.mark_tried("b", "y")
        self.assertEqual(s.tried_count(), 2)


class TestAbsorbSharedInAgent(unittest.TestCase):
    def test_agent_absorbs_peer_finding(self):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.belief import WorldModel

        share = ShareContext(peers=["target-b"])
        # peer on another target published a victim_ip
        share.publish_finding("victim_ip", "203.0.113.7",
                              {"ip": "203.0.113.7"}, "target-b")
        agent = AutonomousAgent(
            target="target-a", profile="enterprise", share=share)
        agent._absorb_shared()
        # the peer finding landed in this agent's world model as 'peer'
        self.assertTrue(agent.wm.has_any("victim_ip"))
        f = agent.wm.find("victim_ip")[0]
        self.assertEqual(f.value.get("ip"), "203.0.113.7")
        self.assertEqual(f.source, "peer")

    def test_agent_does_not_overwrite_local_victim_ip(self):
        from phantom.automation.agent import AutonomousAgent

        share = ShareContext(peers=["target-b"])
        share.publish_finding("victim_ip", "203.0.113.7",
                              {"ip": "203.0.113.7"}, "target-b")
        agent = AutonomousAgent(
            target="target-a", profile="enterprise", share=share)
        # local validated IP first
        agent.wm.add_finding("victim_ip", "local", {"ip": "198.51.100.1"},
                             confidence=0.95, source="grabber")
        agent._absorb_shared()
        self.assertEqual(agent.wm.find("victim_ip")[0].value["ip"],
                         "198.51.100.1")

    def test_agent_skips_own_broadcast(self):
        from phantom.automation.agent import AutonomousAgent

        share = ShareContext(peers=["target-a"])
        share.publish_finding("os", "linux", {"os": "linux"}, "target-a")
        agent = AutonomousAgent(
            target="target-a", profile="enterprise", share=share)
        agent._absorb_shared()
        # own broadcast: nothing imported (src_target == target)
        self.assertFalse(agent.wm.has_any("os"))


if __name__ == "__main__":
    unittest.main()