"""Tests for the WorldModel and perception interpreters."""
import unittest

from phantom.automation.belief import WorldModel, IdentityGraph
from phantom.automation.perception import (
    parse_nmap_ports,
    parse_nmap_os,
    parse_http_banner,
    detect_cms,
    parse_smb_shares,
    parse_redis_info,
    parse_ssh_banner,
)


class TestWorldModel(unittest.TestCase):

    def test_add_and_get_finding(self):
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        wm.add_finding("service", "tcp/22", {"port": "22", "service": "ssh"}, confidence=0.9)
        f = wm.get("service", "tcp/22")
        self.assertIsNotNone(f)
        self.assertEqual(f.value["service"], "ssh")
        self.assertTrue(wm.trust("service", "tcp/22"))

    def test_has_and_find(self):
        wm = WorldModel()
        wm.add_finding("creds", "ssh:root", {"username": "root", "password": "root", "valid": True})
        wm.add_finding("creds", "ssh:admin", {"username": "admin", "password": "x", "valid": False})
        valid = wm.find("creds", valid=True)
        self.assertEqual(len(valid), 1)
        self.assertEqual(valid[0].key, "ssh:root")

    def test_opsec_ledger_audit_only(self):
        wm = WorldModel()
        self.assertTrue(wm.spend_opsec(6.0))
        self.assertTrue(wm.spend_opsec(5.0))  # never blocks: audit only
        self.assertEqual(wm.opsec_spent, 11.0)

    def test_hypothesis_flow(self):
        wm = WorldModel()
        h = wm.add_hypothesis("smb_share_enum", "smb open", cost=2.0, priority=0.8)
        self.assertEqual(h.status, "pending")
        self.assertEqual(len(wm.pending_hypotheses()), 1)

    def test_audit_trail(self):
        wm = WorldModel()
        wm.record_action("ssh_deploy", {"port": 22}, "sshpass ...", ok=True, opsec=1.5)
        wm.record_failure("redis_rce", "no writable dir")
        self.assertEqual(len(wm.actions_taken), 1)
        self.assertEqual(len(wm.failures), 1)
        self.assertIn("ssh_deploy", wm.to_json())


class TestIdentityGraph(unittest.TestCase):

    def test_link_and_neighbors(self):
        g = IdentityGraph()
        g.link("username", "bob", "email", "bob@corp.com")
        g.link("email", "bob@corp.com", "phone", "+15551234567")
        neighbors = g.neighbors("email", "bob@corp.com")
        vals = sorted(n.value for n in neighbors)
        self.assertEqual(vals, ["+15551234567", "bob"])

    def test_add_node_attrs(self):
        g = IdentityGraph()
        n = g.add_node("person", "Bob", real_name="Bob Smith", location="NY")
        self.assertEqual(n.attributes["real_name"], "Bob Smith")
        self.assertIs(g.get("person", "Bob"), n)

    def test_duplicate_node_updates(self):
        g = IdentityGraph()
        g.add_node("username", "bob", public=True)
        g.add_node("username", "Bob", private_note="x")
        self.assertEqual(g.get("username", "bob").attributes["private_note"], "x")


class TestPerception(unittest.TestCase):

    def test_parse_nmap_ports(self):
        out = """22/tcp open ssh OpenSSH 7.9p1
443/tcp open https
3306/tcp open mysql MySQL 5.7.30"""
        findings = parse_nmap_ports(out)
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0].get("key"), "tcp/22")
        self.assertEqual(findings[2]["value"]["product"], "MySQL")

    def test_parse_nmap_os(self):
        findings = parse_nmap_os("OS details: Linux 4.15 (Ubuntu 18.04)")
        self.assertEqual(len(findings), 1)
        self.assertIn("Linux", findings[0]["value"]["name"])

    def test_parse_ssh_banner(self):
        f = parse_ssh_banner("SSH-2.0-OpenSSH_7.9p1 Debian-10")
        self.assertIsNotNone(f)
        self.assertEqual(f["value"]["product"], "OpenSSH_7.9p1")

    def test_parse_http_banner(self):
        headers = """Server: nginx/1.18.0
X-Powered-By: PHP/7.4
Content-Type: text/html"""
        findings = parse_http_banner(headers)
        kinds = {f["key"] for f in findings}
        self.assertIn("server", kinds)
        self.assertIn("x-powered-by", kinds)

    def test_detect_cms(self):
        f = detect_cms('<html><link href="/wp-content/themes/x/style.css"></html>')
        self.assertIsNotNone(f)
        self.assertEqual(f["key"], "wordpress")
        self.assertIsNone(detect_cms("<html>nothing here</html>"))

    def test_parse_smb_shares(self):
        out = """Sharename       Type   Permissions  Comment
---------       ----   -----------  -------
IPC$            IPC    READ ONLY
wwwroot         Disk   READ WRITE   web files"""
        shares = parse_smb_shares(out)
        self.assertEqual(len(shares), 2)
        www = next(s for s in shares if s["key"] == "wwwroot")
        self.assertTrue(www["value"]["writable"])

    def test_parse_redis_info(self):
        out = """redis_version:5.0.7
role:master
protected mode: no"""
        findings = parse_redis_info(out)
        keys = {f["key"] for f in findings}
        self.assertIn("version", keys)
        self.assertIn("no_auth", keys)

    def test_parse_json_output(self):
        from phantom.automation.perception import parse_json_output
        findings = parse_json_output('[{"id": 1}, {"id": 2}]', "cve")
        self.assertEqual(len(findings), 2)


if __name__ == "__main__":
    unittest.main()
