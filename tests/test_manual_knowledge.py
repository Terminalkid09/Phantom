"""Tests for the manual-shell knowledge layer (shared WorldModel):
- typed writers + summary
- live reasoning hypotheses in suggest
- brute credential harvesting into the WM
"""

import unittest

from phantom.core.knowledge import (
    add_creds, add_service, add_vuln, add_web_app,
    knowledge_summary, reset_wm, session_wm)


class TestKnowledgeLayer(unittest.TestCase):

    def setUp(self):
        reset_wm(target="10.0.0.5")

    def test_typed_writers_and_summary(self):
        add_service("22", "ssh", product="OpenSSH", version="7.9p1")
        add_service("445", "microsoft-ds", version="10")
        add_creds("root", "toor", "ssh", valid=True)
        add_vuln("CVE-2024-1234", "test vuln", score=85)
        add_web_app("wordpress", "http://10.0.0.5/")
        self.assertEqual(knowledge_summary(),
                         {"service": 2, "creds": 1, "vuln": 1, "web_app": 1})

    def test_wm_target_set(self):
        self.assertEqual(session_wm().target, "10.0.0.5")

    def test_creds_written_with_service_key(self):
        add_creds("admin", "secret", "ssh")
        f = session_wm().get("creds", "ssh:admin")
        self.assertIsNotNone(f)
        self.assertTrue(f.value["valid"])

    def test_reset_wm_clears_findings(self):
        add_service("22", "ssh")
        self.assertGreater(len(session_wm().all_findings()), 0)
        reset_wm(target="10.0.0.6")
        self.assertEqual(len(session_wm().all_findings()), 0)
        self.assertEqual(session_wm().target, "10.0.0.6")


class TestLiveReasoning(unittest.TestCase):

    def test_reasoning_suggests_from_scan_findings(self):
        reset_wm(target="10.0.0.5")
        add_service("445", "microsoft-ds", version="10")
        from phantom.modules.suggest import reasoning_suggestion_group
        group = reasoning_suggestion_group()
        self.assertIn("SUGGESTED (reasoning)", group)
        text = " ".join(group["SUGGESTED (reasoning)"])
        # the reasoning engine must propose the SMB enumeration path
        self.assertIn("smb_enum", text)

    def test_reasoning_suggests_cred_reuse(self):
        reset_wm(target="10.0.0.5")
        add_service("22", "ssh", product="OpenSSH", version="7.9p1")
        add_creds("root", "toor", "ssh", valid=True)
        from phantom.modules.suggest import reasoning_suggestion_group
        group = reasoning_suggestion_group()
        text = " ".join(group.get("SUGGESTED (reasoning)", []))
        self.assertIn("ssh_login", text)

    def test_no_findings_no_suggestions(self):
        reset_wm(target="10.0.0.5")
        from phantom.modules.suggest import reasoning_suggestion_group
        self.assertEqual(reasoning_suggestion_group(), {})


class TestOsintIdentity(unittest.TestCase):

    def test_phone_osint_writes_identity(self):
        from phantom.core.session import session
        from phantom.modules.osint import OsintModule
        session.target = "+393331234567"   # Vodafone IT test range
        reset_wm(target="+393331234567")
        OsintModule().do_phone("")
        f = session_wm().get("identity", "phone")
        self.assertIsNotNone(f)
        self.assertIn("carrier", f.value)
        self.assertIn("region", f.value)

    def test_harvest_identity_writes_emails_and_subdomains(self):
        from phantom.core.session import session
        from phantom.modules.osint import OsintModule
        session.target = "corp.com"
        reset_wm(target="corp.com")
        session.results["osint"] = {
            "dns_intel": {"emails": ["admin@corp.com"]},
            "crt_sh_subdomains": ["mail.corp.com"],
            "social_profiles": ["https://x.com/corpuser"],
        }
        OsintModule()._harvest_identity()
        self.assertIsNotNone(session_wm().get("identity", "email:admin@corp.com"))
        self.assertIsNotNone(session_wm().get("subdomain", "mail.corp.com"))
        self.assertIsNotNone(session_wm().get("social_profile",
                                              "https://x.com/corpuser"))


class TestWebModule(unittest.TestCase):

    def test_analyze_detects_cms_in_wm(self):
        from phantom.core.session import session
        from phantom.modules.web import WebModule
        session.target = "corp.com"
        reset_wm(target="corp.com")
        WebModule()._analyze_web_results({
            "whatweb": "WordPress 6.4 in use",
        })
        self.assertIsNotNone(session_wm().get("web_app", "wordpress"))


class TestStepAwareRun(unittest.TestCase):

    def test_required_facts(self):
        from phantom.core.shell import PhantomShell
        reset_wm(target="10.0.0.5")
        sh = PhantomShell()
        self.assertEqual(sh._required_fact("scan"), "")       # producer
        self.assertEqual(sh._required_fact("exploit"), "service")
        add_service("22", "ssh")
        self.assertEqual(sh._required_fact("exploit"), "")    # satisfied now


class TestSessionWmRoundTrip(unittest.TestCase):

    def test_save_load_restores_wm(self):
        from phantom.core.session import Session
        reset_wm(target="10.0.0.9")
        add_service("443", "https", product="nginx", version="1.24")
        add_creds("admin", "toor", "https")
        s = Session(target="10.0.0.9")
        import tempfile, os
        from phantom.utils.paths import sessions_dir
        tmp = tempfile.mkdtemp()
        name = "wm_roundtrip_test"
        s.save(name)
        try:
            reset_wm(target="")
            s2 = Session()
            s2.load(name)
            wm = session_wm()
            self.assertEqual(wm.target, "10.0.0.9")
            self.assertIsNotNone(wm.get("service", "tcp/443"))
            self.assertIsNotNone(wm.get("creds", "https:admin"))
        finally:
            p = os.path.join(sessions_dir(), f"{name}.json")
            if os.path.exists(p):
                os.remove(p)


class TestBruteHarvest(unittest.TestCase):

    def test_harvest_creds_parses_hydra_output(self):
        from phantom.modules.brute import BruteModule
        reset_wm(target="10.0.0.5")
        results = {
            "HYDRA": "[22][ssh] host: 10.0.0.5   login: root   password: toor\n"
                     "[445][smb] host: 10.0.0.5   login: admin   password: P@ss\n"}
        BruteModule()._harvest_creds(results)
        self.assertIsNotNone(session_wm().get("creds", "ssh:root"))
        self.assertIsNotNone(session_wm().get("creds", "smb:admin"))

    def test_harvest_ignores_non_success_lines(self):
        from phantom.modules.brute import BruteModule
        reset_wm(target="10.0.0.5")
        results = {"HYDRA": "0 valid password found\n[ERROR] target busy\n"}
        BruteModule()._harvest_creds(results)
        self.assertEqual(len(session_wm().find("creds")), 0)


if __name__ == "__main__":
    unittest.main()
