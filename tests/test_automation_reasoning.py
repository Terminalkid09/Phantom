"""Tests for the deterministic red-team inference engine (reasoning.py)."""
import unittest
from unittest.mock import Mock

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.planner import Planner
from phantom.automation.reasoning import ReasoningEngine


def _wm(services=None, target="10.0.0.5", target_type="ip"):
    wm = WorldModel(target=target, target_type=target_type)
    for port, product, version in (services or []):
        wm.add_finding(
            "service", f"tcp/{port}",
            {"port": str(port), "protocol": "tcp", "service": product.lower(),
             "product": product, "version": version or ""},
            confidence=0.9, source="nmap")
    return wm


class TestOSInference(unittest.TestCase):

    def test_windows_inferred_from_smb(self):
        wm = _wm(services=[(445, "Microsoft", "Windows 10")])
        eng = ReasoningEngine()
        eng.run(wm)
        osf = wm.find("os_inferred")
        self.assertTrue(osf, "no os_inferred finding")
        self.assertEqual(osf[0].value["os"], "windows")
        self.assertEqual(osf[0].source, "reasoning")

    def test_linux_inferred_from_ssh(self):
        wm = _wm(services=[(22, "OpenSSH", "OpenSSH 7.9p1")])
        ReasoningEngine().run(wm)
        self.assertEqual(wm.find("os_inferred")[0].value["os"], "linux")

    def test_no_os_inference_when_confirmed(self):
        wm = _wm(services=[(445, "Microsoft", "Windows 10")])
        wm.add_finding("os", "detected", {"name": "Windows 11"}, confidence=0.9)
        ReasoningEngine().run(wm)
        self.assertFalse(wm.find("os_inferred"))


class TestServiceRoles(unittest.TestCase):

    def test_roles_classified(self):
        wm = _wm(services=[(80, "Apache", ""), (445, "Microsoft", ""),
                           (3306, "MySQL", "")])
        ReasoningEngine().run(wm)
        roles = {f.key: f.value["role"] for f in wm.find("service_role")}
        self.assertEqual(roles.get("80"), "web")
        self.assertEqual(roles.get("445"), "windows-remote")
        self.assertEqual(roles.get("3306"), "database")


class TestADInference(unittest.TestCase):

    def test_dc_ports_imply_domain(self):
        wm = _wm(services=[(88, "Kerberos", ""), (389, "LDAP", ""),
                           (445, "Microsoft", "")])
        eng = ReasoningEngine(make_registry())
        eng.run(wm)
        self.assertTrue(wm.find("ad_hint"), "no ad_hint finding")
        # ad_hint is NOT the gating ad_domain kind
        self.assertFalse(wm.find("ad_domain"))
        cap_ids = {h.capability_id for h in wm.hypotheses}
        self.assertIn("ad_enum", cap_ids)
        self.assertIn("kerberoast", cap_ids)
        self.assertIn("as_rep_roast", cap_ids)


class TestCredentialReuse(unittest.TestCase):

    def test_valid_creds_propose_ssh_reuse(self):
        wm = _wm(services=[(22, "OpenSSH", "")])
        wm.add_finding("creds", "ssh:root",
                       {"username": "root", "password": "toor", "valid": True,
                        "service": "ssh"}, confidence=0.8)
        ReasoningEngine().run(wm)
        caps = {h.capability_id for h in wm.hypotheses}
        self.assertIn("ssh_login", caps)


class TestVulnClass(unittest.TestCase):

    def test_apache_249_path_traversal(self):
        wm = _wm(services=[(80, "Apache", "Apache httpd 2.4.49")])
        ReasoningEngine().run(wm)
        vc = wm.find("vuln_class", software="apache")
        self.assertTrue(vc, "no apache vuln_class")
        self.assertIn("path-traversal", vc[0].value["class"])
        self.assertIn("service_exploit",
                      {h.capability_id for h in wm.hypotheses})

    def test_smb_port_eternalblue_class(self):
        wm = _wm(services=[(445, "Microsoft", "")])
        ReasoningEngine().run(wm)
        self.assertTrue(wm.find("vuln_class", software="smb"))


class TestWebTech(unittest.TestCase):

    def test_wordpress_hunts_bug_classes(self):
        wm = _wm(services=[(80, "Apache", "")])
        wm.add_finding("web_app", "wordpress",
                       {"name": "wordpress", "version": ""}, confidence=0.8)
        ReasoningEngine().run(wm)
        self.assertIn("hunt_web", {h.capability_id for h in wm.hypotheses})


class TestAttackPath(unittest.TestCase):

    def test_graph_and_lateral_when_beacon_creds_peers(self):
        wm = _wm(services=[(445, "Microsoft", "")])
        wm.add_finding("creds", "smb:admin",
                       {"username": "admin", "password": "x", "valid": True,
                        "service": "smb"}, confidence=0.8)
        wm.add_finding("beacon", "established", {"target": "10.0.0.5"},
                       confidence=0.9)
        eng = ReasoningEngine()
        eng.run(wm, peers=["10.0.0.6"])
        ap = wm.find("attack_path")
        self.assertTrue(ap, "no attack_path graph")
        # target host + peer host + account = 3 nodes
        self.assertGreaterEqual(len(ap[0].value["nodes"]), 3)
        self.assertIn("lateral_pivot", {h.capability_id for h in wm.hypotheses})


class TestEngineBehavior(unittest.TestCase):

    def test_idempotent(self):
        wm = _wm(services=[(22, "OpenSSH", "OpenSSH 7.9p1"),
                           (80, "Apache", "Apache httpd 2.4.49")])
        eng = ReasoningEngine(make_registry())
        eng.run(wm)
        first = len(wm.hypotheses)
        eng.run(wm)
        self.assertEqual(len(wm.hypotheses), first, "hypotheses duplicated")

    def test_preferences_are_capability_ids(self):
        wm = _wm(services=[(445, "Microsoft", "")])
        eng = ReasoningEngine(make_registry())
        result = eng.run(wm)
        self.assertTrue(result.preferences)
        registry = make_registry()
        for cap_id in result.preferences:
            self.assertIsNotNone(registry.get(cap_id), f"unknown cap {cap_id}")

    def test_paranoid_drops_aggressive_hypotheses(self):
        wm = _wm(services=[(88, "Kerberos", ""), (389, "LDAP", ""),
                           (445, "Microsoft", "")])
        eng = ReasoningEngine(make_registry(), paranoid=True)
        eng.run(wm)
        cap_ids = {h.capability_id for h in wm.hypotheses}
        self.assertIn("ad_enum", cap_ids)          # active, kept
        self.assertNotIn("kerberoast", cap_ids)     # aggressive, dropped
        self.assertNotIn("as_rep_roast", cap_ids)   # aggressive, dropped


class TestCloudAndMobileRules(unittest.TestCase):

    def test_container_beacon_proposes_cloud_harvest(self):
        wm = _wm()
        wm.add_finding("beacon", "established", {"ok": True})
        wm.add_finding("environment", "box",
                       {"kinds": [{"kind": "container"}]})
        eng = ReasoningEngine()
        res = eng.run(wm)
        caps = {h.capability_id for h in res.hypotheses}
        self.assertIn("cloud_creds_harvest", caps)

    def test_k8s_box_proposes_escape(self):
        wm = _wm()
        wm.add_finding("beacon", "established", {"ok": True})
        wm.add_finding("environment", "box",
                       {"kinds": [{"kind": "kubernetes"}]})
        eng = ReasoningEngine()
        res = eng.run(wm)
        caps = {h.capability_id for h in res.hypotheses}
        self.assertIn("k8s_escape", caps)

    def test_cloud_creds_propose_storage_enum(self):
        wm = _wm()
        wm.add_finding("cloud_creds", "iam_aws",
                       {"provider": "aws", "via": "metadata"})
        eng = ReasoningEngine()
        res = eng.run(wm)
        caps = {h.capability_id for h in res.hypotheses}
        self.assertIn("cloud_s3_enum", caps)

    def test_mobile_surface_proposes_service_exploit(self):
        wm = _wm()
        wm.add_finding("mobile", "surface",
                       {"endpoints": ["/api/v2/mdm"]})
        eng = ReasoningEngine()
        res = eng.run(wm)
        caps = {h.capability_id for h in res.hypotheses}
        self.assertIn("service_exploit", caps)

    def test_no_cloud_hypotheses_without_signal(self):
        wm = _wm(services=[(22, "OpenSSH", "")])
        eng = ReasoningEngine()
        res = eng.run(wm)
        caps = {h.capability_id for h in res.hypotheses}
        self.assertNotIn("cloud_creds_harvest", caps)
        self.assertNotIn("k8s_escape", caps)


class TestAnomalyClassChaining(unittest.TestCase):
    """The reasoning engine must bridge the new anomaly bug classes into
    the kill chain: RCE primitives (cmdi/jndi/header_ssti) -> foothold,
    nosqli/exposure -> credential harvest."""

    def _hunt(self, wm, cls, confirmed=True):
        wm.add_finding(
            "hunt_anomaly", f"{cls}:80:probe",
            {"cls": cls, "confirmed": confirmed, "endpoint": "/x",
             "evidence": "evidence-string"},
            confidence=0.6, source="hunt_web")
        return ReasoningEngine().run(wm)

    def _keys(self, wm, kind):
        return [f.key for f in wm.all_findings() if f.kind == kind]

    def test_cmdi_bridges_to_rce_foothold(self):
        wm = _wm(services=[(80, "Apache", "")])
        res = self._hunt(wm, "cmdi")
        caps = {h.capability_id for h in res.hypotheses}
        self.assertIn("rce_foothold", caps)
        self.assertIn("cmdi:rce", self._keys(wm, "vuln_class"))
        self.assertIn("cmdi-rce",
                      [f.value.get("class") for f in wm.all_findings()
                       if f.kind == "vuln_class"])

    def test_jndi_bridges_to_rce_foothold(self):
        wm = _wm(services=[(80, "Apache", "")])
        res = self._hunt(wm, "jndi")
        caps = {h.capability_id for h in res.hypotheses}
        self.assertIn("rce_foothold", caps)

    def test_header_ssti_bridges_to_rce_foothold(self):
        wm = _wm(services=[(80, "Apache", "")])
        res = self._hunt(wm, "header_ssti")
        caps = {h.capability_id for h in res.hypotheses}
        self.assertIn("rce_foothold", caps)

    def test_unconfirmed_does_not_bridge(self):
        wm = _wm(services=[(80, "Apache", "")])
        res = self._hunt(wm, "cmdi", confirmed=False)
        caps = {h.capability_id for h in res.hypotheses}
        self.assertNotIn("rce_foothold", caps)

    def test_nosqli_bridges_to_web_creds(self):
        wm = _wm(services=[(80, "Apache", "")])
        res = self._hunt(wm, "nosqli")
        caps = {h.capability_id for h in res.hypotheses}
        self.assertIn("web_creds", caps)

    def test_exposure_bridges_to_web_creds_and_secrets(self):
        wm = _wm(services=[(80, "Apache", "")])
        res = self._hunt(wm, "exposure")
        caps = {h.capability_id for h in res.hypotheses}
        self.assertIn("web_creds", caps)
        self.assertIn("exposure:secrets", self._keys(wm, "vuln_class"))

    def test_foothold_always_proposes_beacon_injection(self):
        wm = _wm(services=[(80, "Apache", "")])
        wm.add_finding("rce_foothold", "web_upload", {"kind": "upload"})
        res = ReasoningEngine().run(wm)
        caps = {h.capability_id for h in res.hypotheses}
        self.assertIn("beacon_via_rce", caps)


class TestHypothesisResolution(unittest.TestCase):

    def _engine(self):
        return ReasoningEngine(make_registry())

    def test_confirms_when_effect_fact_present(self):
        wm = _wm(services=[(80, "Apache", "")])
        wm.add_finding("web_header", "server", {"server": "nginx"},
                       confidence=0.8)
        eng = self._engine()
        eng.run(wm)
        eng.resolve(wm)
        hp = [h for h in wm.hypotheses if h.capability_id == "http_probe"]
        self.assertTrue(hp, "no http_probe hypothesis")
        self.assertEqual(hp[0].status, "confirmed")

    def test_refutes_when_attempted_without_effect(self):
        wm = _wm(services=[(22, "OpenSSH", "OpenSSH 7.9p1")])
        eng = self._engine()
        eng.run(wm)
        wm.record_action("ssh_banner", {}, "nc -w 5 10.0.0.5 22", ok=True)
        eng.resolve(wm)
        sb = [h for h in wm.hypotheses if h.capability_id == "ssh_banner"]
        self.assertTrue(sb, "no ssh_banner hypothesis")
        self.assertEqual(sb[0].status, "refuted")

    def test_abandons_when_failed_without_attempt(self):
        wm = _wm(services=[(88, "Kerberos", ""), (389, "LDAP", ""),
                           (445, "Microsoft", "")])
        eng = self._engine()
        eng.run(wm)
        eng.resolve(wm, failed_cap_ids={"ad_enum"})
        ae = [h for h in wm.hypotheses if h.capability_id == "ad_enum"]
        self.assertTrue(ae, "no ad_enum hypothesis")
        self.assertEqual(ae[0].status, "abandoned")

    def test_reasoning_does_not_readd_resolved(self):
        wm = _wm(services=[(80, "Apache", "Apache httpd 2.4.49"),
                           (22, "OpenSSH", "OpenSSH 7.9p1")])
        eng = self._engine()
        eng.run(wm)
        first = len(wm.hypotheses)
        self.assertGreater(first, 0)
        for h in wm.hypotheses:
            h.status = "confirmed"  # close every hypothesis
        eng.run(wm)
        self.assertEqual(len(wm.hypotheses), first, "resolved hypotheses re-added")


class TestPlannerPreference(unittest.TestCase):

    def test_preference_reorders_source_pick(self):
        wm = _wm()
        planner = Planner(make_registry(),
                          StealthEngine(wm, StealthConfig()))
        plan = planner.plan(wm, goal="footprint", preference=["version_detect"])
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("version_detect", ids)
        self.assertNotIn("scan_tcp", ids)  # preferred over the default


class TestAgentIntegration(unittest.TestCase):

    def _runner(self):
        def runner(cmd, timeout=None):
            res = Mock()
            res.ok = True
            res.stdout = ""
            res.stderr = ""
            if "nmap" in cmd:
                res.stdout = ("22/tcp open ssh OpenSSH 7.9p1\n"
                              "80/tcp open http Apache httpd 2.4.49")
            elif "curl" in cmd:
                res.stdout = "Server: nginx/1.18.0\n<title>Login</title>"
            elif "nc -w" in cmd:
                res.stdout = "SSH-2.0-OpenSSH_7.9p1 Debian-10"
            return res
        return runner

    def test_run_emits_reason_and_records_inferences(self):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.runtime.stealth_runtime import (
            StealthRuntime, TimingGovernor)
        from phantom.automation.runtime.toolchain import ToolRegistry

        events = []
        agent = AutonomousAgent(
            target="10.0.0.5", target_type="ip", profile="enterprise",
            on_event=lambda k, d: events.append((k, d)),
            runtime=StealthRuntime(
                StealthEngine(WorldModel(target="10.0.0.5"), StealthConfig()),
                runner=self._runner(), cost_per_action=0.5,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0)),
            toolchain=ToolRegistry(installed={"nmap", "curl", "nc"}))
        result = agent.run(goal="footprint", max_iterations=3)
        kinds = [k for k, _ in events]
        self.assertIn("reason", kinds)
        self.assertGreaterEqual(result["inferences"], 1)
        self.assertGreaterEqual(result["hypotheses"], 1)

    def test_run_resolves_hypotheses_fact_based(self):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.runtime.stealth_runtime import (
            StealthRuntime, TimingGovernor)
        from phantom.automation.runtime.toolchain import ToolRegistry

        events = []
        agent = AutonomousAgent(
            target="10.0.0.5", target_type="ip", profile="enterprise",
            on_event=lambda k, d: events.append((k, d)),
            runtime=StealthRuntime(
                StealthEngine(WorldModel(target="10.0.0.5"), StealthConfig()),
                runner=self._runner(), cost_per_action=0.5,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0)),
            toolchain=ToolRegistry(installed={"nmap", "curl", "nc"}))
        result = agent.run(goal="footprint", max_iterations=3)
        self.assertGreaterEqual(result["hypotheses_confirmed"], 1)
        self.assertIn("hypothesis", [k for k, _ in events])
        # a confirmed hypothesis survives re-planning without being re-added
        self.assertEqual(
            result["hypotheses"],
            len([h for h in agent.wm.hypotheses if h.status == "confirmed"])
            + len([h for h in agent.wm.hypotheses if h.status == "pending"])
            + len([h for h in agent.wm.hypotheses if h.status == "refuted"])
            + len([h for h in agent.wm.hypotheses if h.status == "abandoned"]))


if __name__ == "__main__":
    unittest.main()
