"""Tests for the dual reporting engine (raw audit + client report)."""
import os
import tempfile
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthEngine, StealthConfig
from phantom.automation.agent import AutonomousAgent
from phantom.automation.reporting import (
    RawReport,
    ClientReport,
    ClientFinding,
    CampaignReport,
    ReportWriter,
)


def _agent_with_findings(beacon=False, creds=False, services=True, post=False):
    agent = AutonomousAgent(
        target="10.0.0.5", profile="enterprise",
        registry=make_registry())
    agent.wm = WorldModel(target="10.0.0.5")
    if services:
        agent.wm.add_finding("service", "tcp/22",
                             {"port": "22", "service": "ssh", "version": "OpenSSH 7.9p1"},
                             confidence=0.9, source="scan_tcp")
    if creds:
        agent.wm.add_finding("creds", "ssh:root",
                             {"username": "root", "password": "toor",
                              "valid": True, "service": "ssh"},
                             confidence=0.8, source="offline_brute_ssh")
    if beacon:
        agent.wm.add_finding("beacon", "established",
                             {"port": 4444}, confidence=0.95,
                             source="reverse_callback")
    if post:
        agent.wm.add_finding("persistence", "systemd", {"method": "systemd"},
                             confidence=0.9, source="persistence_install")
        agent.wm.add_finding("system_privilege", "escalated", {"identity": "root"},
                             confidence=0.9, source="privesc_system")
        agent.wm.add_finding("injection", "systemd", {"target_process": "systemd"},
                             confidence=0.9, source="inject_beacon")
    agent.wm.record_action("scan_tcp", {}, "nmap -Pn -sT 10.0.0.5",
                           ok=True, opsec=2.0)
    agent.wm.spend_opsec(2.0)
    agent.goal = "complete_kill_chain"
    return agent


class TestRawReport(unittest.TestCase):

    def test_from_agent_captures_trail(self):
        agent = _agent_with_findings(beacon=True, creds=True)
        raw = RawReport.from_agent(agent)
        self.assertEqual(raw.target, "10.0.0.5")
        self.assertGreaterEqual(len(raw.findings), 3)
        self.assertEqual(len(raw.actions), 1)
        self.assertGreaterEqual(len(raw.campaign_trail), 0)

    def test_to_dict_roundtrip(self):
        agent = _agent_with_findings()
        raw = RawReport.from_agent(agent)
        d = raw.to_dict()
        self.assertEqual(d["report_type"], "raw")
        self.assertIn("findings", d)
        self.assertIn("campaign_trail", d)
        self.assertEqual(d["opsec_spent"], 2.0)

    def test_to_json_is_valid(self):
        agent = _agent_with_findings()
        raw = RawReport.from_agent(agent)
        import json
        parsed = json.loads(raw.to_json())
        self.assertEqual(parsed["target"], "10.0.0.5")


class TestClientReport(unittest.TestCase):

    def test_beacon_is_critical(self):
        agent = _agent_with_findings(beacon=True)
        report = ClientReport.from_agent(agent)
        sevs = [f.severity for f in report.findings]
        self.assertIn("critical", sevs)
        self.assertIn("beacon", report.executive_summary)

    def test_creds_never_leak_to_client_report(self):
        agent = _agent_with_findings(creds=True, services=False)
        report = ClientReport.from_agent(agent)
        md = report.to_markdown()
        self.assertNotIn("toor", md)
        self.assertNotIn("root", md)  # no username, no password
        self.assertNotIn("Valid credentials", md)
        # the count is still visible to the client (impact, not secrets)
        self.assertIn("1 credential sets", report.executive_summary)

    def test_raw_report_keeps_credentials_for_operators(self):
        agent = _agent_with_findings(creds=True, services=False)
        raw = RawReport.from_agent(agent)
        values = [f.value for f in raw.findings if f.kind == "creds"]
        self.assertEqual(values[0]["username"], "root")
        self.assertEqual(values[0]["password"], "toor")

    def test_post_exploit_impact_in_client_report(self):
        agent = _agent_with_findings(beacon=True, post=True, services=False)
        report = ClientReport.from_agent(agent)
        titles = [f.title for f in report.findings]
        self.assertTrue(any("Persistence" in t for t in titles))
        self.assertTrue(any("root" in t for t in titles))
        self.assertTrue(any("injected" in t for t in titles))
        sevs = [f.severity for f in report.findings]
        self.assertTrue(all(s == "critical" for s in sevs))
        self.assertIn("root", report.executive_summary)

    def test_services_info_findings(self):
        agent = _agent_with_findings(services=True)
        report = ClientReport.from_agent(agent)
        info = [f for f in report.findings if f.severity == "info"]
        self.assertEqual(len(info), 1)
        self.assertIn("ssh", info[0].title)

    def test_hardening_recommendations(self):
        agent = _agent_with_findings()
        report = ClientReport.from_agent(agent)
        self.assertGreater(len(report.to_dict()["recommended_hardening"]), 0)

    def test_markdown_structure(self):
        agent = _agent_with_findings(beacon=True, creds=True)
        report = ClientReport.from_agent(agent)
        md = report.to_markdown()
        self.assertIn("# Phantom Assessment", md)
        self.assertIn("## Executive Summary", md)
        self.assertIn("## Findings", md)
        self.assertIn("[CRITICAL]", md)
        self.assertIn("## Recommended Hardening", md)


class TestCampaignReport(unittest.TestCase):

    def _campaign(self):
        return {
            "targets": ["10.0.0.5", "10.0.0.6"],
            "goal": "complete_kill_chain",
            "results": {
                "10.0.0.5": {"beacon_established": True,
                             "persistence_installed": True,
                             "system_privilege": True,
                             "services_enumerated": 2,
                             "creds_found": 1},
                "10.0.0.6": {"beacon_established": False,
                             "persistence_installed": False,
                             "system_privilege": False,
                             "services_enumerated": 1,
                             "creds_found": 0},
            },
            "beacons": 1, "persistent": 1, "compromised_creds": 1,
            "services": 3, "failures": 0,
        }

    def test_aggregates_and_per_target(self):
        report = CampaignReport(self._campaign())
        d = report.to_dict()
        self.assertEqual(d["aggregates"]["beacons"], 1)
        self.assertEqual(len(d["per_target"]), 2)
        self.assertEqual(d["per_target"][0]["beacon"], True)
        self.assertEqual(d["per_target"][1]["beacon"], False)

    def test_markdown_table_per_target(self):
        report = CampaignReport(self._campaign())
        md = report.to_markdown()
        self.assertIn("# Phantom Campaign Assessment", md)
        self.assertIn("| 10.0.0.5 |", md)
        self.assertIn("| 10.0.0.6 |", md)
        self.assertIn("1/2 targets compromised", md)


class TestC2Evidence(unittest.TestCase):
    """A6: C2 evidence side-by-side with the agent findings."""

    def setUp(self):
        from phantom.core.c2_server import c2_state
        c2_state.beacons.clear()
        c2_state.tasks.clear()
        c2_state.results.clear()

    def _agent_with_session(self, tasks=()):
        from phantom.automation.agent import AutonomousAgent, _BeaconSession
        from phantom.core.c2_server import c2_state
        agent = AutonomousAgent(target="10.0.0.5", profile="enterprise",
                                registry=make_registry())
        agent.wm = WorldModel(target="10.0.0.5")
        agent.wm.add_finding("beacon", "established",
                             {"payload": "true"}, confidence=0.95,
                             source="beacon_deploy")
        agent._session = _BeaconSession("beacon-ev1")
        c2_state.update_beacon("beacon-ev1",
                               {"ip": "10.0.0.5", "os": "Linux 5.15",
                                "hostname": "victim01", "user": "root"})
        for cmd in tasks:
            c2_state.add_result("beacon-ev1", f"t-{cmd}", f"{cmd}: OK")
        return agent

    def test_raw_report_keeps_outputs(self):
        agent = self._agent_with_session(tasks=("persist systemd", "screenshot"))
        raw = RawReport.from_agent(agent)
        self.assertEqual(raw.c2_evidence[0]["beacon_id"], "beacon-ev1")
        self.assertEqual(raw.c2_evidence[0]["tasks_executed"], 2)
        outputs = [e for e in raw.c2_evidence if "output_tail" in e]
        self.assertEqual(len(outputs), 2)
        self.assertEqual(outputs[0]["output_tail"], "persist systemd: OK")

    def test_client_report_sanitizes_c2_evidence(self):
        agent = self._agent_with_session(tasks=("persist systemd",))
        report = ClientReport.from_agent(agent)
        self.assertEqual(len(report.c2_evidence), 2)  # session row + task row
        session = report.c2_evidence[0]
        self.assertEqual(session["beacon_id"], "beacon-ev1")
        self.assertEqual(session["os"], "Linux 5.15")
        self.assertEqual(session["tasks_executed"], 1)
        task_row = report.c2_evidence[1]
        self.assertIn("task_id", task_row)
        self.assertNotIn("output_tail", task_row)  # no secrets to the client

    def test_client_markdown_has_c2_section(self):
        agent = self._agent_with_session(tasks=("persist systemd",))
        report = ClientReport.from_agent(agent)
        md = report.to_markdown()
        self.assertIn("## C2 Evidence (sanitized)", md)
        self.assertIn("beacon-ev1", md)
        self.assertIn("Executed tasks:", md)
        # outputs must NOT leak into the client markdown
        self.assertNotIn("persist systemd: OK", md)

    def test_client_markdown_no_section_without_session(self):
        agent = _agent_with_findings(beacon=True)
        report = ClientReport.from_agent(agent)
        md = report.to_markdown()
        self.assertNotIn("C2 Evidence", md)

    def test_client_dict_includes_c2_evidence(self):
        agent = self._agent_with_session(tasks=("whoami",))
        d = ClientReport.from_agent(agent).to_dict()
        self.assertIn("c2_evidence", d)
        self.assertGreaterEqual(len(d["c2_evidence"]), 2)


class TestReasoningReport(unittest.TestCase):
    """The client report carries the reasoning trail + inferred context."""

    def _agent_with_reasoning(self):
        agent = _agent_with_findings(creds=True, services=False)
        agent.wm.add_hypothesis("ssh_login",
                                "credentials available: test reuse over SSH",
                                cost=1.2, priority=0.85)
        agent.wm.add_hypothesis("ad_enum", "AD domain inferred from DC ports",
                                cost=2.0, priority=0.8)
        agent.wm.hypotheses[0].status = "confirmed"
        agent.wm.add_finding("os_inferred", "detected", {"os": "linux"},
                             confidence=0.6, source="reasoning")
        agent.wm.add_finding("ad_hint", "domain", {"domain": "", "inferred": True},
                             confidence=0.7, source="reasoning")
        agent.wm.add_finding(
            "vuln_class", "apache:path-traversal-rce",
            {"class": "path-traversal-rce", "detail": "Apache 2.4.49",
             "priority": 0.95}, confidence=0.55, source="reasoning")
        return agent

    def test_client_report_includes_reasoning_trail(self):
        report = ClientReport.from_agent(self._agent_with_reasoning())
        self.assertEqual(len(report.reasoning), 2)
        statuses = {h["capability"]: h["status"] for h in report.reasoning}
        self.assertEqual(statuses["ssh_login"], "confirmed")
        self.assertEqual(statuses["ad_enum"], "pending")
        md = report.to_markdown()
        self.assertIn("## Reasoning & Hypotheses", md)
        self.assertIn("[CONFIRMED]", md)

    def test_client_report_includes_inferred_context(self):
        report = ClientReport.from_agent(self._agent_with_reasoning())
        titles = [f.title for f in report.findings]
        self.assertTrue(any("Inferred target OS" in t for t in titles))
        self.assertTrue(any("Active Directory" in t for t in titles))
        vc = [f for f in report.findings if "path-traversal-rce" in f.title]
        self.assertEqual(len(vc), 1)
        self.assertEqual(vc[0].severity, "high")

    def test_reasoning_in_to_dict(self):
        report = ClientReport.from_agent(self._agent_with_reasoning())
        d = report.to_dict()
        self.assertIn("reasoning", d)
        self.assertEqual(len(d["reasoning"]), 2)

    def test_reasoning_never_leaks_secrets(self):
        report = ClientReport.from_agent(self._agent_with_reasoning())
        md = report.to_markdown()
        self.assertNotIn("toor", md)
        self.assertNotIn("root", md)

    def test_client_report_has_methodology_skeleton(self):
        report = ClientReport.from_agent(self._agent_with_reasoning())
        self.assertTrue(report.methodology, "methodology skeleton missing")
        self.assertIn("Reconnaissance", report.methodology[0])
        self.assertIn("## Scope & Methodology", report.to_markdown())
        self.assertIn("methodology", report.to_dict())

    def test_client_report_attack_path_summary_no_secrets(self):
        agent = _agent_with_findings(services=False)
        agent.wm.add_finding(
            "attack_path", "graph",
            {"nodes": [{"type": "host", "value": "10.0.0.5"},
                        {"type": "account", "value": "root"},
                        {"type": "domain", "value": "corp"}],
             "edges": []}, confidence=0.6, source="reasoning")
        report = ClientReport.from_agent(agent)
        self.assertEqual(report.attack_path,
                         {"hosts": 1, "accounts": 1, "domains": 1})
        md = report.to_markdown()
        self.assertIn("## Attack Path (summary)", md)
        self.assertNotIn("root", md)  # account names never leak to the client

    def test_raw_report_markdown_is_full_detail(self):
        agent = _agent_with_findings(creds=True, beacon=True)
        raw = RawReport.from_agent(agent)
        md = raw.to_markdown()
        self.assertIn("# Phantom Raw Report", md)
        self.assertIn("## Summary", md)
        self.assertIn("## Findings", md)
        self.assertIn("## Actions", md)
        self.assertIn("toor", md)  # operator report keeps credentials

    def test_client_report_includes_mitre_and_risk(self):
        agent = _agent_with_findings(services=False)
        agent.wm.add_finding(
            "attack_technique", "T1021.004",
            {"id": "T1021.004", "name": "Remote Services: SSH",
             "tactic": "Lateral Movement", "phase": "lateral_movement"},
            confidence=0.7, source="attack_mapping")
        agent.wm.add_finding(
            "target_risk", "overall",
            {"score": 85.0, "service_count": 1, "ad": False},
            confidence=0.7, source="risk_engine")
        report = ClientReport.from_agent(agent)
        self.assertEqual(len(report.mitre), 1)
        self.assertEqual(report.target_risk, 85.0)
        md = report.to_markdown()
        self.assertIn("## MITRE ATT&CK Mapping", md)
        self.assertIn("T1021.004", md)
        d = report.to_dict()
        self.assertIn("mitre", d)
        self.assertEqual(d["target_risk"], 85.0)
        self.assertIn("85.0/100", report.executive_summary)


class TestReportWriter(unittest.TestCase):

    def test_writes_both_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = _agent_with_findings(beacon=True, creds=True)
            raw = RawReport.from_agent(agent)
            client = ClientReport.from_agent(agent)
            paths = ReportWriter(tmp).write(raw, client)
            self.assertTrue(os.path.exists(paths["raw"]))
            self.assertTrue(os.path.exists(paths["client"]))
            with open(paths["raw"], encoding="utf-8") as f:
                content = f.read()
            self.assertIn("raw", content)
            with open(paths["client"], encoding="utf-8") as f:
                self.assertIn("# Phantom Assessment", f.read())

    def test_writes_campaign_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            campaign = {
                "targets": ["10.0.0.5"], "goal": "complete_kill_chain",
                "results": {"10.0.0.5": {"beacon_established": True,
                                         "persistence_installed": False,
                                         "system_privilege": False,
                                         "services_enumerated": 1,
                                         "creds_found": 0}},
                "beacons": 1, "persistent": 0, "compromised_creds": 0,
                "services": 1, "failures": 0,
            }
            paths = ReportWriter(tmp).write_campaign(CampaignReport(campaign))
            self.assertTrue(os.path.exists(paths["campaign_json"]))
            self.assertTrue(os.path.exists(paths["campaign_md"]))
            with open(paths["campaign_md"], encoding="utf-8") as f:
                self.assertIn("Campaign Assessment", f.read())


if __name__ == "__main__":
    unittest.main()
