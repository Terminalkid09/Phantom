"""Auditable decision telemetry (ManusReview §7.3.5, AutoModeBrief §11.2).

Pins the typed decision trail (kinds, hash-chain verification, redaction),
the enabled() switch, and the two concrete producers: a driver crossing the
approval gate, and a target refused by scope.
"""
import os
import tempfile
import unittest
from unittest import mock

from phantom.automation import decision_audit
from phantom.utils.audit_log import AuditLog


class _AuditCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.log = AuditLog(path=os.path.join(self.tmp, "decisions.log"))
        self.audit = decision_audit.DecisionAudit(log=self.log)
        decision_audit.set_instance(self.audit)

    def tearDown(self):
        decision_audit.set_instance(None)


class TestDecisionAudit(_AuditCase):
    def test_records_typed_kinds(self):
        self.audit.capability_enabled("my_scanner", approver="op",
                                      policy="toolbelt.approved")
        self.audit.scope_decision("10.0.0.1", "deny", scope="10.0.0.0/24",
                                  reason="outside")
        self.audit.policy_decision("payload_bind", "deny",
                                   policy="aggressive_gate", reason="loud")
        self.audit.chosen("scan_tcp", driver="coverage", value=1.23)
        self.audit.rejected("nmap_os", reason="raw socket needed")
        kinds = [r["event"] for r in self.audit.tail(10)]
        self.assertIn("capability_enabled", kinds)
        self.assertIn("scope_decision", kinds)
        self.assertIn("policy_decision", kinds)
        self.assertIn("capability_chosen", kinds)
        self.assertIn("capability_rejected", kinds)

    def test_chain_verifies(self):
        for i in range(5):
            self.audit.chosen(f"cap{i}", driver="d")
        ok, n, bad = self.audit.verify()
        self.assertTrue(ok, bad)
        self.assertEqual(n, 5)

    def test_tampering_breaks_the_chain(self):
        self.audit.chosen("a")
        self.audit.chosen("b")
        with open(self.log.path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        lines[0] = lines[0].replace('"capability":"a"', '"capability":"zzz"')
        with open(self.log.path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        ok, _, _ = self.audit.verify()
        self.assertFalse(ok)

    def test_secret_in_reason_is_redacted(self):
        self.audit.policy_decision("ssh_login", "deny",
                                   reason="sshpass -p hunter2 ssh root@h")
        rec = self.audit.tail(1)[0]
        self.assertNotIn("hunter2", str(rec))

    def test_explain_is_readable(self):
        self.audit.scope_decision("h", "deny", reason="outside")
        lines = self.audit.explain()
        self.assertTrue(any("scope h" in ln for ln in lines))

    def test_enabled_switch(self):
        with mock.patch.dict(os.environ, {"PHANTOM_DECISION_AUDIT": "0"}):
            self.assertFalse(decision_audit.enabled())
            self.assertIsNone(self.audit.record("whatever"))
        with mock.patch.dict(os.environ, {"PHANTOM_DECISION_AUDIT": "1"}):
            self.assertTrue(decision_audit.enabled())


class TestProducers(_AuditCase):
    def test_driver_enablement_is_recorded(self):
        from phantom.automation.runtime import drivers
        manifest = {
            "id": "my_scanner", "tool": "my-scanner", "category": "recon",
            "command": "my-scanner --target {target}",
            "effects": ["service"], "requires": ["target"],
        }
        with mock.patch.object(drivers, "load_drivers",
                               return_value=[drivers.parse_driver(manifest)]), \
             mock.patch.object(drivers, "approved_ids",
                               return_value={"my_scanner"}):
            caps = drivers.load_driver_capabilities(approved_only=True)
        self.assertTrue(caps)
        events = [r["event"] for r in self.audit.tail(5)]
        self.assertIn("capability_enabled", events)

    def test_out_of_scope_refusal_is_recorded(self):
        from phantom.automation.swarm import _refuse_out_of_scope
        refused = _refuse_out_of_scope(["10.9.9.9"], ["10.0.0.0/24"])
        self.assertIn("10.9.9.9", refused)
        events = [r["event"] for r in self.audit.tail(5)]
        self.assertIn("scope_decision", events)
        rec = self.audit.tail(1)[0]
        self.assertEqual(rec.get("decision"), "deny")


if __name__ == "__main__":
    unittest.main()
