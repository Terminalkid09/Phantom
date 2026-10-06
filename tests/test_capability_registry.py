"""Capability trust state machine + provenance (AutoModeBrief §5–§6)."""
import os
import tempfile
import unittest

from phantom.automation.runtime.capability_registry import (
    STATES,
    CapabilityRecord,
    CapabilityRegistry,
)


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        self.now += 1.0
        return self.now


def _rec(cap="scanner", sha="abc", state="discovered"):
    return CapabilityRecord(capability=cap, tool=cap, state=state, sha256=sha,
                            source="operator-local")


class TestStateMachine(unittest.TestCase):
    def setUp(self):
        self.reg = CapabilityRegistry(path=os.devnull, clock=_Clock())

    def test_new_capability_is_discovered_not_enabled(self):
        r = self.reg.discover(_rec())
        self.assertEqual(r.state, "discovered")
        self.assertFalse(r.enabled)
        self.assertEqual(self.reg.enabled_ids(), set())

    def test_cannot_jump_straight_to_approved(self):
        self.reg.discover(_rec())
        self.assertFalse(self.reg.transition("scanner", "approved"))
        self.assertFalse(self.reg.transition("scanner", "enabled"))

    def test_approve_walks_review_states(self):
        self.reg.discover(_rec())
        self.assertTrue(self.reg.approve("scanner", actor="op"))
        row = self.reg.of("scanner")
        self.assertEqual(row.state, "approved")
        self.assertEqual(row.approved_by, "op")
        self.assertTrue(row.approved)
        self.assertEqual(row.status_history,
                         ["discovered", "candidate", "reviewed", "approved"])

    def test_enable_then_executed_validated(self):
        self.reg.discover(_rec())
        self.assertTrue(self.reg.enable("scanner"))
        self.assertIn("scanner", self.reg.enabled_ids())
        self.assertTrue(self.reg.transition("scanner", "executed"))
        self.assertTrue(self.reg.transition("scanner", "validated"))
        self.assertFalse(self.reg.transition("scanner", "executed"))


class TestIntegrity(unittest.TestCase):
    def setUp(self):
        self.reg = CapabilityRegistry(path=os.devnull, clock=_Clock())
        self.reg.discover(_rec(sha="good"))
        self.reg.enable("scanner")

    def test_matching_hash_keeps_approval(self):
        self.assertTrue(self.reg.verify_integrity("scanner", "good"))
        self.assertTrue(self.reg.of("scanner").enabled)

    def test_changed_binary_demotes_and_clears_approval(self):
        self.assertFalse(self.reg.verify_integrity("scanner", "tampered"))
        row = self.reg.of("scanner")
        self.assertEqual(row.state, "discovered")
        self.assertFalse(row.enabled)
        self.assertEqual(row.approved_by, "")
        self.assertNotIn("scanner", self.reg.enabled_ids())

    def test_re_discovery_with_changed_hash_demotes(self):
        self.reg.discover(_rec(sha="newhash"))
        self.assertEqual(self.reg.of("scanner").state, "discovered")
        self.assertFalse(self.reg.of("scanner").enabled)


class TestPersistence(unittest.TestCase):
    def test_round_trip(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "reg.json")
        reg = CapabilityRegistry(path=path, clock=_Clock())
        reg.discover(_rec(sha="h1"))
        reg.enable("scanner")
        self.assertTrue(reg.save())
        revived = CapabilityRegistry(path=path)
        revived.load()
        self.assertTrue(revived.of("scanner").enabled)
        self.assertIn("scanner", revived.enabled_ids())

    def test_broken_store_is_empty(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "reg.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        reg = CapabilityRegistry(path=path)
        reg.load()
        self.assertEqual(reg.all(), [])

    def test_states_tuple_is_ordered(self):
        self.assertEqual(STATES[0], "discovered")
        self.assertEqual(STATES[-1], "validated")


if __name__ == "__main__":
    unittest.main()
