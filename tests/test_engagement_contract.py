"""Tests for the versioned engagement contract (phantom/core/engagement.py)
and for the session-bridge kind coverage invariant.

The engagement mirror used to be written with implicit shape and no version,
so data written by one build could be dropped by the next. These tests lock
the shape, the version stamp and the tolerant load, and assert that every
terminal fact of the network/enterprise goals is actually bridged into the
manual core (so a new goal cannot learn something the operator never sees).
"""
import os
import tempfile
import unittest

from phantom.core import engagement
from phantom.core.session import session


class _SessionState(unittest.TestCase):
    def setUp(self):
        self._saved = {k: getattr(session, k, None)
                       for k in engagement.SNAPSHOT_FIELDS}

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(session, k, v)


class TestSnapshotShape(_SessionState):
    def test_snapshot_is_versioned_and_complete(self):
        snap = engagement.snapshot()
        self.assertEqual(snap["version"], engagement.SNAPSHOT_VERSION)
        for field in engagement.SNAPSHOT_FIELDS:
            self.assertIn(field, snap)


class TestRestore(_SessionState):
    def test_roundtrip(self):
        session.target = "10.0.0.5"
        session.notes = ["n1"]
        session.history = ["scan 10.0.0.5"]
        snap = engagement.snapshot()
        session.target = ""
        session.notes = []
        session.history = []
        report = engagement.restore(snap)
        self.assertEqual(session.target, "10.0.0.5")
        self.assertEqual(session.notes, ["n1"])
        # other fields may be non-default from sibling tests; the fields we
        # care about must be among the applied ones
        self.assertTrue({"target", "notes", "history"}
                        <= set(report["applied"]))

    def test_v1_snapshot_without_version_still_loads(self):
        session.target = ""
        report = engagement.restore({"target": "10.0.0.9", "scope": []})
        self.assertEqual(session.target, "10.0.0.9")
        self.assertEqual(report["version"], engagement.SNAPSHOT_VERSION)

    def test_unknown_keys_are_ignored(self):
        session.target = ""
        engagement.restore({"target": "10.0.0.7", "future_key": 123})
        self.assertEqual(session.target, "10.0.0.7")
        self.assertFalse(hasattr(session, "future_key"))

    def test_unset_values_never_overwrite(self):
        session.target = "keep-me"
        engagement.restore({"target": ""})
        self.assertEqual(session.target, "keep-me")


class TestSaveLoad(_SessionState):
    def test_save_then_load_through_a_file(self):
        session.target = "10.0.0.8"
        d = tempfile.mkdtemp()
        path = os.path.join(d, "_auto.json")
        self.assertTrue(engagement.save(path))
        session.target = ""
        report = engagement.load(path)
        self.assertEqual(session.target, "10.0.0.8")
        self.assertIn("target", report["applied"])

    def test_load_missing_file_is_a_noop(self):
        self.assertEqual(engagement.load("/nonexistent/xyz.json"), {})


class TestBridgedKindCoverage(unittest.TestCase):
    # goals the manual core (map / suggest / exploit / payload / report) must
    # be able to consume after an auto-mode run
    NET_GOALS = ("footprint", "creds", "beacon", "deliver",
                 "complete_kill_chain", "post_exploit", "ad", "crack",
                 "lateral", "web", "environment", "mobile", "expand",
                 "evasion", "cloud", "cloud_lateral")

    def test_every_terminal_fact_of_core_goals_is_bridged(self):
        from phantom.automation.goals import GOAL_FACTS
        from phantom.core.session_bridge import BRIDGED_KINDS
        bridged = set(BRIDGED_KINDS)
        missing = {}
        for goal in self.NET_GOALS:
            gap = set(GOAL_FACTS[goal]) - bridged
            if gap:
                missing[goal] = sorted(gap)
        self.assertEqual(missing, {},
                         f"auto-mode facts the manual core never sees: {missing}")


if __name__ == "__main__":
    unittest.main()
