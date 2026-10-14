"""P1: caught errors get a NAME, and the scope gate fails CLOSED.

The defect: `except Exception: pass` in central paths made four very
different situations indistinguishable from the outside — the target had
nothing, the tool was missing, the scope refused the move, or our own code
raised. The broker even failed OPEN on a broken scope check (`return True`),
turning an exception into an implicit authorization.
"""
import json
import socket
import unittest
from unittest.mock import Mock, patch

from phantom.utils import failure_taxonomy as ft


class TestClassification(unittest.TestCase):
    def test_the_vocabulary_is_the_audit_one(self):
        for token in ("unsupported", "tool_missing", "out_of_scope",
                      "network_timeout", "auth_failed", "parse_failed",
                      "target_negative", "internal_bug",
                      "operator_cancelled"):
            self.assertIn(token, ft.CATEGORIES, token)

    def test_only_unambiguous_types_are_mapped(self):
        cases = [
            (TimeoutError("slow"), "network_timeout"),
            (socket.timeout("slow"), "network_timeout"),
            (socket.gaierror("dns"), "network_timeout"),
            (ConnectionResetError("rst"), "network_timeout"),
            (PermissionError("denied"), "io_error"),
            (FileNotFoundError("gone"), "io_error"),
            (ModuleNotFoundError("nope"), "unsupported"),
            (KeyboardInterrupt(), "operator_cancelled"),
            (json.JSONDecodeError("x", "y", 0), "parse_failed"),
        ]
        for exc, expected in cases:
            self.assertEqual(ft.classify(exc), expected, type(exc).__name__)

    def test_an_ambiguous_type_is_a_confession_not_a_guess(self):
        # a bare ValueError could be anything; claiming "parse_failed" would
        # make the vocabulary decorative
        for exc in (ValueError("?"), KeyError("k"), TypeError("t"), None):
            self.assertEqual(ft.classify(exc), "internal_bug", repr(exc))

    def test_a_site_that_knows_better_says_so(self):
        self.assertEqual(ft.record("x.y", category="tool_missing"), "tool_missing")
        # an invented token is NOT accepted: it degrades to the classifier
        self.assertEqual(
            ft.record("x.y", ValueError("?"), category="made_up"),
            "internal_bug")

    def test_every_category_has_a_label(self):
        for token in ft.CATEGORIES:
            self.assertTrue(ft.category_label(token))


class TestRecord(unittest.TestCase):
    def setUp(self):
        ft.reset()

    def tearDown(self):
        ft.reset()

    def test_it_records_the_site_the_category_and_the_detail(self):
        ft.record("broker._scope_ok", ValueError("broken"),
                  detail="target=10.0.0.5")
        entries = ft.recent()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["where"], "broker._scope_ok")
        self.assertEqual(entries[0]["category"], "internal_bug")
        self.assertEqual(entries[0]["exception"], "ValueError")
        self.assertIn("10.0.0.5", entries[0]["detail"])

    def test_recent_is_a_snapshot_not_the_live_ring(self):
        ft.record("a", ValueError("x"))
        snapshot = ft.recent()
        snapshot.clear()
        self.assertEqual(len(ft.recent()), 1)

    def test_the_ring_is_bounded(self):
        for i in range(ft._RECENT_LIMIT + 25):
            ft.record("site", ValueError(str(i)))
        self.assertEqual(len(ft.recent()), ft._RECENT_LIMIT)
        # the NEWEST survive
        self.assertEqual(ft.recent()[-1]["detail"], "ValueError: 224")

    def test_summary_counts_by_category(self):
        ft.record("a", category="tool_missing")
        ft.record("b", category="tool_missing")
        ft.record("c", category="out_of_scope")
        s = ft.summary()
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["by_category"], {"out_of_scope": 1,
                                            "tool_missing": 2})

    def test_it_reaches_the_decision_audit(self):
        with patch("phantom.automation.decision_audit.record") as audit:
            ft.record("a", category="tool_missing")
        self.assertTrue(audit.called)
        self.assertEqual(audit.call_args.args[0], "failure")

    def test_a_broken_sink_cannot_make_recording_raise(self):
        with patch("phantom.automation.decision_audit.record",
                   side_effect=RuntimeError("audit dead")), \
                patch("phantom.utils.notifier.notifier.warn",
                      side_effect=RuntimeError("console dead")):
            token = ft.record("a", ValueError("x"))
        self.assertEqual(token, "internal_bug")

    def test_best_effort_is_recorded_but_not_alarming(self):
        with patch("phantom.utils.notifier.notifier.warn") as warn, \
                patch("phantom.utils.notifier.notifier.info") as info:
            ft.record("hint", ValueError("x"), best_effort=True)
        self.assertFalse(warn.called)
        self.assertTrue(info.called)


class _RaisingToolchain:
    def has(self, _tool):
        raise RuntimeError("toolchain dead")


class TestTheBrokerFailsClosedOnScope(unittest.TestCase):
    def _broker(self, scope):
        from phantom.automation.runtime.broker import ExecutionBroker
        return ExecutionBroker(scope_list=scope)

    def setUp(self):
        ft.reset()

    def tearDown(self):
        ft.reset()

    def test_an_empty_scope_list_still_warn_and_continues(self):
        self.assertTrue(self._broker([])._scope_ok("10.0.0.5"))
        self.assertEqual(ft.recent(), [])

    def test_a_broken_scope_check_REFUSES_the_target(self):
        broker = self._broker(["10.0.0.0/8"])
        with patch("phantom.core.scope.is_in_scope",
                   side_effect=RuntimeError("scope engine dead")):
            self.assertFalse(broker._scope_ok("10.1.2.3"))
        entries = ft.recent()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["where"], "broker._scope_ok")
        self.assertEqual(entries[0]["category"], "internal_bug")

    def test_a_working_check_is_unchanged(self):
        broker = self._broker(["10.0.0.0/8"])
        self.assertTrue(broker._scope_ok("10.1.2.3"))
        self.assertFalse(broker._scope_ok("192.168.1.1"))
        self.assertEqual(ft.recent(), [])

    def test_a_broken_availability_probe_stays_permissive_but_visible(self):
        from phantom.automation.runtime.broker import ExecutionBroker
        broker = ExecutionBroker(toolchain=_RaisingToolchain())
        driver = Mock(tool="nmap")
        self.assertTrue(broker._availability_ok(driver))
        self.assertEqual(ft.recent()[0]["where"], "broker._availability_ok")


class TestTheStreamKnowsFailures(unittest.TestCase):
    def test_the_failure_kind_is_registered(self):
        from phantom.core import stream_contract as sc
        self.assertIn("failure", sc.EVENTS)
        rendered = sc.render_event(
            "failure", {"category": "tool_missing", "where": "driver.run",
                        "detail": "nmap missing"})
        self.assertIsNotNone(rendered)
        self.assertIn("tool_missing", rendered.text)
        self.assertIn("driver.run", rendered.text)

    def test_a_degradation_carries_its_category(self):
        from phantom.core import stream_contract as sc
        self.assertIn("category", sc.EVENTS["degraded"].fields)


if __name__ == "__main__":
    unittest.main()
