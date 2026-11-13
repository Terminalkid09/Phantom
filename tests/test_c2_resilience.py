"""A3: beacon resilience.

Coverage:
- the C++ loop resets exponential backoff once the C2 is reachable again
- the C2 keeps the same session record for a re-connecting beacon_id
- a re-check-in within the normal window does NOT re-queue auto-persist
- a session that was silent >60s is flagged as resumed (session_resumed_at)
- tasks queued during the outage are preserved and drained on re-entry
- results accumulated before the outage survive a re-check-in
"""
import os
import unittest
from datetime import datetime, timedelta

from phantom.core.c2_server import c2_state


def _reset():
    c2_state.beacons.clear()
    c2_state.tasks.clear()
    c2_state.results.clear()


class TestBeaconCppBackoffReset(unittest.TestCase):
    """Static checks on the beacon main loop (mirrors test_media_features)."""

    def setUp(self):
        with open("phantom/payloads/beacon/src/main.cpp", "r") as f:
            self.content = f.read()

    def test_backoff_restored_on_recovery(self):
        # Recovery must restore the operator-configured base sleep, not a
        # hardcoded 5000 (a custom `sleep 30000` must survive an outage).
        self.assertIn("cfg.sleep_ms != cfg.base_sleep_ms", self.content)
        self.assertIn("cfg.sleep_ms = cfg.base_sleep_ms;", self.content)

    def test_backoff_is_capped(self):
        self.assertIn("std::min(60000, cfg.sleep_ms * 2)", self.content)

    def test_jitter_computed(self):
        self.assertIn("get_sleep_ms()", self.content)

    def test_pending_results_retried_without_overwrite(self):
        self.assertIn("pending_results", self.content)
        self.assertIn("pending_results.emplace_back", self.content)


class TestServerSessionResume(unittest.TestCase):

    def setUp(self):
        _reset()

    def test_same_beacon_id_keeps_single_record(self):
        c2_state.update_beacon("b1", {"ip": "10.0.0.1", "os": "Linux"})
        c2_state.update_beacon("b1", {"ip": "10.0.0.1", "os": "Linux"})
        beacons = c2_state.get_beacons()
        self.assertEqual(len(beacons), 1)
        # auto-persist queued exactly once
        pending = c2_state.get_pending_tasks("b1")
        persists = [t for t in pending if t["command"].startswith("persist")]
        self.assertEqual(len(persists), 1)

    def test_recheckin_within_window_no_resume_flag(self):
        c2_state.update_beacon("b1", {"ip": "10.0.0.1", "os": "Linux"})
        c2_state.update_beacon("b1", {"ip": "10.0.0.1", "os": "Linux"})
        info = c2_state.get_beacons()["b1"]
        self.assertNotIn("session_resumed_at", info)
        self.assertIn("last_seen", info)

    def test_long_gap_flags_session_resumed(self):
        c2_state.update_beacon("b1", {"ip": "10.0.0.1", "os": "Linux"})
        # simulate an outage: backdate last_seen by 5 minutes
        c2_state.beacons["b1"]["last_seen"] = (
            datetime.now() - timedelta(minutes=5)).isoformat(timespec="seconds")
        c2_state.update_beacon("b1", {"ip": "10.0.0.1", "os": "Linux"})
        info = c2_state.get_beacons()["b1"]
        self.assertIn("session_resumed_at", info)

    def test_tasks_queued_during_outage_drained_on_rentry(self):
        c2_state.update_beacon("b1", {"ip": "10.0.0.1", "os": "Linux"})
        # drain the initial auto-persist
        c2_state.get_pending_tasks("b1")
        # operator queues commands while the beacon is offline
        c2_state.queue_task("b1", "keylog 10")
        c2_state.queue_task("b1", "screenshot")
        # beacon comes back: it must receive ALL queued tasks
        c2_state.update_beacon("b1", {"ip": "10.0.0.1", "os": "Linux"})
        pending = c2_state.get_pending_tasks("b1")
        commands = [t["command"] for t in pending]
        self.assertIn("keylog 10", commands)
        self.assertIn("screenshot", commands)

    def test_results_survive_recheckin(self):
        c2_state.update_beacon("b1", {"ip": "10.0.0.1", "os": "Linux"})
        c2_state.add_result("b1", "t-1", "PERSISTENCE_OK")
        c2_state.update_beacon("b1", {"ip": "10.0.0.1", "os": "Linux"})
        results = c2_state.get_results("b1")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["output"], "PERSISTENCE_OK")

    def test_reentry_does_not_requeue_persist(self):
        c2_state.update_beacon("b1", {"ip": "10.0.0.1", "os": "Linux"})
        c2_state.get_pending_tasks("b1")  # drained
        c2_state.beacons["b1"]["last_seen"] = (
            datetime.now() - timedelta(minutes=10)).isoformat(timespec="seconds")
        c2_state.update_beacon("b1", {"ip": "10.0.0.1", "os": "Linux"})
        pending = c2_state.get_pending_tasks("b1")
        self.assertFalse(any(t["command"].startswith("persist")
                             for t in pending))


if __name__ == "__main__":
    unittest.main()
