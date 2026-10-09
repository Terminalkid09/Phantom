"""P2: the AutoMode → C2 handoff must be a RECORD, not a thing the UI guesses.

AutoMode establishes beacons. The operator then has to move them into the C2
by hand, and until now the UI gave them nothing to do that: the event stream
flattens every event into a log line and drops the event KIND, so the panel
could only diff the whole beacon list and guess whether a beacon belonged to
this run or was already sitting there. That guess is wrong exactly when it
matters — a pre-existing beacon makes a finished run look like it delivered
something.

These pin the contract: the job records the handoff where the knowledge is
(the callback), the stream serves it, and the Electron store keeps ONE record
per beacon with an explicit accept/dismiss decision.
"""
import json
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SERVER = (_ROOT / "phantom" / "api" / "server.py").read_text(encoding="utf-8")
_STORE = (_ROOT / "electron" / "src" / "store" / "index.ts").read_text(
    encoding="utf-8")
_PANEL = (_ROOT / "electron" / "src" / "components" /
          "AutoModePanel.tsx").read_text(encoding="utf-8")


class TestJobRecordsTheHandoff(unittest.TestCase):
    def test_the_job_has_a_handoff_list(self):
        self.assertIn("self.handoffs", _SERVER)

    def test_the_callback_records_it_not_a_dedicated_hook(self):
        # Recording in callback() means every emitter (agent AND swarm) is
        # covered without anyone remembering to call a second function.
        block = _SERVER[_SERVER.index("def callback(self, kind: str"):]
        block = block[:block.index("def handoff_records")]
        self.assertIn('kind == "handoff"', block)
        self.assertIn('beacon_id', block)

    def test_an_empty_beacon_id_is_not_recorded(self):
        block = _SERVER[_SERVER.index("def callback(self, kind: str"):]
        block = block[:block.index("def handoff_records")]
        self.assertIn("if beacon_id and not any(", block)

    def test_the_same_beacon_is_not_recorded_twice(self):
        block = _SERVER[_SERVER.index("def callback(self, kind: str"):]
        block = block[:block.index("def handoff_records")]
        self.assertIn("h.get(\"beacon_id\") == beacon_id", block)

    def test_the_snapshot_does_not_hand_out_the_live_list(self):
        # A UI poll iterating the job's own list would mutate run state.
        self.assertIn("return [dict(h) for h in self.handoffs]", _SERVER)


class TestStreamServesHandoffs(unittest.TestCase):
    def test_the_stream_includes_them(self):
        self.assertIn('"handoffs": job.handoff_records()', _SERVER)

    def test_the_empty_case_declares_the_field_too(self):
        # A missing key and an empty list read differently in TS; always send it.
        block = _SERVER[_SERVER.index("def automode_stream"):]
        block = block[:block.index("@routes.get")]
        self.assertIn('"handoffs": []', block)


class TestElectronStoreContract(unittest.TestCase):
    def test_the_handoff_type_exists(self):
        for field in ("beaconId", "status", "source", "kind"):
            self.assertIn(field, _STORE)

    def test_one_record_per_beacon_and_kind(self):
        # A beacon that re-checks-in must not stack cards to dismiss.
        self.assertIn("x.beaconId === h.beaconId && x.kind === h.kind",
                      _STORE)

    def test_pending_is_the_ready_status_only(self):
        self.assertIn("h.status === 'ready'", _STORE)

    def test_status_transitions_are_explicit(self):
        for status in ("'ready'", "'accepted'", "'dismissed'", "'expired'"):
            self.assertIn(status, _STORE)


class TestElectronConsumesIt(unittest.TestCase):
    def test_the_panel_registers_stream_handoffs(self):
        self.assertIn("d.handoffs", _PANEL)
        self.assertIn("addHandoff({", _PANEL)

    def test_the_panel_offers_the_handoff(self):
        self.assertIn("pendingHandoffs", _PANEL)
        self.assertIn("Beacon available", _PANEL)

    def test_opening_a_beacon_selects_it_and_switches_tab(self):
        self.assertIn("setActiveBeacon(beaconId)", _PANEL)
        self.assertIn("setActiveTab('c2')", _PANEL)

    def test_opening_a_beacon_queues_no_task(self):
        # The handoff is a navigation action. Queueing work on the target as a
        # side effect of clicking "Open C2" would be an unrequested action.
        open_body = _PANEL[_PANEL.index("const openBeacon ="):]
        open_body = open_body[:open_body.index("const handleStop")]
        # No network call at all, and specifically no task-queueing endpoint.
        self.assertNotIn("api(", open_body,
                         "openBeacon must not talk to the backend")
        for forbidden in ("/api/c2/task", "/api/c2/queue", "sendTask"):
            self.assertNotIn(forbidden, open_body)

    def test_the_card_can_be_dismissed(self):
        self.assertIn("setHandoffStatus(h.id, 'dismissed')", _PANEL)


if __name__ == "__main__":
    unittest.main()