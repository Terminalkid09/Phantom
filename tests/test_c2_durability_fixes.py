"""The three durability defects the architecture audit found in the C2 state.

Each one is a case where the code PROMISED something in a comment or a log
line and did not do it:

1. a registration landing inside the 2s debounce window only set
   ``_state_dirty``; nothing ever retried the write, so two beacons checking in
   back to back and a crash lost the second one;
2. a state file that was REFUSED ("kept for inspection") was overwritten by the
   next write, so the operator lost exactly the file the log told them to read;
3. a check-in whose response could not be sealed answered 200 with an EMPTY
   body after leasing the tasks, which is indistinguishable from "no work" and
   stranded the batch for the whole lease.

All three are driven through the real store; only the debounce interval and the
env-provided paths are redirected.
"""
import json

import pytest

from phantom.core import c2_server as CS
from phantom.core.c2_server import C2State

BEACON_A = "B-A"
BEACON_B = "B-B"


@pytest.fixture()
def state_path(tmp_path, monkeypatch):
    path = tmp_path / "c2_state.json"
    monkeypatch.setenv("PHANTOM_C2_STATE_PATH", str(path))
    return path


@pytest.fixture()
def state(state_path):
    return C2State()


def _read(path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ── 1. a registration is never left only in memory ─────────────────────────

def test_a_registration_inside_the_debounce_window_still_lands(state, state_path,
                                                               monkeypatch):
    """Two beacons in the same second must both be on disk.

    The debounce is real (2s) here on purpose: it is the window that used to
    swallow the write. No `flush()` is called — a crash would not call one.
    """
    monkeypatch.setattr(CS, "_STATE_PERSIST_INTERVAL", 2.0)
    state.update_beacon(BEACON_A, {"ip": "10.0.0.5"})
    state.update_beacon(BEACON_B, {"ip": "10.0.0.6"})
    data = _read(state_path)
    assert set(data["beacons"]) == {BEACON_A, BEACON_B}


def test_a_queued_task_inside_the_window_is_on_disk(state, state_path,
                                                    monkeypatch):
    monkeypatch.setattr(CS, "_STATE_PERSIST_INTERVAL", 2.0)
    state.update_beacon(BEACON_A, {"ip": "10.0.0.5"})
    state.queue_task(BEACON_A, "whoami")
    state.queue_task(BEACON_A, "screenshot")
    # registration also auto-persists a task of its own; what matters is that
    # the operator's two are on disk without any flush
    queued = [t["command"] for t in _read(state_path)["tasks"][BEACON_A]]
    assert "whoami" in queued[-2:]
    assert "screenshot" in queued[-2:]


def test_a_dirty_store_is_drained_by_the_next_check_in(state, state_path,
                                                       monkeypatch):
    """Even a `last_seen`-only change must not leave the flag set for ever."""
    monkeypatch.setattr(CS, "_STATE_PERSIST_INTERVAL", 2.0)
    state.update_beacon(BEACON_A, {"ip": "10.0.0.5"})
    # simulate a deferred write (the debounce sets the flag and returns)
    state._state_dirty = True
    state._state_persist_last = 1e9           # "we just wrote"
    state.get_pending_tasks(BEACON_A)
    assert state._state_dirty is False, (
        "a check-in is the one event guaranteed to keep happening: it must "
        "drain the deferred write instead of leaving it for the next crash")


# ── 2. a refused state file is preserved, not overwritten ──────────────────

def test_an_unreadable_state_file_is_set_aside_not_overwritten(state_path,
                                                               monkeypatch):
    state_path.write_text("{not json", encoding="utf-8")
    state = C2State()
    rejected = list(state_path.parent.glob("c2_state.json.rejected-*"))
    assert rejected, "the refused file must still exist for inspection"
    assert rejected[0].read_text(encoding="utf-8") == "{not json"

    # ...and the next write goes to the normal path, leaving the rejected one
    state.update_beacon(BEACON_A, {"ip": "10.0.0.5"})
    assert _read(state_path)["beacons"]
    assert rejected[0].read_text(encoding="utf-8") == "{not json"


def test_a_state_file_from_another_schema_version_is_set_aside(state_path):
    state_path.write_text(json.dumps({"version": 999, "beacons": {}}),
                          encoding="utf-8")
    C2State()
    rejected = list(state_path.parent.glob("c2_state.json.rejected-version-*"))
    assert rejected, "a newer schema must be kept, not interpreted"


# ── 3. a seal failure is a 500 and gives the lease back ────────────────────

def test_a_failed_seal_releases_the_batch(state):
    state.update_beacon(BEACON_A, {"ip": "10.0.0.5"})
    state.queue_task(BEACON_A, "whoami")
    pending = state.get_pending_tasks(BEACON_A)
    mine = [t for t in pending if t["command"] == "whoami"]
    assert len(mine) == 1, pending
    # leased: a second call inside the lease window delivers nothing
    assert all(t["command"] != "whoami"
               for t in state.get_pending_tasks(BEACON_A))

    released = state.release_lease(BEACON_A, [t["task_id"] for t in mine])
    assert released == 1
    # the next check-in must be able to deliver it again
    again = state.get_pending_tasks(BEACON_A)
    assert [t["command"] for t in again if t["command"] == "whoami"] == [
        "whoami"]


def test_release_lease_ignores_unknown_ids(state):
    state.update_beacon(BEACON_A, {"ip": "10.0.0.5"})
    state.queue_task(BEACON_A, "whoami")
    assert state.release_lease(BEACON_A, ["", "nope"]) == 0
    assert state.release_lease(BEACON_A, []) == 0
