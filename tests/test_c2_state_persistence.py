"""The C2 engagement state must survive a listener restart.

Beacons, their queued tasks and the collected results used to live ONLY in
memory: restarting the listener (or rebooting the box) wiped the operation
while the beacons themselves were still checking in, and the operator had no
way to tell what had been lost.

Every test here drives the state through a REAL boundary — mutate, let it
write, then construct a fresh `C2State` over the same file, which is exactly
what the next process does. Nothing is mocked: the store on disk is the thing
under test. The state path is redirected with `PHANTOM_C2_STATE_PATH` so a
test run can never touch (or poison) the operator's real state file.
"""
import json
import time

import pytest

from phantom.core import c2_server as CS
from phantom.core.c2_server import C2State

BEACON = "B-1"


@pytest.fixture()
def state_path(tmp_path, monkeypatch):
    """The tmp state file every test writes to (never the real data dir)."""
    path = tmp_path / "c2_state.json"
    monkeypatch.setenv("PHANTOM_C2_STATE_PATH", str(path))
    return path


@pytest.fixture()
def fast_writes(monkeypatch):
    """No debounce: every mutation lands on disk immediately."""
    monkeypatch.setattr(CS, "_STATE_PERSIST_INTERVAL", 0.0)


@pytest.fixture()
def state(state_path, fast_writes):
    return C2State()


def _read(path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ── the write ─────────────────────────────────────────────────────────────

def test_a_registration_is_on_disk_and_carries_its_version(state, state_path):
    state.update_beacon(BEACON, {"ip": "10.0.0.5", "os": "Linux 5.15"})
    data = _read(state_path)
    assert data["version"] == CS._STATE_VERSION
    assert data["beacons"][BEACON]["ip"] == "10.0.0.5"
    assert BEACON in data["tasks"]      # the per-beacon queue is created too


def test_the_write_is_atomic_and_leaves_no_temp_file(tmp_path, state):
    state.update_beacon(BEACON, {"ip": "10.0.0.5"})
    state.queue_task(BEACON, "screenshot")
    assert list(tmp_path.glob("*.tmp")) == []


def test_secrets_never_reach_the_file(state, state_path):
    """A beacon HMAC key on disk would let a reader impersonate the beacon."""
    state.update_beacon(BEACON, {"ip": "10.0.0.5", "os": "Linux",
                                 "hmac_secret": "s3cr3t-key",
                                 "api_token": "tok-123"})
    text = state_path.read_text(encoding="utf-8")
    assert "s3cr3t-key" not in text
    assert "tok-123" not in text
    assert "hmac_secret" not in text
    # a non-secret field DOES land: the scrub is not "drop everything"
    assert _read(state_path)["beacons"][BEACON]["ip"] == "10.0.0.5"


# ── the restart ───────────────────────────────────────────────────────────

def test_a_restart_brings_back_the_beacons_the_queue_and_the_evidence(
        state, state_path, fast_writes):
    """The whole point: a new process picks up the engagement."""
    state.update_beacon(BEACON, {"ip": "10.0.0.5", "os": "Linux 5.15"})
    finished = state.queue_task(BEACON, "screenshot")
    state.queue_task(BEACON, "keylog 10")
    state.add_result(BEACON, finished, "screenshot: OK")
    state.set_auto_shell(True)

    restarted = C2State()                      # the next process

    beacons = restarted.get_beacons()
    assert BEACON in beacons
    assert beacons[BEACON]["ip"] == "10.0.0.5"

    # the operator's evidence came back, with the command it answers
    results = restarted.get_results(BEACON)
    assert [r["output"] for r in results] == ["screenshot: OK"]
    assert results[0]["command"] == "screenshot"

    # the finished task is NOT redelivered, the unfinished one still is
    pending = [t["command"] for t in restarted.get_pending_tasks(BEACON)]
    assert "screenshot" not in pending
    assert "keylog 10" in pending

    # and the operator's runtime choice survived with it
    assert restarted.auto_shell is True


def test_a_queued_task_is_durable_without_a_registration(state, state_path,
                                                         fast_writes):
    """An operator can queue work the moment a listener is up."""
    state.update_beacon(BEACON, {"ip": "10.0.0.5"})
    state.queue_task(BEACON, "health")
    restarted = C2State()
    assert "health" in [t["command"]
                        for t in restarted.get_pending_tasks(BEACON)]


# ── refusing what cannot be trusted ───────────────────────────────────────

def test_a_corrupt_file_starts_empty_instead_of_raising(state_path, fast_writes):
    state_path.write_text("{not json at all", encoding="utf-8")
    state = C2State()                          # must not raise
    assert state.get_beacons() == {}
    assert state.tasks == {}
    # the unreadable file is KEPT for inspection, not overwritten in place
    assert state_path.exists()


def test_a_foreign_version_is_refused_not_interpreted(state_path, fast_writes):
    state_path.write_text(json.dumps({
        "version": CS._STATE_VERSION + 97,
        "beacons": {BEACON: {"ip": "10.0.0.5"}},
        "tasks": {}, "results": {}}), encoding="utf-8")
    state = C2State()
    assert state.get_beacons() == {}


def test_a_missing_file_is_not_an_error(state_path, fast_writes):
    assert not state_path.exists()
    state = C2State()
    assert state.get_beacons() == {}


def test_a_beacon_without_a_queue_in_the_file_is_still_drainable(
        state_path, fast_writes):
    """A partial/older file must not make its beacons unreachable."""
    state_path.write_text(json.dumps({
        "version": CS._STATE_VERSION,
        "beacons": {BEACON: {"ip": "10.0.0.5"}},
    }), encoding="utf-8")
    state = C2State()
    assert BEACON in state.get_beacons()
    assert state.get_pending_tasks(BEACON) == []


def test_a_wrong_shaped_field_is_ignored_not_fatal(state_path, fast_writes):
    """Valid JSON of the wrong shape must not crash the listener's start."""
    state_path.write_text(json.dumps({
        "version": CS._STATE_VERSION,
        "beacons": [1, 2, 3],          # a list where a mapping belongs
        "tasks": "nonsense",
        "results": None,
    }), encoding="utf-8")
    state = C2State()
    assert state.get_beacons() == {}
    assert state.tasks == {}


# ── the debounce ──────────────────────────────────────────────────────────

def test_a_write_inside_the_window_is_deferred_not_lost(state_path, monkeypatch):
    """A change must not wait for a quiet moment, and must not be dropped."""
    monkeypatch.setattr(CS, "_STATE_PERSIST_INTERVAL", 3600.0)
    state = C2State()
    state.update_beacon(BEACON, {"ip": "10.0.0.1"})
    state.flush()                              # baseline: the file is current

    state.queue_task(BEACON, "screenshot")
    assert "screenshot" not in state_path.read_text(encoding="utf-8")
    assert state._state_dirty is True

    state.flush()                              # the shutdown flush
    assert "screenshot" in state_path.read_text(encoding="utf-8")
    assert state._state_dirty is False


def test_stopping_the_listener_flushes_the_deferred_state(state_path,
                                                          monkeypatch):
    monkeypatch.setattr(CS, "_STATE_PERSIST_INTERVAL", 3600.0)
    state = C2State()
    state.update_beacon(BEACON, {"ip": "10.0.0.1"})
    state.flush()
    state.queue_task(BEACON, "screenshot")
    assert "screenshot" not in state_path.read_text(encoding="utf-8")

    monkeypatch.setattr(CS, "c2_state", state)
    server = CS.C2Server()                     # never started: flush only
    server.stop()
    assert "screenshot" in state_path.read_text(encoding="utf-8")


def test_a_fresh_write_happens_once_the_window_has_passed(state_path,
                                                          monkeypatch):
    monkeypatch.setattr(CS, "_STATE_PERSIST_INTERVAL", 2.0)
    state = C2State()
    state.update_beacon(BEACON, {"ip": "10.0.0.1"})
    state.flush()
    state._state_persist_last = time.monotonic() - 10.0      # window passed
    state.queue_task(BEACON, "screenshot")
    assert "screenshot" in state_path.read_text(encoding="utf-8")


# ── reload policy ─────────────────────────────────────────────────────────

def test_reload_fills_an_empty_store_and_never_replaces_live_records(
        state, state_path, fast_writes):
    state.update_beacon(BEACON, {"ip": "10.0.0.1"})

    live = C2State()
    live.update_beacon("B-2", {"ip": "10.0.0.2"})
    # a process that holds records keeps them: the file is older than memory
    assert live.reload() is False
    assert set(live.get_beacons()) == {BEACON, "B-2"}

    live.beacons.clear()
    live.tasks.clear()
    live.results.clear()
    assert live.reload() is True
    assert BEACON in live.get_beacons()
