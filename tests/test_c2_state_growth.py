"""The persisted engagement state must not grow without a bound.

Measured 2026-11-05: `data/c2_state.json` was 116 KB carrying 45 beacon
records — most of them stale test artefacts from a single afternoon — and the
file is rewritten WHOLE on every save, so the write cost grew with a history
nobody would ever read again. Retention keeps the newest records and reports
what it dropped instead of making the operator discover it.

Every test drives a REAL `C2State` over a `tmp_path` file (the same boundary
`test_c2_state_persistence.py` uses), never the operator's state file.
"""
import json

import pytest

from phantom.core import c2_server as CS
from phantom.core.c2_server import C2State


@pytest.fixture()
def state_path(tmp_path, monkeypatch):
    path = tmp_path / "c2_state.json"
    monkeypatch.setenv("PHANTOM_C2_STATE_PATH", str(path))
    return path


@pytest.fixture()
def state(state_path, monkeypatch):
    # no debounce: a save lands when the test asks for it
    monkeypatch.setattr(CS, "_STATE_PERSIST_INTERVAL", 0.0)
    return C2State()


def _read(path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _stamp(i: int) -> str:
    """Monotonic, parseable, and in the past: index order == age order."""
    return f"2026-10-01T00:{i // 60:02d}:{i % 60:02d}"


def test_a_save_keeps_only_the_newest_beacons(state, state_path):
    total = CS.MAX_BEACONS + 50
    with state.lock:
        for i in range(total):
            state.beacons[f"B-{i:03d}"] = {"ip": "10.0.0.5",
                                           "last_seen": _stamp(i)}
    state.flush()

    saved = _read(state_path)["beacons"]
    assert len(saved) == CS.MAX_BEACONS
    assert f"B-{total - 1:03d}" in saved          # newest survived
    assert "B-000" not in saved                   # oldest went
    # the window is contiguous: the survivors are the last MAX_BEACONS
    assert min(saved) == f"B-{total - CS.MAX_BEACONS:03d}"


def test_the_drop_count_is_reported_not_silent(state, state_path):
    total = CS.MAX_BEACONS + 50
    with state.lock:
        for i in range(total):
            state.beacons[f"B-{i:03d}"] = {"last_seen": _stamp(i)}
    state.flush()

    assert state.compacted()["beacons"] == 50
    stats = state.stats()
    assert stats["dropped_last_save"]["beacons"] == 50
    assert stats["max_beacons"] == CS.MAX_BEACONS
    # memory keeps the whole engagement: only the FILE is bounded
    assert stats["beacons"] == total


def test_an_undatable_record_is_dropped_before_a_dated_one(state, state_path):
    with state.lock:
        for i in range(CS.MAX_BEACONS):
            state.beacons[f"D-{i:03d}"] = {"last_seen": _stamp(i)}
        # no timestamp at all: it cannot be shown to be recent
        state.beacons["U-1"] = {"ip": "10.0.0.9"}
    state.flush()

    saved = _read(state_path)["beacons"]
    assert "U-1" not in saved
    assert len(saved) == CS.MAX_BEACONS


def test_a_legacy_file_without_timestamps_still_loads(state_path, monkeypatch):
    monkeypatch.setattr(CS, "_STATE_PERSIST_INTERVAL", 0.0)
    state_path.write_text(json.dumps({
        "version": CS._STATE_VERSION,
        "saved_at": "2026-01-01T00:00:00",
        "beacons": {"B-legacy": {"ip": "10.0.0.5"}},
        "tasks": {},
        "results": {},
        "auto_shell": False,
    }), encoding="utf-8")

    state = C2State()
    assert "B-legacy" in state.beacons
    state.flush()
    # under the cap nothing is dropped, and the unparseable record survives
    assert "B-legacy" in _read(state_path)["beacons"]
    assert state.compacted()["beacons"] == 0


def test_results_and_tasks_have_their_own_caps(state, state_path):
    with state.lock:
        for i in range(CS.MAX_TASKS + 5):
            state.tasks[f"T-{i:04d}"] = [{"cmd": "whoami",
                                          "created": _stamp(i % 60)}]
    state.flush()

    stats = state.stats()
    assert stats["max_tasks"] == CS.MAX_TASKS
    assert state.compacted()["tasks"] == 5
    assert len(_read(state_path)["tasks"]) == CS.MAX_TASKS
