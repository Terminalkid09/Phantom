"""Tests for the C2 intel carried inside .pm session bundles.

Boundaries verified: beacon TABLE (intel) is exported, HMAC secrets are
NOT, and importing surfaces the intel under session.knowledge_base.
"""
import gzip
import json

import pytest

from phantom.utils import session_bundle as sb


def _fake_state(beacons, tasks, results):
    """A C2State stand-in: real lock semantics, injected tables."""
    import threading

    class FakeState:
        def __init__(self):
            self.lock = threading.Lock()
            self.beacons = beacons
            self.tasks = tasks
            self.results = results
    return FakeState()


def _fake_server():
    class FakeServer:
        thread = None
    return FakeServer()


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    from phantom.core.session import session as sess
    monkeypatch.setattr(sess, "target", "10.0.0.5", raising=False)
    monkeypatch.setattr(sess, "scope", [], raising=False)
    monkeypatch.setattr(sess, "results", {}, raising=False)
    monkeypatch.setattr(sess, "notes", [], raising=False)
    monkeypatch.setattr(sess, "history", [], raising=False)
    monkeypatch.setattr(sb, "_sessions_root", lambda: str(tmp_path))
    yield


def test_export_includes_c2_intel(tmp_path, monkeypatch):
    import phantom.core.c2_server as c2
    monkeypatch.setattr(c2, "c2_state", _fake_state(
        {"b1": {"ip": "10.0.0.9", "os": "Windows", "user": "u",
                "hostname": "h", "last_seen": "now"}},
        {"b1": [{"task_id": "t1", "command": "whoami"}]},
        {"b1": [{"task_id": "t1", "output": "u\\nh"}]}), raising=False)
    monkeypatch.setattr(c2, "server_instance", _fake_server(), raising=False)
    out = tmp_path / "s.pm"
    path = sb.export_session(out_path=str(out))
    data = sb.read_bundle(path)
    c2p = data.get("c2") or {}
    assert c2p["beacons"]["b1"]["ip"] == "10.0.0.9"
    assert c2p["tasks"]["b1"][0]["command"] == "whoami"
    assert "note" in c2p


def test_export_never_carries_hmac_secrets(tmp_path, monkeypatch):
    import phantom.core.c2_server as c2
    monkeypatch.setattr(c2, "c2_state", _fake_state(
        {"b1": {"ip": "x", "hmac_secret": "SUPER-SECRET",
                "auth_key": "ALSO-SECRET"}}, {}, {}), raising=False)
    monkeypatch.setattr(c2, "server_instance", _fake_server(), raising=False)
    path = sb.export_session(out_path=str(tmp_path / "s.pm"))
    data = sb.read_bundle(path)
    blob = json.dumps(data.get("c2") or {})
    assert "SUPER-SECRET" not in blob
    assert "ALSO-SECRET" not in blob


def test_import_surfaces_c2_intel(tmp_path, monkeypatch):
    import phantom.core.c2_server as c2
    monkeypatch.setattr(c2, "c2_state", _fake_state(
        {"b1": {"ip": "10.0.0.9"}},
        {"b1": [{"task_id": "t1", "command": "ls"}]},
        {"b1": [{"task_id": "t1", "output": "f"}]}), raising=False)
    monkeypatch.setattr(c2, "server_instance", _fake_server(), raising=False)
    path = sb.export_session(out_path=str(tmp_path / "s.pm"))
    from phantom.core.session import session as sess
    result = sb.import_session(str(path))
    assert result["c2_intel"]["beacons"] == 1
    intel = sess.knowledge_base.get("c2_intel") or {}
    assert intel.get("beacons", {}).get("b1", {}).get("ip") == "10.0.0.9"


def test_export_without_c2_importable(tmp_path):
    # no C2 state at all: export still works, c2 block is empty
    path = sb.export_session(out_path=str(tmp_path / "s.pm"))
    data = sb.read_bundle(path)
    assert "c2" in data
