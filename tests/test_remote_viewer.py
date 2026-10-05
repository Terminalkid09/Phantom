"""Tests for the browser-based remote session viewer (CLI → real GUI).

Since P0-5 every data route (/frames, /frame, /send) requires the
per-session bearer token issued by launch_viewer; only the HTML shell
is public (it carries the token to the page via the URL fragment).
"""
import json
import threading
import time
import urllib.request

import pytest


@pytest.fixture
def fake_beacon():
    from phantom.core.c2_server import c2_state
    c2_state.beacons["R-VIEWTEST1"] = {
        "id": "R-VIEWTEST1", "hostname": "victim",
        "os": "windows", "status": "LIVE"}
    yield "R-VIEWTEST1"
    c2_state.beacons.pop("R-VIEWTEST1", None)


@pytest.fixture
def viewer(fake_beacon):
    from phantom.core import remote_viewer
    port, _t, token = remote_viewer.launch_viewer(
        "R-VIEWTEST", open_browser=False)
    time.sleep(0.4)
    yield port, token


def _get(url, token=""):
    req = urllib.request.Request(
        url, headers=({"Authorization": "Bearer " + token} if token else {}))
    return urllib.request.urlopen(req, timeout=5).read()


def _post(url, body, token=""):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers=headers)
    return urllib.request.urlopen(req, timeout=5).read()


def test_viewer_binds_loopback_random_port(viewer, fake_beacon):
    port, _token = viewer
    assert port > 0
    html = _get(f"http://127.0.0.1:{port}/").decode()
    assert "PHANTOM" in html and fake_beacon in html
    # the page wires the full control surface
    for needle in ("remote input", "remote start", "remote live",
                   "remote stop", "remote frame"):
        assert needle in html


def test_viewer_rejects_network_bind():
    """The site must be loopback-only — the control surface of a live
    session can never listen on a routable interface."""
    from phantom.core import remote_viewer
    import inspect
    src = inspect.getsource(remote_viewer)
    assert '"127.0.0.1", 0' in src


def test_viewer_data_routes_require_token(viewer, fake_beacon):
    port, token = viewer
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(f"http://127.0.0.1:{port}/frames")
    assert exc.value.code == 401
    # with the token everything works
    frames = json.loads(_get(f"http://127.0.0.1:{port}/frames", token))
    assert frames["beacon"] == fake_beacon and "frames" in frames


def test_viewer_send_queues_task(viewer, fake_beacon):
    from phantom.core.c2_server import c2_state
    port, token = viewer
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"http://127.0.0.1:{port}/send",
              {"cmd": "remote input move 5 6"})
    assert exc.value.code == 401
    resp = json.loads(_post(f"http://127.0.0.1:{port}/send",
                            {"cmd": "remote input move 5 6"}, token))
    assert resp["ok"] is True
    assert c2_state.tasks[fake_beacon][-1]["command"] == "remote input move 5 6"


def test_viewer_only_serves_its_own_beacon_frames(tmp_path, monkeypatch):
    """F-02: a viewer authenticated for beacon A must neither LIST nor
    FETCH beacon B's frames, even though both live in data/remote/."""
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    from phantom.core.c2_server import c2_state
    from phantom.core import remote_viewer
    from phantom.core.artifact_ownership import record_owner

    c2_state.beacons["R-ABCDEF01"] = {"id": "R-ABCDEF01", "hostname": "a",
                                      "status": "LIVE"}
    c2_state.beacons["R-ABCDEF02"] = {"id": "R-ABCDEF02", "hostname": "b",
                                      "status": "LIVE"}
    d = tmp_path / "remote"
    d.mkdir(parents=True, exist_ok=True)
    (d / "a_frame.jpg").write_bytes(b"\xff\xd8A")
    (d / "b_frame.jpg").write_bytes(b"\xff\xd8B")
    record_owner("remote", "a_frame.jpg", "R-ABCDEF01")
    record_owner("remote", "b_frame.jpg", "R-ABCDEF02")

    port, _t, token = remote_viewer.launch_viewer("R-ABCDEF01",
                                                  open_browser=False)
    time.sleep(0.4)
    try:
        frames = json.loads(
            _get(f"http://127.0.0.1:{port}/frames", token))["frames"]
        names = {f["name"] for f in frames}
        assert "a_frame.jpg" in names
        assert "b_frame.jpg" not in names
        # B's frame is not fetchable BY NAME either — 404, not the bytes
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(f"http://127.0.0.1:{port}/frame?name=b_frame.jpg", token)
        assert exc.value.code == 404
        # A's own frame is served
        body = _get(f"http://127.0.0.1:{port}/frame?name=a_frame.jpg", token)
        assert body.startswith(b"\xff\xd8")
    finally:
        c2_state.beacons.pop("R-ABCDEF01", None)
        c2_state.beacons.pop("R-ABCDEF02", None)


def test_viewer_ambiguous_prefix_rejected(fake_beacon):
    from phantom.core.c2_server import c2_state
    c2_state.beacons["R-VIEWTEST2"] = {"id": "R-VIEWTEST2", "hostname": "h2"}
    from phantom.core import remote_viewer
    with pytest.raises(Exception):
        remote_viewer.make_app("R-VIEWTEST")  # two R-VIEWTEST* beacons
    c2_state.beacons.pop("R-VIEWTEST2", None)
