"""Tests for the browser-based remote session viewer (CLI → real GUI)."""
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


def _get(url):
    return urllib.request.urlopen(url, timeout=5).read()


def _post(url, body):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    return urllib.request.urlopen(req, timeout=5).read()


def test_viewer_binds_loopback_random_port(fake_beacon):
    from phantom.core import remote_viewer
    port, _t = remote_viewer.launch_viewer("R-VIEWTEST", open_browser=False)
    assert port > 0
    time.sleep(0.4)
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


def test_viewer_frames_and_send_endpoints(fake_beacon):
    from phantom.core import remote_viewer
    from phantom.core.c2_server import c2_state
    port, _t = remote_viewer.launch_viewer("R-VIEWTEST", open_browser=False)
    time.sleep(0.4)
    frames = json.loads(_get(f"http://127.0.0.1:{port}/frames"))
    assert frames["beacon"] == fake_beacon and "frames" in frames
    resp = json.loads(_post(f"http://127.0.0.1:{port}/send",
                            {"cmd": "remote input move 5 6"}))
    assert resp["ok"] is True
    assert c2_state.tasks[fake_beacon][-1]["command"] == "remote input move 5 6"


def test_viewer_ambiguous_prefix_rejected(fake_beacon):
    from phantom.core.c2_server import c2_state
    c2_state.beacons["R-VIEWTEST2"] = {"id": "R-VIEWTEST2", "hostname": "h2"}
    from phantom.core import remote_viewer
    with pytest.raises(Exception):
        remote_viewer.make_app("R-VIEWTEST")  # two R-VIEWTEST* beacons
    c2_state.beacons.pop("R-VIEWTEST2", None)
