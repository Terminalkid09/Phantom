"""Sealing keeps the plaintext off the operator's disk without changing bytes.

The property that matters is that the C2 serves EXACTLY the bytes it served
before: the seal is storage, not payload obfuscation. A round-trip mismatch
here would ship a broken implant, so it is pinned, and so is the opt-out.
"""

from __future__ import annotations

import os

from phantom.utils import beacon_artifacts


def _write(tmp_path, name: str, data: bytes):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_sealing_removes_the_plaintext_and_round_trips(tmp_path, monkeypatch):
    monkeypatch.delenv(beacon_artifacts.ENV_KEEP, raising=False)
    payload = b"MZ" + bytes(range(256)) * 8
    path = _write(tmp_path, "beacon.pe", payload)

    assert beacon_artifacts.seal(path) is True
    assert not path.exists(), "the plaintext must be gone"
    assert (tmp_path / "beacon.pe.enc").exists()
    assert (tmp_path / ".artifact_key").exists()
    assert beacon_artifacts.present(path) is True
    assert beacon_artifacts.payload(path) == payload


def test_the_sealed_bytes_are_not_the_plaintext(tmp_path, monkeypatch):
    monkeypatch.delenv(beacon_artifacts.ENV_KEEP, raising=False)
    payload = b"MZ" + b"\x00" * 512
    path = _write(tmp_path, "beacon.bin", payload)
    beacon_artifacts.seal(path)
    raw = (tmp_path / "beacon.bin.enc").read_bytes()
    assert raw != payload
    assert b"MZ" not in raw[:64]


def test_the_opt_out_keeps_the_plaintext(tmp_path, monkeypatch):
    monkeypatch.setenv(beacon_artifacts.ENV_KEEP, "1")
    path = _write(tmp_path, "beacon.pe", b"MZ" + b"x" * 64)
    assert beacon_artifacts.seal(path) is False
    assert path.exists()


def test_a_missing_artefact_is_reported_not_raised(tmp_path):
    missing = tmp_path / "nope.pe"
    assert beacon_artifacts.present(missing) is False
    assert beacon_artifacts.payload(missing) is None
    assert beacon_artifacts.size(missing) == 0


def test_a_plaintext_artefact_is_still_readable(tmp_path):
    path = _write(tmp_path, "beacon_linux", b"\x7fELF" + b"\x00" * 32)
    assert beacon_artifacts.present(path)
    assert beacon_artifacts.payload(path).startswith(b"\x7fELF")
