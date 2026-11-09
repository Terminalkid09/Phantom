"""The Windows execution backend must parse `wsl -l -q`'s real encoding.

Measured on Windows 10/11: the listing is UTF-16LE even though the rest of
the command line is UTF-8. Decoding it as text produced names full of NULs,
so `detect()` returned an available backend with a distro that did not
exist, and `run_pipeline()` waited until its timeout. These tests keep the
decoding and the distro choice honest without requiring WSL on CI.
"""
from __future__ import annotations

import subprocess
from types import SimpleNamespace

from phantom.api.backend import BackendDispatcher


def _mock_wsl_present(monkeypatch):
    # The parser contract is host-independent: CI runners do not ship
    # wsl.exe, but that must not stop these tests from exercising _describe.
    monkeypatch.setattr(
        "phantom.api.backend.shutil.which", lambda name: "wsl.exe"
    )


def test_utf16_wsl_listing_is_decoded_without_nul_bytes(monkeypatch):
    _mock_wsl_present(monkeypatch)
    raw = "Ubuntu\r\ndocker-desktop\r\nkali-linux\r\n".encode("utf-16-le")
    monkeypatch.setattr(
        "phantom.api.backend.subprocess.run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=raw),
    )
    info = BackendDispatcher()._describe("wsl2")
    assert info["distros"] == ["Ubuntu", "docker-desktop", "kali-linux"]
    assert info["available"] is True
    assert info["distro"] in {"Ubuntu", "kali-linux"}


def test_utf16_bom_and_utf8_listing_are_both_accepted(monkeypatch):
    _mock_wsl_present(monkeypatch)
    for raw in (
        "\ufeffUbuntu\r\nkali-linux\r\n".encode("utf-16"),
        b"Ubuntu\r\nkali-linux\r\n",
    ):
        monkeypatch.setattr(
            "phantom.api.backend.subprocess.run",
            lambda *a, **k: SimpleNamespace(returncode=0, stdout=raw),
        )
        info = BackendDispatcher()._describe("wsl2")
        assert info["distros"] == ["Ubuntu", "kali-linux"], raw


def test_a_registered_but_hung_distro_is_not_advertised(monkeypatch):
    """Registration is not availability.

    This is the Windows failure measured in the audit: `wsl -l -q` listed
    Kali, but `wsl -d kali-linux ...` never answered. `detect()` used to
    return an available backend anyway, so every routed command waited for
    its full timeout. The probe must turn that into an honest "no backend".
    """
    _mock_wsl_present(monkeypatch)
    raw = "Ubuntu\r\nkali-linux\r\n".encode("utf-16-le")

    def fake_run(argv, **kwargs):
        if "-l" in argv:
            return SimpleNamespace(returncode=0, stdout=raw)
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 3))

    monkeypatch.setattr("phantom.api.backend.subprocess.run", fake_run)
    info = BackendDispatcher()._describe("wsl2")
    assert info["available"] is False
    assert info["distro"] == ""
    assert "not executable" in info["details"]


def test_docker_desktop_alone_is_not_an_execution_backend(monkeypatch):
    _mock_wsl_present(monkeypatch)
    raw = "docker-desktop\r\ndocker-desktop-data\r\n".encode("utf-16-le")
    monkeypatch.setattr(
        "phantom.api.backend.subprocess.run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=raw),
    )
    info = BackendDispatcher()._describe("wsl2")
    # docker-desktop-data is also Docker's own utility distro; the important
    # contract is that Docker's utility distros never become the backend.
    assert info["available"] is False
    assert info["distro"] == ""
