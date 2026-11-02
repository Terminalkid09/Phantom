"""The Windows beacon needs a C++ compiler that a stock Windows box does not have.

Before this, `check_build_env("windows")` printed "Install them manually" and
stopped: a dead end with no command attached, so the operator had to work out
that the build wants a MinGW cross-compiler at all. The fix offers a winget
install, and these tests pin the two halves that matter: it never installs
without consent, and when it does install it makes the compiler usable in the
SAME process (a fresh install does not update PATH, and the build runs
in-process).
"""
from __future__ import annotations

import os
import subprocess
from unittest import mock

import pytest

from phantom.utils import build_helper as bh


def _fake_package_tree(tmp_path, compiler=True):
    """A winget-shaped package dir; returns (LOCALAPPDATA, bin dir)."""
    bin_dir = (tmp_path / "Microsoft" / "WinGet" / "Packages"
               / f"{bh._MINGW_WINGET_ID}_Microsoft.Winget.Source_abc"
               / "mingw64" / "bin")
    bin_dir.mkdir(parents=True)
    if compiler:
        (bin_dir / (bh._MINGW_COMPILER + ".exe")).write_text("")
    return str(tmp_path), str(bin_dir)


class TestFindingTheCompiler:
    def test_a_compiler_on_path_wins(self):
        with mock.patch.object(bh.shutil, "which",
                               return_value=r"C:\mingw64\bin\x86_64-w64-mingw32-g++.exe"):
            assert bh.mingw_bin_dir() == r"C:\mingw64\bin"

    def test_a_winget_install_is_found_even_though_Path_is_stale(self, tmp_path):
        local, bin_dir = _fake_package_tree(tmp_path)
        with mock.patch.object(bh.shutil, "which", return_value=None), \
                mock.patch.dict(os.environ, {"LOCALAPPDATA": local}):
            assert bh.mingw_bin_dir() == bin_dir

    def test_nothing_installed_means_no_directory(self, tmp_path):
        local, _ = _fake_package_tree(tmp_path, compiler=False)
        with mock.patch.object(bh.shutil, "which", return_value=None), \
                mock.patch.dict(os.environ, {"LOCALAPPDATA": local}):
            assert bh.mingw_bin_dir() == ""


class TestInstallingNeedsConsent:
    def test_no_consent_installs_nothing(self):
        with mock.patch.object(bh.subprocess, "run") as run:
            assert bh.install_windows_toolchain(consent=False) is False
        run.assert_not_called()

    def test_a_non_windows_host_is_refused_not_guessed(self):
        with mock.patch.object(bh.os, "name", "posix"), \
                mock.patch.object(bh.subprocess, "run") as run:
            assert bh.install_windows_toolchain(consent=True) is False
        run.assert_not_called()

    def test_no_winget_is_a_named_failure(self):
        with mock.patch.object(bh.os, "name", "nt"), \
                mock.patch.object(bh.shutil, "which", return_value=None), \
                mock.patch.object(bh.subprocess, "run") as run:
            assert bh.install_windows_toolchain(consent=True) is False
        run.assert_not_called()


class TestAPositiveInstallLeavesAUsableCompiler:
    def test_winget_runs_unattended_and_the_compiler_lands_on_Path(self, tmp_path, monkeypatch):
        local, bin_dir = _fake_package_tree(tmp_path)
        monkeypatch.setenv("LOCALAPPDATA", local)
        monkeypatch.setenv("PATH", "/usr/bin")

        calls = []

        def _which(name):
            # the compiler only resolves AFTER the install path is prepended
            if name == bh._MINGW_COMPILER and bin_dir in os.environ.get("PATH", ""):
                return os.path.join(bin_dir, name + ".exe")
            if name == "winget":
                return r"C:\winget.exe"
            return None

        def _run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "ok", "")

        monkeypatch.setattr(bh.shutil, "which", _which)
        monkeypatch.setattr(bh.subprocess, "run", _run)

        assert bh.install_windows_toolchain(consent=True) is True
        assert calls, "winget was never invoked"
        cmd = calls[0]
        assert cmd[1:4] == ["install", "-e", "--id"]
        assert bh._MINGW_WINGET_ID in cmd
        # unattended: a prompt here would hang an operator script
        assert "--accept-package-agreements" in cmd
        assert "--accept-source-agreements" in cmd
        assert "--disable-interactivity" in cmd
        assert os.environ["PATH"].startswith(bin_dir + os.pathsep)

    def test_a_failed_winget_install_is_not_reported_as_success(self, tmp_path, monkeypatch):
        local, _ = _fake_package_tree(tmp_path, compiler=False)
        monkeypatch.setenv("LOCALAPPDATA", local)
        monkeypatch.setattr(bh.shutil, "which",
                            lambda name: r"C:\winget.exe" if name == "winget" else None)
        monkeypatch.setattr(bh.subprocess, "run",
                            lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "boom"))
        assert bh.install_windows_toolchain(consent=True) is False

    def test_an_already_installed_package_is_success_not_failure(self, tmp_path, monkeypatch):
        # winget answers "Found an existing package already installed" with a
        # NON-ZERO exit code. The toolchain is there and usable: reading the
        # exit code first called a working install a failure (measured
        # 2026-10-30), so detection decides.
        local, bin_dir = _fake_package_tree(tmp_path)
        monkeypatch.setenv("LOCALAPPDATA", local)
        monkeypatch.setenv("PATH", "/usr/bin")
        monkeypatch.setattr(
            bh.shutil, "which",
            lambda name: (os.path.join(bin_dir, name + ".exe")
                          if name == bh._MINGW_COMPILER and bin_dir in os.environ.get("PATH", "")
                          else (r"C:\winget.exe" if name == "winget" else None)))
        monkeypatch.setattr(
            bh.subprocess, "run",
            lambda cmd, **kw: subprocess.CompletedProcess(
                cmd, 2316632107, "Found an existing package already installed.", ""))
        assert bh.install_windows_toolchain(consent=True) is True
        assert os.environ["PATH"].startswith(bin_dir + os.pathsep)


class TestCheckBuildEnvAsksBeforeDownloadingAnything:
    """`check_build_env` is the path every build takes, so the consent gate lives here."""

    def _run(self, monkeypatch, *, opt_in, installs):
        monkeypatch.setattr(bh, "_deps_ready", lambda platform: False)
        monkeypatch.setattr(bh, "_mark_deps_ready", lambda platform: None)
        monkeypatch.setattr(bh.shutil, "which", lambda name: None)
        monkeypatch.setattr(bh.sys.stdin, "isatty", lambda: False)
        monkeypatch.setattr(bh, "install_windows_toolchain",
                            lambda consent=False: installs.append(consent) or True)
        monkeypatch.setattr(bh.os, "name", "nt")
        if opt_in:
            monkeypatch.setenv("PHANTOM_AUTO_INSTALL_TOOLCHAIN", "1")
        else:
            monkeypatch.delenv("PHANTOM_AUTO_INSTALL_TOOLCHAIN", raising=False)
        return bh.check_build_env("windows", "x64")

    def test_without_consent_it_refuses_and_installs_nothing(self, monkeypatch):
        installs = []
        assert self._run(monkeypatch, opt_in=False, installs=installs) is False
        assert installs == []

    def test_the_env_opt_in_is_consent(self, monkeypatch):
        installs = []
        assert self._run(monkeypatch, opt_in=True, installs=installs) is True
        assert installs == [True]
