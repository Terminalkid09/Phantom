"""Tests: the tool provisioning helper (phantom/utils/toolchain.py).

A missing external tool used to be indistinguishable from a clean run — the
command produced "" and the module stored an empty result. These tests pin the
three things that make the fix honest: the environment is detected correctly on
every platform Phantom is used from (Kali WSL, other Linux, macOS, Windows), the
install command is right for THAT platform, and nothing is ever installed
without an explicit confirmation.
"""
from __future__ import annotations

import subprocess

import pytest

from phantom.utils import toolchain as tc


KALI = 'ID=kali\nID_LIKE=debian\nPRETTY_NAME="Kali GNU/Linux Rolling"\n'
UBUNTU = 'ID=ubuntu\nID_LIKE=debian\n'
ARCH = 'ID=arch\n'
FEDORA = 'ID=fedora\nID_LIKE="rhel fedora"\n'
OPENSUSE = 'ID="opensuse-leap"\n'
UNKNOWN = 'ID=weirddistro\n'
WSL_KALI = KALI + 'WSL_DISTRO_NAME=kali-linux\nMICROSOFT = 1\n'


class _Runner:
    """Records argv, returns a scripted CompletedProcess."""

    def __init__(self, returncode: int = 0, stderr: str = "", stdout: str = ""):
        self.calls = []
        self._rc = returncode
        self._err = stderr
        self._out = stdout

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, self._rc, self._out, self._err)


def _no_tools(_name):
    return None


def _all_tools(_name):
    return f"/usr/bin/{_name}"


# ── environment detection ────────────────────────────────────────────────────

@pytest.mark.parametrize("os_release,distro,manager", [
    (KALI, "kali", "apt"),
    (UBUNTU, "ubuntu", "apt"),
    (ARCH, "arch", "pacman"),
    (FEDORA, "fedora", "dnf"),
    (OPENSUSE, "opensuse-leap", "zypper"),
    (UNKNOWN, "weirddistro", "none"),
])
def test_linux_distros_map_to_their_package_manager(os_release, distro, manager):
    env = tc.detect_env(os_release, platform_name="Linux")
    assert (env.os, env.distro, env.manager) == ("linux", distro, manager)


def test_kali_is_recognised_as_kali_not_just_debian():
    # The distro name is the point: Kali ships the recon stack, Debian does not,
    # so "which package" can legitimately differ.
    assert tc.detect_env(KALI, platform_name="Linux").distro == "kali"


def test_wsl_is_flagged_so_the_operator_knows_which_linux_they_are_on():
    assert tc.detect_env(WSL_KALI, platform_name="Linux").wsl is True
    assert tc.detect_env(KALI, platform_name="Linux").wsl is False
    assert tc.detect_env("", platform_name="Linux", wsl_marker=True).wsl is True


def test_macos_uses_brew_without_sudo():
    env = tc.detect_env("", platform_name="Darwin")
    assert (env.os, env.manager, env.needs_sudo) == ("macos", "brew", False)


def test_windows_falls_back_to_choco_when_winget_is_absent(monkeypatch):
    monkeypatch.setattr(tc.shutil, "which", _no_tools)
    assert tc.detect_env("", platform_name="Windows").manager == "choco"
    monkeypatch.setattr(tc.shutil, "which", _all_tools)
    assert tc.detect_env("", platform_name="Windows").manager == "winget"


def test_sudo_is_not_assumed_when_we_are_already_root(monkeypatch):
    monkeypatch.setattr(tc.os, "geteuid", lambda: 0, raising=False)
    assert tc.detect_env(KALI, platform_name="Linux").needs_sudo is False
    monkeypatch.setattr(tc.os, "geteuid", lambda: 1000, raising=False)
    assert tc.detect_env(KALI, platform_name="Linux").needs_sudo is True


# ── the install command ──────────────────────────────────────────────────────

def test_apt_command_uses_sudo_and_the_distro_package():
    env = tc.detect_env(KALI, platform_name="Linux")
    env = env._replace(needs_sudo=True)
    assert tc.install_command("nmap", env) == [
        "sudo", "apt-get", "install", "-y", "nmap"]


def test_brew_command_never_prefixes_sudo():
    env = tc.detect_env("", platform_name="Darwin")
    assert tc.install_command("nmap", env) == ["brew", "install", "nmap"]


def test_a_pip_only_tool_installs_with_pip_when_no_package_exists():
    env = tc.Env("linux", "fedora", "none", False, False)
    assert tc.install_command("sherlock", env) == [
        "python", "-m", "pip", "install", "--user", "sherlock-project"]


def test_a_tool_with_no_mapping_returns_no_command():
    env = tc.Env("linux", "weirddistro", "none", False, False)
    assert tc.install_command("nmap", env) is None      # no pip fallback exists
    assert tc.install_command("does-not-exist", env) is None


def test_unknown_distro_lists_the_tools_it_can_still_install():
    env = tc.Env("linux", "weirddistro", "none", False, False)
    assert tc.install_command("holehe", env) == [
        "python", "-m", "pip", "install", "--user", "holehe"]


# ── presence detection ───────────────────────────────────────────────────────

def test_missing_reports_only_what_is_absent():
    present = {"nmap", "whois"}
    gone = tc.missing(which=lambda n: n if n in present else None)
    assert "nmap" not in gone and "whois" not in gone
    assert "sherlock" in gone and "holehe" in gone


# ── install(): the confirmation gate ─────────────────────────────────────────

def test_install_refuses_a_tool_it_does_not_know():
    ok, msg = tc.install("nope", tc.Env("linux", "kali", "apt", False, False))
    assert ok is False and "unknown tool" in msg


def test_install_is_a_noop_when_the_tool_is_already_there():
    ok, msg = tc.install("nmap", tc.Env("linux", "kali", "apt", False, False),
                         which=_all_tools)
    assert ok is True and "already installed" in msg


def test_install_refuses_without_a_confirmation_callback():
    runner = _Runner()
    ok, msg = tc.install("nmap", tc.Env("linux", "kali", "apt", False, False),
                         runner=runner, which=_no_tools)
    assert ok is False and "confirmation" in msg
    assert runner.calls == [], "nothing may be executed without a confirmation"


def test_install_refuses_when_the_operator_says_no():
    runner = _Runner()
    ok, msg = tc.install("nmap", tc.Env("linux", "kali", "apt", False, False),
                         confirm=lambda tool, cmd: False,
                         runner=runner, which=_no_tools)
    assert ok is False and "not installed" in msg
    assert runner.calls == []


def test_install_refuses_when_the_confirmation_itself_breaks():
    def boom(tool, cmd):
        raise RuntimeError("ui closed")

    runner = _Runner()
    ok, msg = tc.install("nmap", tc.Env("linux", "kali", "apt", False, False),
                         confirm=boom, runner=runner, which=_no_tools)
    assert ok is False and "RuntimeError" in msg
    assert runner.calls == []


def test_install_runs_the_command_after_a_yes():
    runner = _Runner(returncode=0)
    seen = {}

    def yes(tool, cmd):
        seen["cmd"] = list(cmd)
        return True

    env = tc.Env("linux", "kali", "apt", False, False)
    ok, msg = tc.install("nmap", env, confirm=yes, runner=runner,
                         which=_no_tools)
    assert ok is True and "installed nmap" in msg
    assert runner.calls == [["apt-get", "install", "-y", "nmap"]]
    assert seen["cmd"] == ["apt-get", "install", "-y", "nmap"]


def test_install_reports_a_failed_package_manager_without_raising():
    runner = _Runner(returncode=100, stderr="E: Unable to locate package nmap")
    ok, msg = tc.install("nmap", tc.Env("linux", "kali", "apt", False, False),
                         confirm=lambda tool, cmd: True, runner=runner,
                         which=_no_tools)
    assert ok is False and "exit 100" in msg and "Unable to locate" in msg


def test_install_reports_that_a_platform_has_no_mapping():
    ok, msg = tc.install("nmap", tc.Env("linux", "weirddistro", "none",
                                        False, False),
                         confirm=lambda tool, cmd: True, runner=_Runner(),
                         which=_no_tools)
    assert ok is False and "no install mapping" in msg


# ── report ───────────────────────────────────────────────────────────────────

def test_report_names_the_missing_tools_and_how_to_fix_them():
    env = tc.Env("linux", "kali", "apt", True, True)
    text = tc.report(env, which=lambda n: n if n == "nmap" else None)
    assert "kali" in text and "wsl" in text
    assert "sherlock" in text and "sudo apt-get install -y sherlock" in text
    assert "nmap" not in text.split("missing:")[-1]


def test_report_says_so_when_nothing_is_missing():
    text = tc.report(tc.Env("linux", "kali", "apt", False, False),
                     which=_all_tools)
    assert "nothing missing" in text


def test_every_registry_entry_explains_itself_and_has_a_way_in():
    for name, spec in tc.TOOLS.items():
        assert spec.why, name
        assert spec.packages or spec.pip, name
