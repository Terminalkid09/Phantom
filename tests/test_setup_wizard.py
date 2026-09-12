"""Tests for the installer stack: tool manifest, doctor, setup wizard.

Offline by construction: tool detection uses injected `which` results and
the install step is asserted on the PRINTED PLAN (the consent list), not
on a real package manager — a unit test must never apt-install anything.

Agreed policy being pinned here:
  * the manifest dedupes (5 impacket tools -> 1 package);
  * the wizard shows the exact package list BEFORE any consent, and
    installs nothing when the operator declines;
  * WSL states are detected and reported honestly (no silent elevation);
  * `doctor` changes nothing (read-only snapshot).
"""
import sys
from unittest.mock import patch

import pytest

from phantom.utils import tool_manifest as TM
from phantom.utils import setup_wizard as SW


# ── manifest ─────────────────────────────────────────────────────────────

class TestManifest:
    def test_all_capability_tools_covered(self):
        """Every tool the capabilities reference must have a manifest
        entry — a reference without an entry is how phantom once produced
        'apt-get install deploy-agent'."""
        used = set()
        from phantom.automation.guidance.kit import CAPABILITIES
        for cap in CAPABILITIES:
            used.update(cap.tools)
        covered = {e.name for e in TM.all_tools()}
        # sudo/wget are base-system tools also referenced by capabilities
        assert used - covered == set(), f"unmapped tools: {used - covered}"

    def test_impacket_dedupes_on_apt(self):
        plan = TM.install_plan("apt", ["GetNPUsers.py", "GetUserSPNs.py",
                                       "secretsdump.py", "psexec.py"])
        assert plan == ["impacket-scripts"]

    def test_plan_respects_family(self):
        plan = TM.install_plan("dnf", ["nmap", "hydra"])
        assert plan == ["nmap", "hydra"]

    def test_base_tools_never_installed_individually(self):
        plan = TM.install_plan("apt")
        assert "sudo" not in plan

    def test_check_snapshot_shape(self):
        with patch.object(TM, "_which", return_value=None):
            snap = TM.check()
        assert snap["installed"] == 0
        assert snap["total"] == len(TM.all_tools())
        assert "nmap" in snap["missing"]


# ── wizard: ask-once consent ─────────────────────────────────────────────

class TestToolsStep:
    def test_decline_installs_nothing(self, capsys):
        printed: list = []
        with patch.object(SW, "PLATFORM", "linux"), \
             patch.object(SW, "capability_tools",
                          return_value=[TM.entry("nmap")]), \
             patch.object(SW.shutil, "which", return_value=None), \
             patch.object(SW, "_apt_install") as inst:
            SW.tools_step(say=printed.append, ask=lambda q: False)
        inst.assert_not_called()
        text = "\n".join(printed)
        assert "nmap" in text           # the plan was SHOWN
        assert "Skipped" in text        # and nothing ran

    def test_consent_runs_install_with_deduped_plan(self):
        printed: list = []
        calls = []
        with patch.object(SW, "PLATFORM", "linux"), \
             patch.object(SW, "capability_tools",
                          return_value=[TM.entry("GetNPUsers.py"),
                                        TM.entry("secretsdump.py")]), \
             patch.object(SW.shutil, "which", return_value=None), \
             patch.object(SW, "_apt_install",
                          side_effect=lambda pkgs, say: calls.append(pkgs)):
            SW.tools_step(say=printed.append, ask=lambda q: True)
        assert calls == [["impacket-scripts"]]

    def test_windows_points_at_wsl(self):
        printed = []
        with patch.object(SW, "PLATFORM", "windows"):
            SW.tools_step(say=printed.append, ask=lambda q: False)
        assert "WSL" in "\n".join(printed)

    def test_nothing_missing_is_a_noop(self):
        printed = []
        with patch.object(SW, "PLATFORM", "linux"), \
             patch.object(SW, "capability_tools",
                          return_value=[TM.entry("nmap")]), \
             patch.object(SW.shutil, "which",
                          return_value="/usr/bin/nmap"):
            SW.tools_step(say=printed.append, ask=lambda q: True)
        assert "complete" in "\n".join(printed)


# ── WSL state machine ────────────────────────────────────────────────────

class TestWslStates:
    def test_not_windows_is_none(self):
        with patch.object(SW, "PLATFORM", "linux"):
            assert SW.wsl_state_check() is None

    def test_not_installed(self):
        with patch.object(SW, "PLATFORM", "windows"), \
             patch.object(SW.shutil, "which", return_value=None):
            kind, detail = SW.wsl_state_check()
        assert kind == SW.NOT_INSTALLED
        assert "ADMIN" in detail and "REBOOT" in detail

    def test_no_distro(self):
        printed = []
        with patch.object(SW, "PLATFORM", "windows"), \
             patch.object(SW.shutil, "which",
                          return_value="C:\\Windows\\wsl.exe"), \
             patch.object(SW, "_run", return_value=(True, "\x00\n\x00")):
            kind, _ = SW.wsl_state_check()
        assert kind == SW.NO_DISTRO

    def test_ready_lists_distros(self):
        with patch.object(SW, "PLATFORM", "windows"), \
             patch.object(SW.shutil, "which",
                          return_value="C:\\Windows\\wsl.exe"), \
             patch.object(SW, "_run",
                          return_value=(True, "kali-linux\nUbuntu\n")):
            kind, detail = SW.wsl_state_check()
        assert kind == SW.READY
        assert "kali-linux" in detail

    def test_guided_decline_changes_nothing(self):
        printed = []
        with patch.object(SW, "PLATFORM", "windows"), \
             patch.object(SW.shutil, "which", return_value=None):
            ok = SW.wsl_guided(say=printed.append, ask=lambda q: False)
        assert ok is False
        assert "Skipped" in "\n".join(printed)


# ── doctor is read-only ──────────────────────────────────────────────────

class TestDoctor:
    def test_doctor_runs_and_reports(self, capsys):
        with patch.object(SW, "PLATFORM", "linux"):
            snap = SW.doctor(say=print)
        out = capsys.readouterr().out
        assert "python" in out and "tools" in out and "docker" in out
        assert isinstance(snap["tools_missing"], list)

    def test_doctor_never_installs(self):
        with patch.object(SW, "_apt_install") as apt, \
             patch.object(SW, "PLATFORM", "linux"):
            SW.doctor(say=lambda *_: None)
        apt.assert_not_called()


# ── wizard entry ─────────────────────────────────────────────────────────

class TestWizard:
    def test_unknown_target_refused(self):
        assert SW.run_wizard("banana", say=lambda *_: None,
                             ask=lambda *_: False) == 2

    def test_idempotent_message(self, capsys):
        # declining every consent must still end cleanly (rc 0)
        rc = SW.run_wizard("", assume_yes=False, say=lambda *_: None,
                           ask=lambda *_: False)
        assert rc == 0
