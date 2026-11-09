"""Tool management: the runner and the setup wizard must use ONE resolver.

Measured defect: `ToolRunner` called `shutil.which` directly while the rest of
Phantom resolves through `ToolRegistry` (aliases + WSL bridge). On a Windows
host whose Kali distro owns netcat, the listener path reported the tool missing
even though the executor would have rewritten the line to `wsl -d kali ...`.
"""
from __future__ import annotations

import pytest

from phantom.automation.runtime import toolrunner
from phantom.utils import setup_wizard as SW
from phantom.utils import tool_manifest as TM


class _Registry:
    def __init__(self, available=("nc",), *args, **kwargs):
        self.available = set(available)

    def has(self, name):
        return name in self.available


def test_native_path_wins(monkeypatch):
    monkeypatch.setattr(toolrunner.shutil, "which",
                        lambda name: "/usr/bin/" + name)
    assert toolrunner._require_tool(["nc"]) == "/usr/bin/nc"


def test_a_wsl_only_tool_is_not_reported_missing(monkeypatch):
    monkeypatch.setattr(toolrunner.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        "phantom.automation.runtime.toolchain.ToolRegistry", _Registry)
    # The bare name is what `execute_quiet_bg` rewrites to the distro wrapper.
    assert toolrunner._require_tool(["nc"]) == "nc"


def test_nothing_found_is_still_a_typed_error(monkeypatch):
    monkeypatch.setattr(toolrunner.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        "phantom.automation.runtime.toolchain.ToolRegistry",
        lambda *a, **k: _Registry(available=()))
    with pytest.raises(toolrunner.ToolMissingError):
        toolrunner._require_tool(["nc"])


def test_setup_accepts_an_impacket_entry_point(monkeypatch, capsys):
    """`impacket-GetNPUsers` satisfies the manifest's `GetNPUsers.py`."""
    monkeypatch.setattr(SW, "PLATFORM", "linux")
    monkeypatch.setattr(SW, "capability_tools",
                        lambda: [TM.entry("GetNPUsers.py")])
    monkeypatch.setattr(
        "phantom.automation.runtime.toolchain.ToolRegistry",
        lambda *a, **k: _Registry(available=("GetNPUsers.py",)))
    printed = []
    SW.tools_step(say=printed.append, ask=lambda question: False)
    text = "\n".join(printed)
    assert "toolbox complete" in text
    assert "Missing tool packages" not in text
