"""Local probe chains must run under THIS host's shell.

Several adapters (curl_probe, web_rce, env_probe, mobile_probe) build a
command that `execute_quiet` runs on the operator's box with
`subprocess(shell=True)`. On Windows that shell is cmd.exe, which has no
`;` separator: it hands every token after the first command to that
command as arguments. A `;`-joined chain therefore collapsed into one
`echo` and returned NO probe markers at all — measured on the lab box on
2026-10-17, the curl_probe chain returned 66 bytes and
`head: unknown option -- s` instead of its 10 probe sections, while the
same chain joined with `&` returned all 10. These tests pin the separator
to the platform so the probes keep producing output on both shells.
"""
import os
import subprocess
from types import SimpleNamespace

from phantom.automation.belief import WorldModel


def _wm(target="10.0.0.5"):
    return WorldModel(target=target, target_type="ip")


def test_join_uses_the_separator_the_platform_shell_runs(monkeypatch):
    from phantom.automation.guidance import kit

    monkeypatch.setattr(kit, "os", SimpleNamespace(name="nt"))
    assert kit._join_local_shell(["a", "b", "c"]) == "a & b & c"

    monkeypatch.setattr(kit, "os", SimpleNamespace(name="posix"))
    assert kit._join_local_shell(["a", "b", "c"]) == "a ; b ; c"


def test_curl_probe_chain_has_no_cmd_swallowing_separator():
    from phantom.automation.guidance import kit

    cmd = kit._curl_probe_adapter(_wm(), {})
    sep = " & " if os.name == "nt" else " ; "
    assert cmd.count(sep) >= 9, cmd
    if os.name == "nt":
        assert " ; " not in cmd, "cmd.exe would swallow everything after the first `;`"


def test_the_chain_actually_executes_end_to_end():
    """Run a two-segment chain exactly the way execute_quiet does: both
    markers must come back. This is the check the `;` version failed on
    Windows (one marker echoed as text, zero probes run)."""
    from phantom.automation.guidance import kit

    cmd = kit._join_local_shell(["echo __A__", "echo __B__"])
    out = subprocess.run(cmd, shell=True, capture_output=True,
                         text=True).stdout or ""
    assert "__A__" in out and "__B__" in out, out
