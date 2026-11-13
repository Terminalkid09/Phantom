"""`install <tool>` runs a package MANAGER — it must ask, like `deps install`.

The audit found the manual shell had two doors to the same effect and two
policies: `deps install` asked for confirmation (and refused in a
non-interactive shell), while `install <tool>` ran apt/brew/choco/pip straight
away. A command that installs software on the operator's machine is exactly the
place where "it was typed, so it was intended" stops being a good argument: the
prompt names the package manager invocation, so the operator sees what will run
BEFORE it runs, and a scripted/CI shell can never trigger one by accident.

Both doors now share `phantom.core.shell.ui.ask_to_install`.
"""
import io
import sys

import pytest

from phantom.core.shell import PhantomShell
from phantom.core.shell.commands import ops as ops_cmd
from phantom.core.shell.commands import run as run_cmd
from phantom.core.shell import ui as shell_ui


def _capture(fn) -> str:
    buffer = io.StringIO()
    original = sys.stdout
    sys.stdout = buffer
    try:
        fn()
    finally:
        sys.stdout = original
    return buffer.getvalue()


@pytest.fixture
def no_install(monkeypatch):
    """Record every installer call; the installer itself never runs."""
    calls = []

    def fake_install_tool(tool, **kw):
        calls.append(tool)
        return {"ok": True, "command": f"install {tool}", "output": ""}

    monkeypatch.setattr("phantom.core.executor.install_tool", fake_install_tool)
    return calls


def test_a_refused_prompt_never_reaches_the_package_manager(no_install,
                                                           monkeypatch):
    monkeypatch.setattr(shell_ui, "ask_to_install", lambda tool, cmd: False)
    text = _capture(lambda: PhantomShell().do_install("hydra"))
    assert no_install == [], "install ran without consent"
    assert "NOT installed" in text


def test_an_accepted_prompt_installs(no_install, monkeypatch):
    monkeypatch.setattr(shell_ui, "ask_to_install", lambda tool, cmd: True)
    shell = PhantomShell()
    _capture(lambda: shell.do_install("hydra"))
    assert no_install == ["hydra"]


def test_the_prompt_is_shown_the_command_that_would_run(monkeypatch):
    seen = {}

    def spy(tool, cmd):
        seen["tool"], seen["cmd"] = tool, list(cmd)
        return False

    monkeypatch.setattr(shell_ui, "ask_to_install", spy)
    # hydra has no package-manager mapping in this environment, so the prompt
    # falls back to the install HINT — the point is that it is never blank.
    _capture(lambda: PhantomShell().do_install("hydra"))
    assert seen["tool"] == "hydra"
    assert seen["cmd"], "the operator must see WHAT would run"
    assert any("hydra" in str(part) for part in seen["cmd"])


def test_the_preview_is_never_empty(monkeypatch):
    """Whatever the environment, the operator sees a non-blank command."""
    for tool in ("nmap", "hydra", "nikto", "a-tool-nobody-mapped"):
        preview = run_cmd._install_preview(tool)
        assert preview and all(str(p).strip() for p in preview), \
            f"blank preview for {tool}"


def test_the_same_helper_gates_both_doors(monkeypatch):
    """`deps install` and `install` must not drift back apart."""
    seen = []
    monkeypatch.setattr(shell_ui, "ask_to_install",
                        lambda tool, cmd: seen.append(tool) or False)
    assert ops_cmd._ask_to_install("nmap", ["apt-get", "install", "nmap"]) \
        is False
    assert seen == ["nmap"], "ops must delegate to the shared policy"


def test_an_empty_argument_is_a_usage_error_not_an_install(no_install):
    text = _capture(lambda: PhantomShell().do_install(""))
    assert no_install == []
    assert "Usage" in text


def test_the_help_documents_that_it_asks():
    """A promise in the help text is only as good as the code behind it.

    Checked on `help install` (the handler's docstring) rather than the panel:
    the panel clips long descriptions at an 80-column console, so a row that
    SAYS the right thing can render as "Install a …".
    """
    doc = (PhantomShell.do_install.__doc__ or "").lower()
    assert "asks first" in doc, "`help install` does not mention consent"


def test_the_panel_lists_the_install_command():
    text = _capture(lambda: PhantomShell().do_help(""))
    assert "install <tool>" in text


def test_a_declined_install_leaves_the_tool_missing(no_install, monkeypatch):
    """Nothing is hidden: the operator is told the tool is still absent."""
    monkeypatch.setattr(shell_ui, "ask_to_install", lambda tool, cmd: False)
    text = _capture(lambda: PhantomShell().do_install("nikto"))
    assert "nikto" in text
    assert run_cmd._install_preview("nikto"), \
        "the preview must still name an approach when it is declined"
