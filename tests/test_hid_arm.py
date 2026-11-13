"""The Arduino arm button — a board that does not fire the moment it is powered.

`payload hid arduino` types as soon as the board is powered, which is what an
operator wants in the field (flash once, unplug, carry, plug into the target)
and exactly what nobody wants at a desk: the Leonardo resets into `setup()` the
moment an upload finishes, so an in-place reflash types the payload into the
machine you are sitting at.

`arm=True` costs a wired button and buys that property back. The tests here pin
the three things that make it a SAFETY control rather than a delay:

  * nothing fires until TWO full press+release cycles have happened;
  * a button stuck down (or shorted to GND) never returns, so a faulty switch
    fails SILENT — the board stays quiet instead of typing into the wrong box;
  * the LED says which state the board is in, because "did it fire?" is not a
    question an operator should have to answer by watching the target.

The command is typed only AFTER the second press: an ordering the sketch could
silently get wrong while still containing every one of those strings.
"""
from phantom.utils.hid_builder import board_notes, build_hid_payload


class TestTheArmButton:
    def test_arming_is_off_by_default_and_the_sketch_says_so(self):
        body = build_hid_payload("arduino", "whoami").content
        assert "SAFETY ARMING NOT USED" in body
        assert "ARM_PIN" not in body

    def test_the_default_really_types_without_a_press(self):
        # the documented default is plug-and-play: no waitPress at all
        body = build_hid_payload("arduino", "whoami").content
        assert "waitPress" not in body
        assert "Keyboard.print" in body

    def test_arming_requires_two_full_press_cycles(self):
        body = build_hid_payload("arduino", "whoami", arm=True).content
        assert body.count("waitPress();") == 2
        assert "1st press: arm" in body
        assert "2nd press: fire" in body

    def test_the_typical_pin_reaches_the_sketch(self):
        body = build_hid_payload("arduino", "whoami", arm=True,
                                 arm_pin=9).content
        assert "static const uint8_t ARM_PIN = 9;" in body
        assert "pinMode(ARM_PIN, INPUT_PULLUP);" in body

    def test_the_default_pin_is_seven(self):
        body = build_hid_payload("arduino", "whoami", arm=True).content
        assert "static const uint8_t ARM_PIN = 7;" in body

    def test_a_stuck_button_fails_safe(self):
        # waitPress waits for the button to be RELEASED as well as pressed: a
        # switch held down or shorted to GND never returns, and the board then
        # types nothing rather than firing on the wrong machine
        body = build_hid_payload("arduino", "whoami", arm=True).content
        assert "while (digitalRead(ARM_PIN) != LOW) delay(10);" in body
        assert "while (digitalRead(ARM_PIN) == LOW) delay(10);" in body

    def test_the_led_reports_armed_and_not_armed(self):
        body = build_hid_payload("arduino", "whoami", arm=True).content
        assert "dark = not armed" in body
        assert "lit = armed" in body
        assert "pinMode(LED_PIN, OUTPUT);" in body

    def test_the_command_is_typed_only_after_the_second_press(self):
        body = build_hid_payload("arduino", "whoami", arm=True).content
        assert body.index("2nd press: fire") < body.index("Keyboard.print")

    def test_the_host_still_gets_time_to_enumerate_the_device(self):
        # arming must not eat the delay that stops the first keystrokes from
        # being lost to HID enumeration
        body = build_hid_payload("arduino", "whoami", arm=True,
                                 delay_ms=2500).content
        assert "delay(2500);" in body

    def test_arming_survives_a_negative_delay(self):
        body = build_hid_payload("arduino", "whoami", arm=True,
                                 delay_ms=-5).content
        assert "delay(0);" in body


class TestArmingIsArduinoSpecific:
    """`--arm` is documented as Arduino-only: the CircuitPython and DuckyScript
    generators type their script with no firmware loop to hang a button on."""

    def test_the_arduino_sketch_is_what_changes(self):
        plain = build_hid_payload("arduino", "whoami").content
        armed = build_hid_payload("arduino", "whoami", arm=True).content
        assert plain != armed

    def test_the_other_boards_are_unaffected_by_the_flag(self):
        for board in ("pico", "flipper", "omg"):
            plain = build_hid_payload(board, "whoami").content
            armed = build_hid_payload(board, "whoami", arm=True).content
            assert plain == armed
            assert "ARM_PIN" not in armed

    def test_board_notes_point_at_the_flag_and_its_wiring(self):
        notes = board_notes("arduino")
        joined = " ".join(notes)
        assert "--arm" in joined
        assert "--arm-pin" in joined
        assert "GND" in joined


class TestTheArmFlagsOnTheCommandLine:
    """The CLI half of the same control: `--arm` and `--arm-pin` have to
    reach the sketch, and a bad pin must be refused rather than guessed."""

    def _sketch(self, arg, tmp_path):
        import os
        from unittest import mock

        from phantom.modules.payload import PayloadModule
        out = os.path.join(str(tmp_path), "arm", "arm.ino")
        with mock.patch("phantom.modules.payload.notifier") as note:
            PayloadModule().do_hid(f"{arg} --out {out}")
        if not os.path.isfile(out):
            return None, note
        with open(out, encoding="utf-8") as handle:
            return handle.read(), note

    @staticmethod
    def _errors(note):
        return " ".join(str(c) for c in note.error.call_args_list)

    def test_arm_reaches_the_sketch(self, tmp_path):
        body, _ = self._sketch("arduino whoami --arm", tmp_path)
        assert body is not None
        assert body.count("waitPress();") == 2

    def test_arm_pin_reaches_the_sketch(self, tmp_path):
        body, _ = self._sketch("arduino whoami --arm --arm-pin 3", tmp_path)
        assert body is not None
        assert "static const uint8_t ARM_PIN = 3;" in body

    def test_a_non_numeric_pin_is_refused(self, tmp_path):
        body, note = self._sketch("arduino whoami --arm --arm-pin", tmp_path)
        assert "--arm-pin wants a pin number" in self._errors(note)

    def test_the_help_documents_the_safety_meaning(self, tmp_path):
        from phantom.modules.payload import PayloadModule
        doc = PayloadModule().do_hid.__doc__
        assert "--arm-pin" in doc and "--arm " in doc
        assert "before the board types" in doc
