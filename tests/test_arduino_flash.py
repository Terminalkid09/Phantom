"""F4 — flashing a HID sketch with arduino-cli.

Real flashing needs a board on a COM port, so these tests drive the module
through its injectable runner instead and pin the decisions: the exact argv of
compile and upload, that a failed compile never uploads, the folder-name rule
the Arduino toolchain enforces, that a missing arduino-cli is a clear error
rather than a traceback, and that the port and the FQBN are READ OFF the board
when the operator names neither — with a refusal, not a guess, when the answer
is ambiguous.
"""
import json
import os

import pytest

from phantom.utils import arduino_flash
from phantom.utils.arduino_flash import (
    DEFAULT_FQBN,
    BoardCandidate,
    FlashResult,
    choose_board,
    compile_sketch,
    detect_boards,
    find_cli,
    flash_sketch,
    upload_sketch,
    validate_sketch_dir,
)


class FakeRunner:
    """Records every argv and replays a scripted (rc, out, err) per call."""

    def __init__(self, results=None):
        self.calls = []
        self.results = list(results or [])

    def __call__(self, argv, timeout):
        self.calls.append((tuple(argv), timeout))
        if self.results:
            return self.results.pop(0)
        return 0, "ok", ""


def _sketch(tmp_path, name="arduino_phantom_hid", ino=None):
    folder = tmp_path / name
    folder.mkdir()
    (folder / (ino or f"{name}.ino")).write_text(
        "#include <Keyboard.h>\nvoid setup(){}\nvoid loop(){}\n",
        encoding="utf-8")
    return str(folder)


class TestValidateSketchDir:
    def test_a_matching_folder_is_accepted(self, tmp_path):
        assert validate_sketch_dir(_sketch(tmp_path)) is None

    def test_a_mismatched_folder_names_the_right_one(self, tmp_path):
        sketch = _sketch(tmp_path, name="sketch",
                         ino="arduino_phantom_hid.ino")
        problem = validate_sketch_dir(sketch)
        assert problem and "arduino_phantom_hid" in problem

    def test_a_missing_folder_is_refused(self, tmp_path):
        assert validate_sketch_dir(str(tmp_path / "nope"))

    def test_a_folder_without_an_ino_is_refused(self, tmp_path):
        folder = tmp_path / "empty"
        folder.mkdir()
        assert validate_sketch_dir(str(folder))


class TestTheCommands:
    def test_find_cli_prefers_the_env_override(self):
        assert find_cli({arduino_flash.CLI_ENV_VAR: "/opt/acli"}) == "/opt/acli"

    def test_compile_builds_the_argv(self, tmp_path):
        runner = FakeRunner()
        step = compile_sketch(_sketch(tmp_path), fqbn=DEFAULT_FQBN,
                              cli="arduino-cli", runner=runner)
        assert step.ok
        argv, _ = runner.calls[0]
        assert argv[1] == "compile"
        assert "--fqbn" in argv and argv[argv.index("--fqbn") + 1] == \
            DEFAULT_FQBN
        assert argv[-1].endswith("arduino_phantom_hid")

    def test_upload_builds_the_argv(self, tmp_path):
        runner = FakeRunner()
        step = upload_sketch(_sketch(tmp_path), "COM5", cli="arduino-cli",
                             runner=runner)
        assert step.ok
        argv, _ = runner.calls[0]
        assert argv[1] == "upload"
        assert "-p" in argv and argv[argv.index("-p") + 1] == "COM5"


class TestFlashSketch:
    def test_it_compiles_then_uploads(self, tmp_path):
        runner = FakeRunner([(0, "compiled", ""), (0, "uploaded", "")])
        result = flash_sketch(_sketch(tmp_path), "COM5", cli="arduino-cli",
                              runner=runner)
        assert result.ok and result.port == "COM5"
        assert [c[0][1] for c in runner.calls] == ["compile", "upload"]
        assert [s.name for s in result.steps] == ["compile", "upload"]

    def test_a_failed_compile_never_uploads(self, tmp_path):
        runner = FakeRunner([(1, "", "avr-g++: error")])
        result = flash_sketch(_sketch(tmp_path), "COM5", cli="arduino-cli",
                              runner=runner)
        assert not result.ok
        assert len(runner.calls) == 1
        assert "error" in result.summary()

    def test_a_bad_folder_stops_before_running_anything(self, tmp_path):
        runner = FakeRunner()
        sketch = _sketch(tmp_path, name="sketch",
                         ino="arduino_phantom_hid.ino")
        result = flash_sketch(sketch, "COM5", cli="arduino-cli", runner=runner)
        assert not result.ok and runner.calls == []

    def test_a_missing_port_is_refused(self, tmp_path):
        # Detection off: this is the contract of the NON-detecting path, and
        # the message an operator sees when they turn detection off.
        runner = FakeRunner()
        result = flash_sketch(_sketch(tmp_path), "", cli="arduino-cli",
                              runner=runner, allow_autodetect=False)
        assert not result.ok and "no serial port given" in result.error
        assert runner.calls == []

    def test_a_missing_cli_is_a_clear_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(arduino_flash, "find_cli", lambda env=None: "")
        result = flash_sketch(_sketch(tmp_path), "COM5", runner=FakeRunner())
        assert not result.ok and "arduino-cli not found" in result.error

    def test_a_raising_runner_becomes_a_failed_step(self, tmp_path):
        def boom(argv, timeout):
            raise OSError("spawn failed")

        result = flash_sketch(_sketch(tmp_path), "COM5", cli="arduino-cli",
                              runner=boom)
        assert not result.ok
        assert "spawn failed" in result.steps[0].error


class TestHidCommandFlash:
    def _run(self, arg, tmp_path):
        from unittest import mock

        from phantom.modules.payload import PayloadModule
        module = PayloadModule()
        with mock.patch("phantom.modules.payload.notifier") as notifier, \
                mock.patch("phantom.utils.arduino_flash.flash_sketch") as flash:
            flash.return_value = FlashResult(ok=True, port="COM9")
            module.do_hid(arg)
            return flash, notifier

    def test_flash_is_off_unless_asked(self, tmp_path):
        from unittest import mock

        from phantom.modules.payload import PayloadModule
        out = tmp_path / "arduino_phantom_hid" / "arduino_phantom_hid.ino"
        with mock.patch("phantom.modules.payload.notifier"), \
                mock.patch("phantom.utils.arduino_flash.flash_sketch") as flash:
            PayloadModule().do_hid(f"arduino 'whoami' --out {out}")
        flash.assert_not_called()

    def test_flash_runs_against_the_written_sketch_folder(self, tmp_path):
        out = tmp_path / "arduino_phantom_hid" / "arduino_phantom_hid.ino"
        flash, notifier = self._run(
            f"arduino --stager linux --target linux --out {out} --flash COM9",
            tmp_path)
        flash.assert_called_once()
        args, kwargs = flash.call_args
        assert args[0] == os.path.dirname(str(out))
        assert args[1] == "COM9"
        assert notifier.success.called

    def test_flash_on_a_non_arduino_board_is_refused(self, tmp_path):
        out = tmp_path / "pico_main.py"
        flash, notifier = self._run(
            f"pico 'whoami' --out {out} --flash COM9", tmp_path)
        flash.assert_not_called()
        assert notifier.error.called


def _board_list(*entries):
    """One ``board list --format json`` payload, in the 0.35+ shape."""
    return json.dumps({"detected_ports": list(entries)})


def _port(address, vid="0x2341", pid="0x8036"):
    return {"address": address, "properties": {"vid": vid, "pid": pid}}


def _board(address="COM5", fqbn="arduino:avr:leonardo",
           name="Arduino Leonardo", vid="0x2341", pid="0x8036"):
    """A board arduino-cli can NAME: ``matching_boards`` is populated."""
    return {"port": _port(address, vid, pid),
            "matching_boards": [{"name": name, "fqbn": fqbn}]}


def _clone(address="COM7", vid="0x1b4f", pid="0x9205"):
    """A clone whose descriptor is not in the Arduino board database."""
    return {"port": _port(address, vid, pid), "matching_boards": None}


def _unknown(address="COM3"):
    """Somebody else's serial port: no Arduino descriptor at all.

    `board list` reports these too — a Bluetooth COM port, a USB-serial
    adapter, a printer — and they are the reason the ambiguity rule counts
    only boards the toolchain can NAME.
    """
    return {"port": {"address": address, "properties": {}},
            "matching_boards": None}


class TestDetection:
    """`--flash` with no port: the board says what it is, or nothing happens."""

    def test_one_board_gives_up_both_the_port_and_the_fqbn(self, tmp_path):
        runner = FakeRunner([(0, _board_list(_board()), ""),
                             (0, "compiled", ""), (0, "uploaded", "")])
        result = flash_sketch(_sketch(tmp_path), "", cli="arduino-cli",
                              runner=runner)
        assert result.ok
        assert result.port == "COM5" and result.fqbn == "arduino:avr:leonardo"
        assert result.detected
        assert runner.calls[0][0][1:3] == ("board", "list")
        # the FQBN the board reported is the one the upload was given, not the
        # tool's default: that substitution is the whole point
        upload_argv = runner.calls[-1][0]
        assert upload_argv[upload_argv.index("--fqbn") + 1] == \
            "arduino:avr:leonardo"

    def test_two_boards_are_refused_and_every_port_is_named(self, tmp_path):
        runner = FakeRunner([(0, _board_list(
            _board("COM5"),
            _board("COM7", fqbn="arduino:avr:micro")), "")])
        result = flash_sketch(_sketch(tmp_path), "", cli="arduino-cli",
                              runner=runner)
        assert not result.ok
        assert "COM5" in result.error and "COM7" in result.error
        assert [candidate.port for candidate in result.candidates] == \
            ["COM5", "COM7"]
        # nothing was compiled and nothing was written
        assert [call[0][1] for call in runner.calls] == ["board"]

    def test_a_named_board_wins_over_serial_ports_that_are_not_boards(
            self, tmp_path):
        """Measured on a real bench: COM3, COM4 and a Leonardo on COM7.

        Counting every serial port as a candidate made detection useless on
        any machine with another COM device, which is most of them.
        """
        runner = FakeRunner([(0, _board_list(_unknown("COM3"),
                                             _unknown("COM4"),
                                             _board("COM7")), ""),
                             (0, "compiled", ""), (0, "uploaded", "")])
        result = flash_sketch(_sketch(tmp_path), "", cli="arduino-cli",
                              runner=runner)
        assert result.ok, result.summary()
        assert result.port == "COM7"
        assert result.fqbn == "arduino:avr:leonardo"
        assert result.detected

    def test_ports_nobody_can_name_are_refused_with_the_ports_listed(
            self, tmp_path):
        runner = FakeRunner([(0, _board_list(_unknown("COM3"),
                                             _unknown("COM4")), "")])
        result = flash_sketch(_sketch(tmp_path), "", cli="arduino-cli",
                              runner=runner)
        assert not result.ok
        assert "COM3" in result.error and "COM4" in result.error
        assert "--fqbn" in result.error
        assert [call[0][1] for call in runner.calls] == ["board"]

    def test_an_empty_bench_is_refused(self, tmp_path):
        runner = FakeRunner([(0, _board_list(), "")])
        result = flash_sketch(_sketch(tmp_path), "", cli="arduino-cli",
                              runner=runner)
        assert not result.ok and "no board detected" in result.error
        assert result.candidates == ()

    def test_a_clone_without_a_matching_board_uses_the_table(self, tmp_path):
        runner = FakeRunner([(0, _board_list(_clone()), ""),
                             (0, "compiled", ""), (0, "uploaded", "")])
        result = flash_sketch(_sketch(tmp_path), "", cli="arduino-cli",
                              runner=runner)
        assert result.ok and result.fqbn == "arduino:avr:micro"
        assert result.port == "COM7"

    def test_an_unrecognised_board_asks_for_the_fqbn(self, tmp_path):
        runner = FakeRunner([(0, _board_list(_clone(vid="0x9999",
                                                   pid="0x0001")), "")])
        result = flash_sketch(_sketch(tmp_path), "", cli="arduino-cli",
                              runner=runner)
        assert not result.ok and "--fqbn" in result.error

    def test_an_explicit_fqbn_still_beats_the_detected_one(self, tmp_path):
        runner = FakeRunner([(0, _board_list(_board()), ""),
                             (0, "compiled", ""), (0, "uploaded", "")])
        result = flash_sketch(_sketch(tmp_path), "", fqbn="arduino:avr:micro",
                              cli="arduino-cli", runner=runner)
        assert result.fqbn == "arduino:avr:micro"

    def test_the_older_bare_list_shape_is_read_too(self):
        runner = FakeRunner([(0, json.dumps([_board()]), "")])
        found = detect_boards(cli="arduino-cli", runner=runner)
        assert [candidate.port for candidate in found] == ["COM5"]
        assert found[0].source == "matching_boards"

    def test_a_candidate_carries_its_vid_and_pid(self):
        runner = FakeRunner([(0, _board_list(_clone()), "")])
        found = detect_boards(cli="arduino-cli", runner=runner)
        assert (found[0].vid, found[0].pid) == ("1b4f", "9205")
        assert found[0].source == "clone_table"

    def test_bad_json_is_not_a_crash(self):
        assert detect_boards(
            cli="arduino-cli",
            runner=lambda argv, timeout: (0, "not json", "")) == ()

    def test_a_failing_cli_is_not_a_crash(self):
        assert detect_boards(
            cli="arduino-cli",
            runner=lambda argv, timeout: (1, "", "boom")) == ()

    def test_a_raising_runner_is_not_a_crash(self):
        def boom(argv, timeout):
            raise OSError("spawn failed")

        assert detect_boards(cli="arduino-cli", runner=boom) == ()

    def test_an_explicit_port_still_skips_the_detector(self, tmp_path):
        runner = FakeRunner()
        flash_sketch(_sketch(tmp_path), "COM9", cli="arduino-cli",
                     runner=runner)
        assert [call[0][1] for call in runner.calls] == ["compile", "upload"]

    def test_choosing_from_an_empty_list_says_what_to_do(self):
        chosen, reason = choose_board(())
        assert chosen is None and "board list" in reason

    def test_a_candidate_says_itself_what_it_is(self):
        assert BoardCandidate(port="COM5", fqbn="", name="").summary() == \
            "COM5=unknown"
        assert BoardCandidate(port="COM5", fqbn=DEFAULT_FQBN,
                              name="").summary() == f"COM5={DEFAULT_FQBN}"
