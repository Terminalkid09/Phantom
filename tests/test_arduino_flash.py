"""F4 — flashing a HID sketch with arduino-cli.

Real flashing needs a board on a COM port, so these tests drive the module
through its injectable runner instead and pin the decisions: the exact argv of
compile and upload, that a failed compile never uploads, the folder-name rule
the Arduino toolchain enforces, and that a missing arduino-cli is a clear error
rather than a traceback.
"""
import os

import pytest

from phantom.utils import arduino_flash
from phantom.utils.arduino_flash import (
    DEFAULT_FQBN,
    FlashResult,
    compile_sketch,
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
        runner = FakeRunner()
        result = flash_sketch(_sketch(tmp_path), "", cli="arduino-cli",
                              runner=runner)
        assert not result.ok and "port" in result.error
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
