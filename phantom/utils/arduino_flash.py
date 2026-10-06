"""arduino_flash.py — compile and upload a HID sketch with arduino-cli.

The HID artefact for an Arduino-IDE board is a ``.ino`` sketch that turns the
board into a keyboard (``hid_builder``). Getting it onto the board is two
``arduino-cli`` calls — ``compile`` then ``upload`` — and both are pure argv
invocations, so this module drives them through an INJECTABLE runner: real
flashing needs a board plugged in, but every decision (which commands, in which
order, what counts as failure) is testable without one.

Two things the Arduino toolchain is pedantic about, checked here rather than
discovered after a 40-second compile:

* the sketch folder must be named exactly like the ``.ino`` file;
* the board family needs the right FQBN (``arduino:avr:micro`` for the
  ATmega32U4 Arduino Micro / Pro Micro class).

Nothing here runs at import: the default runner shells out to
``subprocess.run`` with an argv list (no ``shell=True``, so the paths cannot be
re-parsed), and the CLI only reaches it when ``--flash`` is given.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional, Sequence, Tuple

CLI_ENV_VAR = "PHANTOM_ARDUINO_CLI"
DEFAULT_FQBN = "arduino:avr:micro"
DEFAULT_TIMEOUT_S = 300

# board family -> FQBN, for the boards the HID vector targets
FQBN_BOARDS = {
    "micro": "arduino:avr:micro",
    "leonardo": "arduino:avr:leonardo",
    "pro-micro": "arduino:avr:micro",
    "atmega32u4": "arduino:avr:micro",
}

# runner(argv, timeout) -> (returncode, stdout, stderr)
Runner = Callable[[Sequence[str], float], Tuple[int, str, str]]


def _default_runner(argv: Sequence[str], timeout: float) -> Tuple[int, str, str]:
    proc = subprocess.run(list(argv), capture_output=True, text=True,
                          timeout=timeout)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


@dataclass
class FlashStep:
    """One arduino-cli invocation and what it printed."""

    name: str
    argv: Tuple[str, ...]
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.error

    @property
    def output(self) -> str:
        return (self.stdout + self.stderr).strip()

    def summary(self) -> str:
        state = "ok" if self.ok else "FAILED"
        return f"{self.name} {state}: {' '.join(self.argv)}"


@dataclass
class FlashResult:
    ok: bool
    sketch_dir: str = ""
    port: str = ""
    fqbn: str = ""
    steps: Tuple[FlashStep, ...] = ()
    error: str = ""

    def summary(self) -> str:
        failed = next((s for s in self.steps if not s.ok), None)
        if failed is not None:
            tail = (failed.error or failed.output)[-400:]
            head = f"flash failed at {failed.name}"
            return f"{head}: {tail}" if tail else head
        if self.error:
            return f"flash failed: {self.error}"
        return (f"flashed {os.path.basename(self.sketch_dir)} to {self.port} "
                f"({self.fqbn})")


def find_cli(env: Optional[dict] = None) -> str:
    """Where arduino-cli is: ``PHANTOM_ARDUINO_CLI`` first, then PATH."""
    environ = os.environ if env is None else env
    override = (environ.get(CLI_ENV_VAR) or "").strip()
    if override:
        return override
    return shutil.which("arduino-cli") or ""


def validate_sketch_dir(sketch_dir: str) -> Optional[str]:
    """Return why the sketch cannot be compiled, or ``None`` when it can."""
    if not sketch_dir or not os.path.isdir(sketch_dir):
        return f"no such sketch folder: {sketch_dir!r}"
    inos = sorted(f for f in os.listdir(sketch_dir) if f.endswith(".ino"))
    if not inos:
        return f"no .ino file in {sketch_dir!r}"
    stem = os.path.splitext(inos[0])[0]
    folder = os.path.basename(os.path.normpath(os.path.abspath(sketch_dir)))
    if folder != stem:
        return (f"the Arduino toolchain needs the sketch folder named after "
                f"the .ino file: rename {folder!r} to {stem!r} (or regenerate "
                f"with the default output path)")
    return None


def _run_step(name: str, argv: Sequence[str], runner: Runner,
              timeout: float) -> FlashStep:
    step = FlashStep(name=name, argv=tuple(argv))
    try:
        code, out, err = runner(step.argv, timeout)
    except FileNotFoundError as exc:
        step.error = f"arduino-cli not found: {exc}"
        return step
    except subprocess.TimeoutExpired:
        step.error = f"timed out after {timeout:g}s"
        return step
    except Exception as exc:  # a hostile runner must not crash the caller
        step.error = f"{type(exc).__name__}: {exc}"
        return step
    step.returncode, step.stdout, step.stderr = code, out, err
    return step


def compile_sketch(sketch_dir: str, *, fqbn: str = DEFAULT_FQBN,
                   cli: str = "arduino-cli", runner: Runner = _default_runner,
                   timeout: float = DEFAULT_TIMEOUT_S) -> FlashStep:
    argv = (cli, "compile", "--fqbn", fqbn, sketch_dir)
    return _run_step("compile", argv, runner, timeout)


def upload_sketch(sketch_dir: str, port: str, *, fqbn: str = DEFAULT_FQBN,
                  cli: str = "arduino-cli", runner: Runner = _default_runner,
                  timeout: float = DEFAULT_TIMEOUT_S) -> FlashStep:
    argv = (cli, "upload", "-p", port, "--fqbn", fqbn, sketch_dir)
    return _run_step("upload", argv, runner, timeout)


def flash_sketch(sketch_dir: str, port: str, *, fqbn: str = DEFAULT_FQBN,
                 cli: Optional[str] = None, runner: Runner = _default_runner,
                 timeout: float = DEFAULT_TIMEOUT_S) -> FlashResult:
    """Compile then upload ``sketch_dir`` to ``port`` — never both on failure.

    A failed compile does not reach the board: uploading a stale binary is how
    an operator ends up debugging the wrong sketch.
    """
    problem = validate_sketch_dir(sketch_dir)
    if problem:
        return FlashResult(ok=False, sketch_dir=sketch_dir, port=port,
                           fqbn=fqbn, error=problem)
    if not (port or "").strip():
        return FlashResult(ok=False, sketch_dir=sketch_dir, fqbn=fqbn,
                           error="no serial port given (e.g. --flash COM5)")
    binary = cli if cli else find_cli()
    if not binary:
        return FlashResult(
            ok=False, sketch_dir=sketch_dir, port=port, fqbn=fqbn,
            error=(f"arduino-cli not found: install it or point "
                   f"{CLI_ENV_VAR} at the binary"))

    steps = []
    compiled = compile_sketch(sketch_dir, fqbn=fqbn, cli=binary, runner=runner,
                              timeout=timeout)
    steps.append(compiled)
    if not compiled.ok:
        return FlashResult(ok=False, sketch_dir=sketch_dir, port=port,
                           fqbn=fqbn, steps=tuple(steps),
                           error=compiled.error or "compile failed")
    uploaded = upload_sketch(sketch_dir, port, fqbn=fqbn, cli=binary,
                             runner=runner, timeout=timeout)
    steps.append(uploaded)
    return FlashResult(ok=uploaded.ok, sketch_dir=sketch_dir, port=port,
                       fqbn=fqbn, steps=tuple(steps),
                       error="" if uploaded.ok else (uploaded.error
                                                     or "upload failed"))
