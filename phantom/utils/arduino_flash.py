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

It also answers "which board is this?", which is not cosmetic. The FQBN picks
the core, and a Leonardo uploaded as ``arduino:avr:micro`` compiles and usually
runs — so the wrong board is chosen in SILENCE, and the operator is left
debugging a sketch that half works. ``board list`` is therefore asked first,
and its answer is REFUSED rather than guessed when it is ambiguous: overwriting
whichever of two plugged-in boards happens to sort first is not a decision this
module is allowed to make on the operator's behalf.

Nothing here runs at import: the default runner shells out to
``subprocess.run`` with an argv list (no ``shell=True``, so the paths cannot be
re-parsed), and the CLI only reaches it when ``--flash`` is given.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple

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

def fqbn_for(board: str) -> str:
    """The FQBN a board family needs, or ``""`` when it has no default.

    A Leonardo is not a Micro: the board map knows both, and the flasher is
    the only place that has to care. "" means "let the caller fall back to
    ``DEFAULT_FQBN``".
    """
    return FQBN_BOARDS.get((board or "").strip().lower(), "")


# Boards that present themselves as a keyboard but whose USB descriptor is not
# in the Arduino board database — a Pro Micro clone, most of them. arduino-cli
# reports those with NO ``matching_boards`` at all, so the only thing left to go
# on is the VID/PID pair, and both families below are the ATmega32U4 whose core
# is what the FQBN actually decides. Keys are lowercase hex, no ``0x``.
KNOWN_32U4_CLONES = {
    ("2341", "8036"): "arduino:avr:leonardo",
    ("2341", "0035"): "arduino:avr:micro",
    ("1b4f", "9205"): "arduino:avr:micro",
    ("1b4f", "9206"): "arduino:avr:micro",
    ("1b4f", "9207"): "arduino:avr:micro",
}


@dataclass
class BoardCandidate:
    """One port ``board list`` reported, and what it could say about it.

    ``fqbn`` empty is a real answer, not a failure: the port exists and the
    tool cannot name the board. It is carried to the operator that way instead
    of being dropped, because "your clone is on COM7 and I do not know its
    core" is actionable and "no board found" is not.
    """

    port: str
    fqbn: str
    name: str
    vid: str = ""
    pid: str = ""
    source: str = ""

    def summary(self) -> str:
        return f"{self.port}={self.fqbn or 'unknown'}"


# runner(argv, timeout) -> (returncode, stdout, stderr)
Runner = Callable[[Sequence[str], float], Tuple[int, str, str]]


def _default_runner(argv: Sequence[str], timeout: float) -> Tuple[int, str, str]:
    proc = subprocess.run(list(argv), capture_output=True, text=True,
                          timeout=timeout)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _hex_id(value) -> str:
    """``0x2341`` and ``2341`` name the same vendor; compare them one way."""
    text = str(value or "").strip().lower()
    return text[2:] if text.startswith("0x") else text


def _port_entries(payload) -> List[dict]:
    """The port list, whichever shape the installed arduino-cli printed.

    Older CLIs print a bare JSON array; 0.35+ wraps it in ``detected_ports``.
    Both are read here because the operator's CLI version is not something this
    module gets to choose, and silently finding nothing is the worst outcome.
    """
    if isinstance(payload, dict):
        for key in ("detected_ports", "ports"):
            value = payload.get(key)
            if isinstance(value, list):
                return [entry for entry in value if isinstance(entry, dict)]
        return []
    if isinstance(payload, list):
        return [entry for entry in payload if isinstance(entry, dict)]
    return []


def detect_boards(cli: str = "", runner: Runner = _default_runner,
                  timeout: float = 30.0) -> Tuple[BoardCandidate, ...]:
    """What ``arduino-cli board list`` says is plugged in, and nothing else.

    Never raises and never guesses: a CLI that is missing, exits non-zero or
    prints something that is not JSON answers ``()`` — "I could not look" and
    "there is nothing there" both mean the caller must not proceed, and only
    the operator can tell them apart.

    Ordered by port so two runs on the same bench report the same list.
    """
    binary = cli or find_cli()
    if not binary:
        return ()
    try:
        code, out, _err = runner((binary, "board", "list", "--format", "json"),
                                 timeout)
    except Exception:  # a hostile or missing CLI must not crash the caller
        return ()
    if code != 0:
        return ()
    try:
        payload = json.loads(out)
    except (TypeError, ValueError):
        return ()

    found: List[BoardCandidate] = []
    for entry in _port_entries(payload):
        port_info = entry.get("port")
        if not isinstance(port_info, dict):
            continue
        address = str(port_info.get("address") or "").strip()
        if not address:
            continue
        props = port_info.get("properties")
        prop = props if isinstance(props, dict) else {}
        vid, pid = _hex_id(prop.get("vid")), _hex_id(prop.get("pid"))

        boards = entry.get("matching_boards")
        first = boards[0] if isinstance(boards, list) and boards else {}
        if not isinstance(first, dict):
            first = {}
        fqbn = str(first.get("fqbn") or "").strip()
        name = str(first.get("name") or "").strip()
        if fqbn:
            source = "matching_boards"
        else:
            fqbn = KNOWN_32U4_CLONES.get((vid, pid), "")
            source = "clone_table" if fqbn else "none"
            name = name or ("32u4 clone" if fqbn else "")
        found.append(BoardCandidate(port=address, fqbn=fqbn, name=name,
                                    vid=vid, pid=pid, source=source))
    found.sort(key=lambda candidate: candidate.port)
    return tuple(found)


def choose_board(candidates: Sequence[BoardCandidate]
                 ) -> Tuple[Optional[BoardCandidate], str]:
    """The one board to flash, or the reason this cannot be decided.

    Refusing beats guessing every time here: the wrong choice writes firmware
    over somebody else's board, and the operator sees a successful upload.
    """
    usable = tuple(candidates or ())
    if not usable:
        return None, ("no board detected on any serial port: plug the board in "
                      "and make sure `arduino-cli board list` sees it, or "
                      "pass the port explicitly (--flash COM5)")

    # `board list` reports EVERY serial port, not only keyboards: a machine
    # with a Bluetooth COM port and a USB-serial adapter would otherwise look
    # like a three-board bench and make detection useless everywhere. Only a
    # candidate the toolchain can NAME is a board this module may flash, so
    # the ambiguity rule counts those; the rest are other people's devices.
    known = tuple(candidate for candidate in usable if candidate.fqbn)
    if len(known) > 1:
        seen = ", ".join(candidate.summary() for candidate in known)
        return None, (f"{len(known)} Arduino boards are plugged in ({seen}): "
                      f"refusing to guess which one to flash — pass the port "
                      f"explicitly (--flash {known[0].port})")
    if len(known) == 1:
        return known[0], ""

    # Nothing identifiable. If there is exactly one port, the actionable
    # answer is "I see it, I cannot name it, tell me the board id"; if there
    # are several, the operator needs to know WHICH ports exist before guessing.
    if len(usable) == 1:
        only = usable[0]
        where = (f"VID/PID {only.vid}:{only.pid}" if only.vid and only.pid
                 else "no usable USB descriptor")
        return None, (f"the board on {only.port} has no FQBN this tool knows "
                      f"({where}): pass it explicitly (--fqbn "
                      f"arduino:avr:micro for an ATmega32U4 board)")
    ports = ", ".join(candidate.port for candidate in usable)
    return None, (f"no Arduino board identified on {len(usable)} serial ports "
                  f"({ports}): none of them reports a board descriptor, so "
                  f"pass the port AND the board id explicitly (--flash "
                  f"{usable[0].port} --fqbn arduino:avr:micro)")


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
    #: True when the port and the FQBN came from the board itself rather than
    #: from the operator: the run is identical, what it PROVES is not.
    detected: bool = False
    candidates: Tuple[BoardCandidate, ...] = ()

    def summary(self) -> str:
        failed = next((s for s in self.steps if not s.ok), None)
        if failed is not None:
            tail = (failed.error or failed.output)[-400:]
            head = f"flash failed at {failed.name}"
            return f"{head}: {tail}" if tail else head
        if self.error:
            return f"flash failed: {self.error}"
        line = (f"flashed {os.path.basename(self.sketch_dir)} to {self.port} "
                f"({self.fqbn})")
        if self.detected:
            line += " [port and FQBN auto-detected]"
        return line


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


def flash_sketch(sketch_dir: str, port: str = "", *, fqbn: str = "",
                 cli: Optional[str] = None, runner: Runner = _default_runner,
                 timeout: float = DEFAULT_TIMEOUT_S,
                 allow_autodetect: bool = True) -> FlashResult:
    """Compile then upload ``sketch_dir`` to ``port`` — never both on failure.

    A failed compile does not reach the board: uploading a stale binary is how
    an operator ends up debugging the wrong sketch.

    ``port`` may be left empty (or given as ``auto``): the port AND the FQBN are
    then read off ``arduino-cli board list``. Both, because the FQBN is not a
    detail — flashing a Leonardo as an ``arduino:avr:micro`` succeeds and the
    operator never learns the board was described wrongly.
    """
    problem = validate_sketch_dir(sketch_dir)
    if problem:
        return FlashResult(ok=False, sketch_dir=sketch_dir, port=port,
                           fqbn=fqbn, error=problem)

    wanted = (port or "").strip()
    binary = cli if cli else find_cli()
    detected = False
    candidates: Tuple[BoardCandidate, ...] = ()

    if allow_autodetect and wanted.lower() in ("", "auto", "detect"):
        if not binary:
            return FlashResult(
                ok=False, sketch_dir=sketch_dir, fqbn=fqbn,
                error=(f"arduino-cli not found: install it or point "
                       f"{CLI_ENV_VAR} at the binary"))
        candidates = detect_boards(cli=binary, runner=runner)
        chosen, reason = choose_board(candidates)
        if chosen is None:
            return FlashResult(ok=False, sketch_dir=sketch_dir, fqbn=fqbn,
                               error=reason, candidates=candidates)
        wanted = chosen.port
        fqbn = fqbn or chosen.fqbn
        detected = True
    elif wanted.lower() in ("auto", "detect"):
        # "auto" with detection switched off is a contradiction, not a port
        # name: handing the literal string to avrdude would be a worse error
        return FlashResult(ok=False, sketch_dir=sketch_dir, fqbn=fqbn,
                           error=("auto-detection is disabled here: pass the "
                                  "port explicitly (--flash COM5)"))

    if not wanted:
        return FlashResult(ok=False, sketch_dir=sketch_dir, fqbn=fqbn,
                           error="no serial port given (e.g. --flash COM5)")
    if not binary:
        return FlashResult(
            ok=False, sketch_dir=sketch_dir, port=wanted, fqbn=fqbn,
            error=(f"arduino-cli not found: install it or point "
                   f"{CLI_ENV_VAR} at the binary"))
    fqbn = fqbn or DEFAULT_FQBN

    steps = []
    compiled = compile_sketch(sketch_dir, fqbn=fqbn, cli=binary, runner=runner,
                              timeout=timeout)
    steps.append(compiled)
    if not compiled.ok:
        return FlashResult(ok=False, sketch_dir=sketch_dir, port=wanted,
                           fqbn=fqbn, steps=tuple(steps),
                           error=compiled.error or "compile failed",
                           detected=detected, candidates=candidates)
    uploaded = upload_sketch(sketch_dir, wanted, fqbn=fqbn, cli=binary,
                             runner=runner, timeout=timeout)
    steps.append(uploaded)
    return FlashResult(ok=uploaded.ok, sketch_dir=sketch_dir, port=wanted,
                       fqbn=fqbn, steps=tuple(steps),
                       error="" if uploaded.ok else (uploaded.error
                                                     or "upload failed"),
                       detected=detected, candidates=candidates)
