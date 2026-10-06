"""hid_layouts.py — make a US-scan-code printer type the TARGET's layout.

A keystroke injector does not send characters. It sends HID *usage codes* and
modifiers, and the TARGET OS translates them with WHATEVER LAYOUT IT HAS
ACTIVE. ``Keyboard.print`` (Arduino), ``KeyboardLayoutUS`` (CircuitPython) and
a DuckyScript ``STRING`` all carry a **US** table: they send the scan code a US
keyboard needs for the character. On an Italian target that is plain wrong for
about a dozen characters — ``/`` and ``(`` among them, and ``{}``/``@``/``#``
worse, because those live behind AltGr.

The fix is not on the board and it is not guesswork: it is a table. Given the
layout the target actually has, pre-translate the text here so that the US scan
code that gets SENT is the one an Italian keyboard maps back to the character we
MEANT. ``/`` becomes ``&`` (Shift+7 is ``/`` on IT), ``(`` becomes ``*``
(Shift+8), ``)`` becomes ``(``, ``=`` becomes ``)``, and so on for the keys
where IT and US disagree. Characters that only exist behind AltGr are returned
as explicit key combinations, and characters an Italian keyboard has no key for
at all are reported so the operator hears about it instead of watching the
board type the wrong thing.

Pure text/data: no I/O. ``hid_builder`` renders this into each board's artefact.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

HID_LAYOUTS = ("us", "it")

_ALIASES = {
    "": "us",
    "us": "us",
    "us-en": "us",
    "en": "us",
    "it": "it",
    "it-it": "it",
    "italian": "it",
}

# Italian layout: character -> the US character whose scan code lands on the
# SAME PHYSICAL KEY. A US-based printer that sends that scan code therefore
# produces the Italian character we want. Only the characters where IT and US
# disagree are listed; everything else (letters, digits, space, ``- _ ' , . |
# \ ! $ %``) sits on the same key in both layouts and needs no rewrite.
_IT_SUBSTITUTIONS = {
    "=": ")",
    "+": "]",
    "(": "*",
    ")": "(",
    "/": "&",
    "&": "^",
    ":": ">",
    ";": "<",
    "?": '"',
    '"': "@",
    "*": "}",
    "^": "+",
}

# Italian characters that exist only behind AltGr: ``(HID usage, shift held)``.
# The usage is the US position of the SAME physical key, e.g. ``[`` is AltGr on
# the "è" key, which a US layout has as ``[`` (0x2F).
_IT_ALTGR = {
    "[": (0x2F, False),
    "]": (0x30, False),
    "{": (0x2F, True),
    "}": (0x30, True),
    "@": (0x33, False),
    "#": (0x34, False),
}

# Italian characters on a key no US layout has: the non-US backslash, HID usage
# 0x64, which an Italian keyboard carries as ``<`` and ``>``. No printable US
# character maps there, so these always need an explicit key event.
_IT_RAW = {
    "<": (0x64, False),
    ">": (0x64, True),
}

# characters an Italian keyboard simply has no key for
_IT_UNSUPPORTED = frozenset("`~")


@dataclass(frozen=True)
class Segment:
    """One piece of the typed text: a printable run, or one key combination."""

    kind: str          # "print" (send the text) or "key" (press a usage code)
    text: str = ""     # the printable run, for ``kind == "print"``
    usage: int = 0     # the raw HID usage code, for ``kind == "key"``
    shift: bool = False
    altgr: bool = False


def normalize_layout(layout: str) -> str:
    """Resolve a layout name (and its aliases) or refuse it loudly."""
    key = (layout or "").strip().lower().replace("_", "-")
    if key in _ALIASES:
        return _ALIASES[key]
    raise ValueError(f"unknown keyboard layout {layout!r}: choose from "
                     f"{', '.join(HID_LAYOUTS)}")


def translate_text(text: str, layout: str) -> str:
    """Rewrite ``text`` so a US-table printer types it on ``layout``.

    This is a per-character map, not a cascade: ``?`` becomes ``"`` and the
    ``"`` that produced is NOT then re-read as ``@``.
    """
    if layout == "us":
        return text
    return "".join(_IT_SUBSTITUTIONS.get(c, c) for c in text)


def special_key_chars(text: str, layout: str) -> Tuple[str, ...]:
    """Characters on ``layout`` that need AltGr or a non-US key.

    A board that can press modifiers (Arduino, CircuitPython) types these with
    an explicit key event; a DuckyScript ``STRING`` cannot, which is the
    operator's cue to reword the command.
    """
    if layout == "us":
        return ()
    hit = {c for c in text if c in _IT_ALTGR or c in _IT_RAW}
    return tuple(sorted(hit))


def unsupported_chars(text: str, layout: str) -> Tuple[str, ...]:
    """Characters ``layout`` has no key for: the board would type junk."""
    if layout == "us":
        return ()
    bad = {c for c in text
           if c in _IT_UNSUPPORTED
           or ord(c) > 0x7E
           or (ord(c) < 0x20 and c not in "\t\n")}
    return tuple(sorted(bad))


def segments(text: str, layout: str) -> Tuple[Segment, ...]:
    """Split ``text`` into printable runs and explicit key combinations.

    For ``us`` the whole text is one printable run. For ``it`` the characters
    that need AltGr or the non-US key break the text into runs, and the run
    text is translated so the same US codes come out right.
    """
    if layout == "us":
        return (Segment("print", text=text),) if text else ()
    out = []
    buf = []

    def flush():
        if buf:
            out.append(Segment("print", text="".join(buf)))
            buf.clear()

    for char in text:
        if char in _IT_ALTGR:
            flush()
            usage, shift = _IT_ALTGR[char]
            out.append(Segment("key", usage=usage, shift=shift, altgr=True))
        elif char in _IT_RAW:
            flush()
            usage, shift = _IT_RAW[char]
            out.append(Segment("key", usage=usage, shift=shift))
        else:
            # an unsupported character stays in the run, untranslated: the
            # caller warns about it rather than silently dropping it
            buf.append(_IT_SUBSTITUTIONS.get(char, char))
    flush()
    return tuple(out)
