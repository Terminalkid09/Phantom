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

import locale
import os
from dataclasses import dataclass
from typing import Optional, Tuple

HID_LAYOUTS = ("us", "it", "de")

_ALIASES = {
    "": "us",
    "us": "us",
    "us-en": "us",
    "en": "us",
    "it": "it",
    "it-it": "it",
    "italian": "it",
    "de": "de",
    "de-de": "de",
    "german": "de",
    "deutsch": "de",
}

# Italian layout: character -> the US character whose scan code lands on the
# SAME PHYSICAL KEY. A US-based printer that sends that scan code therefore
# produces the Italian character we want.
#
# The list is empirical, not "the ones that look different": the IT layout
# SWAPS the two keys US uses for ``- _`` and ``' ?`` — on IT, ``'``/``?`` sit
# right of ``0`` (US ``-``/``_``) and ``-``/``_`` sit left of right-Shift (US
# ``/``/``?``). ``\``/``|`` likewise live on the US `` ` ``/``~`` key, and
# ``'`` has no US equivalent but ``-``. A command with an ordinary
# ``powershell -w h ... 'url'`` therefore types ``powershell 'w h`` and a
# broken quote on an Italian host unless all of them are rewritten. Only
# letters, digits, space and ``, . ; ! $ %`` are key-for-key between the two
# layouts.
_IT_SUBSTITUTIONS = {
    "=": ")",
    "+": "]",
    "(": "*",
    ")": "(",
    "/": "&",
    "&": "^",
    ":": ">",
    ";": "<",
    "?": "_",
    '"': "@",
    "*": "}",
    "^": "+",
    "-": "/",
    "_": "?",
    "'": "-",
    "\\": "`",
    "|": "~",
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

# ── German (de) — QWERTZ, same idea, different swaps ────────────────────────
# German does to the number row and to Y/Z what Italian does to `-` and `'`:
# `-` sits where US has `/`, `'` where US has `\`, `^`/`` ` `` where US has
# `` ` `` and `=`, and `[ ] { } @ \ | ~` are AltGr. A US printer must send a
# DIFFERENT physical key for the same character, exactly as for `it`.
_DE_SUBSTITUTIONS = {
    "y": "z", "z": "y",
    "=": ")", "+": "]", "(": "*", ")": "(",
    "/": "&", "&": "^", ":": ">", ";": "<", "?": "_",
    '"': "@", "*": "}", "-": "/", "_": "?", "'": "|", "#": "\\",
    # German letters that sit ON a key a US keyboard has: printing the US
    # character types the German one, so these need no key event at all.
    "\u00e4": "'", "\u00f6": ";", "\u00fc": "[", "\u00df": "-",
}

# German AltGr combinations (usage = the US position of the SAME key)
_DE_ALTGR = {
    "@": (0x14, False),   # AltGr+Q
    "{": (0x24, False),   # AltGr+7
    "[": (0x25, False),   # AltGr+8
    "]": (0x26, False),   # AltGr+9
    "}": (0x27, False),   # AltGr+0
    "\\": (0x38, False),  # AltGr+\u00df
    "|": (0x64, False),   # AltGr+<
    "~": (0x2E, False),   # AltGr++
}

# On a German keyboard `^` and `` ` `` are plain keys on US positions no US
# printable character uses the same way: explicit key events, no modifier.
_DE_RAW = {
    "^": (0x35, False),
    "`": (0x2E, True),
}

_DE_UNSUPPORTED = frozenset()

# One table per non-US layout; `us` needs none (the boards' own table).
# Adding a layout means adding ONE row here plus a round-trip test, so the
# four consumers below cannot drift apart.
_TABLES = {
    "it": {"subs": _IT_SUBSTITUTIONS, "altgr": _IT_ALTGR,
           "raw": _IT_RAW, "unsupported": _IT_UNSUPPORTED},
    "de": {"subs": _DE_SUBSTITUTIONS, "altgr": _DE_ALTGR,
           "raw": _DE_RAW, "unsupported": _DE_UNSUPPORTED},
}


@dataclass(frozen=True)
class Segment:
    """One piece of the typed text: a printable run, or one key combination."""

    kind: str          # "print" (send the text) or "key" (press a usage code)
    text: str = ""     # the printable run, for ``kind == "print"``
    usage: int = 0     # the raw HID usage code, for ``kind == "key"``
    shift: bool = False
    altgr: bool = False


def detected_layout(locale_name: Optional[str] = None) -> str:
    """The layout the OPERATOR's machine has — the best guess there is.

    A keystroke board cannot read the target's layout; it only sends scan
    codes and the target translates them. Phantom shipped ``us`` as the
    silent default, which on an Italian target is measurably wrong: the
    ``:`` of ``192.168.1.155:9443`` is Shift+``;`` in the US table, and on an
    Italian keyboard that key is ``ò`` whose shifted form is ``ç`` — the URL
    on screen became ``192.168.1.155ç9443`` while the sketch looked perfect.

    The bench and the target usually share a locale, so the operator's own
    machine is the only honest default: it is stated in the artefact, it is
    overridable with ``--layout``, and it is wrong far less often than
    assuming US. ``locale_name`` is injectable so this stays testable.
    """
    name = locale_name
    if name is None:
        name = (os.environ.get("LC_ALL") or os.environ.get("LC_MESSAGES")
                or os.environ.get("LANG") or "")
        if not name:
            try:
                name = locale.getdefaultlocale()[0] or ""
            except (ValueError, TypeError):
                name = ""
        if not name:
            # Windows keeps the answer in the kernel, not the POSIX env, and
            # a Git Bash session frequently has LANG unset.
            try:
                import ctypes

                buf = ctypes.create_unicode_buffer(85)
                if ctypes.windll.kernel32.GetUserDefaultLocaleName(buf, 85):
                    name = buf.value
            except (AttributeError, OSError, ImportError):
                name = ""
    key = (name or "").strip().lower().replace("_", "-")
    if key.startswith("it") or key == "italian":
        return "it"
    return "us"


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
    table = _TABLES.get(layout)
    if table is None:
        return text
    return "".join(table["subs"].get(c, c) for c in text)


def special_key_chars(text: str, layout: str) -> Tuple[str, ...]:
    """Characters on ``layout`` that need AltGr or a non-US key.

    A board that can press modifiers (Arduino, CircuitPython) types these with
    an explicit key event; a DuckyScript ``STRING`` cannot, which is the
    operator's cue to reword the command.
    """
    table = _TABLES.get(layout)
    if table is None:
        return ()
    hit = {c for c in text if c in table["altgr"] or c in table["raw"]}
    return tuple(sorted(hit))


def unsupported_chars(text: str, layout: str) -> Tuple[str, ...]:
    """Characters ``layout`` has no key for: the board would type junk."""
    table = _TABLES.get(layout)
    if table is None:
        return ()
    bad = {c for c in text
           # a non-ASCII character the table can PRODUCE (ä, ö, ü, ß) is not
           # unsupported: it is typed by sending a US key that lands on it
           if (c in table["unsupported"]
               or (ord(c) > 0x7E and c not in table["subs"])
               or (ord(c) < 0x20 and c not in "\t\n"))}
    return tuple(sorted(bad))


def segments(text: str, layout: str) -> Tuple[Segment, ...]:
    """Split ``text`` into printable runs and explicit key combinations.

    For ``us`` the whole text is one printable run. For ``it`` the characters
    that need AltGr or the non-US key break the text into runs, and the run
    text is translated so the same US codes come out right.
    """
    table = _TABLES.get(layout)
    if table is None:
        return (Segment("print", text=text),) if text else ()
    out = []
    buf = []

    def flush():
        if buf:
            out.append(Segment("print", text="".join(buf)))
            buf.clear()

    for char in text:
        if char in table["altgr"]:
            flush()
            usage, shift = table["altgr"][char]
            out.append(Segment("key", usage=usage, shift=shift, altgr=True))
        elif char in table["raw"]:
            flush()
            usage, shift = table["raw"][char]
            out.append(Segment("key", usage=usage, shift=shift))
        else:
            # an unsupported character stays in the run, untranslated: the
            # caller warns about it rather than silently dropping it
            buf.append(table["subs"].get(char, char))
    flush()
    return tuple(out)
