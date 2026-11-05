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

Layouts beyond ``us``/``it``/``de`` are now declared as DATA in the same
shape: ``fr`` (AZERTY), ``es``, ``uk``, ``pt``, ``br`` and ``us-intl``. They
differ in HOW HONEST they can be. ``it`` and ``de`` were measured on hardware
and every character they cannot type is reported through ``unsupported_chars``
so the caller can warn. The newer tables are NOT hardware-verified yet, so
they are **strict**: a character whose key mapping has not been confirmed is
REFUSED with an error naming the character and the layout, and never typed as
an approximation. Typing ``!`` as whatever sits on that key is how a stager
arrives with a wrong character, and that defect class is the whole reason this
module exists. ``pt`` and ``br`` are deliberately partial for the same reason:
their layouts move keys this repository has not measured, and a refusal is a
better artefact than a plausible-looking guess.

Pure text/data: no I/O. ``hid_builder`` renders this into each board's artefact.
"""

from __future__ import annotations

import locale
import os
from dataclasses import dataclass
from typing import Optional, Tuple

HID_LAYOUTS = ("us", "it", "de", "fr", "es", "uk", "pt", "br", "us-intl")

_ALIASES = {
    "": "us",
    "us": "us",
    "us-en": "us",
    "en": "us",
    "en-us": "us",
    "it": "it",
    "it-it": "it",
    "italian": "it",
    "de": "de",
    "de-de": "de",
    "german": "de",
    "deutsch": "de",
    # ── the layouts added 2026-11-02 ────────────────────────────────────
    "fr": "fr",
    "fr-fr": "fr",
    "french": "fr",
    "francais": "fr",
    "es": "es",
    "es-es": "es",
    "esp": "es",
    "spanish": "es",
    "espanol": "es",
    "uk": "uk",
    "uk-gb": "uk",
    "en-gb": "uk",
    "gb": "uk",
    "british": "uk",
    "pt": "pt",
    "pt-pt": "pt",
    "portuguese": "pt",
    "portugues": "pt",
    "br": "br",
    "pt-br": "br",
    "br-br": "br",
    "brazilian": "br",
    "abnt2": "br",
    "us-intl": "us-intl",
    "usintl": "us-intl",
    "intl": "us-intl",
    "en-us-intl": "us-intl",
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

_PRINTABLE_ASCII = frozenset(chr(code) for code in range(0x20, 0x7F))


# ── French (fr) — AZERTY ───────────────────────────────────────────────────
# The letters a/q, z/w and m move, and the DIGITS are the SHIFTED forms of
# the punctuation keys: on AZERTY key 3 is `"` unshifted and `3` shifted, so
# typing `"` means sending the US key 3 with no modifier, while typing `3`
# means sending US `#`. Getting that direction backwards is the exact defect
# this module exists for, so each pair below is written next to its key.
# `!` and the dead keys (``^`` ``~`` `` ` ``) are NOT mapped: `!` sits on the
# ISO extra key and the dead keys need a following space, which a Segment
# cannot express. A strict layout refuses them instead of guessing.
_FR_SUBSTITUTIONS = {
    # letters that are not where the US has them
    "a": "q", "q": "a", "z": "w", "w": "z", "m": ";",
    "A": "Q", "Q": "A", "Z": "W", "W": "Z", "M": ":",
    # digits: AZERTY needs Shift for the digit itself
    "1": "!", "2": "@", "3": "#", "4": "$", "5": "%",
    "6": "^", "7": "&", "8": "*", "9": "(", "0": ")",
    # symbols that live on the digit keys (unshifted there)
    "&": "1", '"': "3", "'": "4", "(": "5", "-": "6", "_": "8",
    ")": "-", "%": '"', "$": "]", "*": "\\",
    # Bottom row, MEASURED 2026-11-02 against Windows' `0000040c` via
    # `VkKeyScanExW` + `MapVirtualKeyExW`, not reasoned from a picture: the
    # first table written here mapped `:` to `/` and `/` to `?`, which types
    # `/?` where the operator asked for `:/`. On AZERTY the US `m , . /`
    # positions carry `, ; : !`, so the mapping runs the other way.
    ":": ".", "/": ">", ";": ",", "?": "M", ".": "<", ",": "m",
    "!": "/",
}
_FR_ALTGR = {
    "{": (0x21, False),   # AltGr+4
    "[": (0x22, False),   # AltGr+5
    "|": (0x23, False),   # AltGr+6
    "\\": (0x25, False),  # AltGr+8
    "]": (0x2D, False),   # AltGr+)
    "}": (0x2E, False),   # AltGr+=
    "@": (0x27, False),   # AltGr+0
    "#": (0x20, False),   # AltGr+3
    "~": (0x1F, False),   # AltGr+2 (measured: VK 0x32)
}
_FR_RAW = {
    # `<`/`>` are the ISO extra key left of Z (usage 0x64), NOT the US Z key:
    # Z itself is where AZERTY puts `w`, so sending `z` for `<` would type w.
    "<": (0x64, False),
    ">": (0x64, True),
}
#: Everything else that is on the same physical key as US: these letters,
#: ``,`` `=` and ``+``.
_FR_IDENTITY = frozenset("bcdefghijklnoprstuvxyBCDEFGHIJKLNOPRSTUVXY ,=+")


# ── Spanish (es) — QWERTY with a moved symbol row ──────────────────────────
# Digits stay where US has them; the symbols on top of them do not: key 2 is
# `"` shifted, key 6 is `&` shifted, key 7 is `/` and 0 is `=`. `@` and `#`
# are AltGr. The brackets, braces, backslash and pipe are NOT mapped: their
# AltGr positions differ between the Spanish and Latin-American variants and
# this repository has not measured either, so a strict layout refuses them.
_ES_SUBSTITUTIONS = {
    '"': "@", "&": "^", "/": "&", "(": "*", ")": "(", "=": ")",
    "'": "-", "?": "_", "+": "]", "*": "}",
    ":": ">", ";": "<", "-": "/", "_": "?",
}
_ES_ALTGR = {
    "@": (0x1F, False),   # AltGr+2
    "#": (0x20, False),   # AltGr+3
}
_ES_RAW = {
    # same ISO extra key as French: `<`/`>` are not on the US Z key
    "<": (0x64, False),
    ">": (0x64, True),
}
_ES_IDENTITY = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!$%,. ")


# ── United Kingdom (uk) — four characters differ from US ───────────────────
# UK swaps `"` and `@`, puts `#`/`~` on the key US uses for `]`/`}`, and the
# backslash/pipe live on the ISO key left of Z (usage 0x64).
# Measured 2026-11-02 against Windows' `00000809`: `#` and `~` live on the
# key US uses for backslash/pipe (the first table put them on `]`/`}`, which
# types two wrong characters in every PowerShell one-liner).
_UK_SUBSTITUTIONS = {
    '"': "@",    # Shift+2
    "@": '"',    # Shift+apostrophe
    "#": "\\",   # the key US has as backslash
    "~": "|",    # Shift+that key
}
_UK_ALTGR = {}
_UK_RAW = {
    "\\": (0x64, False),
    "|": (0x64, True),
}
_UK_IDENTITY = _PRINTABLE_ASCII - set(_UK_SUBSTITUTIONS) - set(_UK_RAW)


# ── United States-International (us-intl) — same keys, dead characters ─────
# The physical layout is US, so every ordinary character is typed as-is. The
# five dead keys need a following space to produce the literal character, and
# a Segment cannot express "press, then space": they are therefore REFUSED
# rather than typed as an accent waiting to combine with the next keystroke.
_US_INTL_DEAD = frozenset("'\"`^~")
_US_INTL_SUBSTITUTIONS = {}
_US_INTL_ALTGR = {}
_US_INTL_RAW = {}
_US_INTL_IDENTITY = _PRINTABLE_ASCII - _US_INTL_DEAD


# ── Portuguese (pt-PT) — the number row moves like Spanish ─────────────────
# Confirmed: the digit keys carry their punctuation shifted (`"` on 2, `&` on
# 6, `/` on 7, `(` on 8, `)` on 9, `=` on 0), `'`/`?` sit on the US `-` key,
# `+`/`*` on the US `]` key, `-`/`_` on the US `/` key and `;`/`:` on the
# shifted comma/period. The brackets, braces, backslash, pipe and the ISO
# `<`/`>` key are NOT mapped: their positions vary with the keyboard vendor
# and a strict layout refuses them.
_PT_SUBSTITUTIONS = {
    '"': "@", "&": "^", "/": "&", "(": "*", ")": "(", "=": ")",
    "'": "-", "?": "_", "+": "[", "*": "{",
    ":": ">", ";": "<", "-": "/", "_": "?",
    "|": "~", "\\": "`", "~": "\\",
}
# `#` is an ORDINARY key on pt-PT (measured), not AltGr+3: the first table
# copied the Spanish AltGr entry and would have typed nothing.
_PT_ALTGR = {
    "@": (0x1F, False),   # AltGr+2
}
_PT_RAW = {}
_PT_IDENTITY = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%,. ")


# ── Brazilian ABNT2 (br) — DELIBERATELY partial ────────────────────────────
# ABNT2 keeps letters, digits and `, . / ? = + - _` on the US keys; the rest
# of the punctuation (quotes, colon, brackets, backslash, pipe) sits on keys
# and dead-key combinations this repository has not measured. There is no
# substitution table because none is needed for the characters listed, and
# every other character is refused with an error. A half-guessed ABNT2 table
# would type wrong characters silently, which is worse than saying "I do not
# know this key".
_BR_SUBSTITUTIONS = {":": "?", ";": "/"}
# Measured 2026-11-02 against Windows' `00000416`: `/` is AltGr+Q and `?` is
# AltGr+W (the first table listed both as ordinary keys, which would have
# typed a different character for every path and every query string).
_BR_ALTGR = {"/": (0x14, False), "?": (0x1A, False)}
_BR_RAW = {}
_BR_IDENTITY = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.=+-_ ")


# One table per non-US layout; `us` needs none (the boards' own table).
# Adding a layout means adding ONE row here plus a round-trip test, so the
# four consumers below cannot drift apart. ``strict`` means "refuse what this
# table does not cover" (the newer layouts); the hardware-verified ``it`` and
# ``de`` instead report the gap so the caller can warn and still type.
_TABLES = {
    "it": {"subs": _IT_SUBSTITUTIONS, "altgr": _IT_ALTGR,
           "raw": _IT_RAW, "unsupported": _IT_UNSUPPORTED},
    "de": {"subs": _DE_SUBSTITUTIONS, "altgr": _DE_ALTGR,
           "raw": _DE_RAW, "unsupported": _DE_UNSUPPORTED},
    "fr": {"subs": _FR_SUBSTITUTIONS, "altgr": _FR_ALTGR,
           "raw": _FR_RAW, "identity": _FR_IDENTITY, "strict": True},
    "es": {"subs": _ES_SUBSTITUTIONS, "altgr": _ES_ALTGR,
           "raw": _ES_RAW, "identity": _ES_IDENTITY, "strict": True},
    "uk": {"subs": _UK_SUBSTITUTIONS, "altgr": _UK_ALTGR,
           "raw": _UK_RAW, "identity": _UK_IDENTITY, "strict": True},
    "pt": {"subs": _PT_SUBSTITUTIONS, "altgr": _PT_ALTGR,
           "raw": _PT_RAW, "identity": _PT_IDENTITY, "strict": True},
    "br": {"subs": _BR_SUBSTITUTIONS, "altgr": _BR_ALTGR,
           "raw": _BR_RAW, "identity": _BR_IDENTITY, "strict": True},
    "us-intl": {"subs": _US_INTL_SUBSTITUTIONS, "altgr": _US_INTL_ALTGR,
                "raw": _US_INTL_RAW, "identity": _US_INTL_IDENTITY,
                "strict": True},
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
    if key.startswith("de") or key in ("german", "deutsch"):
        return "de"
    if key.startswith("fr") or key in ("french", "francais"):
        return "fr"
    if key.startswith("es") or key in ("spanish", "espanol"):
        return "es"
    if key.startswith("en-gb") or key in ("uk", "uk-gb", "gb", "british"):
        return "uk"
    if key.startswith("pt-br") or key in ("br", "brazilian", "abnt2"):
        return "br"
    if key.startswith("pt") or key in ("portuguese", "portugues"):
        return "pt"
    if key in ("us-intl", "usintl", "intl", "en-us-intl"):
        return "us-intl"
    return "us"


def normalize_layout(layout: str) -> str:
    """Resolve a layout name (and its aliases) or refuse it loudly."""
    key = (layout or "").strip().lower().replace("_", "-")
    if key in _ALIASES:
        return _ALIASES[key]
    raise ValueError(f"unknown keyboard layout {layout!r}: choose from "
                     f"{', '.join(HID_LAYOUTS)}")


def _typeable(table: dict) -> frozenset:
    """Every character the table can produce without guessing."""
    return frozenset(set(table.get("subs") or ())
                     | set(table.get("altgr") or ())
                     | set(table.get("raw") or ())
                     | set(table.get("identity") or ()))


def is_strict(layout: str) -> bool:
    """Is this layout fail-closed (refuses what its table does not cover)?

    The hardware-verified ``it`` and ``de`` report an untypeable character so
    the caller can warn and still build the artefact; the newer layouts REFUSE
    the build. That distinction is data, not a special case at each call site.
    """
    table = _TABLES.get(layout)
    return bool(table and table.get("strict"))


def validate_text(text: str, layout: str) -> str:
    """Refuse text a strict layout cannot type; returns ``text`` unchanged.

    Called by ``translate_text`` and ``segments`` so no caller can bypass it:
    if the mapping for a character is not in the table, the build fails with
    the character and the layout in the message. Typing an approximation is
    exactly the failure this module exists to prevent (the ``ç`` that arrived
    in ``192.168.1.155:9443`` was an approximation nobody had measured).
    """
    if not is_strict(layout):
        return text
    bad = unsupported_chars(text, layout)
    if bad:
        shown = ", ".join(repr(c) for c in bad)
        raise ValueError(
            f"layout {layout!r} cannot type {shown}: that key has no verified "
            f"mapping, and typing an approximation would put the wrong "
            f"character in the command. Reword it or choose a layout whose "
            f"table covers it")
    return text


def translate_text(text: str, layout: str) -> str:
    """Rewrite ``text`` so a US-table printer types it on ``layout``.

    This is a per-character map, not a cascade: ``?`` becomes ``"`` and the
    ``"`` that produced is NOT then re-read as ``@``.

    Raises ``ValueError`` for a strict layout when a character is not covered
    by its table (see ``validate_text``).
    """
    validate_text(text, layout)
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
    """Characters ``layout`` has no verified key for.

    For a strict layout this is the set ``validate_text`` refuses — the
    builder uses it to explain WHY the artefact was not produced. For the
    legacy tables it stays the warning path: ``it``/``de`` are measured on
    hardware and an unmapped character is reported rather than fatal.
    """
    table = _TABLES.get(layout)
    if table is None:
        return ()
    if table.get("strict"):
        ok = _typeable(table)
        bad = {c for c in text
               if c not in "\t\n" and c not in ok}
        return tuple(sorted(bad))
    bad = {c for c in text
           # a non-ASCII character the table can PRODUCE (ä, ö, ü, ß) is not
           # unsupported: it is typed by sending a US key that lands on it
           if (c in table.get("unsupported", ())
               or (ord(c) > 0x7E and c not in table["subs"])
               or (ord(c) < 0x20 and c not in "\t\n"))}
    return tuple(sorted(bad))


def segments(text: str, layout: str) -> Tuple[Segment, ...]:
    """Split ``text`` into printable runs and explicit key combinations.

    For ``us`` the whole text is one printable run. For ``it`` the characters
    that need AltGr or the non-US key break the text into runs, and the run
    text is translated so the same US codes come out right.
    """
    validate_text(text, layout)
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
