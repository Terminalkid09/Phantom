"""target_platform.py — ONE source for "what artefact does this target get".

Five sites answered the same question with five different string sniffs:

* ``modules/payload.py``  — its own OS→(arch, platform) table, and a
  fallback that returned **linux, silently**, so an *unknown* Windows
  target was handed a Linux beacon with nothing said;
* ``automation/guidance/kit._target_os`` — the senior reading of the
  WorldModel's ``os``/``os_inferred`` findings;
* ``automation/agent._target_platform`` — a third sniff over that string
  (``"windows" in x or "win" in x``);
* ``core/netmap._guess_os`` — a fourth sniff over banners and open ports;
* ``core/c2_shell._beacon_platform`` — a fifth over the beacon-id prefix.

They disagreed on the edges ("Microsoft Windows Server 2019" is Windows to
three of them, ``bios`` contains "ios" to a naive one), and the ONE thing
that must never be a guess — which binary family the target receives — was
the thing they guessed. This module is the single decision point.

Nothing here executes anything: it maps signals (an OS finding, a banner,
open ports, a beacon id) to a :class:`TargetPlatform`, and it always says
WHERE the answer came from and whether it was DETECTED or merely ASSUMED.
An assumed answer is not an error — it is the default the run must state
out loud before shipping an artefact that may be the wrong family.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Iterable, Optional, Sequence, Tuple

# the platform families the payload builders can actually emit
PLATFORMS = ("windows", "linux", "macos", "android", "ios")

# beacon ids are minted per platform with a prefix (WIN-…, LNX-…, AND-…)
_BEACON_PREFIXES = (("WIN", "windows"), ("LNX", "linux"), ("MAC", "macos"),
                    ("AND", "android"), ("IOS", "ios"), ("DRD", "android"))

# OS-name tokens, MOST SPECIFIC FIRST: "windows server 2019" must not be
# classified by the "server" part, and "ios" must not match "bios" (see
# `_has`: short alphanumeric tokens are matched on a word boundary).
_OS_TOKENS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("ios", ("ios", "iphone", "ipados", "airplay", "raop")),
    ("android", ("android", "adb", "magisk")),
    ("macos", ("macos", "mac os", "os x", "darwin", "macbook", "imac")),
    ("windows", ("windows", "win32", "win64", "winnt", "microsoft",
                 "windows server", "iis", "httpapi")),
    ("linux", ("linux", "ubuntu", "debian", "centos", "rhel", "red hat",
               "fedora", "alpine", "openssh", "busybox", "unix", "freebsd")),
)

# port fingerprints for a COARSE family guess (netmap's terrain view)
_WINDOWS_PORTS = frozenset({135, 139, 445, 3389, 5985, 5986})
_UNIX_PORTS = frozenset({22, 111, 2049})

# arch tokens; a 32-bit guess is only made on positive evidence, because a
# 64-bit binary on a 64-bit OS is the safe default everywhere
_ARCH_32 = ("i386", "i486", "i586", "i686", "x86-32", "32-bit", "win32",
            "armv7", "armhf")
_ARCH_64 = ("x86-64", "x86_64", "amd64", "64-bit", "win64", "x64", "arm64",
            "aarch64")


def _has(text: str, token: str) -> bool:
    """Token match that does not fire on a substring by accident.

    Short alphanumeric tokens ("ios", "adb", "iis") are matched on word
    boundaries — otherwise ``bios`` classifies as iOS and ``iisadmin`` as
    IIS. Longer tokens are matched as substrings, which is what makes
    "Microsoft Windows Server 2019" work.
    """
    if token.isalnum() and len(token) <= 4:
        return re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])",
                         text) is not None
    return token in text


def _detect_arch(text: str, default: str = "x64") -> str:
    low = (text or "").lower()
    if any(_has(low, tok) for tok in _ARCH_32):
        return "x86"
    if any(_has(low, tok) for tok in _ARCH_64):
        return "x64"
    return default


@dataclass(frozen=True)
class TargetPlatform:
    """Which family the target belongs to, and how confident we are."""

    platform: str = ""          # windows|linux|macos|android|ios, "" if none
    arch: str = "x64"
    os_name: str = ""           # the detected OS string, as reported
    source: str = ""            # the signal that produced this answer
    assumed: bool = False       # True when nothing was detected

    @property
    def known(self) -> bool:
        """A real detection happened (not the default)."""
        return self.platform in PLATFORMS and not self.assumed

    @property
    def label(self) -> str:
        """Operator-facing one-liner, honest about the confidence."""
        name = self.os_name or (self.platform or "unknown")
        where = f", from {self.source}" if self.source else ""
        if not self.known:
            where = f", ASSUMED{where}" if self.source else ", ASSUMED"
        return f"{name} ({self.arch}, {self.platform or 'unknown'}{where})"

    def with_arch(self, arch: str) -> "TargetPlatform":
        return replace(self, arch=arch or self.arch)


def from_os_string(os_string: str, source: str = "os string",
                   arch: str = "") -> TargetPlatform:
    """Classify a human OS string (nmap -O, a banner, an operator flag)."""
    text = (os_string or "").strip()
    if not text:
        return TargetPlatform()
    low = text.lower()
    # the arch is read from the SAME string in both branches: an
    # unclassifiable family still knows whether it said "i686"
    resolved_arch = arch or _detect_arch(low)
    for platform, tokens in _OS_TOKENS:
        if any(_has(low, tok) for tok in tokens):
            return TargetPlatform(platform=platform, arch=resolved_arch,
                                  os_name=text, source=source)
    return TargetPlatform(arch=resolved_arch, os_name=text, source=source)


def from_findings(wm: Any, source: str = "wm os finding") -> TargetPlatform:
    """The senior source: a confirmed `os` finding, then `os_inferred`.

    Reads a WorldModel (or anything exposing ``find(kind)`` with findings
    carrying ``.value``). Returns an EMPTY platform when nothing was
    detected — never a fabricated default.
    """
    if wm is None:
        return TargetPlatform()
    for kind, label in (("os", source), ("os_inferred", "inferred os")):
        try:
            found = wm.find(kind)
        except Exception:
            continue
        for finding in found or []:
            value = getattr(finding, "value", None)
            if not isinstance(value, dict):
                continue
            name = str(value.get("os") or value.get("name") or "").strip()
            if len(found) > 1:
                # several findings (two hosts, two probes): say which key
                label = f"{source}:{getattr(finding, 'key', '') or kind}"
            if name:
                answer = from_os_string(name, source=label)
                if answer.known or answer.os_name:
                    return answer
    return TargetPlatform()


def from_banner(banner: str, open_ports: Sequence[int] = (),
                source: str = "banner") -> TargetPlatform:
    """Coarse family guess from a banner, then from the port fingerprint."""
    text = (banner or "").strip()
    if text:
        answer = from_os_string(text, source=source)
        if answer.platform:
            return answer
    ports = {int(p) for p in (open_ports or []) if str(p).strip().isdigit()}
    if ports & _WINDOWS_PORTS:
        return TargetPlatform(platform="windows", arch="x64",
                              os_name="Windows (likely)", source="ports")
    if ports & _UNIX_PORTS and not ports & _WINDOWS_PORTS:
        return TargetPlatform(platform="linux", arch="x64",
                              os_name="Linux (likely)", source="ports")
    return TargetPlatform()


def from_beacon_id(beacon_id: str) -> TargetPlatform:
    """The platform a live beacon reported through its id prefix."""
    bid = (beacon_id or "").strip().upper()
    for prefix, platform in _BEACON_PREFIXES:
        if bid.startswith(prefix):
            return TargetPlatform(platform=platform, arch="x64",
                                  os_name=platform.capitalize(),
                                  source=f"beacon id {prefix}")
    return TargetPlatform()


def assumed_linux(reason: str = "nothing detected",
                  arch: str = "x64") -> TargetPlatform:
    """The default the caller must ANNOUNCE before shipping an artefact.

    Kept as an explicit constructor so the assumption is greppable: a
    silent Linux default is exactly the bug this module exists to stop.
    """
    return TargetPlatform(platform="linux", arch=arch,
                          os_name="Unknown (defaulting to Linux x64)",
                          source=reason, assumed=True)


def resolve(*candidates: Optional[TargetPlatform]) -> TargetPlatform:
    """First candidate that DETECTED something; the empty platform else.

    The order is the caller's confidence order (findings, then XML, then
    scan text), and an assumed answer never wins over a detected one —
    that is the whole point of tracking `assumed` separately.
    """
    for candidate in candidates:
        if candidate is not None and candidate.known:
            return candidate
    for candidate in candidates:
        if candidate is not None and candidate.platform and not candidate.known:
            return candidate
    return TargetPlatform()


def is_kernel_compatible(platform: str, artefact_platform: str) -> bool:
    """True when an artefact built for `artefact_platform` could run here.

    PE ≠ ELF ≠ Mach-O: shipping a binary across families is not a degraded
    deployment, it is a guaranteed failure. Used to refuse instead of
    hoping. Android is Linux-compatible (same ELF), iOS is not.
    """
    a = (platform or "").strip().lower()
    b = (artefact_platform or "").strip().lower()
    if not a or not b:
        return False
    if a == b:
        return True
    return {a, b} == {"android", "linux"}
