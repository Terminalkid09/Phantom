#!/usr/bin/env python3
"""beacon_matrix_verify.py — verify ONE cell of the beacon grid.

`ci_beacon_smoke.py` answers "did a real binary come out of the release path?".
This answers the next question, cell by cell: "is it the artefact the GRID says
this (os, arch, transport) cell must produce?" — container, architecture, and
the parity gap that cell is allowed to have.

The expected values come from ``phantom.utils.beacon_matrix``, so there is no
second copy of the truth to drift (the smoke script's own magic table was a
start; this one is derived from the grid the docs quote).

Three modes:

  ``--lint``        validate the grid offline (no build, no artefact)
  ``--write-docs``  regenerate the grid block in docs/beacon_platform_matrix.md
  ``--platform``    verify a built artefact against its cell

Exit codes, matching the smoke script's contract so a job can tell the cases
apart: 0 = verified, 1 = BROKEN (wrong container/architecture/grid), 2 = SKIPPED
because no artefact of that cell is present (``--require`` turns that into a
failure, for a job that is supposed to build it).

What it deliberately does NOT claim: that the transport or a feature is
compiled in. The beacon's command literals are XOR-obfuscated, so string
evidence would be theatre. Format + architecture are facts read out of the
artefact; transport and pinning are REPORTED from the grid as declared, and the
per-OS compile jobs are what exercise them.
"""
from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_MAGIC = {
    "ELF": [(b"\x7fELF", "ELF")],
    "PE": [(b"MZ", "PE")],
    "Mach-O": [
        (b"\xcf\xfa\xed\xfe", "Mach-O 64 (little endian)"),
        (b"\xce\xfa\xed\xfe", "Mach-O 32 (little endian)"),
        (b"\xca\xfe\xba\xbe", "Mach-O universal"),
    ],
}

_SCAN_BYTES = 4096


def _fail(message: str) -> int:
    print(f"MATRIX FAIL: {message}")
    return 1


def _read_head(path: str, size: int = _SCAN_BYTES) -> bytes:
    with open(path, "rb") as handle:
        return handle.read(size)


def artefact_machine(path: str, container: str) -> int:
    """The architecture field of an ELF/PE/Mach-O, or -1 when unreadable.

    One function per container so the caller can say WHICH check failed (the
    smoke script learned that lesson: "it is not an ELF" and "it is an ELF of
    the wrong architecture" are different bugs).
    """
    head = _read_head(path)
    if container == "ELF":
        if len(head) < 20 or head[:4] != b"\x7fELF":
            return -1
        little = head[5] == 1
        return int.from_bytes(head[18:20], "little" if little else "big")
    if container == "PE":
        if len(head) < 0x40 or head[:2] != b"MZ":
            return -1
        offset = int.from_bytes(head[0x3C:0x40], "little")
        if offset <= 0 or len(head) < offset + 6:
            return -1
        if head[offset:offset + 4] != b"PE\x00\x00":
            return -1
        return int.from_bytes(head[offset + 4:offset + 6], "little")
    if container == "Mach-O":
        if len(head) < 8:
            return -1
        magic = head[:4]
        if magic not in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
            return -1
        return int.from_bytes(head[4:8], "little")
    return -1


def _candidates(beacon_dir: str, platform: str, explicit=None) -> list:
    from phantom.utils.beacon_matrix import ARTEFACTS
    names = [str(explicit)] if explicit else list(ARTEFACTS.get(platform, ()))
    out = []
    for name in names:
        candidate = name if os.path.isabs(name) else os.path.join(beacon_dir, name)
        if os.path.exists(candidate):
            out.append(candidate)
    return out


def verify_cell(platform: str, arch: str, beacon_dir: str = "",
                explicit=None, any_arch: bool = False) -> int:
    """Verify one cell's artefact. Returns the process exit code.

    ``any_arch`` accepts any architecture the grid declares for the platform
    (macOS runners are arm64 OR Intel, and the builder compiles for the host),
    while still refusing a wrong container. The matched arch is printed, so the
    job log says which cell was actually built.
    """
    from phantom.utils.beacon_matrix import (
        ARCHES, ARTEFACTS, FORMAT, machine_for, missing_verbs, pin_primitive,
        TRANSPORTS, matrix_errors)
    from phantom.core.task_policy import BEACON_VERBS

    if platform not in FORMAT:
        return _fail(f"unknown platform {platform!r}")
    errors = matrix_errors(BEACON_VERBS)
    if errors:
        return _fail("the grid itself is malformed: " + "; ".join(errors))

    container = FORMAT[platform]
    beacon_dir = beacon_dir or os.path.join(ROOT, "phantom", "payloads", "beacon")
    paths = _candidates(beacon_dir, platform, explicit)
    if not paths:
        print(f"MATRIX SKIP ({platform}/{arch}): no artefact in {beacon_dir} "
              f"(looked for {', '.join(ARTEFACTS.get(platform, ()))})")
        return 2

    want_name, want_value = machine_for(platform, arch)
    accepted = ({arch: (want_name, want_value)}
                if not any_arch else
                {a: machine_for(platform, a) for a in ARCHES[platform]})
    checked = []
    for path in paths:
        size = os.path.getsize(path)
        if size < 1024:
            checked.append(f"{os.path.basename(path)}={size}B (too small)")
            continue
        head = _read_head(path)
        magic_ok = any(head.startswith(magic) for magic, _ in _MAGIC[container])
        if not magic_ok:
            checked.append(f"{os.path.basename(path)}={size}B "
                           f"(magic={head[:4]!r}, want {container})")
            continue
        machine = artefact_machine(path, container)
        matched = next((a for a, (_, value) in accepted.items()
                        if value == machine), "")
        if not matched:
            wanted = ", ".join(f"0x{value:08x} {name} ({a})"
                               for a, (name, value) in accepted.items())
            checked.append(f"{os.path.basename(path)}={size}B "
                           f"(machine=0x{machine:08x}, want {wanted})")
            continue
        want_name, _ = accepted[matched]
        arch = matched
        gap = sorted(missing_verbs(platform, BEACON_VERBS))
        print(f"MATRIX OK ({platform}/{arch}): {os.path.basename(path)} "
              f"({size} bytes, {container}, {want_name})")
        print(f"  transport: {TRANSPORTS[platform]} "
              f"(pin {pin_primitive(platform)}) — declared by the grid; the "
              f"per-OS compile job is what exercises it")
        print(f"  parity gap on this OS: {gap if gap else 'none'}")
        return 0
    return _fail(f"no {platform}/{arch} {container} artefact matches the grid "
                 f"[{'; '.join(checked)}]")


def write_docs(path: str = "") -> int:
    """Regenerate the grid block in the platform-matrix page."""
    from phantom.utils.beacon_matrix import markdown_block, to_markdown
    target = path or os.path.join(ROOT, "docs", "beacon_platform_matrix.md")
    with open(target, encoding="utf-8", newline="") as handle:
        text = handle.read()
    block = to_markdown()
    if markdown_block(text):
        start = text.index(markdown_block(text))
        end = start + len(markdown_block(text))
        updated = text[:start] + block + text[end:]
    else:
        section = ("## The enforced grid (feature × OS × arch × transport)\n\n"
                   "This table is GENERATED from `phantom/utils/beacon_matrix.py`\n"
                   "and checked by `tests/test_beacon_matrix.py`: every C2 verb,\n"
                   "every source header and every documented Windows-only module\n"
                   "is classified here, and the docs quote the same data the code\n"
                   "enforces. Regenerate with\n"
                   "`python scripts/beacon_matrix_verify.py --write-docs`.\n\n"
                   + block + "\n\n")
        marker = text.find("\n## ")
        updated = (text[:marker + 1] + section + text[marker + 1:]
                   if marker != -1 else text.rstrip("\n") + "\n\n" + section)
    with open(target, "w", encoding="utf-8", newline="") as handle:
        handle.write(updated)
    print(f"wrote the grid block into {target}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", default="")
    parser.add_argument("--arch", default="")
    parser.add_argument("--artefact", default="",
                        help="explicit artefact path (default: the grid's "
                             "names inside the beacon dir)")
    parser.add_argument("--beacon-dir", default="")
    parser.add_argument("--any-arch", action="store_true",
                        help="accept any arch the grid declares for the "
                             "platform (macOS runners are arm64 or Intel)")
    parser.add_argument("--require", action="store_true",
                        help="a SKIP becomes a failure")
    parser.add_argument("--lint", action="store_true",
                        help="validate the grid offline")
    parser.add_argument("--write-docs", action="store_true")
    args = parser.parse_args(argv)

    if args.write_docs:
        return write_docs()

    from phantom.core.task_policy import BEACON_VERBS
    from phantom.utils.beacon_matrix import ARCHES, matrix_errors

    if args.lint:
        errors = matrix_errors(BEACON_VERBS)
        if errors:
            return _fail("; ".join(errors))
        print("MATRIX OK: the grid is well formed and covers every C2 verb")
        return 0

    if not args.platform:
        parser.error("--platform is required (or use --lint/--write-docs)")
    arch = args.arch or ARCHES.get(args.platform, ("",))[0]
    if arch not in ARCHES.get(args.platform, ()):
        return _fail(f"{args.platform} has no arch {arch!r} "
                     f"(known: {ARCHES.get(args.platform)})")
    code = verify_cell(args.platform, arch, args.beacon_dir or "",
                       args.artefact or None, any_arch=args.any_arch)
    return 1 if (code == 2 and args.require) else code


if __name__ == "__main__":
    raise SystemExit(main())
