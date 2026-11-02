#!/usr/bin/env python3
"""stage_hid_usb.py — copy the prepared HID drop onto a removable volume.

The engagement artefacts are BUILT into ``data/usb/hp_hid/`` (see the printout
of ``payload hid ...``); this script is only the transport, because Phantom has
no "write to drive E:" command and a stick is not always plugged in.

It refuses to guess: the copy only happens onto a volume Windows reports as
``Removable`` (or a directory the operator names explicitly). A wrong target is
a payload dropped on a corporate share, so the default is to LIST and do
nothing when more than one removable volume is present.

    python scripts/stage_hid_usb.py --list
    python scripts/stage_hid_usb.py --to E:\\ --dry-run
    python scripts/stage_hid_usb.py --to E:\\
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "data" / "usb" / "hp_hid"
TARGET_DIR = "PHANTOM_HP"


def removable_volumes() -> list[dict[str, str]]:
    """``[{letter, label}]`` for volumes Windows reports as Removable.

    WMI/CIM through PowerShell rather than a hard-coded drive list: the letter
    changes between machines and between two plugs on the SAME machine.
    """
    script = ("Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' | "
              "ForEach-Object { \"$($_.DeviceID)\t$($_.VolumeName)\" }")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", script],
                             capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return []
    volumes = []
    for line in (out.stdout or "").splitlines():
        letter, _, label = line.partition("\t")
        letter = letter.strip()
        if letter:
            volumes.append({"letter": letter, "label": label.strip()})
    return volumes


def stage(destination: Path, *, dry_run: bool = False) -> list[str]:
    """Copy every artefact into ``destination/PHANTOM_HP``; return the names."""
    files = sorted(p for p in SOURCE.iterdir() if p.is_file()) if SOURCE.is_dir() else []
    if not files:
        raise FileNotFoundError(
            f"nothing to stage: {SOURCE} is empty (build the artefacts first)")
    target = destination / TARGET_DIR
    copied: list[str] = []
    for path in files:
        if not dry_run:
            target.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target / path.name)
        copied.append(path.name)
    return copied


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--to", default="",
                        help=r"removable volume or directory (e.g. E:\\)")
    parser.add_argument("--list", action="store_true",
                        help="list removable volumes and the staged artefacts")
    parser.add_argument("--dry-run", action="store_true",
                        help="say what would be copied, copy nothing")
    args = parser.parse_args(argv)

    volumes = removable_volumes()
    if args.list or not args.to:
        print(f"artefacts in {SOURCE}:")
        for path in sorted(SOURCE.iterdir()) if SOURCE.is_dir() else []:
            print(f"  {path.name}  ({path.stat().st_size} bytes)")
        if not volumes:
            print("\nno REMOVABLE volume detected: plug the stick in and re-run "
                  "with --to <letter> (or without --to to detect it).")
            return 2 if not args.to else 0
        print("\nremovable volume(s):")
        for volume in volumes:
            print(f"  {volume['letter']}  {volume['label'] or '(no label)'}")
        return 0

    destination = Path(args.to)
    if not destination.exists():
        print(f"no such volume/directory: {destination}")
        return 2
    # A destination that is not a removable volume is allowed (a mounted
    # directory on POSIX), but it has to be said out loud.
    if volumes and destination.drive and not any(
            volume["letter"].startswith(destination.drive.rstrip(":\\/"))
            for volume in volumes):
        print(f"warning: {destination} is not one of the removable volumes "
              f"({', '.join(v['letter'] for v in volumes)})")

    try:
        copied = stage(destination, dry_run=args.dry_run)
    except FileNotFoundError as exc:
        print(exc)
        return 2
    verb = "would copy" if args.dry_run else "copied"
    print(f"{verb} {len(copied)} artefact(s) -> "
          f"{destination / TARGET_DIR}")
    for name in copied:
        print(f"  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
