#!/usr/bin/env python3
"""Real beacon source hygiene checks (the old job only tested file existence).

Every check here is a bug class that has actually bitten the payload at least
once, or that would put a secret in the repo:

  * a required translation unit vanished (build breaks far from here);
  * a generated header (c2_config.h / crypto_config.h / beacon_auth.h /
    build_id.h / config_encrypted.h / malleable_config.h) got COMMITTED —
    these carry per-engagement endpoints, a per-beacon HMAC secret and the
    payload token, and a fresh checkout must regenerate them;
  * a build artefact (*.o / *.exe / *.bin / *.pe) got committed;
  * a debug print left in the shipping source;
  * a deployment-wide secret literal in tracked source.

Run: python scripts/ci_beacon_lint.py
Exits non-zero on the first violated rule, printing the offender.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BEACON = os.path.join(ROOT, "phantom", "payloads", "beacon", "src")
REMOTE = os.path.join(ROOT, "phantom", "payloads", "remote", "src")

REQUIRED = {
    BEACON: ("main.cpp", "crypto.h", "network.h", "recon.h", "screenshot.h",
             "media_utils.h", "gps.h", "camera.h", "audio.h",
             "screen_record.h", "evasion.h", "sleep_mask.h", "peb_unlink.h"),
    REMOTE: ("main.cpp", "crypto.h", "remote_net.h"),
}

# Generated per build/engagement — must never be tracked.
GENERATED = ("c2_config.h", "crypto_config.h", "beacon_auth.h",
             "build_id.h", "config_encrypted.h", "malleable_config.h")
GENERATED_DIRS = ("phantom/payloads/beacon/src", "phantom/payloads/remote/src")

ARTIFACT_SUFFIXES = (".o", ".obj", ".exe", ".bin", ".pe", ".dll", ".so",
                     ".dylib", ".rva", ".map", ".pdb", ".ilk", ".exp", ".lib")

DEBUG_MARKERS = ('printf("DEBUG', 'printf("debug', 'std::cout << "DEBUG',
                 'std::cerr <<', 'fprintf(stderr, "DEBUG')

# A tracked header with a NON-EMPTY value for any of these is a leak.
SECRET_DEFINES = ("C2_PAYLOAD_TOKEN", "BEACON_AUTH_SECRET")


def _fail(message: str) -> int:
    print(f"LINT FAIL: {message}")
    return 1


def _git(*args: str) -> str:
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                              text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return ""


def check_required() -> int:
    for directory, names in REQUIRED.items():
        for name in names:
            if not os.path.isfile(os.path.join(directory, name)):
                return _fail(f"missing beacon source file: {name} "
                             f"(in {os.path.relpath(directory, ROOT)})")
    return 0


def check_pragma_once() -> int:
    for directory in (BEACON, REMOTE):
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".h"):
                continue
            path = os.path.join(directory, name)
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                head = "".join(handle.readline() for _ in range(3))
            if "#pragma once" not in head:
                return _fail(f"{name} is missing '#pragma once'")
    return 0


def check_generated_not_tracked() -> int:
    tracked = _git("ls-files").splitlines()
    if not tracked:
        print("LINT NOTE: not a git checkout — skipping tracked-file checks")
        return 0
    for path in tracked:
        base = os.path.basename(path)
        norm = path.replace("\\", "/")
        if base in GENERATED and any(norm.startswith(d) for d in GENERATED_DIRS):
            return _fail(f"generated header is TRACKED: {path} "
                         f"(run: git rm --cached {path})")
        if norm.endswith(ARTIFACT_SUFFIXES) and norm.startswith(
                ("phantom/payloads/beacon", "phantom/payloads/remote")):
            return _fail(f"build artefact is TRACKED: {path}")
    return 0


def check_gitignore_covers_generated() -> int:
    path = os.path.join(ROOT, ".gitignore")
    if not os.path.isfile(path):
        return _fail(".gitignore is missing")
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    for name in GENERATED:
        if name not in text:
            return _fail(f".gitignore does not ignore the generated {name}")
    return 0


def check_no_debug_prints() -> int:
    for directory in (BEACON, REMOTE):
        for name in sorted(os.listdir(directory)):
            if not name.endswith((".h", ".cpp", ".c")):
                continue
            with open(os.path.join(directory, name), "r",
                      encoding="utf-8", errors="replace") as handle:
                for lineno, line in enumerate(handle, 1):
                    for marker in DEBUG_MARKERS:
                        if marker in line:
                            return _fail(f"debug print left in {name}:{lineno}")
    return 0


def check_no_tracked_secrets() -> int:
    tracked = _git("ls-files").splitlines()
    if not tracked:
        return 0
    for path in tracked:
        if not path.endswith((".h", ".cpp", ".c")):
            continue
        if not path.startswith(("phantom/payloads/beacon",
                                "phantom/payloads/remote")):
            continue
        full = os.path.join(ROOT, path)
        if not os.path.isfile(full):
            continue
        with open(full, "r", encoding="utf-8", errors="replace") as handle:
            for lineno, line in enumerate(handle, 1):
                stripped = line.strip()
                for define in SECRET_DEFINES:
                    # Only a NON-EMPTY literal is a leak; `#define X ""` and a
                    # zero-initialised secret are the documented CI shapes.
                    if (stripped.startswith(f"#define {define} ")
                            and '""' not in stripped):
                        return _fail(f"{path}:{lineno} embeds a {define} "
                                     f"literal in tracked source")
    return 0


CHECKS = (check_required, check_pragma_once, check_generated_not_tracked,
          check_gitignore_covers_generated, check_no_debug_prints,
          check_no_tracked_secrets)


def main() -> int:
    for check in CHECKS:
        rc = check()
        if rc:
            return rc
    total = sum(len(files) for _, _, files in os.walk(BEACON))
    print(f"LINT OK: {len(CHECKS)} hygiene checks passed "
          f"({total} files under beacon/src)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
