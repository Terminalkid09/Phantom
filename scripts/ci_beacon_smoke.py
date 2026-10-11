#!/usr/bin/env python3
"""Release-path beacon smoke test — per target.

Not a syntax check: this runs the SAME ``compile_beacon`` the release and the
``payload beacon`` command run, for ONE concrete target, and asserts the
artefact is a real, non-empty binary of that platform's format. A break in the
generated headers, the build flags or the single-translation-unit link fails
HERE — before release, not at an engagement.

Which targets a runner can actually build:

  linux    g++ + OpenSSL headers (every Linux runner)
  windows  MinGW (g++ AND as) — no OpenSSL needed, the beacon uses BCrypt
  macos    native clang++ with brew's openssl@3, or an osxcross toolchain
  android  the NDK alone is NOT enough: the beacon links OpenSSL, which the
           NDK does not ship. Needs OPENSSL_ANDROID_ROOT (a built OpenSSL for
           the same ABI) and a prebuilt llvm toolchain path (ANDROID_NDK_HOME).
           The artefact is verified as an aarch64 ELF (e_machine 0xB7), not
           merely as "an ELF": the NDK target triple is the requirement.

Exit codes: 0 = built and verified, 1 = broken, 2 = SKIPPED because the
toolchain for that target is not present on this runner. ``--require`` turns a
skip into a failure, so a job that is SUPPOSED to build a target cannot pass
by skipping it.
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Leading bytes of each platform's executable format.
MAGIC = {
    "linux": [(b"\x7fELF", "ELF")],
    "windows": [(b"MZ", "PE")],
    "macos": [
        (b"\xcf\xfa\xed\xfe", "Mach-O 64 (little endian)"),
        (b"\xce\xfa\xed\xfe", "Mach-O 32 (little endian)"),
        (b"\xca\xfe\xba\xbe", "Mach-O universal"),
    ],
    "android": [(b"\x7fELF", "ELF")],
}

# Some targets hand back a DERIVED artefact (Windows returns the raw in-memory
# image the loader injects, not the PE). The PE itself is still the thing that
# proves the toolchain, the generated headers and the link all worked, so it is
# accepted as a sibling of whatever the builder returned.
FALLBACK_ARTEFACT = {
    "windows": ["beacon.pe"],
}

# (e_machine, name) each target MUST carry. The magic byte says "an ELF";
# it does not say WHICH architecture, and the Android job's whole point is
# that an aarch64 payload was actually produced. A wrong NDK triple, or a
# linker that quietly fell back to the host, still starts with \x7fELF — so
# the machine field is checked too, not just the first four bytes.
_ARCH = {
    "linux": (0x3E, "x86-64"),
    "android": (0xB7, "AArch64"),
}

ELF_HEADER_BYTES = 20


def _arch_mismatch(head: bytes, platform: str) -> str:
    """Why this ELF is not what ``platform`` must produce, or "" if it is.

    "" for a platform with no expected architecture (macOS ships Mach-O, not
    ELF) and for anything that is not an ELF at all — the magic check already
    owns that verdict, and saying it twice would only half-fail twice.
    """
    expected = _ARCH.get(platform)
    if not expected or len(head) < ELF_HEADER_BYTES or head[:4] != b"\x7fELF":
        return ""
    ei_class, ei_data = head[4], head[5]
    machine = int.from_bytes(head[18:20], "little" if ei_data == 1 else "big")
    want, name = expected
    if ei_class != 2:
        return f"not 64-bit (EI_CLASS={ei_class})"
    if ei_data != 1:
        return f"not little-endian (EI_DATA={ei_data})"
    if machine != want:
        return f"e_machine=0x{machine:02x}, expected 0x{want:02x} ({name})"
    return ""


def _candidates(path: str, platform: str) -> list:
    out = [path]
    directory = os.path.dirname(os.path.abspath(path))
    for name in FALLBACK_ARTEFACT.get(platform, []):
        out.append(os.path.join(directory, name))
    return [candidate for candidate in out if candidate and os.path.exists(candidate)]


def _toolchain_ready(platform: str) -> "tuple[bool, str]":
    """Can this runner build the target at all? (checked BEFORE compiling so a
    missing toolchain is a clear SKIP, not a confusing compile error)."""
    import shutil
    if platform == "linux":
        return True, ""
    if platform == "windows":
        compiler = shutil.which("x86_64-w64-mingw32-g++") or shutil.which("g++")
        assembler = shutil.which("x86_64-w64-mingw32-as") or shutil.which("as")
        if not compiler or not assembler:
            return False, "MinGW needs both g++ and as on PATH"
        return True, ""
    if platform == "macos":
        if sys.platform == "darwin":
            return True, ""
        root = os.environ.get("OSXCROSS_ROOT", "/opt/osxcross")
        if os.path.exists(os.path.join(root, "bin", "o32-clang++")):
            return True, ""
        return False, ("macOS needs to run on a macOS runner, or a full "
                       "osxcross toolchain in OSXCROSS_ROOT")
    if platform == "android":
        ndk = (os.environ.get("ANDROID_NDK_HOME")
               or os.environ.get("ANDROID_NDK_LATEST_HOME")
               or "/opt/android-ndk")
        compiler = os.path.join(ndk, "toolchains", "llvm", "prebuilt",
                                "linux-x86_64", "bin",
                                "aarch64-linux-android28-clang++")
        if not os.path.exists(compiler):
            return False, f"NDK compiler not found at {compiler}"
        # The NDK does not ship OpenSSL. The build helper cross-compiles it
        # into the NDK sysroot on first use (~a few minutes, needs network),
        # so it is NOT a precondition — just be loud about it.
        if not os.environ.get("OPENSSL_ANDROID_ROOT"):
            print("NOTE: OpenSSL for Android will be cross-compiled on this "
                  "run (or set OPENSSL_ANDROID_ROOT to skip that).")
        return True, ""
    return False, f"unknown platform {platform}"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", default="linux",
                        choices=sorted(MAGIC))
    parser.add_argument("--require", action="store_true",
                        help="a SKIP becomes a failure (for a job that is "
                             "supposed to build this target)")
    args = parser.parse_args(argv)

    ready, reason = _toolchain_ready(args.platform)
    if not ready:
        print(f"SMOKE SKIP ({args.platform}): {reason}")
        return 1 if args.require else 2

    import phantom
    from phantom.utils.builder import compile_beacon
    # compile_beacon() takes the PACKAGE root — the directory that CONTAINS
    # `payloads/` — exactly as the CLI, the API and the payload generator pass
    # it (`os.path.dirname(phantom.__file__)`). Handing it the REPO root made
    # every smoke build look in `<repo>/payloads/beacon`: a path that only
    # exists if an earlier run created it (it is gitignored), so the assembler
    # died with "can't open .../src/syscalls.asm" on Windows and the generated
    # headers were written outside the package elsewhere. Every beacon-smoke
    # job was red for this reason alone.
    pkg_root = os.path.dirname(os.path.abspath(phantom.__file__))
    path = compile_beacon(args.platform, pkg_root, force_rebuild=True,
                          host="127.0.0.1", port=8443, use_ssl=True)
    if not path:
        print(f"SMOKE FAIL: compile_beacon({args.platform}) returned no "
              f"artefact")
        return 1
    checked = []
    for candidate in _candidates(path, args.platform):
        size = os.path.getsize(candidate)
        if size < 1024:
            checked.append(f"{os.path.basename(candidate)}={size}B (too small)")
            continue
        with open(candidate, "rb") as handle:
            head = handle.read(ELF_HEADER_BYTES)
        for magic, label in MAGIC[args.platform]:
            if head.startswith(magic):
                wrong = _arch_mismatch(head, args.platform)
                if wrong:
                    checked.append(f"{os.path.basename(candidate)}={size}B "
                                   f"(ELF, but {wrong})")
                    break
                print(f"SMOKE OK ({args.platform}): "
                      f"{os.path.basename(candidate)} ({size} bytes, {label})")
                return 0
        checked.append(f"{os.path.basename(candidate)}={size}B "
                       f"(magic={head[:4]!r})")
    print(f"SMOKE FAIL: no {args.platform} binary produced "
          f"[returned {os.path.basename(path)}; {', '.join(checked)}]")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
