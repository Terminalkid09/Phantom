#!/usr/bin/env python3
"""Python <-> Go <-> beacon key-derivation parity, checked in one place.

`c2d` is a second implementation of the wire protocol. HKDF-SHA256 is where a
drift is SILENT: nothing errors, the beacon just never decrypts. So the three
implementations pin the SAME vectors, and this script fails the build if any
side stops producing them:

  * Python  — recomputed here from phantom.utils.c2_crypto
  * Go      — the vectors pinned in c2d/c2d_test.go (and `go test` asserts
              the Go code still produces them)
  * beacon  — the vectors pinned in tests/test_c2_crypto_keys.py, which the
              pytest suite runs; the C++ side is compiled by the beacon jobs

Exit code 1 on any mismatch, with the offending side named.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from phantom.utils.c2_crypto import (  # noqa: E402
    beacon_download_token,
    beacon_envelope_key,
)

SECRET = bytes(range(32))
CASES = {
    "B-TEST": "275c2265389eb7081752b239a2ab65fab82938b05e579d7937ded40bc33b5afc",
    "": "88170beeb2e2a92e1c5875050d69741b6d7384ed20e930ceaa366d2fa50ba182",
    "B-\u00e8-t\u00e9st": "7c6eb272b1b1478f38248badb802e48e71c5af45b8a74b6c68aa67aeff7b337e",
}
DOWNLOAD = "f8a955bf74dc5a93aa0407d58429898600aade9123bb3b23f5bb38dadcb608d6"


def check_python() -> bool:
    ok = True
    for beacon_id, expected in CASES.items():
        got = beacon_envelope_key(SECRET, beacon_id).hex()
        if got != expected:
            print(f"FAIL python envelope key for {beacon_id!r}: {got} != {expected}")
            ok = False
    got = beacon_download_token(SECRET, "B-TEST")
    if got != DOWNLOAD:
        print(f"FAIL python download token: {got} != {DOWNLOAD}")
        ok = False
    if ok:
        print("OK   python (phantom.utils.c2_crypto)")
    return ok


def _pinned(source: str, label: str) -> bool:
    text = open(os.path.join(ROOT, source), "r", encoding="utf-8").read()
    ok = True
    for beacon_id, expected in CASES.items():
        if expected not in text:
            print(f"FAIL {label}: vector for {beacon_id!r} ({expected}) is not "
                  f"pinned in {source}")
            ok = False
    if DOWNLOAD not in text:
        print(f"FAIL {label}: download-token vector is not pinned in {source}")
        ok = False
    if ok:
        print(f"OK   {label}")
    return ok


def check_beacon_source() -> bool:
    """The C++ side derives the key at runtime; assert the code that does it is
    still there in BOTH copies (the beacon and the remote module)."""
    ok = True
    for tree in ("beacon", "remote"):
        path = os.path.join(ROOT, "phantom", "payloads", tree, "src", "crypto.h")
        text = open(path, "r", encoding="utf-8").read()
        missing = [token for token in
                   ("hkdf_sha256", "envelope_key()", "payload_token()",
                    "phantom-envelope:", "phantom-download:")
                   if token not in text]
        if missing:
            print(f"FAIL beacon {tree}/crypto.h is missing: {', '.join(missing)}")
            ok = False
        if re.search(r"EVP_(En|De)cryptInit_ex\(ctx, NULL, NULL, AES_KEY, nonce\)", text):
            print(f"FAIL beacon {tree}/crypto.h still uses the static AES_KEY "
                  f"directly instead of the derived key")
            ok = False
    if ok:
        print("OK   beacon + remote crypto.h")
    return ok


def main() -> int:
    results = [
        check_python(),
        _pinned("c2d/c2d_test.go", "go (c2d/c2d_test.go)"),
        _pinned("tests/test_c2_crypto_keys.py", "beacon tests"),
        check_beacon_source(),
    ]
    if all(results):
        print("PARITY OK: python == go == beacon, one set of vectors.")
        return 0
    print("PARITY BROKEN — a beacon built against one side will not be "
          "readable by the other.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
