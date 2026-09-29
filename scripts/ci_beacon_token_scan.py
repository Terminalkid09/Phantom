#!/usr/bin/env python3
"""Gate: a DEPLOYED beacon must not carry the deployment-wide payload token.

The builder enrols a per-beacon identity and writes ``crypto_config.h`` with an
EMPTY ``C2_PAYLOAD_TOKEN``; the beacon then derives its own download token from
its per-beacon secret at runtime. If that ever regresses, one captured binary
hands an analyst the token that unlocks EVERY payload, forever.

Two halves, both required:

  1. generator contract — a legacy build (token passed in) embeds it, an
     enrolled build (``payload_token=""``) does not. This proves the header
     generator, independent of any compiler.
  2. artefact scan — the REAL built binary contains no trace of the canary
     token, in UTF-8 or UTF-16LE.

Usage (CI):
    PHANTOM_PAYLOAD_TOKEN=<canary> python scripts/ci_beacon_smoke.py --platform linux --require
    python scripts/ci_beacon_token_scan.py --artefact <built-binary> --token <canary>
"""
import argparse
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _generator_contract(token: str) -> int:
    from phantom.utils.c2_crypto import write_beacon_crypto_config

    tmp = tempfile.mkdtemp(prefix="tokscan_")
    legacy = write_beacon_crypto_config(tmp, payload_token=token)
    with open(legacy, "r", encoding="utf-8") as handle:
        text = handle.read()
    if token not in text:
        print("TOKEN SCAN FAIL: legacy build did not embed the token "
              "(the canary is meaningless if it never appears)")
        return 1

    enrolled = write_beacon_crypto_config(tmp, payload_token="")
    with open(enrolled, "r", encoding="utf-8") as handle:
        text = handle.read()
    if token in text:
        print("TOKEN SCAN FAIL: an ENROLLED build embedded the deployment "
              "payload token")
        return 1
    if '#define C2_PAYLOAD_TOKEN ""' not in text:
        print("TOKEN SCAN FAIL: enrolled build did not blank "
              "C2_PAYLOAD_TOKEN")
        return 1
    print("TOKEN SCAN: generator contract OK "
          "(legacy embeds, enrolled blanks)")
    return 0


def _scan_artefact(path: str, token: str) -> int:
    if not os.path.isfile(path):
        print(f"TOKEN SCAN FAIL: artefact not found: {path}")
        return 1
    with open(path, "rb") as handle:
        blob = handle.read()
    needles = {
        "utf-8": token.encode("utf-8"),
        "utf-16le": token.encode("utf-16-le"),
        "utf-16be": token.encode("utf-16-be"),
    }
    for label, needle in needles.items():
        if needle in blob:
            print(f"TOKEN SCAN FAIL: {os.path.basename(path)} contains the "
                  f"deployment token as {label} ({len(blob)} bytes scanned)")
            return 1
    print(f"TOKEN SCAN: {os.path.basename(path)} is clean "
          f"({len(blob)} bytes, no canary)")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artefact", default="",
                        help="built beacon binary to scan")
    parser.add_argument("--token", default="",
                        help="canary value the build was told to use "
                             "(defaults to PHANTOM_PAYLOAD_TOKEN)")
    args = parser.parse_args(argv)

    token = args.token or os.environ.get("PHANTOM_PAYLOAD_TOKEN", "")
    if not token:
        token = "phantom-token-canary-do-not-ship"
    if _generator_contract(token):
        return 1
    if args.artefact:
        return _scan_artefact(args.artefact, token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
