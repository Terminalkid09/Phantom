#!/usr/bin/env python3
"""Generate the headers CI needs before compiling a beacon or remote module.

Uses the REAL generators instead of a hand-written stub: a drift in the
generated header (a renamed macro, a malformed array, a new required define)
then fails HERE, in CI, instead of only on an operator's machine.

``--ci-identity`` writes a throwaway identity with an all-zero secret — the
same shape a build with no enrolled identity compiles against, where the
crypto layer falls back to the deployment key. It also empties
``C2_PAYLOAD_TOKEN``, exactly like a real enrolled build, so the syntax job
exercises the per-beacon token path rather than the legacy one.
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dotenv import load_dotenv
load_dotenv(os.path.join(ROOT, ".env"))

from phantom.utils.c2_crypto import (
    write_beacon_c2_config,
    write_beacon_crypto_config,
)

_STUB_IDENTITY = """#pragma once
// CI-only throwaway identity. NOT a secret: the all-zero secret makes the
// crypto layer fall back to the deployment key, which is what a build with no
// enrolled identity speaks.
#define BEACON_AUTH_ENABLED 1
#define BEACON_MTLS_ENABLED 1
#define BEACON_AUTH_ID "CI-BEACON"
#define BEACON_SERVER_FINGERPRINT "0000000000000000000000000000000000000000000000000000000000000000"
static const unsigned char BEACON_AUTH_SECRET[32] = {0};
static const char BEACON_CLIENT_CERT_PEM[] = "";
static const char BEACON_CLIENT_KEY_PEM[] = "";
static const char BEACON_CLIENT_CA_PEM[] = "";
static const unsigned char BEACON_CLIENT_PFX[] = {0};
static const unsigned long BEACON_CLIENT_PFX_LEN = 1;
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default=os.path.join(
        ROOT, "phantom", "payloads", "beacon"),
        help="payload directory to generate headers for")
    parser.add_argument("--ci-identity", action="store_true",
                        help="also write the throwaway CI identity header")
    parser.add_argument("--host", default="127.0.0.1",
                        help="endpoint burned into c2_config.h (never dialled "
                             "by a syntax/build check)")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()

    payload_dir = os.path.abspath(args.dir)
    if not os.path.isdir(os.path.join(payload_dir, "src")):
        print(f"ERROR: {payload_dir} has no src/ directory")
        return 1

    # An enrolled build carries no deployment token; the CI identity models
    # exactly that shape.
    token = "" if args.ci_identity else None
    print(f"Wrote {write_beacon_crypto_config(payload_dir, payload_token=token)}")
    # The C2 endpoint header too: a fresh checkout has neither, the compile
    # step includes it, and they are build artefacts wherever they exist.
    print(f"Wrote {write_beacon_c2_config(payload_dir, host=args.host, port=args.port, use_ssl=False)}")

    if args.ci_identity:
        path = os.path.join(payload_dir, "src", "beacon_auth.h")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(_STUB_IDENTITY)
        print(f"Wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
