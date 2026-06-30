#!/usr/bin/env python3
"""Generate crypto_config.h before CI beacon compilation."""
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dotenv import load_dotenv
load_dotenv(os.path.join(ROOT, ".env"))

from phantom.utils.c2_crypto import write_beacon_crypto_config

if __name__ == "__main__":
    beacon_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "phantom", "payloads", "beacon",
    )
    path = write_beacon_crypto_config(beacon_dir)
    print(f"Wrote {path}")
