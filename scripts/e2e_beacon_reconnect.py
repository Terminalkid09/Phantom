#!/usr/bin/env python3
"""e2e_beacon_reconnect.py — does a REAL beacon survive a C2 outage?

The protocol smoke (``e2e_c2_beacon_smoke.py``) drives HTTP from Python: it
proves the routes, the HMAC and the envelope crypto, and says nothing about the
beacon's own retry loop. The question this script answers is the one an
operator asks before a HID drop:

    "if the listener is down when the implant starts, does it die — and if the
     listener goes away mid-engagement, does it come back on its own?"

It runs the compiled beacon binary, so the answer comes from the C++ loop
(``main.cpp``: ``while (alive)`` + exponential backoff capped at 60 s, base
sleep restored on the first successful check-in), not from a model of it.

Timeline:

    1. the C2 starts on loopback, plaintext (``use_ssl=False``)
    2. the beacon starts -> a LIVE check-in must register it
    3. the C2 stops -> the beacon process must stay alive (it never exits on
       a failed check-in; a task-level kill is the only way out)
    4. the C2 restarts on the SAME port -> a NEW check-in must arrive
       without touching the beacon

A failure in step 3 is "the implant dies with the listener". A failure in
step 4 is "the implant survives but never returns". Both are reported as
distinct failures, because they have different operator consequences.

Platforms: the beacon is a native binary, so this runs on the platform that
can execute it. On Windows, a Linux artefact is executed inside WSL when the
``wsl`` command is present (the C2 stays on the host: WSL2 forwards
``127.0.0.1`` to it). Otherwise pass ``--bin`` pointing at an executable for
the local OS.

Usage:

    python scripts/e2e_beacon_reconnect.py                 # auto-detect
    python scripts/e2e_beacon_reconnect.py --bin ./beacon_linux
    python scripts/e2e_beacon_reconnect.py --outage 8 --wait 90

Exit codes: 0 = reconnected, 1 = the run failed, 2 = SKIPPED (no runnable
beacon or no WSL), which is not a pass.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

BEACON_DIR = os.path.join(ROOT, "phantom", "payloads", "beacon")


class _Fail(AssertionError):
    pass


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _snapshot() -> dict[str, str]:
    from phantom.core.c2_server import c2_state
    return {bid: str(info.get("last_seen") or "")
            for bid, info in c2_state.get_beacons().items()}


def _wait_for_checkin(before: dict[str, str], timeout: float,
                      baseline: str = "") -> tuple[str, str, float] | None:
    """A check-in that is NEW relative to ``before`` (and after ``baseline``).

    ``last_seen`` has second resolution, so a beacon that checked in during the
    same second as the snapshot is caught by the string comparison anyway; a
    record that comes back from the persisted store with its old timestamp is
    NOT a check-in and must not be counted as one (that is exactly the false
    positive this filter exists to prevent).
    """
    started = time.time()
    while time.time() - started < timeout:
        for bid, info in _snapshot().items():
            seen = str(info or "")
            if bid in before and before[bid] == seen:
                continue
            if baseline and seen < baseline:
                continue
            return bid, seen, time.time() - started
        time.sleep(1)
    return None


def _wsl_available() -> bool:
    if os.name != "nt":
        return False
    return bool(shutil.which("wsl") or shutil.which("wsl.exe"))


def _wsl_stage_and_run(binary: str) -> str:
    """The ``bash -lc`` script that stages AND runs the ELF inside WSL.

    A path under ``/mnt/c`` is drvfs: it can be slow to exec and it inherits
    the mount's permissions, so the binary is copied into ``/tmp`` inside WSL
    instead. Staging and running are ONE shell command on purpose: WSL may
    tear the distro down between calls and take ``/tmp`` with it, and a
    "file not found" caused by that looks exactly like a beacon that refuses
    to start.
    """
    target = "/tmp/phantom_e2e_beacon"
    src = f"/mnt/{binary[0].lower()}{binary[2:].replace(os.sep, '/')}"
    return (f"install -m 755 '{src}' {target} && "
            f"{target} > /tmp/phantom_e2e_beacon.log 2>&1")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bin", default="",
                    help="beacon executable built for THIS platform")
    ap.add_argument("--port", type=int, default=0,
                    help="C2 port (default: a free port; must match the "
                         "port baked into the binary)")
    ap.add_argument("--outage", type=float, default=8.0,
                    help="seconds the listener stays down")
    ap.add_argument("--wait", type=float, default=90.0,
                    help="seconds to wait for a check-in / a reconnect")
    ap.add_argument("--no-build", action="store_true",
                    help="never build; only use an existing artefact")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="phantom_reconnect_")
    os.environ.setdefault("PHANTOM_ALLOW_PLAINTEXT", "1")
    os.environ.setdefault("PHANTOM_MTLS_REQUIRED", "0")
    os.environ["PHANTOM_C2_BIND"] = "127.0.0.1"
    os.environ["PHANTOM_DATA_DIR"] = os.environ.get("PHANTOM_DATA_DIR", "")

    binary = args.bin.strip()
    runner: list[str] = []
    if not binary:
        # The Linux artefact is the one that can be executed on both a Linux
        # host and a Windows host (through WSL), so it is the default probe.
        candidate = os.path.join(BEACON_DIR, "beacon_linux")
        if os.path.isfile(candidate):
            binary = candidate
        elif not args.no_build:
            print("[*] no artefact: building the Linux beacon...")
            from phantom.utils.builder import compile_beacon
            port = args.port or _free_port()
            built = compile_beacon("linux", os.path.join(ROOT, "phantom"),
                                   force_rebuild=True, host="127.0.0.1",
                                   port=port, use_ssl=False)
            if not built:
                print("SKIP: the Linux beacon could not be built here.")
                return 2
            binary = built
        else:
            print("SKIP: no beacon artefact (--no-build).")
            return 2

    if os.name == "nt" and binary.endswith(("beacon_linux", ".elf")):
        if not _wsl_available():
            print("SKIP: this is a Linux artefact and WSL is not available.")
            return 2
        runner = ["wsl.exe", "-e", "bash", "-lc",
                  _wsl_stage_and_run(os.path.abspath(binary))]
    else:
        runner = [binary]

    from phantom.core.c2_server import C2Server

    port = args.port or _free_port()
    before = _snapshot()
    srv = C2Server()
    srv.start(host="127.0.0.1", port=port, use_ssl=False)
    print(f"[*] C2 on 127.0.0.1:{port} (plaintext, loopback)")
    print(f"[*] beacon: {' '.join(runner)}")

    proc = subprocess.Popen(runner, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        got = _wait_for_checkin(before, args.wait)
        if not got:
            raise _Fail(
                "no LIVE check-in. The beacon was built for another endpoint "
                "(host/port are baked in), the pin does not match, or the "
                "process could not start. Check /tmp/phantom_e2e_beacon.log "
                "inside WSL.")
        beacon_id, seen, took = got
        print(f"[1] first check-in  OK  {beacon_id} in {took:.1f}s")

        before_outage = _snapshot()
        outage_start = time.strftime("%Y-%m-%dT%H:%M:%S")
        srv.stop()
        print(f"[2] C2 stopped      (outage {args.outage:.0f}s starts)")
        time.sleep(args.outage)
        if proc.poll() is not None:
            raise _Fail(
                f"the beacon EXITED during the outage (rc={proc.returncode}): "
                "an implant that dies with the listener cannot be re-armed")
        print("[3] beacon alive    OK  (it retries instead of exiting)")

        srv2 = C2Server()
        srv2.start(host="127.0.0.1", port=port, use_ssl=False)
        print("[4] C2 restarted    (same port, same registry)")
        try:
            again = _wait_for_checkin(before_outage, args.wait,
                                      baseline=outage_start)
            if not again:
                raise _Fail(
                    f"no RE-CONNECT within {args.wait:.0f}s. The process is "
                    "alive but stopped calling back: the backoff cap or the "
                    "endpoint ladder is stuck.")
            rid, rseen, rtook = again
            print(f"[5] reconnected     OK  {rid} after {rtook:.1f}s "
                  f"(last_seen={rseen})")
        finally:
            srv2.stop()
    finally:
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception:
            pass
        try:
            srv.stop()
        except Exception:
            pass
        if runner and runner[0].endswith("wsl.exe"):
            subprocess.run(["wsl.exe", "-e", "bash", "-lc",
                            "pkill -f phantom_e2e_beacon || true"],
                           capture_output=True, text=True)

    print("E2E beacon reconnect: PASS "
          "(check-in, survives outage, reconnects on its own)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except _Fail as exc:
        print(f"E2E beacon reconnect: FAIL — {exc}", file=sys.stderr)
        sys.exit(1)
