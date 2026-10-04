#!/usr/bin/env python3
"""e2e_c2_beacon_smoke.py — end-to-end C2 <-> beacon protocol smoke.

Starts the REAL Python listener on a loopback port and drives the true
beacon lifecycle over HTTP with the real auth and the real per-beacon
envelope crypto:

    1. check-in        -> the beacon registers and the reply decrypts
    2. task round-trip -> the operator queues a command; the next check-in
                          returns it ENCRYPTED and it decrypts back
    3. replay refused  -> the SAME signed request replayed gets 401
    4. result accepted -> an encrypted + HMAC'd task result is stored

No C++ beacon is compiled: this pins the PROTOCOL contract (routes, HMAC
auth, per-request nonce anti-replay, envelope crypto, task queue, result
store) a real beacon speaks to. It is the seam a beacon breaks first and it
runs wherever Python runs, so CI exercises it without a cross-toolchain.

NONCES ARE UNIQUE PER REQUEST (and per run). The listener persists its
replay state across restarts and refuses a nonce first seen under a
previous epoch, so a fixed nonce makes the smoke non-deterministic on the
second run — a real beacon randomises its nonce for the same reason.

Exit 0 on success, 1 on the first failed assertion.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


class _Fail(AssertionError):
    pass


def _check(cond, msg):
    if not cond:
        raise _Fail(msg)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _post(url: str, body: str, headers: dict) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body.encode("utf-8"),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read() or b"").decode("utf-8", errors="replace")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="phantom_e2e_")
    os.environ["PHANTOM_BEACON_REGISTRY"] = os.path.join(tmp, "registry.json")
    # loopback + plaintext (explicitly allowed): the smoke needs neither TLS
    # material nor a route to a real host.
    os.environ["PHANTOM_ALLOW_PLAINTEXT"] = "1"
    os.environ["PHANTOM_MTLS_REQUIRED"] = "0"
    os.environ["PHANTOM_C2_BIND"] = "127.0.0.1"
    # keep the persisted replay state inside this run's temp dir
    os.environ["PHANTOM_DATA_DIR"] = tmp

    from phantom.core.c2_server import C2Server, c2_state
    from phantom.utils.beacon_auth import enroll_beacon, sign_request
    from phantom.utils.c2_crypto import decrypt_for_beacon, encrypt_for_beacon

    beacon_id = "B-E2E-1"
    secret = enroll_beacon(beacon_id)["secret"]
    port = _free_port()
    srv = C2Server()
    srv.start(host="127.0.0.1", port=port, use_ssl=False)
    base = f"http://127.0.0.1:{port}"
    counter = 0

    def headers(path: str, body: str) -> dict:
        nonlocal counter
        counter += 1
        ts = str(int(time.time()))
        h = {
            "X-Beacon-Id": beacon_id,
            "X-Beacon-Timestamp": ts,
            "X-Beacon-Counter": str(counter),
            "X-Beacon-Nonce": secrets.token_hex(16),
            "Content-Type": "text/plain",
        }
        h["X-Beacon-Auth"] = sign_request(secret, "POST", path, ts,
                                          str(counter), h["X-Beacon-Nonce"],
                                          body)
        return h

    try:
        # 1 ── check-in: registers the beacon, encrypted reply ─────────────
        st, body = _post(base + "/api/v1/ping", "", headers("/api/v1/ping", ""))
        _check(st == 200, f"check-in expected 200, got {st} body={body!r}")
        _check(beacon_id in c2_state.get_beacons(),
               "beacon was not registered after check-in")
        plain = decrypt_for_beacon(body, beacon_id)
        _check(isinstance(json.loads(plain or "{}").get("tasks"), list),
               f"check-in reply must decrypt to a tasks list, got {plain!r}")
        print("[1] check-in        OK (registered, encrypted reply)")

        # 2 ── task round-trip: queue -> next check-in returns it ─────────
        task_id = c2_state.queue_task(beacon_id, "whoami")
        _check(bool(task_id), "queue_task returned no id")
        st, body = _post(base + "/api/v1/ping", "", headers("/api/v1/ping", ""))
        _check(st == 200, f"second check-in expected 200, got {st}")
        tasks = json.loads(decrypt_for_beacon(body, beacon_id) or "{}").get("tasks", [])
        _check("whoami" in [t.get("command") for t in tasks],
               f"queued command not returned: {tasks!r}")
        print("[2] task round-trip OK (queued command returned encrypted)")

        # 3 ── replay refused: the identical signed request is rejected ───
        replay = headers("/api/v1/ping", "")
        st, _ = _post(base + "/api/v1/ping", "", replay)
        _check(st == 200, f"fresh replay request expected 200, got {st}")
        st, _ = _post(base + "/api/v1/ping", "", replay)
        _check(st == 401, f"replayed check-in expected 401, got {st}")
        print("[3] replay refused  OK (401 on the same nonce)")

        # 4 ── result accepted and stored ─────────────────────────────────
        payload = json.dumps({"task_id": task_id, "output": "root"})
        enc = encrypt_for_beacon(payload, beacon_id)
        st, resp = _post(base + "/api/v1/result", enc,
                         headers("/api/v1/result", enc))
        _check(st == 200, f"result push expected 200, got {st} ({resp!r})")
        results = c2_state.get_results(beacon_id)
        _check(any(r.get("task_id") == task_id and r.get("output") == "root"
                   for r in results),
               f"result not stored: {results!r}")
        print("[4] result accepted OK (stored)")
    finally:
        try:
            srv.stop()
        except Exception:
            pass

    print("E2E C2<->beacon smoke: PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except _Fail as exc:
        print(f"E2E C2<->beacon smoke: FAIL — {exc}", file=sys.stderr)
        sys.exit(1)
