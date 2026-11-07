#!/usr/bin/env python3
"""lab_phone_smoke.py — prove the phone lab really behaves like a device.

Three surfaces, three independent checks, no Phantom code involved (a lab
that only passes when the tool under test is the judge is not a lab):

1. **MDM** — every endpoint ``mobile_probe`` probes answers, ``/enroll``
   exposes the profile, and ``/api/v1/devices`` carries the SimpleMDM
   signature ``mobile_mdm_fingerprint`` matches.
2. **Sandbox** — the non-exported app refuses a uid mismatch (403) and the
   **exported** one escapes its own data directory to ``/data/local/tmp``.
   Both assertions matter: a lab where everything is readable proves nothing.
3. **ADB** — the real handshake: CNXN in, CNXN out with the magic complement,
   then OPEN("shell:id") answered by OKAY + WRTE + CLSE.

Exit code 0 only when all three hold. ``--host``/``--mdm-port``/``--adb-port``
let it run against a remote lab.
"""
from __future__ import annotations

import argparse
import http.client
import json
import socket
import ssl
import struct
import sys


def _get(host: str, port: int, path: str, headers=None) -> tuple:
    ctx = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection(host, port, timeout=8, context=ctx)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, body, dict(resp.getheaders())
    finally:
        conn.close()


def check_mdm(host: str, port: int) -> list:
    rows = []
    for path in ("/", "/enroll", "/api/v2/mdm", "/api/device",
                 "/config/mobile", "/v1/push", "/apns", "/gcm", "/fcm",
                 "/api/v1/devices"):
        try:
            status, body, _ = _get(host, port, path)
        except OSError as exc:
            rows.append((path, False, f"connection failed: {exc}"))
            continue
        rows.append((path, status == 200, f"http {status}, {len(body)}B"))
    status, body, _ = _get(host, port, "/api/v1/devices")
    rows.append(("SimpleMDM signature", "SimpleMDM" in body,
                 "vendor string present" if "SimpleMDM" in body
                 else "vendor string missing"))
    status, body, _ = _get(host, port, "/enroll")
    rows.append(("enrollment profile exposed",
                 "enrollment_profile" in body,
                 "profile visible" if "enrollment_profile" in body
                 else "profile not exposed"))
    return rows


def check_sandbox(host: str, port: int) -> list:
    rows = []
    status, body, _ = _get(
        host, port, "/sandbox/apps/com.corp.mail/data?path=files/notes.txt",
        {"X-Android-Uid": "10145"})
    rows.append(("non-exported app blocks another uid", status == 403,
                 f"http {status}"))
    status, body, _ = _get(
        host, port,
        "/sandbox/apps/com.corp.backup/data?path=files/../../../../data/local/tmp/flag.txt")
    escaped = status == 200 and "PHANTOM{phone_sandbox_escape" in body
    rows.append(("exported app escapes its data dir", escaped,
                 f"http {status}" + (", flag read" if escaped else "")))
    status, body, _ = _get(host, port, "/sandbox/apps/com.corp.backup/data?path=files/session.txt")
    rows.append(("exported app reads its own data",
                 status == 200 and "backup-session-token" in body,
                 f"http {status}"))
    status, body, _ = _get(host, port, "/sandbox/policy")
    rows.append(("selinux policy exposed", status == 200 and "enforcing" in body,
                 f"http {status}"))
    return rows


def _packet(cmd: int, arg0: int, arg1: int, payload: bytes = b"",
            framed: bool = True) -> bytes:
    crc = sum(payload) & 0xFFFFFFFF
    blob = struct.pack("<6I", cmd, arg0, arg1, len(payload), crc,
                       cmd ^ 0xFFFFFFFF) + payload
    return (struct.pack("<I", len(blob)) + blob) if framed else blob


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def check_adb(host: str, port: int) -> list:
    rows = []
    sock = socket.create_connection((host, port), timeout=8)
    try:
        # Real adb frames the handshake too; the lab must answer that, or
        # `adb connect 127.0.0.1:5555` would still hang.
        sock.sendall(_packet(0x4E584E43, 0x01000000, 4096,
                             b"host::features=shell_v2"))
        (length,) = struct.unpack("<I", _recv_exact(sock, 4))
        body = _recv_exact(sock, length)
        cmd, _a0, _a1, ln, _crc, magic = struct.unpack("<6I", body[:24])
        banner = body[24:24 + ln]
        ok = cmd == 0x4E584E43 and magic == (cmd ^ 0xFFFFFFFF)
        rows.append(("CNXN handshake", ok, banner.decode("utf-8", "replace")[:60]))
        sock.sendall(_packet(0x4E45504F, 1, 0, b"shell:id\0"))
        (length,) = struct.unpack("<I", _recv_exact(sock, 4))
        body = _recv_exact(sock, length)
        cmd = struct.unpack("<I", body[:4])[0]
        rows.append(("shell OPEN accepted", cmd == 0x59414B4F, hex(cmd)))
        out = b""
        for _ in range(4):
            (length,) = struct.unpack("<I", _recv_exact(sock, 4))
            body = _recv_exact(sock, length)
            cmd, _a0, _a1, ln = struct.unpack("<4I", body[:16])
            if cmd == 0x45545257:
                out += body[24:24 + ln]
            if cmd == 0x45534C43:
                break
        rows.append(("shell:id answered", b"uid=2000(shell)" in out,
                     out.decode("utf-8", "replace").strip()[:60]))
    finally:
        sock.close()
    return rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--mdm-port", type=int, default=8443)
    parser.add_argument("--adb-port", type=int, default=5555)
    args = parser.parse_args(argv)

    checks = {
        "MDM": lambda: check_mdm(args.host, args.mdm_port),
        "SANDBOX": lambda: check_sandbox(args.host, args.mdm_port),
        "ADB": lambda: check_adb(args.host, args.adb_port),
    }
    failed = 0
    for name, check in checks.items():
        print(f"\n{name}")
        try:
            rows = check()
        except Exception as exc:        # one broken surface must not hide the rest
            rows = [("surface reachable", False, f"{type(exc).__name__}: {exc}")]
        for label, ok, detail in rows:
            print(f"  {'PASS' if ok else 'FAIL'}  {label:42s} {detail}")
            failed += 0 if ok else 1
    print(f"\n{'PHONE LAB OK' if not failed else f'{failed} CHECK(S) FAILED'}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
