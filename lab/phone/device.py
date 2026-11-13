"""A phone-like lab target: MDM surface, an ADB daemon and an app sandbox.

Authorized LOCAL testing only — this container models a managed Android
device so Phantom's mobile capabilities have something real to talk to:

* **MDM (8443)** — the endpoints ``mobile_probe`` looks for (``/api/v2/mdm``,
  ``/enroll``, ``/api/device``, ``/config/mobile``, ``/v1/push``, ``/apns``,
  ``/gcm``, ``/fcm``) plus ``/api/v1/devices``, which is the signature
  ``mobile_mdm_fingerprint`` uses for SimpleMDM. The enrollment profile is
  exposed, which is the realistic misconfiguration the fingerprints look for.
* **ADB (5555)** — the real wire protocol (CNXN/AUTH/OPEN/OKAY/WRTE/CLSE with
  the 24-byte header, the magic complement and the post-handshake 4-byte
  length prefix), so ``adb connect 127.0.0.1:5555`` works and ``adb shell``
  answers like a device. It is NOT a full adbd: no file sync, no port
  forwarding, and it accepts any signature — a lab, not a backdoor.
* **Sandbox** — per-app uid separation, an SELinux-style policy page, and one
  ``exported`` app (a backup agent) with a path traversal in its data reader.
  A non-exported app's data is refused on a uid mismatch; the exported one
  escapes its own directory and reads ``/data/local/tmp/flag.txt``. That is
  the realistic split: the boundary exists, and one component is misconfigured.
"""

from __future__ import annotations

import json
import os
import socketserver
import struct
import threading

from flask import Flask, jsonify, request

ADB_PORT = int(os.environ.get("ADB_PORT", "5555"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8443"))

FLAG = "PHANTOM{phone_sandbox_escape_7781}"
FLAG_PATH = "/data/local/tmp/flag.txt"
os.makedirs("/data/local/tmp", exist_ok=True)
if not os.path.exists(FLAG_PATH):
    with open(FLAG_PATH, "w", encoding="utf-8") as handle:
        handle.write(FLAG + "\n")

APPS = {
    # the vulnerable one: exported, and its data reader trusts the path
    "com.corp.backup": {"uid": 10145, "exported": True,
                        "label": "Corp Backup Agent", "version": "4.2.1"},
    "com.corp.mail": {"uid": 10120, "exported": False,
                      "label": "Corp Mail", "version": "9.8.0"},
    "com.android.settings": {"uid": 1000, "exported": False,
                             "label": "Settings", "version": "14"},
}

for pkg, meta in APPS.items():
    base = f"/data/data/{pkg}/files"
    os.makedirs(base, exist_ok=True)
    with open(os.path.join(base, "notes.txt"), "w", encoding="utf-8") as fh:
        fh.write(f"{meta['label']} local cache (uid {meta['uid']})\n")

with open("/data/data/com.corp.backup/files/session.txt", "w",
          encoding="utf-8") as fh:
    fh.write("backup-session-token=bt_9f31c0\n")

app = Flask(__name__)


def _device() -> dict:
    return {
        "id": "lab-phone-01",
        "model": "Pixel 7",
        "manufacturer": "Google",
        "os": "Android 14",
        "build": "UQ1A.240205.004",
        "serial": "LABPHONE0001",
        "mdm": {"vendor": "SimpleMDM", "enrolled": True,
                "supervised": True, "profile": "corp-byod-v3"},
        "push": {"fcm": True, "apns": False},
    }


@app.after_request
def _headers(resp):
    # Real mobile stacks fingerprint on these; the lab should look like a
    # managed endpoint, not like a bare Flask app.
    resp.headers.setdefault("X-MDM-Vendor", "SimpleMDM")
    resp.headers.setdefault("X-Device-Id", "lab-phone-01")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    return resp


@app.route("/")
def home():
    return (
        "<html><head><meta name='viewport' content='width=device-width'>"
        "<title>Corp Mobile Portal</title></head><body>"
        "<h2>Corp Mobile Portal</h2>"
        "<p>Managed device enrollment and self-service.</p>"
        "<ul><li><a href='/enroll'>Enroll this device</a></li>"
        "<li><a href='/api/v1/devices'>Device inventory</a></li></ul>"
        "</body></html>")


@app.route("/enroll")
def enroll():
    # EXPOSED enrollment profile: the realistic finding behind the mobile
    # stage's "enrollment-profile exposure" fingerprint.
    return jsonify({
        "device": _device(),
        "enrollment_profile": {
            "name": "corp-byod-v3",
            "supervised": True,
            "allow_camera": False,
            "allow_usb_debugging": True,
            "scep_url": "https://mdm.lab.local/scep",
            "root_ca": "corp-root-ca.pem",
        },
    })


@app.route("/api/v1/devices")
def devices():
    return jsonify({"vendor": "SimpleMDM", "devices": [_device()]})


@app.route("/api/v2/mdm")
def mdm_v2():
    return jsonify({"version": 2, "vendor": "SimpleMDM",
                    "capabilities": ["enroll", "policy", "inventory"]})


@app.route("/api/device")
def api_device():
    return jsonify(_device())


@app.route("/config/mobile")
def config_mobile():
    return jsonify({"push": "fcm", "min_os": "Android 12",
                    "policy": "corp-byod-v3"})


@app.route("/v1/push")
@app.route("/push")
@app.route("/fcm")
def push():
    return jsonify({"gateway": "fcm", "project": "corp-mobile-lab",
                    "send": "POST /v1/push/send"})


@app.route("/apns")
def apns():
    return jsonify({"gateway": "apns", "topic": "com.corp.mail",
                    "environment": "production"})


@app.route("/gcm")
def gcm():
    return jsonify({"gateway": "gcm", "deprecated": True})


@app.route("/sandbox/apps")
def sandbox_apps():
    return jsonify({
        "enforcing": True,
        "apps": [{"package": pkg, **meta} for pkg, meta in APPS.items()],
    })


@app.route("/sandbox/policy")
def sandbox_policy():
    return jsonify({
        "selinux": "enforcing",
        "contexts": {
            "untrusted_app": "u:r:untrusted_app:s0:c120,c256,c512,c768",
            "platform_app": "u:r:platform_app:s0",
            "shell": "u:r:shell:s0",
        },
        "notes": ("apps run in their own uid domain; /data/data is readable "
                  "only by the owning uid"),
    })


@app.route("/sandbox/apps/<pkg>/data")
def sandbox_data(pkg):
    meta = APPS.get(pkg)
    if meta is None:
        return jsonify({"error": "no such package"}), 404
    rel = request.args.get("path", "files/notes.txt")
    # The uid check is the SANDBOX boundary: a component that is not exported
    # cannot be driven by another uid, and the caller must claim its own uid.
    caller = request.headers.get("X-Android-Uid", "")
    if not meta["exported"] and str(meta["uid"]) != str(caller):
        return jsonify({"error": "Permission denied",
                        "detail": "uid mismatch on a non-exported component",
                        "uid": meta["uid"]}), 403
    # INTENTIONAL VULNERABILITY: the exported backup agent joins the caller's
    # path without confining it to its own data directory.
    path = os.path.join(f"/data/data/{pkg}", rel)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return jsonify({"package": pkg, "path": path,
                            "content": handle.read(4096)})
    except OSError as exc:
        return jsonify({"package": pkg, "path": path,
                        "error": str(exc)}), 404


@app.route("/health")
def health():
    return "ok"


# ------------------------------------------------------------------- ADB
CNXN, AUTH, OPEN, OKAY, CLSE, WRTE = (0x4E584E43, 0x48545541, 0x4E45504F,
                                      0x59414B4F, 0x45534C43, 0x45545257)
BANNER = (b"device::ro.product.name=lab_phone;ro.product.model=Pixel 7;"
          b"ro.product.device=panther;ro.build.version.release=14;"
          b"features=cmd,shell_v2")


def _packet(cmd: int, arg0: int, arg1: int, payload: bytes = b"",
            framed: bool = True) -> bytes:
    crc = sum(payload) & 0xFFFFFFFF
    header = struct.pack("<6I", cmd, arg0, arg1, len(payload), crc,
                         cmd ^ 0xFFFFFFFF)
    blob = header + payload
    return (struct.pack("<I", len(blob)) + blob) if framed else blob


def _shell(command: str) -> bytes:
    """An allow-listed device shell: enough to look and behave like adbd."""
    cmd = command.strip()
    if cmd in ("id", "id -u"):
        return b"uid=2000(shell) gid=2000(shell) groups=2000(shell) " \
               b"context=u:r:shell:s0\n"
    if cmd == "getprop":
        return b"[ro.product.model]: [Pixel 7]\n[ro.build.version.release]: [14]\n"
    if cmd.startswith("getprop "):
        props = {"ro.product.model": "Pixel 7", "ro.build.version.release": "14",
                 "ro.product.device": "panther", "ro.debuggable": "0",
                 "ro.secure": "1"}
        key = cmd.split(None, 1)[1].strip()
        return (props.get(key, "") + "\n").encode()
    if cmd == "pm list packages":
        return ("\n".join(f"package:{pkg}" for pkg in APPS) + "\n").encode()
    if cmd.startswith("ls /data/data"):
        # the shell uid really cannot read this; saying so is the point
        return b"ls: /data/data: Permission denied\n"
    if cmd in (f"cat {FLAG_PATH}", "cat /data/local/tmp/flag.txt"):
        return (FLAG + "\n").encode()
    if cmd.startswith("echo "):
        return (cmd[5:] + "\n").encode()
    return f"/system/bin/sh: {cmd.split()[0]}: inaccessible or not found\n".encode()


class _ADBHandler(socketserver.BaseRequestHandler):
    def _read(self, count: int) -> bytes:
        data = b""
        while len(data) < count:
            chunk = self.request.recv(count - len(data))
            if not chunk:
                raise ConnectionError("closed")
            data += chunk
        return data

    def handle(self) -> None:
        self.request.settimeout(30)
        try:
            # adb frames EVERY packet, the handshake included: 4-byte length,
            # then the 24-byte header + payload. Reading 24 raw bytes worked
            # for a hand-rolled probe but broke the real client, whose CNXN
            # payload (features=…) is framed too.
            (first_len,) = struct.unpack("<I", self._read(4))
            head = struct.unpack("<6I", self._read(first_len)[:24])
            if head[0] != CNXN or head[5] != (head[0] ^ 0xFFFFFFFF):
                return
            self.request.sendall(_packet(CNXN, 0x01000000, 4096, BANNER))
            while True:
                (length,) = struct.unpack("<I", self._read(4))
                body = self._read(length)
                cmd, a0, a1, ln, _crc, magic = struct.unpack("<6I", body[:24])
                if magic != (cmd ^ 0xFFFFFFFF):
                    return
                payload = body[24:24 + ln]
                if cmd in (AUTH, CNXN):
                    # lab: accept any (even unauthenticated) host
                    self.request.sendall(_packet(CNXN, 0x01000000, 4096, BANNER))
                    continue
                if cmd == OPEN:
                    service = payload.rstrip(b"\0").decode(errors="replace")
                    if not service.startswith("shell:"):
                        self.request.sendall(_packet(CLSE, a0, a1))
                        continue
                    self.request.sendall(_packet(OKAY, a0, a1))
                    out = _shell(service.split(":", 1)[1])
                    self.request.sendall(_packet(WRTE, a0, a1, out))
                    self.request.sendall(_packet(CLSE, a0, a1))
                    continue
                if cmd == CLSE:
                    return
        except (ConnectionError, OSError, struct.error):
            return


class _ADBServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _start_adb() -> None:
    server = _ADBServer(("0.0.0.0", ADB_PORT), _ADBHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[phone] adb(5555) http(8443) — authorized local testing", flush=True)


if __name__ == "__main__":
    _start_adb()
    # TLS, not plain HTTP: every consumer of an 8443 service — Phantom's
    # `http_probe`/`mobile_probe` included — assumes https on that port, and a
    # cleartext 8443 answered them all with an SSL error. Self-signed is the
    # realistic managed-endpoint posture.
    app.run(host="0.0.0.0", port=HTTP_PORT, debug=False,
            ssl_context="adhoc")
