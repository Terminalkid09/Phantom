import asyncio
import os
import shlex
import threading
from datetime import datetime
from typing import Any

from aiohttp import web

from phantom.core.logger import logger


TOKEN_ENV = "PHANTOM_C2_TOKEN"
DEFAULT_LAB_TOKEN = "phantom-lab-token"
MAX_RESULT_BYTES = 64 * 1024

ALLOWED_TASKS = {
    "ping": "Round-trip connectivity check for a lab simulator.",
    "status": "Request basic simulator status metadata.",
    "inventory": "Request a minimal, non-invasive lab asset snapshot.",
    "note": "Attach an operator note to the simulator timeline.",
}


def expected_token() -> str:
    """Return the shared lab token used by the simulator API."""
    return os.getenv(TOKEN_ENV, DEFAULT_LAB_TOKEN)


def parse_lab_task(command_line: str) -> dict[str, Any]:
    """Parse and validate a C2 lab task.

    The lab console deliberately does not accept arbitrary shell commands. This
    keeps the feature useful for UI/server workflow testing without becoming a
    remote command execution system.
    """
    try:
        parts = shlex.split(command_line)
    except ValueError as exc:
        raise ValueError(f"Invalid task syntax: {exc}") from exc

    if not parts:
        raise ValueError("Task cannot be empty.")

    name = parts[0].lower()
    if name not in ALLOWED_TASKS:
        allowed = ", ".join(sorted(ALLOWED_TASKS))
        raise ValueError(f"Unsupported lab task '{name}'. Allowed tasks: {allowed}.")

    args = parts[1:]
    if name == "note" and not args:
        raise ValueError("The 'note' task requires a message.")

    return {"name": name, "args": args}


class C2State:
    """Thread-safe state shared by the C2 shell and aiohttp listener."""

    def __init__(self):
        self.lock = threading.Lock()
        self.beacons: dict[str, dict[str, Any]] = {}
        self.tasks: dict[str, list[dict[str, Any]]] = {}
        self.results: dict[str, list[dict[str, Any]]] = {}

    def update_beacon(self, beacon_id: str, info: dict[str, Any]) -> bool:
        with self.lock:
            now = datetime.now().isoformat(timespec="seconds")
            normalized = {
                "ip": info.get("ip", "unknown"),
                "hostname": info.get("hostname", "unknown"),
                "os": info.get("os", "unknown"),
                "arch": info.get("arch", "unknown"),
                "kind": info.get("kind", "lab-simulator"),
                "last_seen": now,
            }
            is_new = beacon_id not in self.beacons
            if is_new:
                self.beacons[beacon_id] = normalized
                self.tasks[beacon_id] = []
                self.results[beacon_id] = []
                logger.info(f"New C2 lab simulator registered: {beacon_id}")
            else:
                self.beacons[beacon_id].update(normalized)
            return is_new

    def queue_task(self, beacon_id: str, command_line: str) -> dict[str, Any]:
        task = parse_lab_task(command_line)
        with self.lock:
            if beacon_id not in self.beacons:
                raise ValueError(f"Unknown simulator id: {beacon_id}")
            task_id = datetime.now().strftime("%Y%m%d%H%M%S%f")
            queued = {
                "task_id": task_id,
                "name": task["name"],
                "args": task["args"],
                "queued_at": datetime.now().isoformat(timespec="seconds"),
            }
            self.tasks.setdefault(beacon_id, []).append(queued)
            return queued

    def get_pending_tasks(self, beacon_id: str) -> list[dict[str, Any]]:
        with self.lock:
            tasks_to_send = list(self.tasks.get(beacon_id, []))
            self.tasks[beacon_id] = []
            return tasks_to_send

    def add_result(self, beacon_id: str, task_id: str, output: str) -> None:
        with self.lock:
            self.results.setdefault(beacon_id, []).append(
                {
                    "task_id": task_id,
                    "output": output,
                    "time": datetime.now().isoformat(timespec="seconds"),
                }
            )

    def get_beacons(self) -> dict[str, dict[str, Any]]:
        with self.lock:
            return {beacon_id: dict(info) for beacon_id, info in self.beacons.items()}

    def get_results(self, beacon_id: str) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.results.get(beacon_id, []))

    def register_simulator(self, beacon_id: str = "lab-001") -> str:
        self.update_beacon(
            beacon_id,
            {
                "ip": "127.0.0.1",
                "hostname": "phantom-lab",
                "os": "simulated",
                "arch": "n/a",
                "kind": "manual-simulator",
            },
        )
        return beacon_id


c2_state = C2State()


def _authorized(request: web.Request) -> bool:
    return request.headers.get("X-Phantom-Token") == expected_token()


def _lab_header_present(request: web.Request) -> bool:
    value = request.headers.get("X-Phantom-Lab", "").lower()
    return value in {"1", "true", "yes"}


async def _guard_request(request: web.Request) -> web.Response | None:
    if not _authorized(request):
        return web.json_response({"error": "unauthorized"}, status=401)
    if not _lab_header_present(request):
        return web.json_response({"error": "lab simulator header required"}, status=403)
    return None


async def handle_health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok", "mode": "lab"})


async def handle_checkin(request: web.Request) -> web.Response:
    """GET /api/v1/ping - lab simulator checks in and receives safe tasks."""
    guard = await _guard_request(request)
    if guard is not None:
        return guard

    beacon_id = request.headers.get("X-Beacon-Id", "").strip()
    if not beacon_id:
        return web.json_response({"error": "missing X-Beacon-Id"}, status=400)

    c2_state.update_beacon(
        beacon_id,
        {
            "ip": request.remote,
            "hostname": request.headers.get("X-Beacon-Host", "unknown"),
            "os": request.headers.get("X-Beacon-Os", "unknown"),
            "arch": request.headers.get("X-Beacon-Arch", "unknown"),
            "kind": request.headers.get("X-Beacon-Kind", "lab-simulator"),
        },
    )
    return web.json_response({"tasks": c2_state.get_pending_tasks(beacon_id)})


async def handle_result(request: web.Request) -> web.Response:
    """POST /api/v1/result - lab simulator returns task output."""
    guard = await _guard_request(request)
    if guard is not None:
        return guard

    beacon_id = request.headers.get("X-Beacon-Id", "").strip()
    if not beacon_id:
        return web.json_response({"error": "missing X-Beacon-Id"}, status=400)

    raw_body = await request.read()
    if len(raw_body) > MAX_RESULT_BYTES:
        return web.json_response({"error": "result too large"}, status=413)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "invalid JSON body"}, status=400)

    task_id = str(data.get("task_id", "unknown"))
    output = str(data.get("output", ""))
    c2_state.add_result(beacon_id, task_id, output)
    return web.json_response({"status": "stored"})


class C2Server:
    def __init__(self, host: str = "127.0.0.1", port: int = 8443):
        self.host = host
        self.port = port
        self.app = web.Application()
        self.app.router.add_get("/api/v1/health", handle_health)
        self.app.router.add_get("/api/v1/ping", handle_checkin)
        self.app.router.add_post("/api/v1/result", handle_result)
        self.runner: web.AppRunner | None = None
        self.site: web.TCPSite | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.thread: threading.Thread | None = None

    def _start_server(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.runner = web.AppRunner(self.app, access_log=None)
        self.loop.run_until_complete(self.runner.setup())
        self.site = web.TCPSite(self.runner, self.host, self.port)
        self.loop.run_until_complete(self.site.start())
        logger.info(f"C2 lab listener started on {self.host}:{self.port}")
        self.loop.run_forever()

    def start(self, host: str | None = None, port: int | None = None) -> None:
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
            async def cleanup() -> None:
                await self.runner.cleanup()

            future = asyncio.run_coroutine_threadsafe(cleanup(), self.loop)
            try:
                future.result(timeout=2)
            except Exception as exc:
                logger.warning(f"C2 lab listener cleanup warning: {exc}")
            self.loop.call_soon_threadsafe(self.loop.stop)
            if self.thread:
                self.thread.join(timeout=2)
        self.runner = None
        self.site = None
        self.loop = None
        self.thread = None


server_instance = C2Server()
