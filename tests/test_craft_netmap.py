"""Tests for the social-engineering crafting workspace, network mapping,
tool installation, and the auto-mode QR lure capability."""
import asyncio
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from aiohttp.test_utils import TestClient, TestServer

from phantom.api.server import create_app
from phantom.automation.social.grabbit import GrabLink
from phantom.modules import craft as craft_mod
from phantom.utils import c2_crypto


class TestCraft(unittest.TestCase):

    def setUp(self):
        self._saved = os.environ.get("PHANTOM_DATA_DIR")
        self._tmp = tempfile.mkdtemp(prefix="phantom-craft-")
        os.environ["PHANTOM_DATA_DIR"] = self._tmp

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("PHANTOM_DATA_DIR", None)
        else:
            os.environ["PHANTOM_DATA_DIR"] = self._saved

    def _fake_grabber(self):
        fake = MagicMock()
        fake.create_link.return_value = GrabLink("https://t.example/abc", "abc")
        fake.create_video_share_link.return_value = GrabLink("https://t.example/reel/xyz", "xyz")
        return fake

    def test_craft_ipgrab_returns_paste_ready(self):
        with patch.object(craft_mod, "_grabber", return_value=self._fake_grabber()):
            out = craft_mod.craft_ipgrab(label="phish")
        self.assertTrue(out["created"])
        self.assertEqual(out["url"], "https://t.example/abc")
        self.assertEqual(out["code"], "abc")
        self.assertEqual(out["kind"], "ipgrab")

    def test_craft_pixel_embeds_html(self):
        with patch.object(craft_mod, "_grabber", return_value=self._fake_grabber()):
            out = craft_mod.craft_pixel(label="px")
        self.assertEqual(out["kind"], "pixel")
        self.assertIn("<img src=\"https://t.example/abc\"", out["html"])

    def test_craft_video_share(self):
        with patch.object(craft_mod, "_grabber", return_value=self._fake_grabber()):
            out = craft_mod.craft_video(platform="instagram")
        self.assertEqual(out["url"], "https://t.example/reel/xyz")

    def test_craft_hits_without_server(self):
        with patch.object(craft_mod, "_store", return_value=None):
            self.assertEqual(craft_mod.craft_hits("x"),
                             {"hits": [], "opens": [], "creds": []})

    def test_craft_beacon_requires_listener(self):
        with patch.object(craft_mod, "_grabber", return_value=self._fake_grabber()):
            out = craft_mod.craft_beacon(platform="android")
        self.assertIn("error", out)  # C2 listener not running in tests

    def test_craft_image_hosts_chosen_file(self):
        img = os.path.join(self._tmp, "photo.jpg")
        with open(img, "wb") as f:
            f.write(b"\xff\xd8\xff\xe0FAKEJPEG")
        server = MagicMock()
        fake = MagicMock()
        fake.create_link.return_value = GrabLink("https://t.example/i/img1", "img1")
        with patch.object(craft_mod, "_grabber", return_value=fake), \
             patch.object(craft_mod, "_server", return_value=server):
            out = craft_mod.craft_image(img)
        self.assertEqual(out["kind"], "image")
        self.assertIn("https://t.example/i/img1", out["html"])
        server.register_image.assert_called_once()
        self.assertEqual(server.register_image.call_args[0][2], "image/jpeg")

    def test_craft_image_missing_file_errors(self):
        with patch.object(craft_mod, "_grabber", return_value=self._fake_grabber()):
            out = craft_mod.craft_image("/nonexistent/nope.png")
        self.assertIn("error", out)

    def test_craft_reel_requires_argument(self):
        out = craft_mod.craft_reel(arg="")
        self.assertIn("error", out)

    def test_craft_beacon_is_link_not_qr(self):
        """The beacon delivery is a reel-looking LINK (camouflaged redirect),
        never a QR — no 'kind: qr', no PNG path."""
        with patch.object(craft_mod, "_server") as server, \
             patch.object(craft_mod, "_tracking_base", return_value="http://127.0.0.1:8099"):
            out = craft_mod.craft_beacon(platform="android")
        self.assertIn("error", out)  # no C2 listener in tests
        self.assertNotIn("kind", out)  # error dict has no lure kind
        self.assertIsNone(out.get("path"))


class TestNetmap(unittest.TestCase):

    def test_parse_arp_scan(self):
        from phantom.core.netmap import _parse_arp_scan
        hosts = _parse_arp_scan(
            "10.0.0.1\taa:bb:cc:dd:ee:ff\tRouter Inc.\n"
            "10.0.0.42\t11:22:33:44:55:66\tPhone Maker\njunk line")
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0]["ip"], "10.0.0.1")
        self.assertEqual(hosts[0]["vendor"], "Router Inc.")

    def test_parse_nmap_sn(self):
        from phantom.core.netmap import _parse_nmap_sn
        hosts = _parse_nmap_sn(
            "Nmap scan report for 10.0.0.9\n"
            "MAC Address: AA:BB:CC:00:11:22 (Samsung)\n"
            "Nmap scan report for 10.0.0.10\n")
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0]["ip"], "10.0.0.9")
        self.assertEqual(hosts[0]["vendor"], "Samsung")

    def test_discover_network_uses_arp_scan_output(self):
        import phantom.core.netmap as nm
        with patch.object(nm, "_run", return_value="10.0.0.7\taa:bb:01:02:03:04\tVendor\n"), \
             patch.object(nm, "shutil") as sh:
            sh.which.return_value = "/usr/bin/arp-scan"
            res = nm.discover_network(target=None, timeout=5)
        self.assertEqual(res["method"], "arp-scan")
        self.assertEqual(len(res["hosts"]), 1)
        self.assertEqual(res["hosts"][0]["ip"], "10.0.0.7")

    def test_seed_worldmodel_writes_host_findings(self):
        from phantom.core.netmap import seed_worldmodel
        from phantom.core.knowledge import reset_wm, session_wm
        reset_wm(target="")
        n = seed_worldmodel([{"ip": "10.0.0.9", "mac": "aa:bb", "vendor": "X"}])
        self.assertEqual(n, 1)
        self.assertTrue(any(f.kind == "host" for f in session_wm().all_findings()))

    def test_seed_worldmodel_carries_enrichment(self):
        """The scan's per-device fingerprint (OS guess, ports, services)
        must reach the WorldModel — that is what the map cards render."""
        from phantom.core.netmap import seed_worldmodel
        from phantom.core.knowledge import reset_wm, session_wm
        reset_wm(target="")
        seed_worldmodel([{"ip": "10.0.0.9", "hostname": "gw", "vendor": "X",
                          "os_guess": "Linux", "ports": [22, 80],
                          "services": "ssh, http"}])
        host = next(f for f in session_wm().all_findings() if f.key == "10.0.0.9")
        self.assertEqual(host.value.get("os"), "Linux")
        self.assertEqual(host.value.get("ports"), [22, 80])
        self.assertIn("ssh", host.value.get("services", ""))

    def test_detect_topology_star_vs_broadcast(self):
        from phantom.core.netmap import detect_topology
        # star: many devices, gateway present, only the gateway exposes SMB
        star = detect_topology([
            {"ip": "192.168.1.1", "hostname": "modemtim", "ports": [53, 80, 445]},
            {"ip": "192.168.1.10", "hostname": "pc1", "ports": []},
            {"ip": "192.168.1.11", "hostname": "pc2", "ports": []},
            {"ip": "192.168.1.12", "hostname": "pc3", "ports": []},
            {"ip": "192.168.1.13", "hostname": "pc4", "ports": []},
        ])
        self.assertEqual(star["kind"], "star")
        self.assertEqual(star["gateway"], "192.168.1.1")
        # broadcast: many hosts expose SMB — flat segment
        flat = detect_topology([
            {"ip": "10.0.0.1", "hostname": "gw", "ports": []},
            {"ip": "10.0.0.2", "hostname": "a", "ports": [445, 139]},
            {"ip": "10.0.0.3", "hostname": "b", "ports": [445]},
            {"ip": "10.0.0.4", "hostname": "c", "ports": [139, 445]},
            {"ip": "10.0.0.5", "hostname": "d", "ports": [445]},
        ])
        self.assertEqual(flat["kind"], "broadcast")

    def test_guess_os_from_banner_and_ports(self):
        from phantom.core.netmap import _guess_os
        self.assertEqual(_guess_os([3389, 135, 445]), "Windows (likely)")
        self.assertEqual(_guess_os([22, 111]), "Linux (likely)")
        self.assertEqual(_guess_os([], "OpenSSH_8.4"), "Linux")
        self.assertEqual(_guess_os([1900, 53]), "Router/IoT firmware")

    def test_quick_probe_enriches_hosts(self):
        """_quick_probe_hosts attaches ports/services/os to enriched hosts."""
        import phantom.core.netmap as nm
        hosts = [{"ip": "127.0.0.1", "hostname": "loopback"}]
        nm._quick_probe_hosts(hosts, timeout=8)
        h = hosts[0]
        # loopback in the dev environment runs the API server on some port;
        # whatever it finds, the shape of the enrichment must hold
        self.assertIn("ports", h)
        self.assertIn("services", h)


class TestInstallTool(unittest.TestCase):

    def test_install_tool_runs_and_reports(self):
        from phantom.core.executor import install_tool
        fake = MagicMock()
        fake.returncode = 0
        fake.stdout = "Setting up hydra..."
        fake.stderr = ""
        with patch("subprocess.run", return_value=fake):
            res = install_tool("hydra", timeout=5)
        self.assertTrue(res["ok"])
        self.assertIn("install", res["command"].lower())
        self.assertIn("hydra", res["command"].lower())

    def test_install_tool_timeout(self):
        from phantom.core.executor import install_tool
        import subprocess
        def _hang(*a, **k):
            raise subprocess.TimeoutExpired(cmd="x", timeout=1)
        with patch("subprocess.run", side_effect=_hang):
            res = install_tool("nmap", timeout=1)
        self.assertFalse(res["ok"])
        self.assertIn("timed out", res["output"])


class TestCraftApi(unittest.TestCase):

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in
                       ("PHANTOM_STATE_FILE", "PHANTOM_API_TOKEN", "PHANTOM_DATA_DIR")}
        for k in self._saved:
            os.environ.pop(k, None)
        self._tmp = tempfile.mkdtemp(prefix="phantom-craft-api-")
        os.environ["PHANTOM_DATA_DIR"] = self._tmp
        os.environ["PHANTOM_STATE_FILE"] = os.path.join(self._tmp, "state.json")

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    @staticmethod
    def _scenario(coro):
        return asyncio.run(coro)

    def test_craft_api_ipgrab(self):
        async def scenario():
            import phantom.modules.craft as cm
            fake = MagicMock()
            fake.create_link.return_value = GrabLink("https://t.example/link1", "link1")
            with patch.object(cm, "_grabber", return_value=fake):
                client = TestClient(TestServer(create_app()))
                await client.start_server()
                try:
                    token = c2_crypto.get_api_token()
                    headers = {"Authorization": f"Bearer {token}"}
                    resp = await client.post("/api/craft",
                                             json={"type": "ipgrab", "label": "api"},
                                             headers=headers)
                    self.assertEqual(resp.status, 200)
                    data = await resp.json()
                    self.assertEqual(data["url"], "https://t.example/link1")
                finally:
                    await client.close()

        self._scenario(scenario())

    def test_craft_api_image_requires_arg(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                token = c2_crypto.get_api_token()
                headers = {"Authorization": f"Bearer {token}"}
                resp = await client.post("/api/craft", json={"type": "image"},
                                         headers=headers)
                return resp.status
            finally:
                await client.close()

        self.assertEqual(self._scenario(scenario()), 400)

    def test_preflight_never_lists_phantom_commands(self):
        """Module action words (deploy-agent, privesc-run, msf-search…) must
        not appear as installable missing tools — clicking Install on them
        used to run `apt-get install deploy-agent` ("Unable to locate
        package deploy-agent")."""
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                token = c2_crypto.get_api_token()
                headers = {"Authorization": f"Bearer {token}"}
                resp = await client.post(
                    "/api/session/preflight", json={"module": "exploit"},
                    headers=headers)
                self.assertEqual(resp.status, 200)
                data = await resp.json()
                tools = [m["tool"] for m in data.get("missing", [])]
                for bad in ("deploy-agent", "privesc-run", "msf-search",
                            "run", "execute", "fire", "list-exploits"):
                    self.assertNotIn(bad, tools,
                                     f"phantom command {bad} listed as missing")
            finally:
                await client.close()

        self._scenario(scenario())

    def test_network_scan_api_seeds_wm(self):
        async def scenario():
            import phantom.core.netmap as nm
            with patch.object(nm, "discover_network", return_value={
                    "hosts": [{"ip": "10.0.0.5", "mac": "aa:bb", "vendor": "X"}],
                    "method": "test", "elapsed": 0.1}), \
                 patch.object(nm, "seed_worldmodel", return_value=1):
                client = TestClient(TestServer(create_app()))
                await client.start_server()
                try:
                    token = c2_crypto.get_api_token()
                    headers = {"Authorization": f"Bearer {token}"}
                    resp = await client.post("/api/network/scan", json={}, headers=headers)
                    self.assertEqual(resp.status, 200)
                    data = await resp.json()
                    self.assertEqual(len(data["hosts"]), 1)
                    self.assertEqual(data["seeded"], 1)
                finally:
                    await client.close()

    def test_enriched_hosts_have_names(self):
        """Discovered devices must be identifiable: never a bare 'unknown'.
        Regression for the Electron map rendering anonymous IP cards."""
        from phantom.core.netmap import discover_network, _LAST_SCAN
        _LAST_SCAN.clear()
        try:
            res = discover_network(timeout=60)
        finally:
            _LAST_SCAN.clear()
        hosts = res.get("hosts", [])
        if not hosts:
            self.skipTest("no live hosts on this network")
        for h in hosts:
            name = h.get("hostname") or ""
            self.assertTrue(name, f"{h.get('ip')} has no hostname fallback")
            self.assertNotIn("unknown", name.lower())

    def test_windows_install_never_uses_sudo(self):
        """On Windows the install path must route apt through WSL root —
        a raw `sudo apt-get ...` hits Win11's disabled native sudo.exe and
        dies with 'Sudo è disabilitato in questo computer'."""
        import sys as _sys
        from phantom.core import executor as ex
        fake = MagicMock()
        fake.returncode = 0
        fake.stdout = "ok"
        fake.stderr = ""
        captured = {}

        def _spy(cmdline, *a, **k):
            captured["cmd"] = cmdline
            return fake

        orig_platform = _sys.platform
        try:
            _sys.platform = "win32"
            with patch.object(_sys, "platform", "win32"), \
                 patch("phantom.automation.runtime.toolchain._wsl_distro_list",
                       return_value=["kali-linux"]), \
                 patch("subprocess.run", side_effect=_spy):
                res = ex.install_tool("hydra", timeout=5)
        finally:
            _sys.platform = orig_platform
        self.assertTrue(res["ok"])
        cmd = str(captured.get("cmd", ""))
        self.assertNotIn("sudo", cmd.lower(), f"sudo leaked into Windows install: {cmd}")
        self.assertIn("wsl", cmd.lower())
        self.assertIn("hydra", cmd.lower())

    def test_preflight_payload_never_lists_handler(self):
        """payload's suggestion group contains `handler <port> <payload>` —
        'handler' is a Phantom module, never an installable package."""
        async def scenario():
            from phantom.api.server import session_preflight

            class Req:
                async def json(self):
                    return {"module": "payload"}

            resp = await session_preflight(Req())
            import json
            data = json.loads(resp.body)
            tools = [m["tool"] for m in data.get("missing", [])]
            for bad in ("handler", "payload", "scan", "osint", "web",
                        "exploit", "brute", "pivot", "analyzer",
                        "report", "wordlist", "wifi", "generate",
                        "deploy", "privesc"):
                self.assertNotIn(bad, tools,
                                 f"{bad} listed as installable tool")

        self._scenario(scenario())

    def test_exposure_rank_excludes_self_and_sorts(self):
        """rank_hosts_exposure skips the local machine and sorts by score
        descending with weighted risky services."""
        from phantom.core.netmap import rank_hosts_exposure

        hosts = [
            {"ip": "127.0.0.1", "hostname": "me"},
            {"ip": "10.9.9.1", "hostname": "gateway"},
            {"ip": "10.9.9.2", "hostname": "iot"},
        ]
        open_map = {
            "10.9.9.1": [22, 445, 3389],   # ssh + smb + rdp
            "10.9.9.2": [80],              # just a web port
        }
        with patch("phantom.core.netmap._probe_ports",
                   side_effect=lambda ip, ports, **kw: open_map.get(ip, [])):
            ranked = rank_hosts_exposure(hosts, timeout=10)
        ips = [r["ip"] for r in ranked]
        self.assertNotIn("127.0.0.1", ips)
        self.assertEqual(ips, ["10.9.9.1", "10.9.9.2"])
        self.assertGreater(ranked[0]["score"], ranked[1]["score"])
        self.assertEqual(ranked[0]["risk"], "CRITICAL")
        self.assertEqual(ranked[0]["open_ports"][0]["service"], "ssh")
