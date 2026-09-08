"""Logic-level tests for modules that need hardware/tools to run end-to-end.

These exercise the pure logic (validation, command construction, state
transitions, result parsing) with the external tool calls mocked, so the
behaviour is covered even on machines without airmon-ng/msfconsole etc.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

from phantom.modules.handler import HandlerModule
from phantom.modules.pivot import PivotModule
from phantom.modules.wifi import WifiModule
import phantom.modules.telegram as telegram_mod


class TestWifiLogic(unittest.TestCase):
    def setUp(self):
        self.wifi = WifiModule()
        self.wifi.interface = "wlan0mon"
        self.wifi.monitor_mode = True
        self._cmds = []
        self._patcher = mock.patch(
            "phantom.modules.wifi.run_command",
            side_effect=lambda cmd: self._cmds.append(cmd) or "",
        )
        self._patcher = self._patcher.start()

    def tearDown(self):
        self._patcher.stop()

    def test_handshake_rejects_invalid_bssid(self):
        self.wifi.do_handshake("not-a-mac 6")
        self.assertEqual(self._cmds, [])

    def test_handshake_rejects_out_of_range_channel(self):
        self.wifi.do_handshake("AA:BB:CC:DD:EE:FF 300")
        self.assertEqual(self._cmds, [])

    def test_handshake_accepts_valid_input(self):
        self.wifi.do_handshake("AA:BB:CC:DD:EE:FF 6")
        self.assertTrue(any("airodump-ng" in c for c in self._cmds))
        self.assertTrue(any("--bssid AA:BB:CC:DD:EE:FF" in c for c in self._cmds))

    def test_deauth_rejects_bad_bssid_and_count(self):
        self.wifi.do_deauth("nope")
        self.assertEqual(self._cmds, [])
        self.wifi.do_deauth("AA:BB:CC:DD:EE:FF notanumber")
        self.assertEqual(self._cmds, [])

    def test_deauth_accepts_valid_input(self):
        self.wifi.do_deauth("AA:BB:CC:DD:EE:FF 15")
        self.assertTrue(any("--deauth 15" in c for c in self._cmds))

    def test_scan_requires_interface(self):
        self.wifi.interface = ""
        self.wifi.do_scan_aps("")
        self.assertEqual(self._cmds, [])

    def test_crack_missing_capture_errors(self):
        with mock.patch.object(phantom_mods_notifier(), "error") as err:
            self.wifi.do_crack("/nonexistent/file")
            self.assertTrue(err.called)


# helper to reference the notifier module used by wifi
def phantom_mods_notifier():
    import phantom.utils.notifier as n

    return n.notifier


class TestHandlerLogic(unittest.TestCase):
    def setUp(self):
        self.handler = HandlerModule()

    def test_list_empty(self):
        with mock.patch.object(phantom_mods_notifier(), "info") as info:
            self.handler.do_list("")
            self.assertTrue(info.called)

    def test_duplicate_listener_warns(self):
        fake_proc = mock.Mock()
        fake_proc.poll.return_value = None
        self.handler._listeners[4444] = fake_proc
        with mock.patch.object(phantom_mods_notifier(), "warn") as warn:
            self.handler.start_listener("4444")
            self.assertTrue(warn.called)

    def test_do_listen_tcp_payload_mapping(self):
        with mock.patch.object(self.handler, "start_listener") as start:
            self.handler.do_listen("--port 4444 --type tcp")
            start.assert_called_once()
            args, kwargs = start.call_args
            self.assertEqual(args[0], "4444")
            self.assertEqual(args[1], "linux/x64/shell_reverse_tcp")

    def test_do_listen_https_payload_mapping(self):
        with mock.patch.object(self.handler, "start_listener") as start:
            self.handler.do_listen("--port 4443 --type https")
            args, kwargs = start.call_args
            self.assertEqual(args[1], "linux/x64/meterpreter/reverse_https")

    def test_kill_unknown_port_warns(self):
        with mock.patch.object(phantom_mods_notifier(), "warn") as warn:
            self.handler.do_kill("9999")
            self.assertTrue(warn.called)


class TestPivotLogic(unittest.TestCase):
    def test_ssh_local_command_construction(self):
        pivot = PivotModule()
        # one extra value so any trailing prompt falls back to its default
        with mock.patch("builtins.input", side_effect=["1", "10.0.0.5", "root",
                                                       "8080", "80", "1080", "8000", ""]):
            with mock.patch.object(phantom_mods_notifier(), "success") as success:
                pivot.do_setup("")
                self.assertTrue(success.called)

    def test_invalid_tunnel_type_rejected(self):
        pivot = PivotModule()
        with mock.patch("builtins.input", return_value="99"):
            with mock.patch.object(phantom_mods_notifier(), "error") as err:
                pivot.do_setup("")
                self.assertTrue(err.called)


class TestTelegramLogic(unittest.TestCase):
    def setUp(self):
        import importlib

        self._saved = {
            "PHANTOM_TELEGRAM_BOT_TOKEN": os.environ.get("PHANTOM_TELEGRAM_BOT_TOKEN"),
            "PHANTOM_C2_API": os.environ.get("PHANTOM_C2_API"),
            "PHANTOM_API_TOKEN": os.environ.get("PHANTOM_API_TOKEN"),
            "PHANTOM_STATE_FILE": os.environ.get("PHANTOM_STATE_FILE"),
        }
        os.environ.pop("PHANTOM_TELEGRAM_BOT_TOKEN", None)
        os.environ.pop("PHANTOM_C2_API", None)
        os.environ.pop("PHANTOM_API_TOKEN", None)
        tmp = tempfile.mkdtemp(prefix="phantom-tg-test-")
        os.environ["PHANTOM_STATE_FILE"] = os.path.join(tmp, "state.json")
        # API_TOKEN is captured at import time; reload so the test sees the
        # isolated state file (this also documents the import-time capture).
        self.tg = importlib.reload(telegram_mod)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_headers_include_api_token(self):
        headers = self.tg._headers()
        self.assertEqual(headers.get("X-Api-Token"), self.tg.API_TOKEN)
        self.assertTrue(headers.get("X-Api-Token"))

    def test_api_get_returns_parsed_json(self):
        fake_resp = mock.Mock()
        fake_resp.read.return_value = json.dumps({"ok": True}).encode()
        with mock.patch(
            "urllib.request.urlopen", return_value=fake_resp
        ) as urlopen:
            result = self.tg._api_get("/api/v1/beacons")
            self.assertEqual(result, {"ok": True})
            req = urlopen.call_args[0][0]
            self.assertTrue(
                any(k.lower() == "x-api-token" for k in req.headers))

    def test_api_get_returns_none_on_error(self):
        with mock.patch(
            "urllib.request.urlopen", side_effect=Exception("network")
        ):
            self.assertIsNone(self.tg._api_get("/api/v1/beacons"))


if __name__ == "__main__":
    unittest.main()