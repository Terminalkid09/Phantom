"""A5: orphaned beacon built-ins mapped to agent capabilities.

The C++ beacon ships cookie_stealer.h, bt_scan.h, cdp_pivot.h and proxy.h
built-ins that were only reachable from the C2 shell. They are now
first-class post-exploitation capabilities with real markers matching the
C++ output:

  cookies-json   -> "COOKIES:[{host,name,path,value},...]"
  bt-scan-json   -> "BT_SCAN:[{name,mac,rssi,class},...]"
  cdp-cookies    -> "=== CDP COOKIES (N) === ..."
  socks <port>   -> "SOCKS5 proxy started on 0.0.0.0:<port>"
"""
import json
import os
import tempfile
import threading
import unittest
from unittest.mock import Mock


def _fake_builder(platform, host, port):
    """Fake compile-on-demand: produces a real file (the deploy path
    checks the binary exists on disk)."""
    fd, path = tempfile.mkstemp(prefix="fake_beacon_", suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(b"PHANTOM-FAKE-BEACON")
    return path

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.post import harvest

VICTIM_IP = "10.0.0.5"


def _reset_c2():
    from phantom.core.c2_server import c2_state
    c2_state.beacons.clear()
    c2_state.tasks.clear()
    c2_state.results.clear()


def _approving_sandbox():
    from phantom.automation.sandbox.sandbox import SandboxEngine, SandboxVerdict, SandboxResult

    class _Approve(SandboxEngine):
        def preflight(self, sample_path):
            return SandboxVerdict(approved=True,
                                  results=[SandboxResult(backend="docker", ok=True)])
    return _Approve()


class TestHarvestInterpreters(unittest.TestCase):

    def test_cookies_interpreter(self):
        wm = WorldModel(target=VICTIM_IP)
        out = ('COOKIES:[{"host":".github.com","name":"session","path":"/",'
               '"value":"abc123"},{"host":"mail.corp.com","name":"SID",'
               '"path":"/","value":"xyz"}]')
        findings = harvest.cookies_interpreter(out, wm, {})
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, "stolen_cookies")
        self.assertEqual(f.value["count"], 2)
        self.assertIn(".github.com", f.value["hosts"])

    def test_cookies_interpreter_empty(self):
        wm = WorldModel(target=VICTIM_IP)
        self.assertEqual(harvest.cookies_interpreter("COOKIES:[]", wm, {}), [])
        self.assertEqual(harvest.cookies_interpreter("no cookies found", wm, {}), [])

    def test_bt_scan_interpreter(self):
        wm = WorldModel(target=VICTIM_IP)
        out = ('BT_SCAN:[{"name":"iPhone","mac":"AA:BB:CC:DD:EE:FF",'
               '"rssi":-42,"class":"phone"}]')
        findings = harvest.bt_scan_interpreter(out, wm, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "bt_device")
        self.assertEqual(findings[0].key, "bt:AA:BB:CC:DD:EE:FF")
        self.assertEqual(findings[0].value["rssi"], -42)

    def test_cdp_cookies_interpreter(self):
        wm = WorldModel(target=VICTIM_IP)
        out = "=== CDP COOKIES (7) ===\nhost: .corp.com\nname: auth"
        findings = harvest.cdp_cookies_interpreter(out, wm, {"port": 9222})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "cdp_cookies")
        self.assertEqual(findings[0].value["count"], 7)
        self.assertEqual(findings[0].value["port"], 9222)
        # failure marker -> no finding
        self.assertEqual(
            harvest.cdp_cookies_interpreter("CDP connection failed.", wm, {}), [])

    def test_socks_interpreter(self):
        wm = WorldModel(target=VICTIM_IP)
        out = "SOCKS5 proxy started on 0.0.0.0:1080"
        findings = harvest.socks_interpreter(out, wm, {"port": 1080})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "socks_proxy")
        self.assertEqual(findings[0].value["port"], 1080)
        self.assertEqual(harvest.socks_interpreter("nope", wm, {}), [])


class TestCapabilitiesRegistered(unittest.TestCase):

    def setUp(self):
        self.registry = make_registry()

    def test_all_four_capabilities_present(self):
        for cid in ("cookie_stealer", "bt_scan", "cdp_pivot", "socks_proxy"):
            cap = self.registry.get(cid)
            self.assertIsNotNone(cap, cid)
            self.assertEqual(cap.category, "post")

    def test_adapter_commands_match_beacon_builtins(self):
        wm = WorldModel(target=VICTIM_IP)
        self.assertEqual(self.registry.get("cookie_stealer").make_command(wm, {}),
                         "cookies-json")
        self.assertEqual(self.registry.get("bt_scan").make_command(wm, {}),
                         "bt-scan-json")
        self.assertEqual(self.registry.get("cdp_pivot").make_command(wm, {}),
                         "cdp-cookies 9222")
        self.assertEqual(self.registry.get("socks_proxy").make_command(wm, {}),
                         "socks 1080")

    def test_preconditions_require_beacon(self):
        wm = WorldModel(target=VICTIM_IP)
        for cid in ("cookie_stealer", "bt_scan", "cdp_pivot", "socks_proxy"):
            cap = self.registry.get(cid)
            self.assertFalse(all(p(wm) for p in cap.preconditions), cid)
        wm.add_finding("beacon", "established",
                       {"ip": VICTIM_IP, "payload": "true"})
        for cid in ("cookie_stealer", "bt_scan", "cdp_pivot", "socks_proxy"):
            cap = self.registry.get(cid)
            self.assertTrue(all(p(wm) for p in cap.preconditions), cid)


class TestEndToEndThroughBeacon(unittest.TestCase):
    """The capabilities run through the C2 task channel like any post cap."""

    def setUp(self):
        _reset_c2()
        self.events = []

    def _make_agent(self, runner, social=None):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
        from phantom.automation.guidance.threatmodel import BlueTeamModel
        from phantom.automation.runtime.stealth_runtime import StealthRuntime, TimingGovernor
        from phantom.automation.runtime.toolchain import ToolRegistry
        return AutonomousAgent(
            target=VICTIM_IP, target_type="ip", profile="enterprise",
            on_event=lambda k, d: self.events.append((k, d)),
            runtime=StealthRuntime(
                StealthEngine(WorldModel(target=VICTIM_IP),
                              StealthConfig()),
                runner=runner, cost_per_action=0.5,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0)),
            toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc"}),
            social_engine=social or Mock())

    def test_post_goal_runs_harvest_caps_through_beacon(self):
        from phantom.automation.agent import AutonomousAgent
        from phantom.core.c2_server import c2_state

        def runner(cmd, timeout=None):
            res = Mock()
            res.ok = True
            res.stdout = ""
            res.stderr = ""
            if "phantom-beacon.service" in cmd or "crontab" in cmd:
                res.stdout = "PERSISTENCE_OK systemd"
            elif "api/v1/payload" in cmd:
                c2_state.update_beacon("beacon-h1", {"ip": VICTIM_IP, "os": "Linux"})
                res.stdout = "PHANTOM"
            elif "sshpass" in cmd and "scp" in cmd:
                # beacon deploy (scp + setsid): beacon starts on target
                c2_state.update_beacon("beacon-h1", {"ip": VICTIM_IP, "os": "Linux"})
                res.stdout = "PHANTOM"
            elif "cookies-json" in cmd:
                res.stdout = ('COOKIES:[{"host":".corp.com","name":"auth",'
                              '"path":"/","value":"tok"}]')
            elif "bt-scan-json" in cmd:
                res.stdout = 'BT_SCAN:[{"name":"Pixel","mac":"11:22:33:44:55:66",' \
                             '"rssi":-60,"class":"phone"}]'
            elif "cdp-cookies" in cmd:
                res.stdout = "=== CDP COOKIES (3) ===\nname: session"
            elif "socks " in cmd:
                res.stdout = "SOCKS5 proxy started on 0.0.0.0:1080"
            elif "nmap" in cmd:
                res.stdout = ("22/tcp open ssh OpenSSH 7.9p1\n"
                              "80/tcp open http Apache httpd 2.4.49")
            elif "nc -w" in cmd:
                res.stdout = "SSH-2.0-OpenSSH_7.9p1 Debian-10"
            elif "sshpass" in cmd:
                res.stdout = "uid=0(root) gid=0(root)"
            else:
                res.stdout = "PHANTOM"
            return res

        from phantom.automation.agent import run_autonomous
        from phantom.automation.runtime.toolchain import ToolRegistry
        stop = threading.Event()

        def sim():
            import time
            while not stop.is_set():
                for bid in list(c2_state.get_beacons().keys()):
                    for task in c2_state.get_pending_tasks(bid):
                        res = runner(task["command"])
                        c2_state.add_result(bid, task["task_id"], res.stdout)
                time.sleep(0.05)

        t = threading.Thread(target=sim, daemon=True)
        t.start()
        try:
            result = run_autonomous(
                target=VICTIM_IP, goal="harvest", max_iterations=20,
                runner=runner,
                cred_discoverer=lambda s: ("root", "toor"),
                sandbox=_approving_sandbox(),
                toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc"}),
                beacon_builder=_fake_builder,
                on_event=lambda k, d: None)
        finally:
            stop.set()
            t.join(timeout=3)

        self.assertTrue(result["beacon_established"], result)
        self.assertEqual(result["stolen_cookies"], 1, result)
        self.assertEqual(result["bt_devices"], 1, result)
        self.assertEqual(result["cdp_cookie_sets"], 1, result)
        self.assertEqual(result["socks_proxies"], 1, result)


if __name__ == "__main__":
    unittest.main()
