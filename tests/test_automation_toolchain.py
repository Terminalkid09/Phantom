"""Toolchain tests: tool detection, graceful degradation, no autofill side effects."""
import unittest
from unittest.mock import Mock

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.runtime.stealth_runtime import StealthRuntime, TimingGovernor
from phantom.automation.runtime.toolchain import ToolRegistry
from phantom.automation.sandbox.sandbox import SandboxEngine, SandboxVerdict, SandboxResult
from phantom.automation.agent import AutonomousAgent

TARGET = "10.0.0.5"


def _fake_builder(platform, host, port):
    """Fake compile-on-demand: produces a real file (the deploy path
    checks the binary exists on disk)."""
    import os
    import tempfile
    fd, path = tempfile.mkstemp(prefix="fake_beacon_", suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(b"PHANTOM-FAKE-BEACON")
    return path


def _fake_runner():
    from phantom.core.c2_server import c2_state
    _idx = [0]

    def runner(cmd, timeout=None):
        res = Mock()
        res.ok = True
        res.stdout = "PHANTOM"
        res.stderr = ""
        if "api/v1/payload" in cmd:  # dropper -> the C++ beacon checks in
            _idx[0] += 1
            c2_state.update_beacon(f"beacon-{TARGET}-{_idx[0]}",
                                   {"ip": TARGET, "os": "Linux 5.15"})
        elif "sshpass" in cmd and "scp" in cmd:
            # beacon deploy (scp + setsid): beacon starts on target
            _idx[0] += 1
            c2_state.update_beacon(f"beacon-{TARGET}-{_idx[0]}",
                                   {"ip": TARGET, "os": "Linux 5.15"})
        elif "nmap" in cmd:
            res.stdout = "22/tcp open ssh OpenSSH 7.9p1"
        elif "sshpass" in cmd:
            res.stdout = "uid=0(root) gid=0(root)"
        return res
    return runner


def _approving_sandbox():
    class _ApproveSandbox(SandboxEngine):
        def preflight(self, sample_path):
            return SandboxVerdict(
                approved=True,
                results=[SandboxResult(backend="docker", ok=True)])
    return _ApproveSandbox()


class TestToolRegistry(unittest.TestCase):

    def test_injected_installed_set(self):
        tr = ToolRegistry(installed={"nmap", "curl"})
        self.assertTrue(tr.has("nmap"))
        self.assertTrue(tr.has("curl"))
        self.assertFalse(tr.has("sshpass"))
        self.assertEqual(tr.resolve(["sshpass", "curl"]), "curl")
        self.assertEqual(tr.missing(["sshpass", "nc"]), ["sshpass", "nc"])
        self.assertEqual(tr.installed_tools(), ["curl", "nmap"])
        self.assertIn("sshpass", tr.missing_tools())

    def test_detection_is_cached(self):
        calls = []
        tr = ToolRegistry(detect=lambda name: calls.append(name) or name == "nmap")
        tr.has("nmap")
        tr.has("nmap")
        tr.has("nmap")
        self.assertEqual(len(calls), 1)

    def test_resolve_none_when_everything_missing(self):
        tr = ToolRegistry(installed=set())
        self.assertIsNone(tr.resolve(["nmap", "nc"]))


class TestToolGatingInAgent(unittest.TestCase):

    def setUp(self):
        self.events = []
        from phantom.core.c2_server import c2_state
        c2_state.beacons.clear()
        c2_state.tasks.clear()
        c2_state.results.clear()

    def _agent(self, installed):
        return AutonomousAgent(
            target=TARGET, target_type="ip", profile="enterprise",
            on_event=lambda k, d: self.events.append((k, d)),
            runtime=StealthRuntime(
                StealthEngine(WorldModel(target=TARGET),
                              StealthConfig()),
                runner=_fake_runner(),
                cost_per_action=0.5,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0),
            ),
            cred_discoverer=lambda service: ("root", "toor"),
            sandbox=_approving_sandbox(),
            toolchain=ToolRegistry(installed=installed),
            beacon_builder=_fake_builder,
        )

    def test_no_tools_no_crash_clean_halt(self):
        agent = self._agent(installed=set())
        result = agent.run(goal="complete_kill_chain", max_iterations=5)
        self.assertFalse(result["beacon_established"])
        # multi-tool era: ZERO external binaries does not mean zero moves —
        # in-process capabilities (ssh_banner via the fingerprint engine)
        # still run and cleanly produce nothing. What must NOT happen:
        # tool-dependent capabilities executing, a beacon, or a crash.
        kinds = [k for k, _ in self.events]
        self.assertIn("tool_missing", kinds)          # scan blocked (nmap/masscan/nc)
        blocked_caps = {d.get("capability") for k, d in self.events
                        if k == "tool_missing"}
        self.assertIn("scan_tcp", blocked_caps)
        ran = {d.get("capability") for k, d in self.events if k == "run"}
        self.assertFalse(ran & {"scan_tcp", "version_detect", "os_detect",
                                "smb_enum", "http_probe", "ssh_login"})
        halts = [d for k, d in self.events if k == "halt"]
        self.assertTrue(halts)

    def test_missing_sshpass_blocks_ssh_login_and_autofill(self):
        # nmap/nc/curl present, sshpass missing -> ssh_login must fail with
        # "tool unavailable" BEFORE autofill records a side-effect credential
        agent = self._agent(installed={"nmap", "nc", "curl"})
        result = agent.run(goal="complete_kill_chain", max_iterations=10)
        self.assertFalse(result["beacon_established"])
        self.assertEqual(result["creds_found"], 0)  # no creds side effect
        missing = [d for k, d in self.events if k == "tool_missing"]
        self.assertTrue(any("sshpass" in d.get("tools", []) for d in missing))
        self.assertTrue(any(a["capability"] == "ssh_login" and "unavailable"
                            in a.get("reason", "")
                            for a in agent.wm.failures))

    def test_full_chain_when_all_tools_present(self):
        agent = self._agent(installed={"nmap", "nc", "curl", "sshpass",
                                       "redis-cli", "smbmap"})
        result = agent.run(goal="complete_kill_chain", max_iterations=10)
        self.assertTrue(result["beacon_established"])


if __name__ == "__main__":
    unittest.main()
