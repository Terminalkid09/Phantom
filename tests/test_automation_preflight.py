"""B3: operation-level preflight against a replica (sandbox + C2 check-in)."""
import tempfile
import unittest

from phantom.automation.exploit.modules import module_registry
from phantom.automation.sandbox.preflight import CheckinProbe, PreflightEngine
from phantom.automation.sandbox.sandbox import SandboxBackend, SandboxEngine, SandboxResult


class _FakeBackend(SandboxBackend):
    name = "fake"

    def __init__(self, ok=True):
        self._ok = ok

    def available(self):
        return True

    def run_sample(self, sample_path):
        return SandboxResult(backend=self.name, ok=self._ok,
                             error="" if self._ok else "detected by AV")


def _clear_c2_state():
    from phantom.core.c2_server import c2_state
    c2_state.beacons.clear()
    c2_state.tasks.clear()
    c2_state.results.clear()
    # HMAC replay protection: probes reuse the same beacon_id across tests,
    # so the per-beacon counter/nonce history must reset with the state.
    c2_state.auth_counters.clear()
    c2_state.auth_nonces.clear()


class TestCheckinProbe(unittest.TestCase):

    def setUp(self):
        _clear_c2_state()

    def test_http_checkin_roundtrip(self):
        res = CheckinProbe().probe(
            beacon_id="beacon-preflight-1",
            sysinfo="OS: Linux 5.15\nUser: root\nArch: x64\nHost: replica",
            netinfo="IP: 127.0.0.1",
            result_payload="PREFLIGHT_OK")
        self.assertTrue(res.ok, res.error)
        self.assertIn("check-in verified", res.detail)
        from phantom.core.c2_server import c2_state
        beacons = c2_state.get_beacons()
        self.assertIn("beacon-preflight-1", beacons)
        self.assertEqual(beacons["beacon-preflight-1"]["os"], "Linux 5.15")
        results = c2_state.get_results("beacon-preflight-1")
        self.assertEqual(results[0]["output"], "PREFLIGHT_OK")

    def test_tls_checkin_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = CheckinProbe(use_ssl=True, cert_dir=tmp).probe(
                beacon_id="beacon-preflight-tls",
                sysinfo="OS: Windows 11\nUser: admin\nArch: x64\nHost: replica",
                netinfo="IP: 127.0.0.1")
        self.assertTrue(res.ok, res.error)
        from phantom.core.c2_server import c2_state
        self.assertIn("beacon-preflight-tls", c2_state.get_beacons())

    def test_listener_setup_failure_clean(self):
        from unittest.mock import patch
        with patch("phantom.automation.sandbox.preflight.CheckinProbe._ssl_context",
                   side_effect=RuntimeError("no crypto")):
            res = CheckinProbe(use_ssl=True).probe(beacon_id="beacon-preflight-bad")
        self.assertFalse(res.ok)
        self.assertIn("listener setup failed", res.error)


class TestPreflightEngine(unittest.TestCase):

    def setUp(self):
        _clear_c2_state()

    def test_rce_module_approved_with_checkin(self):
        module = module_registry.get("CVE-2021-41773")
        report = PreflightEngine().preflight_module(
            module, "10.0.0.5", 443)
        self.assertTrue(report.approved, report.reason)
        self.assertTrue(report.script_path.endswith(".rc"))
        self.assertTrue(report.checkin.ok)
        self.assertIn("APPROVED", report.summary())

    def test_rce_module_approved_with_sandbox_gate(self):
        module = module_registry.get("CVE-2021-41773")
        sandbox = SandboxEngine(backends=[_FakeBackend(ok=True)])
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            payload = f.name
        try:
            report = PreflightEngine(sandbox=sandbox).preflight_module(
                module, "10.0.0.5", 443, payload_path=payload)
            self.assertTrue(report.approved, report.reason)
            self.assertEqual(len(report.sandbox.results), 1)
        finally:
            import os
            os.unlink(payload)

    def test_rce_module_denied_by_sandbox(self):
        module = module_registry.get("CVE-2021-41773")
        sandbox = SandboxEngine(backends=[_FakeBackend(ok=False)])
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            payload = f.name
        try:
            report = PreflightEngine(sandbox=sandbox).preflight_module(
                module, "10.0.0.5", 443, payload_path=payload)
            self.assertFalse(report.approved)
            self.assertIn("sandbox", report.reason)
            self.assertIn("DENIED", report.summary())
        finally:
            import os
            os.unlink(payload)

    def test_auxiliary_module_skips_checkin(self):
        module = module_registry.get("CVE-2014-0160")
        report = PreflightEngine().preflight_module(module, "10.0.0.5", 443)
        self.assertTrue(report.approved, report.reason)
        self.assertIsNone(report.checkin)
        self.assertIn("use auxiliary/scanner/ssl/openssl_heartbleed",
                      open(report.script_path, encoding="utf-8").read())
        # auxiliary script must not contain a payload
        self.assertNotIn("set PAYLOAD",
                         open(report.script_path, encoding="utf-8").read())

    def test_require_checkin_false_skips_gate(self):
        module = module_registry.get("CVE-2021-44228")
        report = PreflightEngine().preflight_module(
            module, "10.0.0.5", 8080, require_checkin=False)
        self.assertTrue(report.approved, report.reason)
        self.assertIsNone(report.checkin)

    def test_script_synthesis_failure_denies(self):
        from unittest.mock import Mock
        runner = Mock()
        runner.exploit_resource_script.side_effect = RuntimeError("no msf")
        module = module_registry.get("CVE-2021-44228")
        report = PreflightEngine(runner=runner).preflight_module(
            module, "10.0.0.5", 8080)
        self.assertFalse(report.approved)
        self.assertIn("resource script synthesis failed", report.reason)

    def test_probe_beacon_registered_with_hostname(self):
        module = module_registry.get("CVE-2021-41773")
        with tempfile.TemporaryDirectory() as tmp:
            report = PreflightEngine().preflight_module(
                module, "10.0.0.5", 443, use_ssl=True, cert_dir=tmp)
        self.assertTrue(report.approved, report.reason)
        from phantom.core.c2_server import c2_state
        self.assertIn("preflight-cve202141773", c2_state.get_beacons())


if __name__ == "__main__":
    unittest.main()
