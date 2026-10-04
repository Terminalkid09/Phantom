"""The passive external-intel recon capability (`external_recon`).

It exists so the wrapped public services (Shodan/crt.sh/BGP) are usable by
the AUTOMATIC planner on every goal/profile — especially where a loud scan
is unavailable or unwanted. These tests pin: host parsing, port→service
mapping, the IP vs domain routing, capability registration, and that it is
the LAST source for `service` (a real scanner still wins).
"""
import unittest

from phantom.automation import external_intel as xi
from phantom.automation.belief import WorldModel


class TestHostParsing(unittest.TestCase):
    def test_url_and_port_forms(self):
        self.assertEqual(xi._host_of("https://corp.example.com/app"),
                         "corp.example.com")
        self.assertEqual(xi._host_of("10.0.0.9:8080"), "10.0.0.9")
        self.assertEqual(xi._host_of("10.0.0.9"), "10.0.0.9")
        self.assertEqual(xi._host_of(""), "")
        self.assertEqual(xi._host_of("[2001:db8::1]:443"), "2001:db8::1")

    def test_is_ip(self):
        self.assertTrue(xi._is_ip("10.0.0.9"))
        self.assertTrue(xi._is_ip("2001:db8::1"))
        self.assertFalse(xi._is_ip("corp.example.com"))


class TestEngine(unittest.TestCase):
    def _wm(self, target):
        return WorldModel(target=target)

    def test_ip_uses_shodan_and_maps_ports(self):
        from phantom.utils import api as ext
        saved = ext.shodan_lookup
        ext.shodan_lookup = lambda ip, api_key="": {
            "ports": [22, 443], "hostnames": ["web.example.com"]}
        try:
            out = xi.external_intel_engine(self._wm("10.0.0.9"), {})
        finally:
            ext.shodan_lookup = saved
        self.assertIn("SHODAN: host=10.0.0.9 port=22", out)
        self.assertIn("HOSTNAME: host=web.example.com source=shodan", out)

    def test_domain_uses_crtsh(self):
        from phantom.utils import api as ext
        saved = ext.crtsh_lookup
        ext.crtsh_lookup = lambda d: [f"a.{d}", f"b.{d}"]
        try:
            out = xi.external_intel_engine(self._wm("corp.example.com"), {})
        finally:
            ext.crtsh_lookup = saved
        self.assertIn("HOSTNAME: host=a.corp.example.com source=crtsh", out)

    def test_failing_service_contributes_nothing(self):
        from phantom.utils import api as ext

        def boom(*a, **k):
            raise RuntimeError("offline")

        saved = ext.shodan_lookup
        ext.shodan_lookup = boom
        try:
            out = xi.external_intel_engine(self._wm("10.0.0.9"), {})
        finally:
            ext.shodan_lookup = saved
        self.assertTrue(out.startswith("#"))  # comment, not a crash


class TestInterp(unittest.TestCase):
    def _wm(self):
        return WorldModel(target="10.0.0.9")

    def test_port_maps_to_service_kind(self):
        out = ("SHODAN: host=10.0.0.9 port=22\n"
               "SHODAN: host=10.0.0.9 port=445\n"
               "SHODAN: host=10.0.0.9 port=6379")
        fs = xi.external_intel_interp(out, self._wm(), {})
        by_key = {f.key: f for f in fs}
        self.assertEqual(by_key["tcp/22"].value["service"], "ssh")
        self.assertEqual(by_key["tcp/445"].value["service"], "smb")
        self.assertEqual(by_key["tcp/6379"].value["service"], "redis")

    def test_unknown_port_still_yields_a_service_fact(self):
        fs = xi.external_intel_interp(
            "SHODAN: host=10.0.0.9 port=9999", self._wm(), {})
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].value["service"], "")

    def test_invalid_port_is_skipped(self):
        fs = xi.external_intel_interp(
            "SHODAN: host=10.0.0.9 port=999999", self._wm(), {})
        self.assertEqual(fs, [])

    def test_hostname_and_bgp_markers(self):
        fs = xi.external_intel_interp(
            "HOSTNAME: host=a.example.com source=crtsh\n"
            "BGP: host=10.0.0.9 prefix=10.0.0.0/8", self._wm(), {})
        kinds = {f.kind for f in fs}
        self.assertEqual(kinds, {"hostname", "netblock"})

    def test_low_confidence_so_a_scan_supersedes(self):
        fs = xi.external_intel_interp(
            "SHODAN: host=10.0.0.9 port=22", self._wm(), {})
        self.assertLess(fs[0].confidence, 0.9)


class TestCapabilityWiring(unittest.TestCase):
    def _cap(self):
        from phantom.automation.guidance.kit import CAPABILITIES
        return {c.id: c for c in CAPABILITIES}["external_recon"]

    def test_registered_as_in_process_recon(self):
        cap = self._cap()
        self.assertEqual(cap.category, "recon")
        self.assertEqual(cap.exec_class, "in_process_engine")
        self.assertIsNotNone(cap.engine)
        self.assertIn("service", cap.effects)
        self.assertIn("hostname", cap.effects)
        self.assertEqual(cap.stealth_level, "passive")

    def test_declared_in_the_phase_index(self):
        from phantom.automation.phases import phase_of
        self.assertEqual(phase_of("external_recon"), "recon")

    def test_is_the_last_source_for_service(self):
        from phantom.automation.planner import _FACT_SOURCES
        order = _FACT_SOURCES["service"]
        self.assertIn("external_recon", order)
        self.assertEqual(order[-1], "external_recon")
        self.assertEqual(_FACT_SOURCES["hostname"], ["external_recon"])

    def test_scanner_still_wins_on_a_bare_world(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.guidance.commands import make_registry
        from phantom.automation.guidance.stealth import (
            StealthEngine, StealthConfig)
        from phantom.automation.planner import Planner
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        planner = Planner(make_registry(), StealthEngine(wm, StealthConfig()))
        plan = planner.plan(wm, goal="footprint")
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("scan_tcp", ids)
        self.assertNotIn("external_recon", ids)

    def test_falls_back_to_external_recon_when_no_scanner_available(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.guidance.commands import make_registry
        from phantom.automation.guidance.stealth import (
            StealthEngine, StealthConfig)
        from phantom.automation.planner import Planner
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        planner = Planner(make_registry(), StealthEngine(wm, StealthConfig()))
        plan = planner.plan(
            wm, goal="footprint",
            dead=frozenset({"scan_tcp", "version_detect", "curl_probe"}))
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("external_recon", ids)


if __name__ == "__main__":
    unittest.main()
