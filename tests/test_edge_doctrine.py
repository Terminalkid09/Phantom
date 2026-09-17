"""EDGE doctrine — never scan the provider's reverse proxy.

The property under test is not "detection works". It is:

    while the address in scope is a CDN edge and no origin is known, the
    chain refuses packet-level work and runs origin discovery instead; once
    an origin is discovered, every network adapter aims at the ORIGIN.

Three layers, all offline (the transport is injected, so no DNS and no
network is involved):

    brain.edge     pure detection + candidate ranking
    kit            `_effective_target` aims at the origin; the HTTP probe
                   turns header evidence into the EDGE gate fact
    agent          the guard refuses and schedules the discovery pass
"""

import types
import unittest

from phantom.automation.brain import edge as e
from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.kit import best_origin, _effective_target


# ── detection ─────────────────────────────────────────────────────────────

class TestEdgeDetection(unittest.TestCase):

    def test_cf_ray_header_is_an_edge(self):
        v = e.detect(headers={"cf-ray": "8a1b2c3d4e5f-FRA", "server": "x"})
        self.assertTrue(v.is_edge)
        self.assertEqual(v.provider, "cloudflare")
        self.assertGreaterEqual(v.confidence, e.EDGE_THRESHOLD)
        self.assertTrue(any("cf-ray" in x for x in v.evidence))

    def test_akamai_and_cloudfront_headers(self):
        self.assertEqual(
            e.detect(headers={"X-Akamai-Transformed": "9 0"}).provider, "akamai")
        self.assertEqual(
            e.detect(headers={"x-amz-cf-id": "abc"}).provider, "cloudfront")
        self.assertEqual(
            e.detect(headers={"x-iinfo": "1-2-3"}).provider, "imperva")

    def test_a_plain_server_header_is_not_an_edge(self):
        v = e.detect(headers={"server": "nginx/1.18.0"})
        self.assertFalse(v.is_edge)
        self.assertEqual(v.provider, "")

    def test_varnish_alone_is_a_hint_not_a_gate(self):
        """`via: varnish` is a shared cache signal, not proof: stopping a run
        on it would be a false positive."""
        v = e.detect(headers={"via": "1.1 varnish"})
        self.assertFalse(v.is_edge)
        self.assertLess(v.confidence, e.EDGE_THRESHOLD)
        self.assertGreater(v.confidence, 0.0)

    def test_cname_to_a_provider_is_an_edge(self):
        v = e.detect(cname="example.com.cdn.cloudflare.net")
        self.assertTrue(v.is_edge)
        self.assertEqual(v.provider, "cloudflare")
        self.assertTrue(any("cname:" in x for x in v.evidence))

    def test_curated_range_is_an_edge(self):
        v = e.detect(ip="104.16.132.229")          # Cloudflare
        self.assertTrue(v.is_edge)
        self.assertEqual(v.provider, "cloudflare")
        self.assertIn("range:", v.evidence[0])

    def test_a_normal_address_is_not_an_edge(self):
        for ip in ("203.0.113.10", "10.0.0.5", "192.168.1.1"):
            self.assertFalse(e.is_edge_ip(ip), ip)

    def test_a_bogus_ip_is_not_an_edge(self):
        self.assertFalse(e.is_edge_ip("not-an-ip"))
        self.assertFalse(bool(e.detect(ip="")))

    def test_markers_are_interpreter_safe(self):
        """Marker values must not contain spaces: the shared interpreter
        splits on whitespace."""
        lines = e.detect(headers={"cf-ray": "abc"}).markers("example.com")
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("EDGE: "))
        self.assertIn("is_edge=true", lines[0])


# ── origin candidates ─────────────────────────────────────────────────────

class TestOriginCandidates(unittest.TestCase):

    def _resolve(self, mapping):
        def fn(host):
            return mapping.get(host, ("", []))
        return fn

    def test_a_named_origin_outside_the_ranges_wins(self):
        hosts = ["www.example.com", "origin.example.com",
                 "cdn.example.com", "mail.example.com"]
        resolve = self._resolve({
            "origin.example.com": ("", ["203.0.113.10"]),
            "mail.example.com": ("", ["198.51.100.7"]),
            "www.example.com": ("example.com.cdn.cloudflare.net", ["104.16.1.1"]),
            "cdn.example.com": ("cdn.example.com.cdn.cloudflare.net",
                                ["104.16.2.2"]),
        })
        got = e.origin_candidates(hosts, domain="example.com", resolve=resolve)
        names = [c.host for c in got]
        self.assertIn("origin.example.com", names)
        self.assertIn("mail.example.com", names)
        # a www/cdn host is never proposed as the origin
        self.assertNotIn("www.example.com", names)
        self.assertNotIn("cdn.example.com", names)
        # and the best one is the named origin
        self.assertEqual(got[0].host, "origin.example.com")
        self.assertGreaterEqual(got[0].confidence, e.ORIGIN_MIN_CONFIDENCE)

    def test_a_host_inside_the_provider_range_is_never_an_origin(self):
        hosts = ["app.example.com"]
        resolve = self._resolve({"app.example.com": ("", ["104.16.9.9"])})
        got = e.origin_candidates(hosts, domain="example.com", resolve=resolve)
        self.assertEqual(got, [])

    def test_a_host_cnamed_to_the_edge_is_never_an_origin(self):
        hosts = ["portal.example.com"]
        resolve = self._resolve({
            "portal.example.com": ("portal.example.com.cdn.cloudflare.net",
                                   ["104.16.9.9"])})
        got = e.origin_candidates(hosts, domain="example.com", resolve=resolve)
        self.assertEqual(got, [])

    def test_hosts_outside_the_namespace_are_ignored(self):
        hosts = ["origin.other-domain.com", "example.com"]
        got = e.origin_candidates(hosts, domain="example.com")
        self.assertEqual([c.host for c in got], ["example.com"])

    def test_naming_alone_is_below_the_confidence_floor(self):
        got = e.origin_candidates(["gateway.example.com"], domain="example.com")
        self.assertEqual(len(got), 1)
        self.assertLess(got[0].confidence, e.ORIGIN_MIN_CONFIDENCE)


# ── the doctrine: what the chain aims at ─────────────────────────────────

class TestEffectiveTargetIsEdgeAware(unittest.TestCase):

    def _wm(self, **facts):
        wm = WorldModel(target="example.com", target_type="domain")
        for kind, value in facts.items():
            wm.add_finding(kind=kind, key=f"{kind}:1", value=value,
                           confidence=0.9, source="test")
        return wm

    def test_without_an_origin_the_target_is_used(self):
        wm = self._wm(edge={"address": "example.com", "provider": "cloudflare",
                            "confidence": 0.95, "is_edge": True})
        self.assertEqual(_effective_target(wm), "example.com")

    def test_with_an_origin_the_origin_is_used(self):
        wm = self._wm(
            edge={"address": "example.com", "provider": "cloudflare",
                  "confidence": 0.95, "is_edge": True},
            origin={"host": "origin.example.com", "ip": "203.0.113.10",
                    "reason": "naming+resolves", "confidence": 0.85})
        self.assertEqual(_effective_target(wm), "origin.example.com")

    def test_a_weak_origin_does_not_redirect_the_chain(self):
        wm = self._wm(
            origin={"host": "maybe.example.com", "ip": "",
                    "reason": "candidate", "confidence": 0.30})
        self.assertIsNone(best_origin(wm))
        self.assertEqual(_effective_target(wm), "example.com")

    def test_a_victim_ip_still_wins_over_an_origin(self):
        """An identity chain converges on the harvested machine: that is a
        real host, and it takes precedence over any origin candidate."""
        wm = self._wm(
            victim_ip={"ip": "198.51.100.9"},
            origin={"host": "origin.example.com", "ip": "203.0.113.10",
                    "reason": "naming+resolves", "confidence": 0.85})
        self.assertEqual(_effective_target(wm), "198.51.100.9")


# ── the HTTP probe arms the gate ─────────────────────────────────────────

class TestHttpProbeDetectsTheEdge(unittest.TestCase):

    def test_cf_ray_in_the_response_emits_an_edge_fact(self):
        cap = make_registry().get("http_probe")
        wm = WorldModel(target="example.com", target_type="domain")
        raw = ("HTTP/1.1 200 OK\r\nServer: cloudflare\r\n"
               "cf-ray: 8a1b2c3d4e5f-FRA\r\nContent-Type: text/html\r\n")
        findings = cap.interpret(raw, wm, {})
        kinds = [f.kind for f in findings]
        self.assertIn(e.EDGE_FACT, kinds)
        edge = [f for f in findings if f.kind == e.EDGE_FACT][0]
        self.assertTrue(edge.value["is_edge"])
        self.assertEqual(edge.value["provider"], "cloudflare")

    def test_a_clean_response_emits_no_edge_fact(self):
        cap = make_registry().get("http_probe")
        wm = WorldModel(target="example.com", target_type="domain")
        raw = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
        self.assertNotIn(e.EDGE_FACT, [f.kind for f in cap.interpret(raw, wm, {})])


# ── the guard ─────────────────────────────────────────────────────────────

class _Res:
    def __init__(self, stdout=""):
        self.ok = True
        self.stdout = stdout
        self.stderr = ""


def _scripted_runner(answers):
    """A `runner(cmd, timeout=…)` that answers DNS/curl from a table."""
    def runner(cmd, timeout=None):
        for needle, out in answers:
            if needle in cmd:
                return _Res(out)
        return _Res("")
    return runner


class TestEdgeGuard(unittest.TestCase):

    def _agent(self, runner=None):
        from phantom.automation.agent import AutonomousAgent
        a = AutonomousAgent("example.com", target_type="domain",
                            edge_runner=runner)
        return a

    def test_a_packet_level_move_is_refused_while_the_edge_stands(self):
        a = self._agent()
        a.wm.add_finding(kind=e.EDGE_FACT, key="edge:example.com",
                         value={"address": "example.com", "provider": "cloudflare",
                                "confidence": 0.95, "is_edge": True},
                         confidence=0.9, source="test")
        reason = a._edge_guard(a.registry.get("scan_tcp"))
        self.assertIn("cloudflare", reason)
        self.assertIn("origin", reason)
        # the refusal armed the discovery pass
        self.assertTrue(a._origin_needed)

    def test_an_ordinary_web_request_is_not_gated(self):
        """http_probe is how the provider is FOUND: gating it would make the
        gate unreachable."""
        a = self._agent()
        a.wm.add_finding(kind=e.EDGE_FACT, key="edge:example.com",
                         value={"address": "example.com", "provider": "cloudflare",
                                "confidence": 0.95, "is_edge": True},
                         confidence=0.9, source="test")
        self.assertEqual(a._edge_guard(a.registry.get("http_probe")), "")

    def test_the_gate_unlocks_once_an_origin_is_known(self):
        a = self._agent()
        a.wm.add_finding(kind=e.EDGE_FACT, key="edge:example.com",
                         value={"address": "example.com", "provider": "cloudflare",
                                "confidence": 0.95, "is_edge": True},
                         confidence=0.9, source="test")
        a.wm.add_finding(kind=e.ORIGIN_FACT, key="origin:origin.example.com",
                         value={"host": "origin.example.com", "ip": "203.0.113.10",
                                "reason": "naming+resolves", "confidence": 0.85},
                         confidence=0.85, source="test")
        self.assertEqual(a._edge_guard(a.registry.get("scan_tcp")), "")

    def test_a_weak_edge_signal_does_not_gate(self):
        a = self._agent()
        a.wm.add_finding(kind=e.EDGE_FACT, key="edge:example.com",
                         value={"address": "example.com", "provider": "varnish",
                                "confidence": 0.60, "is_edge": False},
                         confidence=0.6, source="test")
        self.assertEqual(a._edge_guard(a.registry.get("scan_tcp")), "")

    def test_execution_blocks_and_stays_plannable(self):
        """End of the chain: the move is refused, reported, and NOT marked
        dead — it unlocks later."""
        from phantom.automation.planner import PlanStep
        a = self._agent()
        a.wm.add_finding(kind=e.EDGE_FACT, key="edge:example.com",
                         value={"address": "example.com", "provider": "cloudflare",
                                "confidence": 0.95, "is_edge": True},
                         confidence=0.9, source="test")
        cap = a.registry.get("scan_tcp")
        ran = []
        a._execute_capability_raw = a._execute_capability
        a._execute_capability = lambda s: ran.append(1) or True
        steps = PlanStep(capability=cap, slot_values={})
        self.assertFalse(a._execute_capability_raw(steps))
        self.assertEqual(ran, [])
        reasons = [d.get("reason", "") for d in a.sink.by_kind("blocked")]
        self.assertTrue(any("edge detected" in str(r) for r in reasons))


# ── the discovery pass itself ─────────────────────────────────────────────

class TestOriginDiscoveryPass(unittest.TestCase):

    def _agent(self, answers):
        from phantom.automation.agent import AutonomousAgent
        return AutonomousAgent("example.com", target_type="domain",
                               edge_runner=_scripted_runner(answers))

    def test_the_pass_finds_the_origin_behind_a_cloudflare_edge(self):
        a = self._agent([
            ("curl", "HTTP/1.1 200 OK\r\nserver: cloudflare\r\n"
                     "cf-ray: 8a1b-AMS\r\n"),
            ("CNAME example.com", "example.com.cdn.cloudflare.net."),
            ("A example.com", "104.16.1.1\n"),
            ("CNAME origin.example.com", ""),
            ("A origin.example.com", "203.0.113.10\n"),
        ])
        a.wm.add_finding(kind="environment", key="surface:origin.example.com",
                         value={"asset": "origin.example.com", "kind": "ct_host"},
                         confidence=0.8, source="surface_map")
        self.assertTrue(a._run_origin_discovery())
        self.assertTrue(a.wm.find(e.EDGE_FACT))
        origins = a.wm.find(e.ORIGIN_FACT)
        self.assertTrue(origins)
        self.assertEqual(origins[0].value["host"], "origin.example.com")
        self.assertTrue(a._edge_verdict())
        # and the chain is now pointed at the origin
        self.assertEqual(_effective_target(a.wm), "origin.example.com")

    def test_the_pass_never_proposes_an_edge_host_as_the_origin(self):
        a = self._agent([
            ("curl", "HTTP/1.1 200 OK\r\ncf-ray: 8a1b-AMS\r\n"),
            ("CNAME example.com", "example.com.cdn.cloudflare.net."),
            ("A example.com", "104.16.1.1\n"),
            ("CNAME www.example.com", "www.example.com.cdn.cloudflare.net."),
            ("A www.example.com", "104.16.2.2\n"),
        ])
        a.wm.add_finding(kind="environment", key="surface:www.example.com",
                         value={"asset": "www.example.com", "kind": "ct_host"},
                         confidence=0.8, source="surface_map")
        a._run_origin_discovery()
        self.assertTrue(a.wm.find(e.EDGE_FACT))
        hosts = [f.value["host"] for f in a.wm.find(e.ORIGIN_FACT)]
        self.assertNotIn("www.example.com", hosts)

    def test_the_pass_is_scheduled_once_per_run(self):
        a = self._agent([
            ("curl", "HTTP/1.1 200 OK\r\ncf-ray: 8a1b-AMS\r\n"),
            ("CNAME example.com", "example.com.cdn.cloudflare.net."),
            ("A example.com", "104.16.1.1\n"),
        ])
        a.wm.add_finding(kind=e.EDGE_FACT, key="edge:example.com",
                         value={"address": "example.com", "provider": "cloudflare",
                                "confidence": 0.95, "is_edge": True},
                         confidence=0.9, source="test")
        calls = []
        a._run_origin_discovery = lambda: calls.append(1) or True
        a._maybe_origin_discovery()
        a._maybe_origin_discovery()
        self.assertEqual(calls, [1])

    def test_a_pass_with_no_edge_leaves_the_chain_alone(self):
        """A negative result is recorded as evidence (`is_edge=false`: we
        checked), never as a gate."""
        a = self._agent([
            ("curl", "HTTP/1.1 200 OK\r\nserver: nginx/1.18.0\r\n"),
            ("CNAME example.com", ""),
            ("A example.com", "203.0.113.10\n"),
        ])
        a._run_origin_discovery()
        self.assertEqual([f for f in a.wm.find(e.EDGE_FACT)
                          if f.value.get("is_edge")], [])
        self.assertIsNone(a._edge_verdict())
        self.assertEqual(_effective_target(a.wm), "example.com")


# ── the capability is wired, not decorative ───────────────────────────────

class TestCapabilityWiring(unittest.TestCase):

    def test_the_capability_is_registered_and_in_the_recon_phase(self):
        from phantom.automation.phases.recon.capabilities import (
            RECON_CAPABILITY_IDS, phase_capabilities)
        self.assertIn("origin_discovery", RECON_CAPABILITY_IDS)
        ids = [c.id for c in phase_capabilities(make_registry())]
        self.assertIn("origin_discovery", ids)

    def test_the_capability_is_parsed_by_the_origin_interpreter(self):
        cap = make_registry().get("origin_discovery")
        self.assertEqual(cap.exec_class, "in_process_engine")
        wm = WorldModel(target="example.com", target_type="domain")
        out = ("EDGE: address=example.com provider=cloudflare confidence=0.95 "
               "is_edge=true evidence=header:cf-ray=8a1b|range:104.16.0.0/13\n"
               "ORIGIN: host=origin.example.com ip=203.0.113.10 "
               "reason=naming+resolves confidence=0.85")
        findings = cap.interpret(out, wm, {})
        by_kind = {f.kind: f for f in findings}
        self.assertTrue(by_kind[e.EDGE_FACT].value["is_edge"])
        self.assertEqual(by_kind[e.ORIGIN_FACT].value["ip"], "203.0.113.10")

    def test_the_capability_is_cheap_and_passive(self):
        """The discovery pass must never be the loudest thing in the run: it
        is public data only."""
        cap = make_registry().get("origin_discovery")
        self.assertEqual(cap.stealth_level, "passive")
        self.assertLess(cap.detection_risk, 0.1)
        self.assertEqual(cap.tools, [])


if __name__ == "__main__":
    unittest.main()
