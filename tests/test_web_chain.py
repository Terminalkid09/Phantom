"""Tests: the curl-only web bridge (URL deadlock fix).

Without nmap, no scan can produce `service` facts — and the whole web
chain (web_rce, hunt, exploit) keys off them. Two bridges close the gap:

* http_probe success derives service:http(s) (confidence below nmap,
  same key so a real scan overwrites it);
* curl_probe sweeps TCP openness + banners via telnet:// (every curl,
  every OS), feeding service/banner/os facts.

Plus the `web` terminal goal (footprint -> hunt -> RCE foothold): no
beacon demanded where none can exist by construction.
"""
import unittest

from phantom.automation.belief import WorldModel


def _wm(target="http://example.com/", ttype="url"):
    return WorldModel(target=target, target_type=ttype)


class TestHttpBootstrap(unittest.TestCase):
    def test_http_response_derives_service(self):
        from phantom.automation.guidance.kit import _interp_http
        wm = _wm()
        out = ("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
               "Content-Type: text/html\r\n\r\n<title>x</title>")
        findings = _interp_http(out, wm, {"url": "http://example.com/"})
        kinds = {f.kind for f in findings}
        self.assertIn("service", kinds)
        svc = next(f for f in findings if f.kind == "service")
        self.assertEqual(svc.value["port"], "80")
        self.assertEqual(svc.value["service"], "http")
        self.assertEqual(svc.value["derived"], "http_probe")
        self.assertLess(svc.confidence, 0.9)  # below a real scan

    def test_https_maps_443(self):
        from phantom.automation.guidance.kit import _interp_http
        wm = _wm(target="https://example.com/", ttype="url")
        out = "HTTP/2 200\r\nserver: cloudflare\r\n\r\n"
        findings = _interp_http(out, wm, {"url": "https://example.com/"})
        svc = next(f for f in findings if f.kind == "service")
        self.assertEqual((svc.value["port"], svc.value["service"]),
                         ("443", "https"))

    def test_no_downgrade_when_scan_exists(self):
        from phantom.automation.guidance.kit import _interp_http
        wm = _wm()
        wm.add_finding("service", "tcp/80",
                       {"port": "80", "service": "http"},
                       confidence=0.95, source="scan_tcp")
        out = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
        findings = _interp_http(out, wm, {"url": "http://example.com/"})
        self.assertFalse([f for f in findings if f.kind == "service"])

    def test_garbage_yields_no_service(self):
        from phantom.automation.guidance.kit import _interp_http
        wm = _wm()
        findings = _interp_http("connection refused", wm, {})
        self.assertFalse([f for f in findings if f.kind == "service"])


class TestCurlProbe(unittest.TestCase):
    def test_adapter_is_plain_curl_segments(self):
        from phantom.automation.guidance.kit import _curl_probe_adapter
        cmd = _curl_probe_adapter(_wm(), {})
        self.assertIn("telnet://", cmd)
        for seg in cmd.split(";"):
            tok = seg.strip().split()[0] if seg.strip() else ""
            self.assertIn(tok, ("curl", "echo", ""))

    def test_interp_parses_connect_and_banner(self):
        from phantom.automation.guidance.kit import _curl_probe_interp
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        out = ("==CURLPROBE 22==\n"
               "* Connected to 10.0.0.5 (10.0.0.5) port 22\n"
               "< SSH-2.0-OpenSSH_8.2p1 Debian-4\n"
               "==CURLPROBE 443==\n"
               "* connect to 10.0.0.5 port 443 failed: refused\n")
        findings = _curl_probe_interp(out, wm, {})
        by_kind = {}
        for f in findings:
            by_kind.setdefault(f.kind, []).append(f)
        self.assertIn("tcp/22", [f.key for f in by_kind.get("service", [])])
        svc = next(f for f in by_kind["service"] if f.key == "tcp/22")
        self.assertEqual(svc.value["service"], "ssh")
        self.assertFalse([f for f in by_kind.get("service", [])
                          if f.key == "tcp/443"])  # refused: no fact
        self.assertTrue([f for f in by_kind.get("banner", [])
                         if "SSH-2.0" in f.value["banner"]])
        self.assertTrue([f for f in by_kind.get("os", [])
                         if f.value["name"] == "Linux"])

    def test_registered_as_service_source_after_scan(self):
        from phantom.automation.guidance.commands import make_registry
        from phantom.automation.planner import _FACT_SOURCES
        self.assertIn("curl_probe", _FACT_SOURCES["service"])
        cap = make_registry().get("curl_probe")
        self.assertIsNotNone(cap)
        self.assertIn("curl", cap.tools)
        self.assertIn("service", cap.effects)


class TestWebGoal(unittest.TestCase):
    def test_web_goal_facts_sourced(self):
        from phantom.automation.guidance.commands import make_registry
        from phantom.automation.planner import GOAL_FACTS, _FACT_SOURCES
        ids = {c.id for c in make_registry().all()}
        for fact in GOAL_FACTS["web"]:
            self.assertTrue(any(s in ids for s in _FACT_SOURCES[fact]),
                            fact)

    def test_url_curl_only_reaches_web_chain(self):
        # structural simulation (optimistic execution, like the audit):
        # url + curl-only must now grow service -> web_app -> hunt/rce.
        # Optimistic values are minimal-plausible per kind (a scan that
        # "worked" yields what that scan yields by design).
        from phantom.automation.guidance.stealth import (
            StealthConfig, StealthEngine)
        from phantom.automation.guidance.threatmodel import BlueTeamModel
        from phantom.automation.planner import Planner, _fact_satisfied
        from phantom.automation.guidance.commands import make_registry

        def _optimistic(kind):
            if kind == "service":
                return {"port": "80", "service": "http"}
            if kind == "creds":
                return {"username": "u", "password": "p", "valid": True}
            if kind == "os":
                return {"name": "Linux"}
            if kind == "beacon":
                return {"beacon_id": "B-1"}
            return {}

        wm = _wm()
        stealth = StealthEngine(wm, StealthConfig(),
                                BlueTeamModel.for_profile("enterprise"))
        planner = Planner(make_registry(), stealth)
        tools = {"curl"}
        dead = set()
        reached = False

        def tool_ok(cap):
            return (not getattr(cap, "tools", None)
                    or any(t in tools for t in cap.tools))

        for _ in range(12):
            if all(_fact_satisfied(wm, g)
                   for g in ("web_app", "hunt_anomaly", "rce_foothold")):
                reached = True
                break
            plan = planner.plan(wm, goal="web", dead=frozenset(dead))
            if not plan.steps:
                break
            moved = False
            for step in plan.steps:
                cap = step.capability
                try:
                    if not all(p(wm) for p in cap.preconditions):
                        continue
                except Exception:
                    continue
                if not tool_ok(cap):
                    dead.add(cap.id)
                    continue
                for effect in (cap.effects or []):
                    if not wm.find(effect):
                        wm.add_finding(effect, "audit",
                                       _optimistic(effect),
                                       confidence=0.5, source="audit")
                moved = True
                break
            if not moved:
                break
        self.assertTrue(reached,
                        "web goal unreachable on url+curl-only")


if __name__ == "__main__":
    unittest.main()
