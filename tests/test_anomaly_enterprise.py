"""Tests: enterprise hardening of the anomaly engine — endpoint discovery,
parameter injection, session cookies, validation pass (confirmed/severity)
and the stealth delay_fn, plus their wiring in the agent/report/harvest."""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.exploit.anomaly import (
    Endpoint, HuntEngine, Probe, ProbeResult, _MAX_ENDPOINTS, _parse_crawl,
    _parse_robots, _parse_sitemap, build_cookie_header, curl_runner,
    hunt_target, mutate_probe)
from phantom.automation.guidance.commands import make_registry
from phantom.automation.post.harvest import cookies_interpreter

TARGET = "10.0.0.5"


def _svc(port="80", service="http"):
    return {"port": port, "service": service, "version": ""}


def _all_ok_runner(calls):
    def runner(method, url, body="", timeout=8.0):
        calls.append((method, url, body))
        return ProbeResult(200, 1200, 0.2, "<html>")
    return runner


class TestDiscovery(unittest.TestCase):

    def test_robots_parsing(self):
        text = ("User-agent: *\nDisallow: /\nDisallow: /admin\n"
                "Disallow: /api?debug=1\nAllow: /static\n"
                "Disallow: /private/*.php\n")
        self.assertEqual(_parse_robots(text),
                         ["/admin", "/api", "/static", "/private"])

    def test_sitemap_parsing(self):
        text = ("<urlset><url><loc>https://h/</loc></url>"
                "<url><loc>https://h/about</loc></url>"
                "<url><loc>https://h/about</loc></url>"
                "<url><loc>https://h/contact</loc></url></urlset>")
        self.assertEqual(_parse_sitemap(text), ["/about", "/contact"])

    def test_crawl_parsing_filters_foreign_hosts(self):
        text = ('<a href="/local">x</a><a href="https://evil/x">y</a>'
                '<a href="/dup">z</a><a href="/dup">w</a>')
        self.assertEqual(_parse_crawl(text, "10.0.0.5"), ["/local", "/dup"])

    def test_discovery_finds_common_paths_even_without_fixtures(self):
        calls = []
        runner = _all_ok_runner(calls)
        engine = HuntEngine(runner=runner, max_requests=50)
        eps = engine._discover("http://10.0.0.5", "http")
        paths = [e.path for e in eps]
        self.assertIn("/", paths)
        self.assertTrue(any(p in paths for p in
                            ("/admin", "/login", "/api", "/console")))
        # cap + the always-inserted root endpoint
        self.assertLessEqual(len(eps), _MAX_ENDPOINTS + 1)

    def test_discovery_budget_respected(self):
        calls = []
        engine = HuntEngine(runner=_all_ok_runner(calls), max_requests=4)
        eps = engine._discover("http://10.0.0.5", "http")
        self.assertLessEqual(len(calls), 4)
        self.assertTrue(any(e.path == "/" for e in eps))

    def test_query_params_extracted_from_endpoint(self):
        engine = HuntEngine(runner=_all_ok_runner([]))
        eps = engine._discover("http://10.0.0.5", "http")
        root = eps[0]
        self.assertEqual(root.path, "/")
        ep = Endpoint(path="/api", params=["id", "page"])
        self.assertEqual(ep.params, ["id", "page"])


class TestParameterInjection(unittest.TestCase):

    def test_endpoint_probes_inject_into_params(self):
        from phantom.automation.exploit.anomaly import _endpoint_probes
        ep = Endpoint(path="/api", params=["q"])
        probes = _endpoint_probes("sqli", ep, Endpoint("/"))
        paths = [p.path for p in probes]
        self.assertTrue(any("/api?q=1%20AND%20SLEEP(3)" in p for p in paths))
        self.assertTrue(any(p.baseline and p.path == "/api?q=1"
                            for p in probes))

    def test_endpoint_traversal_keeps_path_prefix(self):
        from phantom.automation.exploit.anomaly import _endpoint_probes
        ep = Endpoint(path="/admin")
        probes = _endpoint_probes("traversal", ep, Endpoint("/"))
        payloads = [p.path for p in probes if not p.baseline]
        self.assertTrue(all(p.startswith("/admin/") for p in payloads))
        self.assertTrue(any(p.endswith("/../../../../etc/passwd")
                            for p in payloads))

    def test_endpoint_xxe_uses_post_body(self):
        from phantom.automation.exploit.anomaly import _endpoint_probes
        ep = Endpoint(path="/upload")
        probes = _endpoint_probes("xxe", ep, Endpoint("/"))
        payloads = [p for p in probes if not p.baseline]
        self.assertTrue(all(p.method == "POST" and p.path == "/upload"
                            for p in payloads))
        self.assertTrue(any("file:///etc/passwd" in p.body
                            for p in payloads))


class TestCookies(unittest.TestCase):

    def test_cookie_header_built_from_harvest_entries(self):
        cookies = [{"host": "10.0.0.5", "name": "sid", "path": "/",
                    "value": "abc123"},
                   {"host": "other", "name": "x", "path": "/",
                    "value": "y"},
                   {"name": "anon", "value": "z"}]
        header = build_cookie_header(cookies, host="10.0.0.5")
        self.assertIn("sid=abc123", header)
        self.assertNotIn("x=y", header)
        self.assertIn("anon=z", header)

    def test_curl_runner_sends_cookie_header(self):
        from unittest.mock import patch
        with patch("phantom.automation.exploit.anomaly.subprocess.run") as m:
            m.return_value.stdout = "\n200 42 0.10"
            result = curl_runner("GET", "http://x/", cookies="sid=abc")
            args = m.call_args.args[0]
            self.assertIn("-H", args)
            self.assertIn("Cookie: sid=abc", args)
            self.assertEqual(result.status, 200)

    def test_harvest_finding_exposes_cookies_list(self):
        wm = WorldModel(target=TARGET, target_type="ip")
        output = ('COOKIES:[{"host":"10.0.0.5","name":"sid","path":"/",'
                  '"value":"abc"}]')
        findings = cookies_interpreter(output, wm, {})
        self.assertEqual(len(findings), 1)
        value = findings[0].value
        self.assertIn("cookies", value)
        self.assertEqual(value["cookies"][0]["name"], "sid")


class TestValidationAndSeverity(unittest.TestCase):

    def test_reproduced_marker_anomaly_is_confirmed(self):
        def runner(method, url, body="", timeout=8.0):
            if "/../../../../etc/passwd" in url:
                return ProbeResult(200, 1800, 0.25,
                                   "root:x:0:0:root:/root:\n")
            return ProbeResult(200, 1200, 0.2, "<html>")

        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        a = next(a for a in anomalies if a.cls == "traversal")
        self.assertTrue(a.confirmed)
        self.assertIn(a.severity(), ("high", "critical"))

    def test_unconfirmed_anomaly_has_severity_medium(self):
        calls = []
        times = {"sleep": 0}

        def runner(method, url, body="", timeout=8.0):
            calls.append(url)
            if "SLEEP(3)" in url:
                return ProbeResult(200, 1300, 3.4, "<html>")
            if "SLEEP(5)" in url:
                return ProbeResult(200, 1300, 0.2, "<html>")
            return ProbeResult(200, 1200, 0.2, "<html>")

        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        a = next(a for a in anomalies if a.cls == "sqli")
        self.assertFalse(a.confirmed)
        self.assertEqual(a.severity(), "medium")

    def test_validation_deepens_timing_probe(self):
        def runner(method, url, body="", timeout=8.0):
            if "SLEEP(5)" in url:
                return ProbeResult(200, 1300, 5.2, "<html>")
            if "SLEEP(3)" in url:
                return ProbeResult(200, 1300, 3.4, "<html>")
            return ProbeResult(200, 1200, 0.2, "<html>")

        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        sqli = [a for a in anomalies if a.cls == "sqli"]
        self.assertTrue(any(a.confirmed and a.name == "validate-deeper"
                            for a in sqli))
        self.assertTrue(any(a.severity() == "high" for a in sqli))


class TestStealthAndBudget(unittest.TestCase):

    def test_delay_fn_applied_between_requests(self):
        calls = []
        sleeps = []

        def runner(method, url, body="", timeout=8.0):
            calls.append(url)
            return ProbeResult(200, 1200, 0.2, "<html>")

        def delay_fn():
            sleeps.append(1)
            return 0.01

        engine = HuntEngine(runner=runner, delay_fn=delay_fn,
                            max_requests=8)
        engine.hunt(TARGET, _svc())
        self.assertGreaterEqual(len(sleeps), 2)
        self.assertLessEqual(len(calls), 8)

    def test_discovery_consumes_budget_but_stays_bounded(self):
        calls = []
        runner = _all_ok_runner(calls)
        engine = HuntEngine(runner=runner, max_requests=10)
        engine.hunt(TARGET, _svc())
        self.assertLessEqual(len(calls), 10)

    def test_on_probe_events_emitted(self):
        events = []
        engine = HuntEngine(runner=_all_ok_runner([]),
                            on_probe=events.append, max_requests=6)
        engine.hunt(TARGET, _svc())
        self.assertTrue(events)
        self.assertTrue(any("GET /robots.txt" in e for e in events))


class TestAgentWiring(unittest.TestCase):

    def setUp(self):
        self.wm = WorldModel(target=TARGET, target_type="ip")

    def test_hunt_uses_stolen_cookies_and_delay(self):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.guidance.stealth import (
            StealthConfig, StealthEngine)
        from phantom.automation.guidance.threatmodel import BlueTeamModel
        from phantom.automation.runtime.stealth_runtime import (
            StealthRuntime, TimingGovernor)
        seen = {}

        def runner(method, url, body="", timeout=8.0):
            seen["url"] = url
            if "/../../../../etc/passwd" in url:
                return ProbeResult(200, 1800, 0.25,
                                   "root:x:0:0:root:/root:\n")
            return ProbeResult(200, 1200, 0.2, "<html>")

        agent = AutonomousAgent(target=TARGET, on_event=None,
                                shared_wm=self.wm)
        agent.runtime = StealthRuntime(
            agent.stealth_engine,
            governor=TimingGovernor(base_delay=0.0, jitter=0.0))
        agent.hunt_runner = runner
        agent.hunt_delay = 0.0
        self.wm.add_finding("service", "tcp/80",
                            {"port": "80", "service": "http"})
        self.wm.add_finding("stolen_cookies", "cookies:1",
                            {"count": 1, "cookies": [
                                {"host": "10.0.0.5", "name": "sid",
                                 "path": "/", "value": "abc"}]})
        result = agent.run(goal="exploit", max_iterations=3)
        self.assertGreater(result["hunt_anomalies"], 0)
        finding = self.wm.find("hunt_anomaly")[0]
        self.assertIn("confirmed", finding.value)
        self.assertIn("severity", finding.value)

    def test_run_autonomous_accepts_hunt_delay(self):
        from phantom.automation.agent import run_autonomous
        from unittest.mock import patch
        with patch("phantom.automation.agent.AutonomousAgent") as fake:
            fake.return_value.run.return_value = {"hunt_anomalies": 0}
            run_autonomous("10.0.0.5", goal="recon",
                           max_iterations=1, hunt_delay=0.5)
            kwargs = fake.call_args.kwargs
            self.assertEqual(kwargs.get("hunt_delay"), 0.5)

    def test_interp_keeps_confirmed_and_severity(self):
        from phantom.automation.guidance.kit import _hunt_web_interp
        output = ("HUNT:cls=traversal name=plain-dots port=80 "
                  "endpoint=/../../../../etc/passwd signals=marker:root: "
                  "score=2.50 confirmed=true severity=high evidence=root:x:")
        findings = _hunt_web_interp(output, self.wm, {})
        self.assertTrue(findings[0].value["confirmed"])
        self.assertEqual(findings[0].value["severity"], "high")


class TestReporting(unittest.TestCase):

    def test_client_report_lists_anomalies(self):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.guidance.stealth import (
            StealthConfig, StealthEngine)
        from phantom.automation.guidance.threatmodel import BlueTeamModel
        from phantom.automation.reporting import ClientReport
        from phantom.automation.runtime.stealth_runtime import (
            StealthRuntime, TimingGovernor)
        from phantom.automation.guidance.kit import _hunt_web_interp
        wm = WorldModel(target=TARGET, target_type="ip")
        wm.add_finding("service", "tcp/80",
                       {"port": "80", "service": "http"})
        output = ("HUNT:cls=traversal name=plain-dots port=80 "
                  "endpoint=/x signals=marker:root: score=2.50 "
                  "confirmed=true severity=high evidence=r")
        for f in _hunt_web_interp(output, wm, {}):
            wm.add_finding(f.kind, f.key, f.value,
                           confidence=f.confidence, source="hunt_web")
        agent = AutonomousAgent(target=TARGET, on_event=None, shared_wm=wm)
        agent.runtime = StealthRuntime(
            agent.stealth_engine,
            governor=TimingGovernor(base_delay=0.0, jitter=0.0))
        report = ClientReport.from_agent(agent)
        titles = [f.title for f in report.findings]
        self.assertTrue(any("behavioural candidate" in t for t in titles))
        self.assertIn("reproduced", " ".join(titles))
        self.assertIn("behavioural candidates", report.executive_summary)


if __name__ == "__main__":
    unittest.main()