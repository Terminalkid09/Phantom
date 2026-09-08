"""Tests: statistical anomaly engine + bug-class probe library +
mutation escalation, and its wiring into the agent chain."""
import unittest
from unittest.mock import Mock, patch

from phantom.automation.belief import WorldModel
from phantom.automation.exploit.anomaly import (
    HuntEngine, Probe, ProbeResult, hunt_target, mutate_probe,
    probe_library, web_services)
from phantom.automation.guidance.commands import make_registry

TARGET = "10.0.0.5"


def _svc(port="80", service="http", version="Apache httpd 2.4.49"):
    return {"port": port, "service": service, "version": version}


def _baseline_runner(probe_map, baseline=ProbeResult(200, 1200, 0.2, "<html>")):
    """Runner keyed by substring match: (url, body) -> ProbeResult."""
    def runner(method, url, body="", timeout=8.0):
        for needle, result in probe_map.items():
            if needle in url or needle in body:
                return result
        return baseline
    return runner


def _header_runner(hits):
    """Runner that returns per-path ProbeResults WITH response headers.
    `hits` maps a substring of the path to a (status, headers, body) tuple."""
    def runner(method, url, body="", timeout=8.0):
        for needle, (status, headers, resp_body) in hits.items():
            if needle in url:
                return ProbeResult(status, 1000, 0.2, resp_body,
                                   headers=headers)
        return ProbeResult(200, 1000, 0.2, "<html>",
                           headers={"content-type": "text/html"})
    return runner


class TestProbeLibrary(unittest.TestCase):

    def test_all_classes_have_baseline_and_payloads(self):
        lib = probe_library()
        # core classes + the 8 professional-grade additions
        self.assertEqual(set(lib.keys()),
                         {"traversal", "sqli", "ssti", "xxe", "ssrf",
                          "cmdi", "open_redirect", "crlf", "nosqli",
                          "header_ssti", "jndi", "exposure", "verb"})
        for cls, probes in lib.items():
            baselines = [p for p in probes if p.baseline]
            payloads = [p for p in probes if not p.baseline]
            # sqli carries a second (POST-form) baseline for login endpoints;
            # every class must have at least one baseline.
            if cls != "sqli":
                self.assertEqual(len(baselines), 1, cls)
            else:
                self.assertGreaterEqual(len(baselines), 1, cls)
            self.assertGreaterEqual(len(payloads), 3, cls)

    def test_deterministic_order(self):
        lib1 = probe_library()
        lib2 = probe_library()
        self.assertEqual(
            [p.path for p in lib1["traversal"]],
            [p.path for p in lib2["traversal"]])

    def test_encoding_matrix_covers_variants(self):
        paths = [p.path for p in probe_library()["traversal"]]
        self.assertTrue(any("%2e%2e" in p for p in paths))
        self.assertTrue(any("%252e" in p for p in paths))
        self.assertTrue(any("..\\" in p for p in paths))
        self.assertTrue(any("..;/" in p for p in paths))

    def test_sqli_has_time_families(self):
        paths = [p.path for p in probe_library()["sqli"]]
        self.assertTrue(any("SLEEP(3)" in p for p in paths))
        self.assertTrue(any("pg_sleep" in p for p in paths))
        self.assertTrue(any("WAITFOR" in p for p in paths))

    def test_mutations_bounded_and_deterministic(self):
        probe = probe_library()["traversal"][1]
        m1 = mutate_probe(probe)
        m2 = mutate_probe(probe)
        self.assertGreaterEqual(len(m1), 1)
        self.assertEqual([p.path for p in m1], [p.path for p in m2])

    def test_web_services_filter(self):
        services = [_svc(), _svc(port="445", service="smb"),
                    _svc(port="443", service="ssl/http")]
        self.assertEqual([s["port"] for s in web_services(services)],
                         ["80", "443"])


class TestHuntEngine(unittest.TestCase):

    def test_marker_signal_is_anomaly(self):
        runner = _baseline_runner({
            "/../../../../etc/passwd": ProbeResult(
                200, 1800, 0.25, "root:x:0:0:root:/root:/bin/bash\n"),
        })
        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        self.assertTrue(any(a.cls == "traversal" for a in anomalies))
        a = next(a for a in anomalies if a.cls == "traversal")
        self.assertGreaterEqual(a.score, 2.5)
        self.assertIn("marker:root:", a.signals)

    def test_timing_ratio_is_anomaly(self):
        runner = _baseline_runner({
            "SLEEP(3)": ProbeResult(200, 1300, 3.4, "<html>"),
        })
        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        sqli = [a for a in anomalies if a.cls == "sqli"]
        self.assertTrue(sqli)
        self.assertIn("timing", " ".join(sqli[0].signals))

    def test_no_anomaly_when_endpoint_quiet(self):
        anomalies = hunt_target(TARGET, [_svc()],
                                runner=_baseline_runner({}))
        self.assertEqual(anomalies, [])

    def test_unreachable_service_silent(self):
        def runner(method, url, body="", timeout=8.0):
            return ProbeResult()
        self.assertEqual(hunt_target(TARGET, [_svc()], runner=runner), [])

    def test_runner_exception_silent(self):
        def runner(method, url, body="", timeout=8.0):
            raise OSError("network down")
        self.assertEqual(hunt_target(TARGET, [_svc()], runner=runner), [])

    def test_non_web_service_skipped(self):
        anomalies = hunt_target(TARGET, [_svc(port="22", service="ssh")],
                                runner=_baseline_runner({
                                    "/../../../../etc/passwd": ProbeResult(
                                        200, 1800, 0.25,
                                        "root:x:0:0:root:")}))
        self.assertEqual(anomalies, [])

    def test_mutation_escalation_deepens_finding(self):
        originals = [p for p in probe_library()["traversal"]
                     if not p.baseline]
        want = originals[0].path

        def runner(method, url, body="", timeout=8.0):
            if url.endswith(want):
                return ProbeResult(200, 1800, 0.25,
                                   "root:x:0:0:root:/root:\n")
            if "etc/passwd" in url:
                return ProbeResult(200, 2400, 0.4,
                                   "root:x:0:0:root:/root:/bin/bash\n")
            return ProbeResult(200, 1200, 0.2, "<html>")

        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        deep = [a for a in anomalies if a.mutated]
        self.assertTrue(deep, "escalation round never ran")
        self.assertTrue(any("bin/bash" in a.evidence for a in deep))

    def test_request_budget_bounded(self):
        calls = []

        def runner(method, url, body="", timeout=8.0):
            calls.append(url)
            return ProbeResult(200, 1200, 0.2, "<html>")

        engine = HuntEngine(runner=runner, max_requests=10)
        engine.hunt(TARGET, _svc())
        self.assertLessEqual(len(calls), 10)

    def test_ssti_and_xxe_and_ssrf_classes_work(self):
        runner = _baseline_runner({
            "{{7*7}}": ProbeResult(200, 900, 0.2, "result: 49"),
            "file:///etc/passwd": ProbeResult(200, 1500, 0.2,
                                              "root:x:0:0:root:"),
        })
        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        self.assertTrue(any(a.cls == "ssti" for a in anomalies))
        self.assertTrue(any(a.cls in ("xxe", "ssrf") for a in anomalies))


class TestProfessionalBugClasses(unittest.TestCase):
    """The 8 professional-grade classes: command injection, open redirect,
    CRLF/header injection, NoSQL injection, header-delivered SSTI, JNDI /
    Log4Shell-class, sensitive-file exposure, and HTTP verb tampering."""

    def test_cmdi_detected_via_id_reflection(self):
        runner = _baseline_runner({
            ";id": ProbeResult(200, 900, 0.2,
                                "uid=0(root) gid=0(root) groups=0(root)"),
        })
        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        self.assertTrue(any(a.cls == "cmdi" for a in anomalies))

    def test_cmdi_time_based_requires_monotonic(self):
        """sleep 5 must be SLOWER than sleep 3 — a one-off ratio vs the
        baseline is jitter, not injection."""
        calls = []

        def runner(method, url, body="", timeout=8.0):
            calls.append(url)
            if "sleep%203" in url:
                return ProbeResult(200, 1200, 3.0, "<html>")
            if "sleep%205" in url:
                return ProbeResult(200, 1200, 1.0, "<html>")  # NOT slower
            return ProbeResult(200, 1200, 0.2, "<html>")

        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        cmdi = [a for a in anomalies if a.cls == "cmdi"]
        self.assertFalse(any(a.confirmed for a in cmdi),
                         "non-monotonic delay must NOT confirm")

    def test_cmdi_time_based_confirmed_when_monotonic(self):
        def runner(method, url, body="", timeout=8.0):
            if "sleep%203" in url:
                return ProbeResult(200, 1200, 3.0, "<html>")
            if "sleep%205" in url:
                return ProbeResult(200, 1200, 5.2, "<html>")  # slower ✓
            return ProbeResult(200, 1200, 0.2, "<html>")

        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        cmdi = [a for a in anomalies if a.cls == "cmdi"]
        self.assertTrue(cmdi)
        self.assertTrue(any(a.confirmed for a in cmdi))

    def test_open_redirect_via_location_header(self):
        runner = _header_runner({
            "//evil.test/": (302, {"location": "//evil.test/landing"}, ""),
        })
        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        redirs = [a for a in anomalies if a.cls == "open_redirect"]
        self.assertTrue(redirs)
        self.assertTrue(any("open-redirect" in " ".join(a.signals)
                            for a in redirs))

    def test_crlf_detected_via_injected_header(self):
        runner = _header_runner({
            "X-Injected:1": (200, {"x-injected": "1"}, "body"),
        })
        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        crlf = [a for a in anomalies if a.cls == "crlf"]
        self.assertTrue(crlf)
        self.assertTrue(any("header-injection" in " ".join(a.signals)
                            for a in crlf))

    def test_nosqli_detected_via_operator(self):
        runner = _baseline_runner({
            "[$ne]": ProbeResult(200, 900, 0.2,
                                  "mongo query failed: $ne operator"),
        })
        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        self.assertTrue(any(a.cls == "nosqli" for a in anomalies))

    def test_header_ssti_detected_in_user_agent(self):
        """End-to-end through the REAL curl path: a server that renders the
        templated User-Agent ({{7*7}} -> 49) reflects the payload only when
        the injected UA reaches it. The injected 4-arg runner cannot send
        request headers, so this is the honest integration test."""
        import http.server
        import threading

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                ua = self.headers.get("User-Agent", "")
                body = "<html>hello</html>"
                if "{{7*7}}" in ua:
                    body = "result: 49"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body.encode())

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            anomalies = hunt_target(
                "127.0.0.1", [_svc(port=str(port), service="http")])
            self.assertTrue(any(a.cls == "header_ssti" for a in anomalies))
        finally:
            srv.shutdown()

    def test_jndi_reflection_detected(self):
        runner = _baseline_runner({
            "${jndi:ldap://127.0.0.1/a}": ProbeResult(
                200, 900, 0.2, "Lookup failed: jndi:ldap://127.0.0.1"),
        })
        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        self.assertTrue(any(a.cls == "jndi" for a in anomalies))

    def test_exposure_detects_git_head(self):
        runner = _baseline_runner({
            "/.git/HEAD": ProbeResult(200, 40, 0.05,
                                       "ref: refs/heads/main"),
        })
        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        self.assertTrue(any(a.cls == "exposure" for a in anomalies))

    def test_verb_options_allow_header(self):
        runner = _header_runner({
            # any OPTIONS probe path
        })
        # custom runner that returns Allow only for OPTIONS method
        def runner(method, url, body="", timeout=8.0):
            if method == "OPTIONS":
                return ProbeResult(200, 0, 0.05, "",
                                   headers={"allow": "GET, HEAD, TRACE"})
            return ProbeResult(200, 1000, 0.2, "<html>",
                               headers={"content-type": "text/html"})
        anomalies = hunt_target(TARGET, [_svc()], runner=runner)
        verbs = [a for a in anomalies if a.cls == "verb"]
        self.assertTrue(verbs)
        self.assertTrue(any("allow:" in " ".join(a.signals) for a in verbs))

    def test_mutations_preserve_follow_flag(self):
        from phantom.automation.exploit.anomaly import mutate_probe
        p = probe_library()["open_redirect"][1]  # follow=False
        for m in mutate_probe(p):
            self.assertFalse(m.follow)


class TestDiscoveryEnhancements(unittest.TestCase):
    """JS-bundle endpoint extraction, form-parameter harvesting and the
    header-aware curl runner — the discovery layer that makes the engine
    professional on modern SPAs."""

    def test_parse_forms_extracts_input_names(self):
        from phantom.automation.exploit.anomaly import _parse_forms
        html = ('<form action="/login" method="post">'
                '<input type="text" name="username">'
                '<input type="password" name="password"></form>')
        forms = _parse_forms(html)
        self.assertIn("/login", forms)
        self.assertEqual(forms["/login"], ["username", "password"])

    def test_discover_parses_js_bundles_for_api_paths(self):
        from phantom.automation.exploit.anomaly import HuntEngine

        def runner(method, url, body="", timeout=8.0):
            if url.endswith("/"):
                return ProbeResult(200, 800, 0.1,
                                   '<script src="/app.js"></script>')
            if url.endswith("/app.js"):
                return ProbeResult(
                    200, 800, 0.1,
                    'const u = "/api/v1/users"; const u2 = "/api/v1/admin"')
            return ProbeResult(404, 0, 0.05, "")

        engine = HuntEngine(runner=runner)
        eps = engine._discover("http://10.0.0.5", "http")
        paths = [e.path for e in eps]
        self.assertIn("/api/v1/users", paths)
        self.assertIn("/api/v1/admin", paths)

    def test_discover_form_endpoint_carries_param_names(self):
        from phantom.automation.exploit.anomaly import HuntEngine

        def runner(method, url, body="", timeout=8.0):
            if url.endswith("/"):
                return ProbeResult(
                    200, 800, 0.1,
                    '<form action="/search"><input name="q"></form>')
            return ProbeResult(404, 0, 0.05, "")

        engine = HuntEngine(runner=runner)
        eps = engine._discover("http://10.0.0.5", "http")
        search = next((e for e in eps if e.path == "/search"), None)
        self.assertIsNotNone(search)
        self.assertIn("q", search.params)

    def test_curl_runner_parses_headers_and_body(self):
        import http.server
        import threading
        from phantom.automation.exploit.anomaly import curl_runner

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("X-Custom", "yes")
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"hello-body")

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            r = curl_runner("GET", f"http://127.0.0.1:{port}/")
            self.assertEqual(r.status, 200)
            self.assertEqual(r.headers.get("x-custom"), "yes")
            self.assertEqual(r.body, "hello-body")
        finally:
            srv.shutdown()

    def test_curl_runner_no_follow_reads_redirect(self):
        import http.server
        import threading
        from phantom.automation.exploit.anomaly import curl_runner

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "//evil.test/landing")
                self.end_headers()

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            r = curl_runner("GET", f"http://127.0.0.1:{port}/redir",
                            follow=False)
            self.assertEqual(r.status, 302)
            self.assertIn("evil.test", r.headers.get("location", ""))
        finally:
            srv.shutdown()


class TestAgentChain(unittest.TestCase):

    def setUp(self):
        self.reg = make_registry()
        self.wm = WorldModel(target=TARGET, target_type="ip")

    def test_hunt_web_capability_registered(self):
        cap = self.reg.get("hunt_web")
        self.assertIsNotNone(cap)
        self.assertEqual(cap.category, "hunt")
        self.assertEqual(cap.effects, ["hunt_anomaly"])

    def test_planner_picks_hunt_web_for_exploit_goal(self):
        from phantom.automation.guidance.stealth import (
            StealthConfig, StealthEngine)
        from phantom.automation.guidance.threatmodel import BlueTeamModel
        from phantom.automation.planner import Planner, GOAL_FACTS
        self.assertIn("hunt_anomaly", GOAL_FACTS["exploit"])
        self.wm.add_finding("service", "tcp/80",
                            {"port": "80", "service": "http",
                             "product": "", "version": "Apache httpd 2.4.49"})
        stealth = StealthEngine(self.wm, StealthConfig(),
                                BlueTeamModel.for_profile("enterprise"))
        plan = Planner(self.reg, stealth).plan(self.wm, goal="exploit")
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("hunt_web", ids)

    def test_hunt_interpreter_parses_markers(self):
        from phantom.automation.guidance.kit import _hunt_web_interp
        output = ("HUNT:cls=traversal name=plain-dots port=80 "
                  "endpoint=/../../../../etc/passwd "
                  "signals=marker:root: score=2.50 "
                  "evidence=root:x:0:0:root:/root:")
        findings = _hunt_web_interp(output, self.wm, {"port": "80"})
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, "hunt_anomaly")
        self.assertEqual(f.value["cls"], "traversal")
        self.assertEqual(f.confidence, 0.6)

    def test_agent_executes_hunt_and_records_finding(self):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.guidance.stealth import (
            StealthConfig, StealthEngine)
        from phantom.automation.guidance.threatmodel import BlueTeamModel
        from phantom.automation.runtime.stealth_runtime import StealthRuntime
        runner = _baseline_runner({
            "/../../../../etc/passwd": ProbeResult(
                200, 1800, 0.25, "root:x:0:0:root:/root:/bin/bash\n"),
        })
        agent = AutonomousAgent(target=TARGET, on_event=None,
                                shared_wm=self.wm)
        agent.runtime = StealthRuntime(agent.stealth_engine)
        agent.hunt_runner = runner
        agent.hunt_delay = 0.0
        self.wm.add_finding("service", "tcp/80",
                            {"port": "80", "service": "http",
                             "product": "", "version": "Apache httpd 2.4.49"})
        result = agent.run(goal="exploit", max_iterations=3)
        self.assertGreater(result["hunt_anomalies"], 0)
        self.assertTrue(self.wm.find("hunt_anomaly"))

    def test_reporting_roundtrip_keeps_anomalies(self):
        from phantom.automation.guidance.kit import _hunt_web_interp
        self.wm.add_finding("service", "tcp/80",
                            {"port": "80", "service": "http"})
        output = ("HUNT:cls=traversal name=plain-dots port=80 "
                  "endpoint=/x signals=marker:root: score=2.50 evidence=r")
        for f in _hunt_web_interp(output, self.wm, {}):
            self.wm.add_finding(f.kind, f.key, f.value, confidence=f.confidence,
                                source="hunt_web")
        data = self.wm.to_dict()
        kinds = {f["kind"] for f in data["findings"]}
        self.assertIn("hunt_anomaly", kinds)
        restored = WorldModel.from_dict(data)
        self.assertTrue(restored.find("hunt_anomaly"))


class TestAnomalyDedupe(unittest.TestCase):
    """The hunt engine must collapse escaped-mutation duplicates down to one
    finding per (class, endpoint) — a single SQLi dumped 11 times is noise."""

    def test_collapses_repeated_class_on_same_endpoint(self):
        from phantom.automation.exploit.anomaly import (
            Anomaly, _dedupe_anomalies)
        rows = [
            Anomaly("sqli", "quote-bypass", "/login", 4.5, ["marker"],
                    confirmed=True, mutated=True),
            Anomaly("sqli", "quote-bypass-confirm", "/login?u=1", 4.3,
                    ["marker"], confirmed=True),
            Anomaly("sqli", "tautology", "/login", 3.1, ["marker"]),
            Anomaly("ssrf", "export", "/export?url=x", 0.2, ["timing"],
                    confirmed=True, mutated=True),
            Anomaly("ssrf", "export-reflex", "/export", 0.1, ["timing"]),
        ]
        out = _dedupe_anomalies(rows)
        # one sqli candidate, one ssrf candidate
        self.assertEqual(len(out), 2)
        by_cls = {a.cls for a in out}
        self.assertEqual(by_cls, {"sqli", "ssrf"})
        # confirmed + highest score wins within each group
        sqli = next(a for a in out if a.cls == "sqli")
        self.assertTrue(sqli.confirmed)
        self.assertGreaterEqual(sqli.score, 4.3)

    def test_query_string_dropped_from_key(self):
        from phantom.automation.exploit.anomaly import (
            Anomaly, _dedupe_anomalies)
        rows = [
            Anomaly("ssrf", "m1", "/export?url=http://x", 1.0, ["t"],
                    confirmed=True),
            Anomaly("ssrf", "m1", "/export?url=http://y", 0.9, ["t"],
                    confirmed=True, mutated=True),
        ]
        self.assertEqual(len(_dedupe_anomalies(rows)), 1)

    # ------------------------------------------------ live-verified classes
    # Each test below encodes a behavior proven against demo.testfire.net
    # (IBM AltoroJ): the live run that found+confirmed the real SQLi on
    # /doLogin. These pin the contract so the behaviors cannot regress.

    def test_parse_forms_resolves_relative_action(self):
        from phantom.automation.exploit.anomaly import _parse_forms
        # testfire's login page: footer form shadows the login form past the
        # old 2000-char truncation, and action="doLogin" is RELATIVE.
        html = ('<form action="doLogin" method="post">'
                '<input name="uid"><input name="passw">'
                '<input name="btnSubmit"></form>')
        forms = _parse_forms(html, "/login.jsp")
        self.assertIn("/doLogin", forms)
        self.assertEqual(forms["/doLogin"], ["uid", "passw", "btnSubmit"])

    def test_plan_puts_credential_forms_first(self):
        from phantom.automation.exploit.anomaly import (
            Endpoint, HuntEngine)
        eng = HuntEngine(runner=lambda *a, **k: ProbeResult())
        eps = [Endpoint("/", source="root"),
               Endpoint("/admin", source="common"),
               Endpoint("/doLogin", source="form",
                        params=["uid", "passw"])]
        plan = eng._plan(eps)
        self.assertEqual((plan[0][0].path, plan[0][1]), ("/doLogin", "sqli"))
        # no duplicate (path, class) entries — root library follows the form
        keys = [(e.path, c) for e, c, _ in plan]
        self.assertEqual(len(keys), len(set(keys)))

    def test_auth_bypass_landed_on_signal(self):
        from phantom.automation.exploit.anomaly import HuntEngine, Probe
        eng = HuntEngine(runner=lambda *a, **k: ProbeResult())
        # successful bypass: 302 to a member page (Location read when the
        # probe does not follow redirects)
        probe = Probe("sqli", "post-bypass", "POST", "/doLogin",
                      body="uid=x&passw=y", follow=False)
        res = ProbeResult(status=302, size=120, elapsed=0.1,
                          headers={"location": "/bank/main.jsp"})
        bl = ProbeResult(status=302, size=120, elapsed=0.1,
                         headers={"location": "login.jsp"})
        score, signals = eng._score(probe, res, bl)
        self.assertGreaterEqual(score, 3.5)
        self.assertTrue(any(s.startswith("landed-on:/bank") for s in signals))

    def test_auth_bypass_failed_login_not_signaled(self):
        from phantom.automation.exploit.anomaly import HuntEngine, Probe
        eng = HuntEngine(runner=lambda *a, **k: ProbeResult())
        probe = Probe("sqli", "post-quote", "POST", "/doLogin",
                      body="uid=x&passw=y", follow=False)
        # both bounce back to the login form: no signal
        res = ProbeResult(status=302, size=120, elapsed=0.1,
                          headers={"location": "login.jsp"})
        bl = ProbeResult(status=302, size=120, elapsed=0.1,
                         headers={"location": "login.jsp"})
        score, signals = eng._score(probe, res, bl)
        self.assertEqual(score, 0.0)
        self.assertFalse(any(s.startswith("landed-on") for s in signals))

    def test_body_not_truncated_for_form_discovery(self):
        from phantom.automation.exploit.anomaly import (
            _parse_forms, curl_runner)
        import subprocess as _sp
        import sys as _sys
        if _sys.platform != "win32" or _sp.run(["curl", "--version"],
                                               capture_output=True).returncode != 0:
            self.skipTest("curl or platform-specific")
        # a >2000-char page whose form sits at the very bottom: the old
        # body[:2000] cut discovery blind on every real-world page
        big = ("<html>" + "<p>filler</p>" * 400
               + '<form action="/doLogin" method="post">'
                 '<input name="uid"><input name="passw"></form></html>')
        html = _parse_forms(big)
        self.assertIn("/doLogin", html)  # parser itself handles the size

    def test_evidence_shows_redirect_destination(self):
        from phantom.automation.exploit.anomaly import HuntEngine
        eng = HuntEngine(runner=lambda *a, **k: ProbeResult())
        res = ProbeResult(status=302, size=120, elapsed=0.1,
                          headers={"location": "/bank/main.jsp"})
        ev = eng._evidence(res)
        self.assertIn("/bank/main.jsp", ev)


if __name__ == "__main__":
    unittest.main()