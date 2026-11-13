"""Tests: the XSS bug class added to the anomaly engine.

XSS is proven by REFLECTION in an executable context, not by a side effect,
so these tests pin exactly the properties that make the signal real:

* a RAW reflection (canary + markup) is detected and confirmed;
* the same payload HTML-encoded is NOT a hit (safe reflection);
* a raw reflection inside application/json is NOT a hit (no execution);
* only the winning payload is mutated, deterministically;
* endpoint adaptation probes the reflection sinks (q/s/search...), capped.
"""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.exploit.anomaly import (
    Endpoint, ProbeResult, _endpoint_probes, hunt_target, mutate_probe,
    probe_library)
from phantom.automation.exploit.xss import (
    STORED_TAG,
    xss_dom_context,
    xss_mutations,
    xss_probes,
    xss_stored_markers,
    xss_stored_payload,
)

TARGET = "10.0.0.5"


def _svc(port="80", service="http"):
    return {"port": port, "service": service, "version": "nginx 1.18.0"}


def _reflect_runner(reflect=True, content_type="text/html"):
    """Echo the query value into the body — raw or HTML-encoded."""
    def runner(method, url, body="", timeout=8.0):
        value = ""
        if "?" in url:
            query = url.split("?", 1)[1]
            value = query.split("=", 1)[1] if "=" in query else ""
        if reflect:
            reflected = value
        else:
            reflected = (value.replace("<", "&lt;").replace(">", "&gt;")
                         .replace('"', "&quot;").replace("'", "&#39;"))
        return ProbeResult(200, 1200, 0.2,
                           f"<html>results for: {reflected}</html>",
                           headers={"content-type": content_type})
    return runner


class TestXSSProbeLibrary(unittest.TestCase):

    def test_family_shape(self):
        probes = xss_probes()
        baseline = [p for p in probes if p.baseline]
        payloads = [p for p in probes if not p.baseline]
        self.assertEqual(len(baseline), 1)
        self.assertGreaterEqual(len(payloads), 3)
        self.assertTrue(all(p.cls == "xss" for p in probes))

    def test_markers_require_the_raw_canary(self):
        """Every payload marker must contain its own canary AND a raw '<'
        or quote — so HTML-encoding the output kills the match."""
        for p in (x for x in xss_probes() if not x.baseline):
            self.assertTrue(p.markers, p.name)
            marker = p.markers[0]
            self.assertIn("phxss", marker, p.name)
            self.assertTrue(("<" in marker) or ("'" in marker)
                            or ('"' in marker), p.name)

    def test_deterministic_order(self):
        self.assertEqual([p.path for p in xss_probes()],
                         [p.path for p in xss_probes()])

    def test_registered_in_the_engine_library(self):
        self.assertIn("xss", probe_library())


class TestXSSDetection(unittest.TestCase):

    def test_raw_reflection_is_detected_and_confirmed(self):
        anomalies = hunt_target(TARGET, [_svc()],
                                runner=_reflect_runner(reflect=True))
        xss = [a for a in anomalies if a.cls == "xss"]
        self.assertTrue(xss, "a raw reflection must be an anomaly")
        self.assertTrue(any(a.confirmed for a in xss),
                        "the reflection reproduces, so it must confirm")
        self.assertTrue(any("marker:" in " ".join(a.signals) for a in xss))

    def test_html_encoded_reflection_is_not_a_hit(self):
        anomalies = hunt_target(TARGET, [_svc()],
                                runner=_reflect_runner(reflect=False))
        self.assertFalse([a for a in anomalies if a.cls == "xss"],
                         "an escaped payload is data, not script")

    def test_json_content_type_is_not_a_hit(self):
        anomalies = hunt_target(
            TARGET, [_svc()],
            runner=_reflect_runner(reflect=True,
                                   content_type="application/json"))
        self.assertFalse([a for a in anomalies if a.cls == "xss"],
                         "reflection outside HTML has no execution context")

    def test_svg_content_type_is_allowed(self):
        anomalies = hunt_target(
            TARGET, [_svc()],
            runner=_reflect_runner(reflect=True,
                                   content_type="image/svg+xml"))
        self.assertTrue([a for a in anomalies if a.cls == "xss"],
                        "an XSS inside inline SVG is still executable")


class TestXSSMutations(unittest.TestCase):

    def test_only_the_winner_is_mutated_deterministically(self):
        winner = xss_probes()[1]  # html-script
        first = mutate_probe(winner)
        self.assertTrue(first)
        self.assertTrue(all(m.cls == "xss" for m in first))
        self.assertTrue(all(m.name.startswith("html-script-mut")
                            for m in first))
        self.assertEqual([m.path for m in first],
                         [m.path for m in mutate_probe(winner)])

    def test_mutations_cover_case_encoding_and_nesting(self):
        paths = xss_mutations("/?q=phxss1<script>alert(1)</script>")
        self.assertTrue(any("<ScRiPt>" in p for p in paths))
        self.assertTrue(any("<scr<script>ipt>" in p for p in paths))
        self.assertTrue(any("%3e" in p for p in paths))


class TestXSSEndpointAdaptation(unittest.TestCase):

    def test_probes_reflection_sinks_not_the_generic_id(self):
        ep = Endpoint(path="/search", params=[])
        probes = _endpoint_probes("xss", ep, Endpoint("/", source="root"))
        params = set()
        for p in probes:
            if "?" in p.path:
                params.add(p.path.split("?", 1)[1].split("=", 1)[0])
        self.assertIn("q", params)
        self.assertNotIn("id", params)

    def test_param_fanout_is_capped(self):
        from phantom.automation.exploit.anomaly import _XSS_PARAMS
        ep = Endpoint(path="/search", params=[])
        probes = _endpoint_probes("xss", ep, Endpoint("/", source="root"))
        params = {p.path.split("?", 1)[1].split("=", 1)[0]
                  for p in probes if "?" in p.path}
        self.assertLessEqual(len(params), _XSS_PARAMS)

    def test_discovered_params_take_priority(self):
        ep = Endpoint(path="/s", params=["post"])
        probes = _endpoint_probes("xss", ep, Endpoint("/", source="root"))
        params = {p.path.split("?", 1)[1].split("=", 1)[0]
                  for p in probes if "?" in p.path}
        self.assertIn("post", params)


class TestXSSDomContext(unittest.TestCase):
    """The browser-less DOM-XSS proxy: a raw reflection that lands in a
    JS execution sink is readable from the bytes alone."""

    def test_reflection_in_script_block(self):
        self.assertEqual(xss_dom_context("<script>phxss7</script>", "phxss7"),
                         "script-block")

    def test_reflection_in_document_write_sink(self):
        body = '<html><script>document.write("phxss7");</script></html>'
        self.assertEqual(xss_dom_context(body, "phxss7"), "document.write")

    def test_reflection_in_innerhtml_sink(self):
        body = '<script>el.innerHTML = "phxss7";</script>'
        self.assertEqual(xss_dom_context(body, "phxss7"), "innerHTML")

    def test_plain_markup_reflection_is_not_a_dom_sink(self):
        self.assertEqual(xss_dom_context("<p>phxss7</p>", "phxss7"), "")

    def test_text_outside_script_is_not_script_block(self):
        # a </script> BEFORE the reflection closes the block
        self.assertEqual(
            xss_dom_context("<script>x</script><p>phxss7</p>", "phxss7"), "")

    def test_case_insensitive_marker(self):
        self.assertEqual(xss_dom_context("<SCRIPT>PHXSS7</SCRIPT>", "phxss7"),
                         "script-block")

    def test_missing_marker_is_empty(self):
        self.assertEqual(xss_dom_context("<p>nothing</p>", "phxss7"), "")


class TestXSSStored(unittest.TestCase):
    """Stored cross-page XSS: write → re-read across a request boundary."""

    def test_payload_carries_canary_plus_raw_markup(self):
        payload = xss_stored_payload("phxst1")
        self.assertIn("phxst1", payload)
        self.assertIn(STORED_TAG, payload)

    def test_markers_are_ordered_markup_first(self):
        markers = xss_stored_markers("phxst1")
        self.assertEqual(markers[0], "phxst1" + STORED_TAG)
        self.assertEqual(markers[1], "phxst1")

    def test_stored_reflection_across_pages_is_found_and_confirmed(self):
        """The canary is written to /feedback and rendered RAW on the view
        page — a different request than the write → stored XSS, confirmed."""
        from phantom.automation.exploit.anomaly import HuntEngine, ProbeResult
        store = {}

        def runner(method, url, body="", timeout=8.0):
            path = url.split(":" + "//", 1)[-1].split("/", 1)[-1]
            path = "/" + path
            if method == "POST" and path == "/feedback":
                store["v"] = body.split("=", 1)[1] if "=" in body else body
                return ProbeResult(200, 50, 0.1, "thanks")
            if method == "GET" and path in ("/", "/feedback"):
                return ProbeResult(200, 200, 0.1,
                                   f"<html>{store.get('v', '')}</html>")
            return ProbeResult(200, 100, 0.1, "<html>ok</html>")

        engine = HuntEngine(runner=runner)
        from phantom.automation.exploit.anomaly import Endpoint
        endpoints = [Endpoint("/", source="root"),
                     Endpoint("/feedback", source="form", params=["msg"])]
        out = []
        engine._stored_xss("http://t", endpoints, out)
        stored = [a for a in out if a.name == "stored-xss"]
        self.assertTrue(stored, "raw stored markup must be found")
        self.assertTrue(stored[0].confirmed,
                        "cross-boundary raw markup reproduces → confirmed")
        self.assertEqual(stored[0].cls, "xss")

    def test_escaped_storage_is_only_an_echo(self):
        """If the app HTML-encodes on render, the bare canary still proves
        STORAGE but not execution → unconfirmed echo."""
        from phantom.automation.exploit.anomaly import Endpoint, HuntEngine, ProbeResult
        store = {}

        def runner(method, url, body="", timeout=8.0):
            path = "/" + url.split(":" + "//", 1)[-1].split("/", 1)[-1]
            if method == "POST" and path == "/feedback":
                store["v"] = body.split("=", 1)[1] if "=" in body else body
                return ProbeResult(200, 50, 0.1, "thanks")
            if method == "GET":
                raw = store.get("v", "")
                safe = (raw.replace("<", "&lt;").replace(">", "&gt;"))
                return ProbeResult(200, 200, 0.1, f"<html>{safe}</html>")
            return ProbeResult(200, 100, 0.1, "ok")

        engine = HuntEngine(runner=runner)
        endpoints = [Endpoint("/", source="root"),
                     Endpoint("/feedback", source="form", params=["msg"])]
        out = []
        engine._stored_xss("http://t", endpoints, out)
        echo = [a for a in out if a.name == "stored-echo"]
        self.assertTrue(echo, "escaped storage still proves the canary stored")
        self.assertFalse(echo[0].confirmed, "escaped markup is not execution")

    def test_no_write_endpoint_means_no_stored_probe(self):
        from phantom.automation.exploit.anomaly import Endpoint, HuntEngine, ProbeResult

        def runner(method, url, body="", timeout=8.0):
            return ProbeResult(200, 100, 0.1, "ok")

        engine = HuntEngine(runner=runner)
        out = []
        engine._stored_xss("http://t", [Endpoint("/", source="root")], out)
        self.assertEqual(out, [])


class TestXSSInterpreter(unittest.TestCase):

    def test_hunt_marker_parses_xss_class(self):
        from phantom.automation.guidance.kit import _hunt_web_interp
        wm = WorldModel(target=TARGET, target_type="ip")
        output = ("HUNT:cls=xss name=html-script port=80 endpoint=/?q=... "
                  "signals=marker:phxss1<script> score=2.50 confirmed=true "
                  "severity=high evidence=<html>results")
        findings = _hunt_web_interp(output, wm, {"port": "80"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].value["cls"], "xss")
        self.assertTrue(findings[0].value["confirmed"])


if __name__ == "__main__":
    unittest.main()
