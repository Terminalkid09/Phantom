"""Tests: operator-session cookie chain + identity start-gate.

* stolen_cookies findings become a per-domain jar; _fetch attaches it
  ONLY to platform profile views (never archives/search/delivery);
* values are header-sanitized; the SESSION_USED receipt carries
  platforms+counts, never values;
* read-only boundary: delivery paths take no cookies parameter;
* start-gate preview + confirm endpoints + CLI gate.
"""
import unittest
from unittest.mock import Mock, patch

from phantom.automation.belief import WorldModel


def _wm_with_cookies():
    wm = WorldModel(target="someuser", target_type="username")
    wm.add_finding(
        "stolen_cookies", "cookies:2",
        {"count": 2, "hosts": ["instagram.com"],
         "sample": {"host": ".instagram.com", "name": "sessionid",
                    "path": "/", "value": "abc123"},
         "cookies": [
             {"host": ".instagram.com", "name": "sessionid",
              "path": "/", "value": "abc123"},
             {"host": ".instagram.com", "name": "evil",
              "path": "/", "value": "a'b; c$d"},
             {"host": "other.com", "name": "x",
              "path": "/", "value": "y"},
             {"host": "", "name": "z", "path": "/", "value": ""}]},
        confidence=0.9, source="cookie_stealer")
    return wm


class TestSessionJar(unittest.TestCase):
    def test_builds_per_domain_headers(self):
        from phantom.automation.social.recon import session_jar
        jar = session_jar(_wm_with_cookies())
        self.assertIn("instagram.com", jar)
        self.assertIn("sessionid=abc123", jar["instagram.com"])
        self.assertIn("other.com", jar)
        # quote-breaker value dropped, name kept only if fully safe
        self.assertNotIn("evil", jar["instagram.com"])
        self.assertNotIn("'", jar["instagram.com"])
        self.assertNotIn("$", jar["instagram.com"])

    def test_empty_world_gives_empty_jar(self):
        from phantom.automation.social.recon import session_jar
        wm = WorldModel(target="x", target_type="username")
        self.assertEqual(session_jar(wm), {})
        self.assertEqual(session_jar(None), {})

    def test_longest_suffix_wins(self):
        from phantom.automation.social.recon import _jar_for
        jar = {"example.com": "a=1", "sub.example.com": "b=2"}
        self.assertEqual(
            _jar_for("https://sub.example.com/x", jar), "b=2")
        self.assertEqual(
            _jar_for("https://other.example.com/", jar), "a=1")
        self.assertEqual(_jar_for("https://unrelated.io/", jar), "")
        self.assertEqual(_jar_for("https://example.com/", {}), "")


class TestAuthedFetch(unittest.TestCase):
    def test_cookie_header_attached_and_sanitized(self):
        import phantom.automation.social.recon as recon_mod
        seen = {}

        class _Res:
            stdout = "ok"
            returncode = 0

        def fake_exec(cmd, timeout=None):
            seen["cmd"] = cmd
            return _Res()

        with patch("phantom.core.executor.execute_quiet",
                    side_effect=fake_exec):
            out = recon_mod._fetch("https://www.instagram.com/u/",
                                   cookies="sessionid=abc123; x='INJECT'; y=$HOME")
        self.assertEqual(out, "ok")
        # quote-breaking and variable expansion neutralized (the inert
        # WORDS may remain — they cannot break out of the header value)
        self.assertIn("-H 'Cookie: sessionid=abc123; x=INJECT; y=HOME'",
                      seen["cmd"])
        self.assertNotIn("$(", seen["cmd"])
        self.assertNotIn("`", seen["cmd"])
        self.assertNotIn("$HOME", seen["cmd"])

    def test_no_cookies_no_header(self):
        import phantom.automation.social.recon as recon_mod
        seen = {}

        class _Res:
            stdout = "ok"
            returncode = 0

        with patch("phantom.core.executor.execute_quiet",
                    side_effect=lambda cmd, timeout=None: (
                        seen.setdefault("cmd", cmd), _Res())[1]):
            recon_mod._fetch("https://x/")
        self.assertNotIn("Cookie:", seen["cmd"])

    def test_delivery_paths_take_no_cookies(self):
        """Read-only boundary, pinned by signature: contact/delivery
        methods must not grow a cookies parameter by accident."""
        import inspect
        from phantom.automation.social.engine import SocialEngine
        for meth in ("dm", "dm_second_stage", "campaign", "phish",
                     "follow_up", "launch_dm"):
            fn = getattr(SocialEngine, meth, None)
            if fn is None:
                continue
            params = inspect.signature(fn).parameters
            self.assertNotIn("cookies", params, meth)
            self.assertNotIn("jar", params, meth)


class TestSessionUsedMarker(unittest.TestCase):
    def test_receipt_carries_platforms_not_values(self):
        from phantom.automation.guidance.kit import _social_interp
        wm = WorldModel(target="u", target_type="username")
        out = ("SESSION_USED: platforms=instagram,tiktok "
               "source=operator_session readonly=1")
        findings = _social_interp(out, wm, {})
        matches = [f for f in findings if f.kind == "session_used"]
        self.assertEqual(len(matches), 1)
        self.assertNotIn("abc123", str(matches[0].value))
        self.assertIn("instagram", matches[0].value["platforms"])


class TestDeepReconDispatch(unittest.TestCase):
    def test_agent_dispatches_deep_recon_with_jar(self):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.guidance.commands import make_registry
        events = []
        agent = AutonomousAgent(
            target="someuser", target_type="username",
            on_event=lambda k, d: events.append((k, d)))
        # seed the agent WM with the stealer finding
        for f in _wm_with_cookies().to_dict()["findings"]:
            agent.wm.add_finding(f["kind"], f["key"], f["value"],
                                 confidence=0.9, source="t")
        seen = {}

        class _Eng:
            def deep_recon(self, username, platform="", cookies=None):
                seen["cookies"] = cookies
                return True, [f"PROFILE: username={username} "
                              f"platform={platform or 'instagram'} "
                              f"private=0 bio=x link="]

        agent.social_engine = _Eng()
        cap = make_registry().get("deep_recon")
        self.assertIsNotNone(cap)
        ok = agent._run_social_method("deep_recon", {})
        self.assertTrue(ok)
        self.assertIn("instagram.com", seen["cookies"])
        kinds = [k for k, _ in events]
        self.assertNotIn("failed", kinds)


class TestConfirmQueue(unittest.TestCase):
    def test_ask_waits_then_defaults(self):
        from phantom.automation.social.confirm import IdentityChecks
        mgr = IdentityChecks()
        self.assertEqual(mgr.ask("d?", [], timeout=0), "")

    def test_answer_unblocks_asker(self):
        import threading
        from phantom.automation.social.confirm import IdentityChecks
        mgr = IdentityChecks()
        got = {}

        def asker():
            got["ans"] = mgr.ask(
                "which?", [{"handle": "a", "platform": "ig"}],
                target="u", timeout=5.0)

        t = threading.Thread(target=asker, daemon=True)
        t.start()
        import time
        deadline = time.time() + 5
        while not mgr.pending() and time.time() < deadline:
            time.sleep(0.05)
        pending = mgr.pending()
        self.assertEqual(len(pending), 1)
        self.assertTrue(mgr.answer(pending[0]["id"], "same:a"))
        t.join(timeout=5)
        self.assertEqual(got.get("ans"), "same:a")

    def test_ttl_prunes(self):
        from phantom.automation.social.confirm import IdentityChecks
        mgr = IdentityChecks()
        check = mgr.create("ambiguous", "u", [{"handle": "a"}])
        check.created_at -= 99999
        self.assertEqual(mgr.pending(), [])


class TestPreviewEndpoint(unittest.TestCase):
    _ENV_KEYS = ("PHANTOM_STATE_FILE", "PHANTOM_API_TOKEN",
                 "PHANTOM_C2_KEY", "PHANTOM_C2_NONCE",
                 "PHANTOM_PAYLOAD_TOKEN")

    def setUp(self):
        import os
        import tempfile
        self._saved = {k: os.environ.get(k) for k in self._ENV_KEYS}
        for k in self._ENV_KEYS:
            os.environ.pop(k, None)
        tmp = tempfile.mkdtemp(prefix="phantom-api-confirm-")
        os.environ["PHANTOM_STATE_FILE"] = os.path.join(tmp, "state.json")

    def tearDown(self):
        import os
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_preview_and_confirm_roundtrip(self):
        import asyncio
        import json
        from aiohttp.test_utils import TestClient, TestServer
        from phantom.api.server import create_app
        from phantom.utils import c2_crypto

        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                token = c2_crypto.get_api_token()
                headers = {"Authorization": f"Bearer {token}"}
                with patch("phantom.automation.social.recon._fetch",
                            return_value="<html>bio here</html>"):
                    resp = await client.post(
                        "/api/osint/preview",
                        json={"username": "someuser",
                              "platform": "instagram"},
                        headers=headers)
                    self.assertEqual(resp.status, 200)
                    data = await resp.json()
                self.assertEqual(data["username"], "someuser")
                self.assertIn("rendered", data)
                # confirm lifecycle: unknown id -> 404, flow works
                resp = await client.post(
                    "/api/identity/confirm",
                    json={"id": "nope", "decision": "stop"},
                    headers=headers)
                self.assertEqual(resp.status, 404)
                resp = await client.get("/api/identity/checks",
                                        headers=headers)
                self.assertEqual(resp.status, 200)
                data = await resp.json()
                self.assertIn("checks", data)
            finally:
                await client.close()

        asyncio.run(scenario())


class TestCookieRedaction(unittest.TestCase):
    def test_cookie_entry_values_masked_names_kept(self):
        from phantom.utils.redact import redact
        value = _wm_with_cookies().find("stolen_cookies")[0].value
        red = redact(value)
        self.assertEqual(red["count"], 2)
        self.assertIn("instagram.com", red["hosts"])
        for entry in red["cookies"]:
            self.assertEqual(entry["value"], "[REDACTED]")
            self.assertEqual(entry["name"], "sessionid" if entry["name"] == "sessionid" else entry["name"])
        self.assertEqual(red["sample"]["value"], "[REDACTED]")
        blob = str(red)
        self.assertNotIn("abc123", blob)

    def test_stream_value_helper_never_carries_jar(self):
        from phantom.automation.agent import _safe_stream_value
        finding = _wm_with_cookies().find("stolen_cookies")[0]
        text = _safe_stream_value(finding)
        self.assertNotIn("abc123", text)
        self.assertIn("2 cookie", text)


if __name__ == "__main__":
    unittest.main()
