"""Tests for the pluggable LLM transport: local GGUF vs remote
OpenAI-compatible endpoint, MANDATORY redaction on the remote path, and the
failure-cause classifier that feeds the experience engine."""
import json
import unittest
from unittest.mock import patch

from phantom.automation.llm_advisor import (
    LLMAdvisor,
    _LocalChat,
    _RemoteChat,
    redact,
)


class _FakeResp:
    """Minimal stand-in for the object urlopen returns."""

    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestRedaction(unittest.TestCase):
    def test_removes_identifiers_but_keeps_structure(self):
        text = (
            "target: 10.0.0.5 (ip)\n"
            "web app: https://portal.acme-corp.com/login\n"
            "creds: user acme\\\\mrossi password=Sup3rSecret!\n"
            "path: C:\\Users\\mrossi\\loot\\secrets.txt\n"
            "email: mario.rossi@acme-corp.com\n"
            "hash: 5f4dcc3b5aa765d61d8327deb882cf99\n"
        )
        out = redact(text)
        for leaked in ("10.0.0.5", "acme-corp.com", "portal.acme-corp.com",
                       "mrossi", "Sup3rSecret", "secrets.txt",
                       "5f4dcc3b5aa765d61d8327deb882cf99"):
            self.assertNotIn(leaked, out)
        self.assertIn("<ip>", out)
        self.assertIn("<url>", out)
        self.assertIn("<email>", out)
        self.assertIn("target:", out)
        self.assertIn("web app:", out)

    def test_empty_and_plain(self):
        self.assertEqual(redact(""), "")
        self.assertEqual(redact("no identifiers here"), "no identifiers here")


class TestTransports(unittest.TestCase):
    def test_local_requires_existing_model(self):
        ok, err = _LocalChat("/nonexistent/model.gguf").available()
        self.assertFalse(ok)
        self.assertIn("not found", err)
        ok, err = _LocalChat("").available()
        self.assertFalse(ok)

    def test_remote_requires_url_and_model(self):
        self.assertFalse(_RemoteChat("", "", "m").available()[0])
        self.assertFalse(_RemoteChat("http://x", "", "").available()[0])
        self.assertTrue(_RemoteChat("http://x", "", "m").available()[0])

    def test_remote_payload_is_redacted(self):
        captured = {}

        def _fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["headers"] = dict(req.headers)
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _FakeResp(
                {"choices": [{"message": {"content": "ok"}}]})

        chat = _RemoteChat("https://llm.example/v1", "k", "model-x")
        with patch("urllib.request.urlopen", _fake_urlopen):
            out = chat.chat([{"role": "user",
                              "content": "scan 10.0.0.7 and C:\\secret\\x"}])
        self.assertEqual(out, "ok")
        self.assertTrue(captured["url"].endswith("/chat/completions"))
        sent = captured["body"]["messages"][0]["content"]
        self.assertNotIn("10.0.0.7", sent)
        self.assertIn("<ip>", sent)

    def test_remote_gateway_result_shape(self):
        with patch("urllib.request.urlopen",
                   lambda req, timeout=None: _FakeResp(
                       {"result": {"response": "from-gateway"}})):
            out = _RemoteChat("http://x", "", "m").chat(
                [{"role": "user", "content": "hi"}])
        self.assertEqual(out, "from-gateway")


class TestAdvisorBackend(unittest.TestCase):
    def test_default_backend_is_local(self):
        adv = LLMAdvisor(enabled=True, model_path="/nonexistent/x.gguf")
        self.assertEqual(adv.backend, "local")
        self.assertFalse(adv.available())
        self.assertIn("local GGUF", adv.describe())

    def test_remote_backend_is_available_without_a_local_model(self):
        adv = LLMAdvisor(enabled=True, backend="remote",
                         remote_url="https://llm.example/v1",
                         remote_model="big-model", remote_key="topsecret")
        self.assertTrue(adv.available())
        self.assertIn("big-model", adv.describe())
        self.assertNotIn("topsecret", adv.describe())

    def test_remote_backend_unavailable_without_config(self):
        adv = LLMAdvisor(enabled=True, backend="remote")
        self.assertFalse(adv.available())

    def test_disabled_advisor_never_available(self):
        self.assertFalse(LLMAdvisor(enabled=False, backend="remote",
                                    remote_url="http://x",
                                    remote_model="m").available())

    def test_suggest_uses_the_transport(self):
        adv = LLMAdvisor(enabled=True, backend="remote",
                         remote_url="http://x", remote_model="m")

        class _WM:
            target = "10.0.0.5"
            target_type = "ip"

            def find(self, kind):
                return []

        raw = '[{"capability_id": "smb_enum", "reason": "445 open"}]'
        with patch.object(adv, "_chat", return_value=raw) as m:
            out = adv.suggest(_WM())
        self.assertEqual(out, ["smb_enum"])
        m.assert_called_once()


class TestCauseClassifier(unittest.TestCase):
    def test_rules_answer_without_any_model(self):
        adv = LLMAdvisor(enabled=False)     # no model at all
        from phantom.automation.brain.experience import causes as C
        self.assertEqual(adv.classify_failure("x", "blocked by cloudflare"),
                         C.WAF_BLOCKED)
        self.assertEqual(adv.classify_failure("x", "out of scope: 10.9.9.9"),
                         C.SCOPE_DENIED)
        # an ambiguous failure degrades to `other`, never raises
        self.assertEqual(adv.classify_failure("x", "it did not work"),
                         C.OTHER)

    def test_llm_only_consulted_for_the_ambiguous_tail(self):
        adv = LLMAdvisor(enabled=True, backend="remote",
                         remote_url="http://x", remote_model="m")
        with patch.object(adv, "_chat", return_value="waf_blocked") as m:
            # clear case -> rules decide, no model call
            adv.classify_failure("x", "HTTP 403 forbidden")
            m.assert_not_called()
            # ambiguous case -> model consulted
            out = adv.classify_failure("x", "something odd happened")
            m.assert_called_once()
        self.assertEqual(out, "waf_blocked")

    def test_out_of_taxonomy_answer_is_rejected(self):
        adv = LLMAdvisor(enabled=True, backend="remote",
                         remote_url="http://x", remote_model="m")
        with patch.object(adv, "_chat", return_value="definitely_pwned"):
            out = adv.classify_failure("x", "something odd happened")
        from phantom.automation.brain.experience import causes as C
        self.assertEqual(out, C.OTHER)

    def test_transport_error_degrades(self):
        adv = LLMAdvisor(enabled=True, backend="remote",
                         remote_url="http://x", remote_model="m")
        with patch.object(adv, "_chat", side_effect=RuntimeError("down")):
            out = adv.classify_failure("x", "something odd happened")
        from phantom.automation.brain.experience import causes as C
        self.assertEqual(out, C.OTHER)


class TestExperienceClassifierWiring(unittest.TestCase):
    def test_classifier_only_fills_the_ambiguous_tail(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.brain.experience import Experience
        from phantom.automation.brain.experience import causes as C
        seen = []

        def _classifier(technique, reason, evidence, command):
            seen.append(reason)
            return C.WAF_BLOCKED

        exp = Experience(cause_classifier=_classifier)
        wm = WorldModel(target="t")
        exp.observe(wm, "a", False, reason="HTTP 403 forbidden")
        exp.observe(wm, "b", False, reason="mysterious failure")
        eps = {e.technique: e.cause for e in exp.store.episodes}
        self.assertEqual(eps["a"], C.WAF_BLOCKED)   # rules decided
        self.assertEqual(eps["b"], C.WAF_BLOCKED)   # classifier filled it
        self.assertEqual(seen, ["mysterious failure"])

    def test_bad_classifier_answer_is_ignored(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.brain.experience import Experience
        from phantom.automation.brain.experience import causes as C
        exp = Experience(cause_classifier=lambda *a: "not_a_cause")
        wm = WorldModel(target="t")
        ep = exp.observe(wm, "a", False, reason="mysterious failure")
        self.assertEqual(ep.cause, C.OTHER)

    def test_classifier_exception_is_swallowed(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.brain.experience import Experience
        from phantom.automation.brain.experience import causes as C

        def _boom(*a):
            raise RuntimeError("model down")

        exp = Experience(cause_classifier=_boom)
        wm = WorldModel(target="t")
        ep = exp.observe(wm, "a", False, reason="mysterious failure")
        self.assertEqual(ep.cause, C.OTHER)


if __name__ == "__main__":
    unittest.main()
