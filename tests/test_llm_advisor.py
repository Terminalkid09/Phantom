"""Tests for the optional local-LLM advisor: strict JSON parsing, registry
validation, paranoid-mode filtering and bounded authority (a successful
'injection' can only add noise, never authorize actions)."""
import unittest
from unittest.mock import Mock, patch

from phantom.automation.llm_advisor import LLMAdvisor, _world_summary


class _FakeWM:
    def __init__(self):
        self.target = "10.0.0.5"
        self.target_type = "ip"
        self._findings = {}

    def find(self, kind):
        return list(self._findings.get(kind, []))

    def add_finding(self, kind, key, value, confidence=0.9, source="t", target=""):
        self._findings.setdefault(kind, []).append(
            type("F", (), {"kind": kind, "key": key, "value": value})())


class _FakeRegistry:
    def __init__(self, known):
        self._known = set(known)

    def get(self, cid):
        if cid in self._known:
            cap = type("C", (), {"stealth_level": "active"})
            return cap
        return None


class TestParse(unittest.TestCase):

    def test_clean_json(self):
        raw = '[{"capability_id": "smb_enum", "reason": "445 open"}]'
        self.assertEqual(LLMAdvisor._parse(raw),
                         [{"capability_id": "smb_enum", "reason": "445 open"}])

    def test_prose_around_json(self):
        raw = ('Here are my suggestions:\n```json\n'
               '[{"capability_id": "http_probe", "reason": "web open"}]\n```')
        parsed = LLMAdvisor._parse(raw)
        self.assertEqual(parsed[0]["capability_id"], "http_probe")

    def test_trailing_comma_tolerated(self):
        raw = '[{"capability_id": "hunt_web", "reason": "php"},]'
        self.assertEqual(LLMAdvisor._parse(raw)[0]["capability_id"], "hunt_web")

    def test_non_list_rejected(self):
        self.assertEqual(LLMAdvisor._parse('{"capability_id": "x"}'), [])

    def test_injection_output_has_no_action_fields(self):
        # even if the model is fully 'injected' and emits command-looking
        # fields, only capability_id/reason survive the schema filter
        raw = ('[{"capability_id": "smb_enum", "reason": "ok", '
               '"action": "run rm -rf /", "command": "evil"}]')
        parsed = LLMAdvisor._parse(raw)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(set(parsed[0].keys()), {"capability_id", "reason"})
        self.assertNotIn("action", parsed[0])
        self.assertNotIn("command", parsed[0])


class TestValidation(unittest.TestCase):

    def _advisor(self, **kw):
        return LLMAdvisor(enabled=True, model_path="fake.gguf", **kw)

    def test_invalid_ids_dropped(self):
        adv = self._advisor()
        reg = _FakeRegistry({"smb_enum", "http_probe"})
        raw = ('[{"capability_id": "smb_enum", "reason": "a"},'
               ' {"capability_id": "invented_cap", "reason": "b"},'
               ' {"capability_id": "exec_anything", "reason": "c"}]')
        with patch.object(adv, "_generate", return_value=raw), \
             patch.object(adv, "available", return_value=True):
            out = adv.suggest(_FakeWM(), reg)
        self.assertEqual(out, ["smb_enum"])

    def test_paranoid_drops_aggressive(self):
        class _LoudRegistry:
            def get(self, cid):
                if cid == "ssh_login":
                    return type("C", (), {"stealth_level": "aggressive"})()
                return type("C", (), {"stealth_level": "active"})()
        adv = self._advisor(paranoid=True)
        raw = ('[{"capability_id": "ssh_login", "reason": "loud"},'
               ' {"capability_id": "smb_enum", "reason": "ok"}]')
        with patch.object(adv, "_generate", return_value=raw), \
             patch.object(adv, "available", return_value=True):
            out = adv.suggest(_FakeWM(), _LoudRegistry())
        self.assertEqual(out, ["smb_enum"])

    def test_degradation_when_disabled_or_missing(self):
        adv = LLMAdvisor(enabled=False)
        self.assertEqual(adv.suggest(_FakeWM(), _FakeRegistry({"smb_enum"})), [])
        adv2 = LLMAdvisor(enabled=True, model_path="/nonexistent/foo.gguf")
        self.assertEqual(adv2.suggest(_FakeWM(), _FakeRegistry({"smb_enum"})), [])

    def test_generate_error_returns_empty(self):
        adv = self._advisor()
        with patch.object(adv, "available", return_value=True), \
             patch.object(adv, "_generate", side_effect=RuntimeError("boom")):
            self.assertEqual(adv.suggest(_FakeWM(), _FakeRegistry({"smb_enum"})), [])


class TestWorldSummary(unittest.TestCase):

    def test_summary_is_compact_and_includes_facts(self):
        wm = _FakeWM()
        wm.add_finding("service", "tcp/445", {"port": "445", "service": "smb",
                                              "product": "Windows", "version": ""})
        wm.add_finding("creds", "k", {"service": "leak", "valid": False})
        s = _world_summary(wm)
        self.assertIn("10.0.0.5", s)
        self.assertIn("445", s)
        self.assertIn("creds", s)

    def test_no_findings(self):
        wm = _FakeWM()
        wm.target = ""
        self.assertIn("no findings", _world_summary(wm))


if __name__ == "__main__":
    unittest.main()
