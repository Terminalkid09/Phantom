"""Tests: target normalization (all types, all adapters) + branch-aware
social tool gating.

A URL target must reach every adapter as a bare host (nmap/ssh/curl)
or a well-formed URL (http tooling) — never `http://http://...`.
Social capabilities refuse with tool_missing (not opaque failure)
when their per-type binary is absent.
"""
import unittest

from phantom.automation.belief import WorldModel


def _wm(target, ttype):
    return WorldModel(target=target, target_type=ttype)


class TestBareHost(unittest.TestCase):
    def test_passthrough_types(self):
        from phantom.automation.guidance.kit import _effective_target
        self.assertEqual(_effective_target(_wm("10.0.0.5", "ip")),
                         "10.0.0.5")
        self.assertEqual(_effective_target(_wm("example.com", "domain")),
                         "example.com")

    def test_url_forms_reduce_to_host(self):
        from phantom.automation.guidance.kit import _effective_target
        for raw in ("http://example.com/", "https://example.com/app?q=1",
                    "https://example.com:8443/app", "HTTP://EXAMPLE.COM",
                    "http://user:pw@example.com/", "example.com/",
                    "example.com."):
            self.assertEqual(_effective_target(_wm(raw, "url")),
                             "example.com", raw)

    def test_victim_ip_still_wins(self):
        from phantom.automation.guidance.kit import _effective_target
        wm = _wm("someuser", "username")
        wm.add_finding("victim_ip", "ip:10.9.9.9", {"ip": "10.9.9.9"},
                       confidence=0.8, source="t")
        self.assertEqual(_effective_target(wm), "10.9.9.9")


class TestEffectiveUrl(unittest.TestCase):
    def test_bare_host_defaults_http(self):
        from phantom.automation.guidance.kit import _effective_url
        self.assertEqual(_effective_url(_wm("10.0.0.5", "ip")),
                         "http://10.0.0.5")

    def test_url_keeps_scheme_port_path(self):
        from phantom.automation.guidance.kit import _effective_url
        self.assertEqual(
            _effective_url(_wm("https://example.com:8443/app", "url")),
            "https://example.com:8443/app")


class TestAdaptersOnUrl(unittest.TestCase):
    URL = "https://example.com/app"

    def test_http_probe_no_double_scheme(self):
        from phantom.automation.guidance.kit import _http_probe_adapter
        cmd = _http_probe_adapter(_wm(self.URL, "url"), {})
        self.assertNotIn("http://https://", cmd)
        self.assertNotIn("https://https://", cmd)
        self.assertIn("https://example.com/app", cmd)

    def test_scan_adapter_gets_bare_host(self):
        from phantom.automation.guidance.kit import _version_adapter
        cmd = _version_adapter(_wm(self.URL, "url"), {"port": "443"})
        self.assertNotIn("http", cmd)
        self.assertIn("example.com", cmd)

    def test_hunt_channel_base_is_bare(self):
        # the anomaly engine builds base URLs itself; the host it gets
        # must never carry a scheme
        from phantom.automation.guidance.kit import _effective_target
        host = _effective_target(_wm(self.URL, "url"))
        self.assertNotIn("://", host)
        self.assertEqual(f"https://{host}:443/", "https://example.com:443/")


class TestSocialToolGating(unittest.TestCase):
    def _agent(self, installed):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.runtime.toolchain import ToolRegistry
        events = []
        agent = AutonomousAgent(
            target="someuser", target_type="username",
            toolchain=ToolRegistry(installed=set(installed)),
            on_event=lambda k, d: events.append((k, d)))
        return agent, events

    def _cap(self, cap_id):
        from phantom.automation.guidance.commands import make_registry
        return make_registry().get(cap_id)

    def test_missing_sherlock_is_tool_missing_not_opaque(self):
        agent, events = self._agent(installed={"curl"})
        ok = agent._execute_social_capability(self._cap("osint_identity"),
                                              {})
        self.assertFalse(ok)
        kinds = [k for k, _ in events]
        self.assertIn("tool_missing", kinds)
        tools = [t for k, d in events if k == "tool_missing"
                 for t in d.get("tools", [])]
        self.assertIn("sherlock", tools)

    def test_present_tool_attempts_run(self):
        agent, events = self._agent(installed={"curl", "sherlock"})
        agent._execute_social_capability(self._cap("osint_identity"), {})
        kinds = [k for k, _ in events]
        self.assertNotIn("tool_missing", kinds)
        self.assertIn("run", kinds)

    def test_phone_needs_no_binary(self):
        from phantom.automation.guidance.kit import social_tools_for
        self.assertEqual(social_tools_for("osint_identity", "phone"), [])
        self.assertEqual(social_tools_for("osint_identity", "username"),
                         ["sherlock"])
        self.assertEqual(social_tools_for("osint_identity", "email"),
                         ["theHarvester"])
        self.assertEqual(social_tools_for("nope", "username"), [])


if __name__ == "__main__":
    unittest.main()
