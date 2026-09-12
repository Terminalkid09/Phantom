"""FASE C tests: the IDOR engine — differential reference walk, oracles,
capability registration and the agent in-process channel."""
import unittest

from phantom.automation.exploit.idor import (
    IdorEngine, _extract_ref_params, _identity_of, _swap_param,
)


def _fake_app(base_url: str):
    """A tiny in-memory 'app': /users/1 is OWNER data; other ids leak
    other users' profiles (the IDOR). No authz check at all."""
    users = {
        "1": {"name": "Alice Admin", "email": "alice@corp.test"},
        "2": {"name": "Bob Other", "email": "bob@corp.test"},
        "3": {"name": "Carol Other", "email": "carol@corp.test"},
        "4": {"name": "Dave Other", "email": "dave@corp.test"},
        "5": {"name": "Eve Other", "email": "eve@corp.test"},
    }
    import re

    def _handler(url):
        m = re.search(r"/users/(\d+)", url)
        if m:
            u = users.get(m.group(1))
            if u:
                return (f"<html><title>Profile</title>"
                        f"<div>name: {u['name']}</div>"
                        f"<div>email: {u['email']}</div></html>")
        return "<html><title>Not Found</title></html>"
    return _handler


class TestIdorHelpers(unittest.TestCase):
    def test_extract_ref_params(self):
        self.assertIn("id", _extract_ref_params("/users/1?id=5"))
        self.assertIn("user_id", _extract_ref_params("/api?user_id=5"))
        self.assertNotIn("q", _extract_ref_params("/search?q=hello"))

    def test_swap_param(self):
        self.assertEqual(_swap_param("/users?id=1", "id", "2"),
                         "/users?id=2")
        self.assertEqual(_swap_param("/a?id=1&x=y", "id", "3"),
                         "/a?id=3&x=y")
        self.assertEqual(_swap_param("/a?id=1", "missing", "9"),
                         "/a?id=1")

    def test_identity_of(self):
        body = '<div>name: Alice Admin</div><div>email: a@b.c</div>'
        found = _identity_of(body)
        self.assertTrue(any("Alice" in m for m in found))
        self.assertTrue(any("a@b.c" in m for m in found))


class TestIdorEngine(unittest.TestCase):
    def test_detects_leak_on_foreign_reference(self):
        handler = _fake_app("http://x")
        engine = IdorEngine(sender=handler)
        sigs = engine.run("10.0.0.9", port=80)
        self.assertTrue(sigs, "no IDOR signal found")
        best = sigs[0]
        self.assertTrue(best.confirmed)
        self.assertGreater(best.score, 0.7)
        self.assertIn("size", best.evidence)

    def test_no_signal_when_all_references_identical(self):
        def _same(url):
            return "<html>Same content for everyone</html>"
        engine = IdorEngine(sender=_same)
        sigs = engine.run("10.0.0.9", port=80)
        # no distinct objects, no size deltas -> no confirmed signals
        self.assertFalse(any(s.confirmed for s in sigs))

    def test_llm_gate_withholds_body(self):
        handler = _fake_app("http://x")
        engine = IdorEngine(sender=handler)
        sigs = engine.run("10.0.0.9", port=80, extract_data=False)
        self.assertTrue(sigs)
        for s in sigs:
            # the leak is PROVEN but the body content is withheld
            self.assertEqual(s.distinct_markers, [])
            self.assertIn("withheld", s.evidence)

    def test_marker_format(self):
        handler = _fake_app("http://x")
        engine = IdorEngine(sender=handler)
        sigs = engine.run("10.0.0.9", port=80)
        marker = sigs[0].to_marker()
        self.assertTrue(marker.startswith("IDOR:param="))
        self.assertIn("confirmed=true", marker)


class TestIdorCapability(unittest.TestCase):
    def test_capability_registered(self):
        from phantom.automation.guidance.kit import CAPABILITIES
        ids = {c.id for c in CAPABILITIES}
        self.assertIn("idor_scan", ids)
        cap = {c.id: c for c in CAPABILITIES}["idor_scan"]
        self.assertEqual(cap.category, "exploit")
        self.assertIn("idor", cap.effects)

    def test_interpreter_parses_markers(self):
        from phantom.automation.guidance.kit import _idor_interp
        from phantom.automation.belief import WorldModel
        wm = WorldModel(target="10.0.0.9")
        out = ("IDOR:param=id endpoint=/users/1 size=120->480 "
               "distinct=Alice|Bob score=0.95 confirmed=true severity=high")
        fs = _idor_interp(out, wm, {})
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].kind, "idor")
        self.assertTrue(fs[0].value["confirmed"])
        self.assertEqual(fs[0].value["param"], "id")

    def test_agent_channels_idor_in_process(self):
        import inspect
        from phantom.automation import agent as agent_mod
        src = inspect.getsource(agent_mod.AutonomousAgent)
        self.assertIn('cap.id == "idor_scan"', src)
        self.assertIn("_execute_idor_capability", src)
        self.assertIn("extract_data=not llm_on", src)

    def test_phase_index_owns_idor(self):
        from phantom.automation.phases import phase_of
        self.assertEqual(phase_of("idor_scan"), "exploit")


if __name__ == "__main__":
    unittest.main()