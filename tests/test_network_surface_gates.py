"""Non-identity auto-mode surface gates (regression).

Three defects made the planner read as "complete" on a host it could not
actually work, so the auto-mode burned the credential path against a
surface that carried no access:

* nmap reports a TLS-wrapped service as ``ssl/<proto>`` (``ssl/http`` on
  443, ``ssl/ldap`` on 636). The interpreter truncated the token to
  ``ssl``, so an LDAPS/IMAPS/SMTPS service was indistinguishable from an
  HTTPS one.
* ``_has_web_service`` accepted a bare ``ssl`` label, which marked
  ``web_creds``/``web_rce`` READY on a bare directory server.
* the planner treated a service-SPECIFIC gate (ssh) as a generic
  ``service`` fact, and accepted mutually-dependent sources (``creds``
  via a beacon-dependent move when the beacon needs the creds), so it
  returned an optimistic plan that could never execute.

These tests pin the honest behaviour: a target with no web/ssh surface is
NOT planned a web/ssh move, and the plan says so.
"""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.perception import parse_nmap_ports
from phantom.automation.planner import Planner


def _planner(wm):
    return Planner(make_registry(), StealthEngine(wm, StealthConfig()))


def _add_service(wm, port, service, product="", version=""):
    wm.add_finding("service", f"tcp/{port}",
                   {"port": str(port), "protocol": "tcp", "service": service,
                    "product": product, "version": version},
                   confidence=0.9, source="scan_tcp")


class TestCompositeServiceToken(unittest.TestCase):
    def test_tls_token_keeps_wrapped_protocol(self):
        out = ("443/tcp open  ssl/http  nginx 1.25.3\n"
               "636/tcp open  ssl/ldap  Microsoft Windows AD LDAP")
        findings = parse_nmap_ports(out, "nmap")
        by_key = {f["key"]: f["value"] for f in findings}
        self.assertEqual(by_key["tcp/443"]["service"], "ssl/http")
        self.assertEqual(by_key["tcp/636"]["service"], "ssl/ldap")

    def test_plain_service_unaffected(self):
        out = "22/tcp open  ssh  OpenSSH 8.9p1"
        findings = parse_nmap_ports(out, "nmap")
        self.assertEqual(findings[0]["value"]["service"], "ssh")


class TestWebSurfaceGate(unittest.TestCase):
    def _has_web(self, wm):
        from phantom.automation.guidance.kit import _has_web_service
        return _has_web_service()(wm)

    def test_https_composite_is_web(self):
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        _add_service(wm, 9443, "ssl/http")
        self.assertTrue(self._has_web(wm))

    def test_ldaps_is_not_web(self):
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        _add_service(wm, 636, "ssl/ldap")
        self.assertFalse(self._has_web(wm))

    def test_bare_ssl_on_non_web_port_is_not_web(self):
        # a truncated label (defensive: older facts, other scanners) must
        # not mark a non-web port as a web surface
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        _add_service(wm, 993, "ssl")
        self.assertFalse(self._has_web(wm))

    def test_ssl_on_web_port_is_web(self):
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        _add_service(wm, 443, "ssl")
        self.assertTrue(self._has_web(wm))


class TestPlannerHonesty(unittest.TestCase):
    def test_ldap_only_host_is_not_planned_web_creds(self):
        wm = WorldModel(target="10.20.30.50", target_type="ip")
        for port, svc in ((88, "kerberos-sec"), (389, "ldap"),
                          (445, "microsoft-ds"), (636, "ssl/ldap")):
            _add_service(wm, port, svc)
        plan = _planner(wm).plan(wm, goal="complete_kill_chain")
        ids = [s.capability.id for s in plan.steps]
        self.assertNotIn("web_creds", ids)
        self.assertNotIn("web_rce", ids)

    def test_web_host_still_plans_web_creds(self):
        wm = WorldModel(target="10.0.0.9", target_type="ip")
        _add_service(wm, 8443, "ssl/http", product="nginx")
        plan = _planner(wm).plan(wm, goal="complete_kill_chain")
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("web_creds", ids)

    def test_ssh_gate_not_planned_when_no_ssh_service(self):
        wm = WorldModel(target="10.20.30.40", target_type="ip")
        for port, svc in ((135, "msrpc"), (445, "microsoft-ds"),
                          (3306, "mysql"), (3389, "ms-wbt-server")):
            _add_service(wm, port, svc)
        plan = _planner(wm).plan(wm, goal="complete_kill_chain")
        ids = [s.capability.id for s in plan.steps]
        self.assertNotIn("ssh_login", ids)
        self.assertNotIn("brute_ssh", ids)
        # ...and the run does not claim a path it cannot walk
        self.assertFalse(plan.complete and not plan.steps)

    def test_ssh_host_still_plans_ssh_login(self):
        wm = WorldModel(target="10.20.30.41", target_type="ip")
        _add_service(wm, 22, "ssh", product="OpenSSH", version="8.9p1")
        plan = _planner(wm).plan(wm, goal="complete_kill_chain")
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("ssh_login", ids)

    def test_cycle_is_refused(self):
        """A move that needs the beacon cannot be the source for the creds
        the beacon itself needs: no mutually-dependent 'complete' plan."""
        wm = WorldModel(target="10.20.30.40", target_type="ip")
        for port, svc in ((135, "msrpc"), (445, "microsoft-ds"),
                          (3306, "mysql"), (3389, "ms-wbt-server")):
            _add_service(wm, port, svc)
        plan = _planner(wm).plan(wm, goal="complete_kill_chain")
        ids = [s.capability.id for s in plan.steps]
        self.assertNotIn("loot_triage", ids)  # needs a beacon; would close a cycle


class TestBruteSshIsPlannable(unittest.TestCase):
    """A host whose ONLY access surface is ssh must have a creds path.

    `brute_ssh` was absent from the planner's creds reverse index, so on an
    ssh-only box (no web, no breach material) the chain simply had no source
    for `creds` and stopped — even under an explicit --aggressive run where
    the brute is exactly the intended move.
    """

    def test_brute_ssh_is_the_last_creds_source(self):
        from phantom.automation.planner import _FACT_SOURCES
        self.assertIn("brute_ssh", _FACT_SOURCES["creds"])
        # quiet/derived sources rank first; the loud brute is the floor
        self.assertEqual(_FACT_SOURCES["creds"][-1], "brute_ssh")

    def test_brute_ssh_viable_only_with_ssh_service(self):
        cap = make_registry().get("brute_ssh")
        ssh_wm = WorldModel(target="10.0.0.1", target_type="ip")
        _add_service(ssh_wm, 22, "ssh")
        no_ssh_wm = WorldModel(target="10.0.0.2", target_type="ip")
        _add_service(no_ssh_wm, 445, "microsoft-ds")
        self.assertTrue(Planner._precondition_viable(cap, ssh_wm))
        self.assertFalse(Planner._precondition_viable(cap, no_ssh_wm))


if __name__ == "__main__":
    unittest.main()
