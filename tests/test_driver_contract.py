"""P1: a driver manifest is a CLAIM, and the binary contract is what checks it.

The defect: `_binary_matches` stopped a manifest from naming one tool and
running another, but nothing stopped SUBSTITUTION — the declared tool resolved,
and a different program answered to the name. The manifest could now PIN the
binary's sha256, and the broker verifies the pin before anything runs,
refusing with a NAMED event (`driver_contract_violation`) instead of a vague
"tool unavailable".
"""
import hashlib
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from phantom.automation.runtime import driver_contract as dc
from phantom.automation.runtime import drivers as dv
from phantom.automation.runtime.manifest import validate_manifest

DIGEST = hashlib.sha256(b"real-binary").hexdigest()


def _write_binary(directory, name, blob=b"real-binary"):
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        handle.write(blob)
    return path


def _broker(**kw):
    from phantom.automation.runtime.broker import ExecutionBroker
    return ExecutionBroker(**kw)


def _manifest(**over):
    data = {"id": "dnscan_subdomains", "tool": "dnscan", "category": "recon",
            "command": "dnscan -d {target} -o -", "effects": ["read"]}
    data.update(over)
    return data


class TestThePinIsParsedStrictly(unittest.TestCase):
    def test_an_absent_pin_is_not_a_failure(self):
        self.assertEqual(dv._norm_sha256(None), "")
        self.assertEqual(dv._norm_sha256(""), "")

    def test_a_pin_is_normalised_not_rejected(self):
        # case, separators and the `sha256-` prefix are formatting, not meaning
        self.assertEqual(dv._norm_sha256(DIGEST.upper()), DIGEST)
        self.assertEqual(dv._norm_sha256("sha256-" + DIGEST), DIGEST)
        self.assertEqual(dv._norm_sha256(DIGEST[:32] + ":" + DIGEST[32:]),
                         DIGEST)

    def test_a_malformed_pin_is_none_never_silently_dropped(self):
        # dropping it would turn a CHECKED driver into an unchecked one while
        # the manifest still claims to be pinned
        for bad in ("deadbeef", DIGEST[:-1], DIGEST + "00", "z" * 64):
            self.assertIsNone(dv._norm_sha256(bad), bad)

    def test_the_parser_refuses_a_manifest_with_a_broken_pin(self):
        self.assertIsNone(dv.parse_driver(_manifest(binary_sha256="nope")))

    def test_the_parser_carries_a_valid_pin_onto_the_driver(self):
        driver = dv.parse_driver(_manifest(binary_sha256=DIGEST.upper()))
        self.assertIsNotNone(driver)
        self.assertEqual(driver.binary_sha256, DIGEST)

    def test_the_driver_summary_reports_which_drivers_are_pinned(self):
        tmp = tempfile.mkdtemp(prefix="phantom-drivers-")
        with open(os.path.join(tmp, "pinned.json"), "w", encoding="utf-8") as fh:
            import json
            json.dump(_manifest(binary_sha256=DIGEST), fh)
        self.addCleanup(lambda: None)
        with patch.dict(os.environ, {"PHANTOM_DRIVERS_DIR": tmp}):
            rows = {row["id"]: row for row in dv.driver_summary()}
        self.assertTrue(rows["dnscan_subdomains"]["pinned"])

    def test_the_validator_explains_a_broken_pin(self):
        result = validate_manifest(_manifest(binary_sha256="deadbeef"))
        self.assertFalse(result.ok)
        self.assertIn("binary_sha256", result.explain())


class TestVerificationIsThreeValued(unittest.TestCase):
    def test_an_unpinned_driver_is_unchecked_not_verified(self):
        check = dc.verify_binary(Mock(id="x", tool="dnscan",
                                      binary_sha256=""))
        self.assertTrue(check.ok)
        self.assertFalse(check.pinned)
        self.assertFalse(check.verified)     # "verified" is reserved
        self.assertEqual(check.reason, "unpinned")

    def test_a_pin_that_matches_verifies(self):
        tmp = tempfile.mkdtemp(prefix="phantom-bin-")
        _write_binary(tmp, "dnscan")
        driver = Mock(id="x", tool="dnscan", binary_sha256=DIGEST)
        with patch.object(dc, "binary_path", lambda tool: os.path.join(tmp, tool)):
            check = dc.verify_binary(driver)
        self.assertTrue(check.ok)
        self.assertTrue(check.verified)
        self.assertEqual(check.actual, DIGEST)

    def test_a_different_binary_is_a_violation(self):
        tmp = tempfile.mkdtemp(prefix="phantom-bin-")
        _write_binary(tmp, "dnscan", b"ATTACKER-SHIM")
        driver = Mock(id="x", tool="dnscan", binary_sha256=DIGEST)
        with patch.object(dc, "binary_path", lambda tool: os.path.join(tmp, tool)):
            check = dc.verify_binary(driver)
        self.assertFalse(check.ok)
        self.assertTrue(check.pinned)
        self.assertIn("mismatch", check.reason)
        # the reason names both digests, so an operator sees WHAT changed
        self.assertIn(DIGEST[:12], check.reason)

    def test_a_pinned_binary_that_is_missing_is_a_violation(self):
        driver = Mock(id="x", tool="dnscan", binary_sha256=DIGEST)
        with patch.object(dc, "binary_path", lambda tool: ""):
            check = dc.verify_binary(driver)
        self.assertFalse(check.ok)
        self.assertIn("not found", check.reason)

    def test_an_unreadable_binary_is_a_violation_not_a_crash(self):
        tmp = tempfile.mkdtemp(prefix="phantom-bin-")
        driver = Mock(id="x", tool="dnscan", binary_sha256=DIGEST)
        with patch.object(dc, "binary_path", lambda tool: tmp):  # a DIRECTORY
            check = dc.verify_binary(driver)
        self.assertFalse(check.ok)
        self.assertIn("cannot read", check.reason)

    def test_hashing_streams_the_file(self):
        tmp = tempfile.mkdtemp(prefix="phantom-bin-")
        path = _write_binary(tmp, "big", b"x" * (3 * dc._CHUNK + 7))
        self.assertEqual(dc.sha256_file(path),
                         hashlib.sha256(b"x" * (3 * dc._CHUNK + 7)).hexdigest())


class TestTheViolationIsANamedEvent(unittest.TestCase):
    def setUp(self):
        from phantom.utils import failure_taxonomy as ft
        ft.reset()
        self.ft = ft

    def tearDown(self):
        self.ft.reset()

    def test_the_taxonomy_has_its_own_category(self):
        self.assertIn("contract_violation", self.ft.CATEGORIES)

    def test_it_reaches_both_sinks(self):
        check = dc.ContractCheck(False, True, "sha256 mismatch", path="/x/y",
                                 actual="a" * 64)
        driver = Mock(id="dnscan_subdomains", tool="dnscan", binary_sha256="b" * 64)
        with patch("phantom.automation.decision_audit.record") as audit:
            token = dc.record_violation(driver, check)
        self.assertEqual(token, dc.CONTRACT_VIOLATION)
        # the NAMED event is the audit trail; the taxonomy also logs its own
        # "failure" entry, so search the calls rather than assume one
        named = [c for c in audit.call_args_list
                 if c.args and c.args[0] == dc.CONTRACT_VIOLATION]
        self.assertEqual(len(named), 1)
        self.assertEqual(named[0].kwargs["capability"], "dnscan_subdomains")
        self.assertEqual(named[0].kwargs["actual_sha256"], "a" * 64)
        entries = self.ft.recent()
        self.assertEqual(entries[-1]["category"], "contract_violation")
        self.assertEqual(entries[-1]["contract"], dc.CONTRACT_VIOLATION)


class _Recorder:
    def __init__(self):
        self.events = []

    def record(self, kind, **fields):
        self.events.append((kind, fields))
        return fields


class TestTheDeclaredTimeoutIsACap(unittest.TestCase):
    """The manifest's timeout used to be a DEFAULT the caller could override,
    which made it decorative. It is now the ceiling."""

    def test_a_caller_can_only_tighten_it(self):
        driver = dv.parse_driver(_manifest(timeout=30))
        broker = _broker()
        self.assertEqual(broker._timeout_for(driver, None), 30)
        self.assertEqual(broker._timeout_for(driver, 10), 10)
        self.assertEqual(broker._timeout_for(driver, 600), 30)

    def test_a_manifest_beyond_the_schema_maximum_is_clamped(self):
        from phantom.automation.runtime.manifest import MAX_TIMEOUT
        # parse_driver alone is lenient about ranges, so the broker clamps
        driver = dv.parse_driver(_manifest(timeout=99999))
        self.assertEqual(_broker()._timeout_for(driver, None), MAX_TIMEOUT)

    def test_a_junk_timeout_degrades_to_the_declared_one(self):
        driver = dv.parse_driver(_manifest(timeout=30))
        self.assertEqual(_broker()._timeout_for(driver, "soon"), 30)

    def test_the_granted_value_reaches_the_runner(self):
        seen = {}

        def runner(cmd, seconds):
            seen["seconds"] = seconds
            return True, "ok"

        driver = dv.parse_driver(_manifest(timeout=30))
        _broker().run(driver, target="10.0.0.5", runner=runner, timeout=900)
        self.assertEqual(seen["seconds"], 30)


class TestTheBrokerEnforcesTheContract(unittest.TestCase):
    def _broker(self, audit=None):
        return _broker(audit=audit)

    def setUp(self):
        from phantom.utils import failure_taxonomy as ft
        ft.reset()
        self.ft = ft

    def tearDown(self):
        self.ft.reset()

    def test_a_mismatched_binary_is_REFUSED(self):
        tmp = tempfile.mkdtemp(prefix="phantom-bin-")
        _write_binary(tmp, "dnscan", b"ATTACKER-SHIM")
        driver = dv.parse_driver(_manifest(binary_sha256=DIGEST))
        audit = _Recorder()
        with patch("phantom.automation.decision_audit.record") as da, \
                patch.object(dc, "binary_path",
                             lambda tool: os.path.join(tmp, tool)):
            decision = self._broker(audit).preflight(driver, target="10.0.0.5",
                                                     slots={"target": "10.0.0.5"})
        self.assertFalse(decision.allowed)
        self.assertIn(dc.CONTRACT_VIOLATION, decision.explain())
        # the named integrity event AND the broker's own refusal are recorded
        named = [c for c in da.call_args_list
                 if c.args and c.args[0] == dc.CONTRACT_VIOLATION]
        self.assertEqual(len(named), 1)
        kinds = [kind for kind, _ in audit.events]
        self.assertIn("capability_refused", kinds)
        self.assertEqual(self.ft.recent()[-1]["category"], "contract_violation")

    def test_an_unpinned_driver_runs_as_before(self):
        driver = dv.parse_driver(_manifest())
        decision = self._broker().preflight(driver, target="10.0.0.5",
                                            slots={"target": "10.0.0.5"})
        self.assertTrue(decision.allowed, decision.explain())
        self.assertIn("dnscan", decision.command)
        self.assertEqual(self.ft.recent(), [])

    def test_a_matching_pin_runs(self):
        tmp = tempfile.mkdtemp(prefix="phantom-bin-")
        _write_binary(tmp, "dnscan")
        driver = dv.parse_driver(_manifest(binary_sha256=DIGEST))
        with patch.object(dc, "binary_path", lambda tool: os.path.join(tmp, tool)):
            decision = self._broker().preflight(driver, target="10.0.0.5",
                                                slots={"target": "10.0.0.5"})
        self.assertTrue(decision.allowed, decision.explain())

    def test_a_broken_verifier_records_but_does_not_brick_every_driver(self):
        driver = dv.parse_driver(_manifest(binary_sha256=DIGEST))
        with patch.object(dc, "verify_binary",
                          side_effect=RuntimeError("verifier dead")):
            decision = self._broker().preflight(driver, target="10.0.0.5",
                                                slots={"target": "10.0.0.5"})
        self.assertTrue(decision.allowed, decision.explain())
        self.assertEqual(self.ft.recent()[-1]["where"],
                         "broker._binary_contract_ok")


if __name__ == "__main__":
    unittest.main()
