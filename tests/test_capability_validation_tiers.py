"""P2: trust and validation are different questions.

`state` answers "may this capability run?". `validation` answers "how well was
it proven?". They were the same field, which made the two impossible to state
independently: a placeholder that reached `validated` looked better proven than
a lab-proven capability that was only `enabled`, and an operator had no way to
ask "is this thing tested, or just written?".

The ladder defaults to the weakest honest claim (`implemented`) and refuses
`lab_validated` without something to cite, because the failure mode here is a
registry that quietly advertises fiction.
"""
import unittest

from phantom.automation.runtime.capability_registry import (
    SCOPE_FLAGS, VALIDATION_ORDER, VALIDATION_TIERS, CapabilityRecord,
    is_lab_validated, is_validated, validation_rank,
)


class TestTheLadder(unittest.TestCase):
    def test_it_is_ordered_by_strength_of_evidence(self):
        self.assertEqual(validation_rank("implemented"),
                         validation_rank("unit_tested") - 1)
        self.assertLess(validation_rank("integration_tested"),
                        validation_rank("lab_validated"))

    def test_scope_flags_never_outrank_anything(self):
        # platform_limited / placeholder / unsupported describe SCOPE. A
        # platform-limited capability is not "less tested" because it is
        # narrower, so these must not carry a rank.
        for flag in SCOPE_FLAGS:
            self.assertEqual(validation_rank(flag), -1, flag)

    def test_an_unknown_tier_is_below_everything(self):
        self.assertEqual(validation_rank("vibes"), -1)

    def test_the_helpers_agree_with_the_rank(self):
        self.assertFalse(is_validated("implemented"))
        self.assertTrue(is_validated("unit_tested"))
        self.assertFalse(is_lab_validated("integration_tested"))
        self.assertTrue(is_lab_validated("lab_validated"))
        # A scope flag is not a validation claim in either direction.
        self.assertFalse(is_validated("placeholder"))


class TestDefaultsAreHonest(unittest.TestCase):
    def test_a_fresh_record_claims_only_that_it_exists(self):
        rec = CapabilityRecord(capability="screenshot")
        self.assertEqual(rec.validation, "implemented")
        self.assertFalse(rec.tested)
        self.assertFalse(rec.proven)

    def test_a_fresh_record_has_no_declaration_problems(self):
        self.assertEqual(CapabilityRecord(capability="x").declaration_errors(),
                         [])


class TestSelfCertificationIsRefused(unittest.TestCase):
    def test_a_lab_claim_without_evidence_is_a_problem(self):
        rec = CapabilityRecord(capability="y", validation="lab_validated")
        problems = rec.declaration_errors()
        self.assertTrue(problems)
        self.assertIn("lab_validated", problems[0])

    def test_a_lab_claim_with_evidence_is_proven(self):
        rec = CapabilityRecord(capability="z", validation="lab_validated",
                               validation_evidence="VM, 2026-10-07")
        self.assertTrue(rec.proven)
        self.assertEqual(rec.declaration_errors(), [])

    def test_whitespace_is_not_evidence(self):
        rec = CapabilityRecord(capability="z", validation="lab_validated",
                               validation_evidence="   \n ")
        self.assertFalse(rec.proven)
        self.assertTrue(rec.declaration_errors())

    def test_an_unknown_tier_is_flagged(self):
        rec = CapabilityRecord(capability="x", validation="fully_baked")
        self.assertTrue(rec.declaration_errors())

    def test_a_scope_flag_must_say_what_is_missing(self):
        for flag in SCOPE_FLAGS:
            rec = CapabilityRecord(capability="x", validation=flag)
            self.assertTrue(rec.declaration_errors(), flag)
            ok = CapabilityRecord(capability="x", validation=flag,
                                  scope_note="macOS 15 only, no HID")
            self.assertEqual(ok.declaration_errors(), [], flag)


class TestTheTwoAxesAreIndependent(unittest.TestCase):
    def test_a_proven_capability_can_still_be_unapproved(self):
        # Evidence does not grant permission: these answer different questions
        # and a change to one must never imply the other.
        rec = CapabilityRecord(capability="hid_flash", state="discovered",
                               validation="lab_validated",
                               validation_evidence="Arduino Micro, 2 sessions")
        self.assertTrue(rec.proven)
        self.assertFalse(rec.approved)
        self.assertFalse(rec.enabled)

    def test_an_approved_capability_can_be_completely_unproven(self):
        rec = CapabilityRecord(capability="gadget", state="enabled",
                               validation="implemented")
        self.assertTrue(rec.enabled)
        self.assertFalse(rec.tested)

    def test_the_dump_exposes_both_axes(self):
        data = CapabilityRecord(capability="x").to_dict()
        for key in ("state", "validation", "tested", "proven",
                    "declaration_errors"):
            self.assertIn(key, data)


class TestRegistryRecording(unittest.TestCase):
    def _registry(self, tmpdir):
        from phantom.automation.runtime.capability_registry import (
            CapabilityRecord, CapabilityRegistry)
        reg = CapabilityRegistry(path=f"{tmpdir}/registry.json", clock=lambda: 1.0)
        reg.discover(CapabilityRecord(
            capability="gadget", tool="g", version="1", path="/bin/g",
            sha256="a" * 64, source="operator-local", platforms=("linux",)))
        return reg

    def test_recording_a_tier_persists(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp)
            self.assertTrue(reg.set_validation("gadget", "unit_tested",
                                                evidence="tests/test_x.py"))
            reg.save()
            again = type(reg)(path=f"{tmp}/registry.json")
            self.assertEqual(again.of("gadget").validation, "unit_tested")

    def test_an_unknown_tier_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp)
            self.assertFalse(reg.set_validation("gadget", "vibes"))
            self.assertEqual(reg.of("gadget").validation, "implemented")

    def test_a_bare_lab_claim_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp)
            self.assertFalse(reg.set_validation("gadget", "lab_validated"))
            self.assertEqual(reg.of("gadget").validation, "implemented")

    def test_a_scope_flag_without_a_note_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp)
            self.assertFalse(reg.set_validation("gadget", "platform_limited"))
            self.assertTrue(reg.set_validation(
                "gadget", "platform_limited", scope_note="no Android build"))

    def test_setting_a_tier_on_an_unknown_capability_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp)
            self.assertFalse(reg.set_validation("ghost", "unit_tested"))


if __name__ == "__main__":
    unittest.main()