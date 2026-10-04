"""The passive phone / geolocation intel capability (`phone_osint`).

It exists so a phone number the engagement already holds (the target, or a
number a breach/identity finding surfaced) becomes structured, planner-visible
facts — E.164, validity, line type, carrier, region, timezone — using only the
OFFLINE ``phonenumbers`` metadata database. These tests pin: number sourcing,
the marker round-trip, the two facts it produces, and its wiring into the
planner/phase/goal tables.
"""
import unittest

from phantom.automation import phone_intel as pi
from phantom.automation.belief import WorldModel


class TestNumberSourcing(unittest.TestCase):
    def test_target_phone_is_used(self):
        wm = WorldModel(target="+393331234567", target_type="phone")
        nums = pi._candidate_numbers(wm, {})
        self.assertEqual(nums, ["+393331234567"])

    def test_identity_finding_number_is_used(self):
        wm = WorldModel(target="user@example.com", target_type="email")
        wm.add_finding("identity", "identity:user", {"phone": "+14155550132"},
                       confidence=0.7, source="osint")
        nums = pi._candidate_numbers(wm, {})
        self.assertEqual(nums, ["+14155550132"])

    def test_explicit_slot_wins(self):
        wm = WorldModel(target="+393331234567", target_type="phone")
        nums = pi._candidate_numbers(wm, {"phone": "+14155550132"})
        self.assertEqual(nums[0], "+14155550132")

    def test_no_number_available(self):
        wm = WorldModel(target="example.com", target_type="domain")
        self.assertEqual(pi._candidate_numbers(wm, {}), [])


class TestEngine(unittest.TestCase):
    def test_emits_e164_marker(self):
        wm = WorldModel(target="+393331234567", target_type="phone")
        out = pi.phone_intel_engine(wm, {})
        self.assertIn("PHONE:", out)
        self.assertIn("e164=+393331234567", out)
        self.assertIn("valid=true", out)

    def test_unparseable_number_is_a_comment(self):
        wm = WorldModel(target="not-a-number", target_type="phone")
        out = pi.phone_intel_engine(wm, {})
        # either a comment or a marker with valid=false — but NEVER a crash
        self.assertTrue(out)
        self.assertIsInstance(out, str)

    def test_no_number_is_a_comment(self):
        wm = WorldModel(target="example.com", target_type="domain")
        out = pi.phone_intel_engine(wm, {})
        self.assertTrue(out.startswith("#"))


class TestInterp(unittest.TestCase):
    def _wm(self):
        return WorldModel(target="+393331234567", target_type="phone")

    def test_phone_and_geolocation_findings(self):
        out = ("PHONE: e164=+393331234567 valid=true type=mobile region=IT "
               "carrier=TIM geo=- tz=Europe/Rome")
        fs = pi.phone_intel_interp(out, self._wm(), {})
        by_kind = {f.kind: f for f in fs}
        self.assertEqual(by_kind["phone"].value["e164"], "+393331234567")
        self.assertEqual(by_kind["phone"].value["type"], "mobile")
        self.assertIn("geolocation", by_kind)
        self.assertEqual(by_kind["geolocation"].value["region"], "IT")

    def test_geolocation_confidence_is_below_a_real_location(self):
        out = ("PHONE: e164=+393331234567 valid=true type=mobile region=IT "
               "carrier=TIM geo=Italy tz=Europe/Rome")
        fs = pi.phone_intel_interp(out, self._wm(), {})
        geo = [f for f in fs if f.kind == "geolocation"][0]
        self.assertLess(geo.confidence, 0.5)

    def test_no_region_no_geolocation(self):
        out = "PHONE: e164=+393331234567 valid=false type=unknown region=- carrier=- geo=- tz=Etc/Unknown"
        fs = pi.phone_intel_interp(out, self._wm(), {})
        self.assertEqual([f.kind for f in fs], ["phone"])

    def test_comment_lines_ignored(self):
        fs = pi.phone_intel_interp("# phone intel: no phone number",
                                   self._wm(), {})
        self.assertEqual(fs, [])


class TestCapabilityWiring(unittest.TestCase):
    def _cap(self):
        from phantom.automation.guidance.kit import CAPABILITIES
        return {c.id: c for c in CAPABILITIES}["phone_osint"]

    def test_registered_as_in_process_osint(self):
        cap = self._cap()
        self.assertEqual(cap.category, "osint")
        self.assertEqual(cap.exec_class, "in_process_engine")
        self.assertIsNotNone(cap.engine)
        self.assertIn("phone", cap.effects)
        self.assertIn("geolocation", cap.effects)
        self.assertEqual(cap.stealth_level, "passive")

    def test_declared_in_the_phase_index(self):
        from phantom.automation.phases import phase_of
        self.assertEqual(phase_of("phone_osint"), "osint")

    def test_planner_reverse_index(self):
        from phantom.automation.planner import _FACT_SOURCES
        self.assertEqual(_FACT_SOURCES["phone"], ["phone_osint"])
        self.assertEqual(_FACT_SOURCES["geolocation"], ["phone_osint"])

    def test_goals_include_the_new_facts(self):
        from phantom.automation.goals import GOAL_FACTS
        self.assertIn("geolocation", GOAL_FACTS["identity"])
        self.assertIn("phone", GOAL_FACTS["enrich"])
        self.assertIn("geolocation", GOAL_FACTS["enrich"])


if __name__ == "__main__":
    unittest.main()
