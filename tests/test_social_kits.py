"""Tests for the lure kit registry (phantom/automation/social/kits.py).

`tracker.skin` was a free-form string: `env_tracker()` lowercased it and the
renderer branched with `if/elif/else`, so an unknown value silently rendered
the YouTube chrome. The operator believed they had selected a kit they had
not, and nothing said otherwise.
"""
import unittest

from phantom.automation.social import kits


class TestTheRegistry(unittest.TestCase):
    def test_the_default_is_a_real_kit(self):
        self.assertIn(kits.DEFAULT_KIT, kits.kit_ids())

    def test_every_id_round_trips(self):
        for kit_id in kits.kit_ids():
            self.assertEqual(kits.kit_by_id(kit_id).id, kit_id)

    def test_the_lookup_is_case_and_space_insensitive(self):
        self.assertEqual(kits.kit_by_id("  TiKToK ").id, "tiktok")

    def test_lookup_of_an_unknown_id_is_none(self):
        self.assertIsNone(kits.kit_by_id("youube"))
        self.assertIsNone(kits.kit_by_id(""))

    def test_rows_match_the_registry(self):
        rows = kits.kit_rows()
        self.assertEqual(len(rows), len(kits.KITS))
        self.assertEqual([r[0] for r in rows], list(kits.kit_ids()))

    def test_every_kit_describes_what_it_captures(self):
        for kit in kits.KITS:
            self.assertTrue(kit.label)
            self.assertTrue(kit.channel)
            self.assertTrue(kit.captures)


class TestResolveKit(unittest.TestCase):
    def test_an_empty_value_is_the_default_and_is_not_an_error(self):
        effective, known = kits.resolve_kit("")
        self.assertEqual(effective, kits.DEFAULT_KIT)
        self.assertTrue(known)

    def test_a_real_id_resolves_to_itself(self):
        for kit_id in kits.kit_ids():
            effective, known = kits.resolve_kit(kit_id)
            self.assertEqual(effective, kit_id)
            self.assertTrue(known)

    def test_a_typo_resolves_to_the_default_AND_reports_it(self):
        """The distinction the module exists for: the fallback still happens,
        but the caller can say which kit actually rendered."""
        effective, known = kits.resolve_kit("youube")
        self.assertEqual(effective, kits.DEFAULT_KIT)
        self.assertFalse(known)

    def test_whitespace_and_case_are_normalised(self):
        effective, known = kits.resolve_kit("  Instagram ")
        self.assertEqual(effective, "instagram")
        self.assertTrue(known)


if __name__ == "__main__":
    unittest.main()
