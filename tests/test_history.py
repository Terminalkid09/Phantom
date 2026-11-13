"""Tests for the Historical Learning System."""
import unittest
import tempfile
import os
from datetime import datetime, timedelta

from phantom.core.history import HistoricalAnalyzer, SIMILAR_TECHNIQUES


class TestHistoricalAnalyzerInit(unittest.TestCase):

    def test_instance_creation(self):
        analyzer = HistoricalAnalyzer()
        self.assertIsNotNone(analyzer)

    def test_default_file_path(self):
        analyzer = HistoricalAnalyzer()
        self.assertIsNotNone(analyzer.history_file)

    def test_similar_techniques_defined(self):
        self.assertIn("kerberoasting", SIMILAR_TECHNIQUES)
        self.assertIn("phishing_spear", SIMILAR_TECHNIQUES)


class TestRecordAttempt(unittest.TestCase):

    def test_record_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hist_file = os.path.join(tmpdir, "history.json")
            analyzer = HistoricalAnalyzer(history_file=hist_file)
            analyzer.record_attempt("test_technique", "ip:target", True)
            self.assertEqual(len(analyzer.records), 1)
            self.assertTrue(analyzer.records[0]["success"])

    def test_record_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hist_file = os.path.join(tmpdir, "history.json")
            analyzer = HistoricalAnalyzer(history_file=hist_file)
            analyzer.record_attempt("test_technique", "ip:target", False)
            self.assertEqual(len(analyzer.records), 1)
            self.assertFalse(analyzer.records[0]["success"])

    def test_record_with_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hist_file = os.path.join(tmpdir, "history.json")
            analyzer = HistoricalAnalyzer(history_file=hist_file)
            analyzer.record_attempt("test_technique", "ip:target", True,
                                   {"phase": "scan", "notes": "Found 5 ports"})
            self.assertEqual(analyzer.records[0]["metadata"]["phase"], "scan")


class TestShouldAvoid(unittest.TestCase):

    def test_no_history_returns_false(self):
        analyzer = HistoricalAnalyzer()
        self.assertFalse(analyzer.should_avoid("unknown_technique", "test_profile"))

    def test_few_failures_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hist_file = os.path.join(tmpdir, "history.json")
            analyzer = HistoricalAnalyzer(history_file=hist_file)
            for _ in range(2):
                analyzer.record_attempt("test_tech", "profile", False)
            self.assertFalse(analyzer.should_avoid("test_tech", "profile", failure_threshold=3))

    def test_many_failures_returns_true(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hist_file = os.path.join(tmpdir, "history.json")
            analyzer = HistoricalAnalyzer(history_file=hist_file)
            for _ in range(5):
                analyzer.record_attempt("test_tech", "profile", False)
            self.assertTrue(analyzer.should_avoid("test_tech", "profile", failure_threshold=3))


class TestSuggestAlternative(unittest.TestCase):

    def test_no_history_returns_none(self):
        analyzer = HistoricalAnalyzer()
        self.assertIsNone(analyzer.suggest_alternative("failed_tech", "profile"))

    def test_returns_successful_alternative(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hist_file = os.path.join(tmpdir, "history.json")
            analyzer = HistoricalAnalyzer(history_file=hist_file)

            # Record failures for a technique
            analyzer.record_attempt("kerberoasting", "ad_profile", False)
            # Record successes for a similar technique
            analyzer.record_attempt("asrm_rogue", "ad_profile", True)
            analyzer.record_attempt("asrm_rogue", "ad_profile", True)

            suggestion = analyzer.suggest_alternative("kerberoasting", "ad_profile")
            self.assertIsNotNone(suggestion)
            self.assertEqual(suggestion, "asrm_rogue")


class TestGetStatistics(unittest.TestCase):

    def test_empty_history(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hist_file = os.path.join(tmpdir, "history.json")
            analyzer = HistoricalAnalyzer(history_file=hist_file)
            stats = analyzer.get_statistics()
            self.assertEqual(stats["total"], 0)
            self.assertEqual(stats["success_rate"], 0.0)

    def test_with_records(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hist_file = os.path.join(tmpdir, "history.json")
            analyzer = HistoricalAnalyzer(history_file=hist_file)
            analyzer.record_attempt("tech1", "profile", True)
            analyzer.record_attempt("tech2", "profile", False)
            analyzer.record_attempt("tech3", "other", True)

            all_stats = analyzer.get_statistics()
            self.assertEqual(all_stats["total"], 3)
            self.assertEqual(all_stats["successes"], 2)
            self.assertEqual(all_stats["failures"], 1)

            profile_stats = analyzer.get_statistics("profile")
            self.assertEqual(profile_stats["total"], 2)

    def test_target_profile_specific(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hist_file = os.path.join(tmpdir, "history.json")
            analyzer = HistoricalAnalyzer(history_file=hist_file)
            analyzer.record_attempt("tech1", "profile_a", True)
            analyzer.record_attempt("tech2", "profile_b", True)

            stats_a = analyzer.get_statistics("profile_a")
            self.assertEqual(stats_a["total"], 1)


class TestGetTechniqueStats(unittest.TestCase):

    def test_empty_stats(self):
        analyzer = HistoricalAnalyzer()
        stats = analyzer.get_technique_stats("unknown")
        self.assertEqual(stats["total_attempts"], 0)

    def test_with_attempts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hist_file = os.path.join(tmpdir, "history.json")
            analyzer = HistoricalAnalyzer(history_file=hist_file)
            analyzer.record_attempt("kerb", "profile", True)
            analyzer.record_attempt("kerb", "profile", False)

            stats = analyzer.get_technique_stats("kerb")
            self.assertEqual(stats["total_attempts"], 2)
            self.assertEqual(stats["successes"], 1)


class TestSuggestAlternativePhase(unittest.TestCase):

    def test_no_history_returns_none(self):
        analyzer = HistoricalAnalyzer()
        self.assertIsNone(analyzer.suggest_alternative_phase("cve_correlate", "profile"))

    def test_returns_successful_alternative(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hist_file = os.path.join(tmpdir, "history.json")
            analyzer = HistoricalAnalyzer(history_file=hist_file)

            # Failed phase
            analyzer.record_attempt("cve_correlate", "profile", False, {"phase": "cve_correlate"})
            # Successful alternative
            analyzer.record_attempt("test_creds", "profile", True, {"phase": "test_creds"})
            analyzer.record_attempt("test_creds", "profile", True, {"phase": "test_creds"})

            suggestion = analyzer.suggest_alternative_phase("cve_correlate", "profile")
            self.assertIsNotNone(suggestion)


if __name__ == "__main__":
    unittest.main()
