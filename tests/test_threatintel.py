"""Tests for the Threat Intelligence integration module (network mocked)."""
import unittest
from unittest.mock import patch, MagicMock
import json

from phantom.core.threatintel import ThreatIntelFeed, FEED_CONFIG


def _mock_response(data, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = data
    return resp


class TestThreatIntelFeedInit(unittest.TestCase):

    def test_feed_config_exists(self):
        self.assertIn("nvd", FEED_CONFIG)
        self.assertIn("otx", FEED_CONFIG)
        self.assertIn("cisa_kev", FEED_CONFIG)

    def test_default_instance(self):
        from phantom.core.threatintel import threat_intel
        self.assertIsInstance(threat_intel, ThreatIntelFeed)

    def test_cache_dir_creation(self):
        feed = ThreatIntelFeed()
        feed.clear_cache()
        feed._ensure_cache()
        import os
        self.assertTrue(os.path.isdir(feed._cache_path_test("x").rsplit(os.sep, 1)[0]))


class TestRecentlyExploitedCheck(unittest.TestCase):

    def setUp(self):
        ThreatIntelFeed().clear_cache()

    def _feed_without_kev(self):
        """Feed whose CISA KEV fetch returns no vulnerability list."""
        feed = ThreatIntelFeed()
        with patch("requests.get", return_value=_mock_response({"vulnerabilities": []})):
            return feed

    def test_cve_not_in_kev_returns_false(self):
        feed = ThreatIntelFeed()
        with patch("requests.get", return_value=_mock_response({"vulnerabilities": []})):
            result = feed.is_recently_exploited("CVE-1999-0001")
        self.assertIsInstance(result, dict)
        self.assertFalse(result["exploited"])
        self.assertIn("confidence", result)

    def test_cve_in_kev_is_flagged(self):
        feed = ThreatIntelFeed()
        kev_data = {"vulnerabilities": [
            {
                "cveID": "CVE-2021-34527",
                "dateAdded": "2021-07-07",
                "requiredAction": "Apply updates",
            }
        ]}
        with patch("requests.get", return_value=_mock_response(kev_data)):
            result = feed.is_recently_exploited("CVE-2021-34527")
        self.assertTrue(result["exploited"])
        self.assertEqual(result["source"], "CISA KEV")
        self.assertEqual(result["confidence"], 95.0)

    def test_otx_branch_does_not_crash(self):
        """Regression: the OTX URL used to be indexed with ['url']['url'] -> TypeError."""
        feed = ThreatIntelFeed(api_key="test-key")
        with patch("requests.get", return_value=_mock_response({"pulses": [{"id": 1}]})):
            result = feed.is_recently_exploited("CVE-2021-44228")
        self.assertIsInstance(result, dict)
        self.assertIn("exploited", result)

    def test_kev_catalog_cached_single_fetch(self):
        """The full KEV catalog must be fetched only once (single cache entry)."""
        feed = ThreatIntelFeed()
        kev_data = {"vulnerabilities": [
            {"cveID": "CVE-2021-34527", "dateAdded": "2021-07-07"}
        ]}
        with patch("requests.get", return_value=_mock_response(kev_data)) as m:
            feed.is_recently_exploited("CVE-2021-34527")
            feed.is_recently_exploited("CVE-2021-44228")
        cisa_calls = [c for c in m.call_args_list if "cisa" in c.args[0]]
        self.assertEqual(len(cisa_calls), 1)


class TestNVDLookup(unittest.TestCase):

    def setUp(self):
        ThreatIntelFeed().clear_cache()

    def test_nvd_parses_cvss(self):
        feed = ThreatIntelFeed()
        nvd_data = {"totalResults": 1, "vulnerabilities": [{
            "cve": {
                "descriptions": [{"value": "test cve"}],
                "published": "2021-01-01",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"}}]},
                "references": [{"url": "https://www.exploit-db.com/exploits/12345"}],
            }
        }]}
        with patch("requests.get", return_value=_mock_response(nvd_data)):
            result = feed._check_nvd("CVE-2021-44228")
        self.assertIsNotNone(result)
        self.assertEqual(result["cvss"], 9.8)
        self.assertTrue(result["exploit_code"])
        self.assertEqual(result["description"], "test cve")

    def test_nvd_missing_cve_returns_defaults(self):
        feed = ThreatIntelFeed()
        with patch("requests.get", return_value=_mock_response({"totalResults": 0})):
            result = feed._check_nvd("CVE-2999-99999")
        self.assertEqual(result["cvss"], 0.0)


class TestAttackPrevalence(unittest.TestCase):

    def test_known_technique_prevalence(self):
        feed = ThreatIntelFeed()
        result = feed.get_attack_technique_prevalence("T1078")
        self.assertIn("technique", result)
        self.assertGreater(result["prevalence"], 50.0)

    def test_unknown_technique_default(self):
        feed = ThreatIntelFeed()
        result = feed.get_attack_technique_prevalence("T9999")
        self.assertEqual(result["prevalence"], 50.0)

    def test_prevalence_source_is_honest(self):
        feed = ThreatIntelFeed()
        result = feed.get_attack_technique_prevalence("T1566")
        self.assertEqual(result.get("source"), "static_heuristic")
        self.assertNotIn("detected", result)  # no fake counts anymore


class TestCacheManagement(unittest.TestCase):

    def test_cache_path_generation(self):
        feed = ThreatIntelFeed()
        path = feed._cache_path_test("test_key")
        self.assertTrue(path.endswith(".json"))

    def test_clear_cache(self):
        feed = ThreatIntelFeed()
        feed.clear_cache()  # should not raise


if __name__ == "__main__":
    unittest.main()
