"""Tests: dynamic CVE resolver (NVD keyword search + TTL disk cache)."""
import os
import tempfile
import unittest
from unittest.mock import patch

from phantom.automation.exploit.resolver import CveResolver

_SAMPLE = [
    {"cve": "CVE-2024-0001", "description": "Apache httpd 2.4.58 rce",
     "score": 9.8, "source": "nvd"},
    {"cve": "CVE-2024-0002", "description": "apache httpd module crash",
     "score": 7.5, "source": "nvd"},
    {"cve": "CVE-2024-0003", "description": "unrelated nginx issue",
     "score": 9.0, "source": "nvd"},
]


class TestCveResolver(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cache_path = os.path.join(self.dir, "cache.json")

    def tearDown(self):
        try:
            os.remove(self.cache_path)
        except OSError:
            pass

    def _resolver(self):
        return CveResolver(cache_path=self.cache_path)

    def test_lookup_returns_sorted_fetch_results(self):
        def fake_fetch(self, product, version):
            return _SAMPLE[:2]
        with patch.object(CveResolver, "_fetch", fake_fetch):
            hits = self._resolver().lookup("apache", "2.4.58")
        self.assertEqual([h["cve"] for h in hits],
                         ["CVE-2024-0001", "CVE-2024-0002"])
        self.assertEqual(hits[0]["score"], 9.8)
        self.assertEqual(hits[0]["source"], "nvd")

    def test_fetch_filters_by_product_and_sorts(self):
        import json
        payload = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2024-0003",
                         "descriptions": [{"lang": "en",
                                           "value": "nginx 1.20 issue"}],
                         "metrics": {"cvssMetricV31": [
                             {"cvssData": {"baseScore": 9.0}}]}}},
                {"cve": {"id": "CVE-2024-0001",
                         "descriptions": [{"lang": "en",
                                           "value": "Apache httpd 2.4.58 rce"}],
                         "metrics": {"cvssMetricV31": [
                             {"cvssData": {"baseScore": 9.8}}]}}},
            ]
        }

        class _Resp:
            def read(self):
                return json.dumps(payload).encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        with patch("urllib.request.urlopen", return_value=_Resp()):
            hits = CveResolver(cache_path=self.cache_path)._fetch(
                "apache", "2.4.58")
        self.assertEqual([h["cve"] for h in hits], ["CVE-2024-0001"])
        self.assertEqual(hits[0]["score"], 9.8)

    def test_lookup_requires_product_and_version(self):
        r = self._resolver()
        self.assertEqual(r.lookup("", "1.2"), [])
        self.assertEqual(r.lookup("apache", ""), [])

    def test_cache_serves_without_second_fetch(self):
        calls = []

        def fake_fetch(self, product, version):
            calls.append(version)
            return _SAMPLE
        with patch.object(CveResolver, "_fetch", fake_fetch):
            r = self._resolver()
            first = r.lookup("apache", "2.4.58")
            second = r.lookup("apache", "2.4.58")
        self.assertEqual(first, second)
        self.assertEqual(len(calls), 1)

    def test_empty_result_cached_short_ttl(self):
        def fake_fetch(self, product, version):
            return []
        with patch.object(CveResolver, "_fetch", fake_fetch):
            r = self._resolver()
            self.assertEqual(r.lookup("apache", "9.9.9"), [])
        self.assertTrue(os.path.exists(self.cache_path))

    def test_network_error_is_silent(self):
        def boom(product, version):
            raise OSError("network down")
        with patch.object(CveResolver, "_fetch", boom):
            self.assertEqual(self._resolver().lookup("apache", "2.4.58"), [])

    def test_persist_roundtrip(self):
        def fake_fetch(self, product, version):
            return _SAMPLE
        with patch.object(CveResolver, "_fetch", fake_fetch):
            r = self._resolver()
            r.lookup("apache", "2.4.58")
        with patch.object(CveResolver, "_fetch", fake_fetch):
            r2 = self._resolver()
            r2.lookup("apache", "2.4.58")  # from disk cache
        self.assertTrue(os.path.exists(self.cache_path))

    def test_clear(self):
        def fake_fetch(self, product, version):
            return _SAMPLE
        with patch.object(CveResolver, "_fetch", fake_fetch):
            r = self._resolver()
            r.lookup("apache", "2.4.58")
        r.clear()
        self.assertFalse(os.path.exists(self.cache_path))

    def test_lookup_enriches_with_threat_intel(self):
        class _Feed:
            def is_recently_exploited(self, cve):
                return {"exploited": cve == "CVE-2024-0002",
                        "confidence": 95.0 if cve == "CVE-2024-0002" else 0.0,
                        "source": "test"}

        def fake_fetch(self, product, version):
            return _SAMPLE[:2]
        with patch.object(CveResolver, "_fetch", fake_fetch):
            r = CveResolver(cache_path=self.cache_path, threat_intel=_Feed())
            hits = r.lookup("apache", "2.4.58")
        # exploited CVE-2024-0002 sorts first despite lower score
        self.assertEqual([h["cve"] for h in hits],
                         ["CVE-2024-0002", "CVE-2024-0001"])
        self.assertTrue(hits[0]["exploited"])
        self.assertEqual(hits[0]["exploit_source"], "test")
        self.assertFalse(hits[1]["exploited"])

    def test_lookup_no_feed_is_unenriched(self):
        def fake_fetch(self, product, version):
            return _SAMPLE[:2]
        with patch.object(CveResolver, "_fetch", fake_fetch):
            hits = self._resolver().lookup("apache", "2.4.58")
        self.assertNotIn("exploited", hits[0])


if __name__ == "__main__":
    unittest.main()