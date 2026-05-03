import json
from unittest.mock import MagicMock

import pytest

from phantom.utils import api


class DummyResponse:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = data or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception("HTTP error")

    def json(self):
        return self._data


class TestApi:
    def test_nvd_lookup_returns_empty_on_network_error(self, monkeypatch):
        """nvd_lookup should return an empty list when requests.get raises."""
        monkeypatch.setattr(api.requests, "get", lambda *args, **kwargs: (_ for _ in ()).throw(Exception("network")))
        assert api.nvd_lookup("apache", "2.4") == []

    def test_nvd_lookup_parses_response_correctly(self, monkeypatch):
        """nvd_lookup should parse vulnerabilities from the NVD JSON response."""
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]
                        },
                        "descriptions": [{"value": "Example vulnerability."}],
                    }
                }
            ]
        }
        monkeypatch.setattr(api.requests, "get", lambda *args, **kwargs: DummyResponse(data=payload))
        results = api.nvd_lookup("apache", "2.4")
        assert results[0]["id"] == "CVE-2024-0001"
        assert results[0]["cvss"] == 7.5
        assert results[0]["description"] == "Example vulnerability."

    def test_crtsh_lookup_returns_sorted_unique_subdomains(self, monkeypatch):
        """crtsh_lookup should return unique, sorted subdomains from duplicate crt.sh entries."""
        payload = [
            {"name_value": "*.example.com\napi.example.com"},
            {"name_value": "www.example.com"},
        ]
        monkeypatch.setattr(api.requests, "get", lambda *args, **kwargs: DummyResponse(data=payload))
        result = api.crtsh_lookup("example.com")
        assert result == ["api.example.com", "example.com", "www.example.com"]

    def test_crtsh_lookup_returns_empty_on_error(self, monkeypatch):
        """crtsh_lookup should return an empty list when the network call fails."""
        monkeypatch.setattr(api.requests, "get", lambda *args, **kwargs: (_ for _ in ()).throw(Exception("timeout")))
        assert api.crtsh_lookup("example.com") == []

    def test_exploitdb_lookup_returns_true_when_results_present(self, monkeypatch):
        """exploitdb_lookup should return True when searchsploit JSON output contains exploits."""
        result = MagicMock()
        result.returncode = 0
        result.stdout = json.dumps({"RESULTS_EXPLOIT": [{"Title": "Proof of concept"}]})
        monkeypatch.setattr(api.subprocess, "run", lambda *args, **kwargs: result)
        assert api.exploitdb_lookup("CVE-2024-0001") is True

    def test_exploitdb_lookup_returns_false_on_subprocess_error(self, monkeypatch):
        """exploitdb_lookup should return False if searchsploit fails."""
        def raise_error(*args, **kwargs):
            raise api.subprocess.TimeoutExpired(cmd=args[0], timeout=10)
        monkeypatch.setattr(api.subprocess, "run", raise_error)
        assert api.exploitdb_lookup("CVE-2024-0001") is False

    def test_github_poc_lookup_returns_true_when_total_count_positive(self, monkeypatch):
        """github_poc_lookup should return True when GitHub search reports matching repos."""
        payload = {"total_count": 5}
        monkeypatch.setattr(api.requests, "get", lambda *args, **kwargs: DummyResponse(data=payload))
        assert api.github_poc_lookup("CVE-2024-0001") is True

    def test_shodan_lookup_returns_dict_on_success(self, monkeypatch):
        """shodan_lookup should return the JSON result when the lookup succeeds."""
        payload = {"ip_str": "1.2.3.4", "ports": [22, 80]}
        monkeypatch.setattr(api.requests, "get", lambda *args, **kwargs: DummyResponse(data=payload))
        assert api.shodan_lookup("1.2.3.4") == payload

    def test_shodan_lookup_returns_empty_dict_on_error(self, monkeypatch):
        """shodan_lookup should return an empty dict when the network call raises."""
        monkeypatch.setattr(api.requests, "get", lambda *args, **kwargs: (_ for _ in ()).throw(Exception("network")))
        assert api.shodan_lookup("1.2.3.4") == {}
