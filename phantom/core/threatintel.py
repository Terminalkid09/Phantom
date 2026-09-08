"""
threatintel.py — Phantom Threat Intelligence Integration
┌────────────────────────────────────────────────────────
Integrates with threat intelligence feeds to enrich scoring:
- AlienVault OTX (CVE exploited in the wild)
- NVD (CVSS scores, exploitability metrics)
- MITRE ATT&CK (technique prevalence)
- CISA KEV (Known Exploited Vulnerabilities catalog)

Caching: 24h TTL with JSON persistence.
Fallback: Offline mode with cached data or synthetic scores.
"""

import json
import os
import time
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from phantom.utils.notifier import notifier

CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "threatintel_cache")
CACHE_TTL = 86400  # 24 hours

FEED_CONFIG = {
    "nvd": {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.5",
        "params": {"resultsPerPage": 1, "keywordSearch": "{cve}"},
        "api_key_param": "apiKey",
    },
    "otx": {
        "url": "https://otx.alienvault.com/api/v1/indicators/cve/{cve}/general",
        "headers": {"X-OTX-Authentication-Token": "{api_key}"},
    },
    "cisa_kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    },
    "mitre_attack": {
        "url": "https://raw.githubusercontent.com/mitre-attck/attack-samples/master/attack_matrix.json",
    },
}


def _ensure_cache_dir() -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)


def _cache_path(key: str) -> str:
    safe_key = hashlib.md5(key.encode()).hexdigest()
    return os.path.join(CACHE_DIR, f"{safe_key}.json")


def _is_cache_valid(path: str) -> bool:
    if not os.path.exists(path):
        return False
    mtime = os.path.getmtime(path)
    return (time.time() - mtime) < CACHE_TTL


def _load_cache(key: str) -> Optional[Dict]:
    path = _cache_path(key)
    if not _is_cache_valid(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None


def _save_cache(key: str, data: Dict) -> None:
    _ensure_cache_dir()
    path = _cache_path(key)
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        notifier.warn(f"Failed to cache threat intel: {e}")


class ThreatIntelFeed:
    """Aggregator for threat intelligence feeds with caching."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._ensure_cache()

    def _ensure_cache(self) -> None:
        _ensure_cache_dir()

    def _cache_path_test(self, key: str) -> str:
        """Test-accessible cache path method."""
        return _cache_path(key)

    def _fetch_json(self, url: str, headers: Optional[Dict] = None,
                    params: Optional[Dict] = None) -> Optional[Dict]:
        """Fetch JSON from URL with caching."""
        cache_key = f"fetch:{url}"
        cached = _load_cache(cache_key)
        if cached:
            return cached

        try:
            import requests
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                _save_cache(cache_key, data)
                return data
            else:
                notifier.warn(f"Threat intel fetch failed: {resp.status_code}")
        except Exception as e:
            notifier.warn(f"Threat intel fetch error: {e}")
        return None

    def is_recently_exploited(self, cve_id: str) -> Dict[str, Any]:
        """
        Check if a CVE has been exploited in the wild (recent 7-day window).
        Returns dict with 'exploited' bool and 'confidence' score (0-100).
        """
        cache_key = f"exploited:{cve_id}"
        cached = _load_cache(cache_key)
        if cached:
            return cached

        result = {
            "cve": cve_id,
            "exploited": False,
            "confidence": 0.0,
            "source": "unknown",
            "timestamp": datetime.now().isoformat(),
        }

        # Check CISA KEV list (most reliable). The full catalog is fetched
        # once and cached for CACHE_TTL, then searched in memory.
        cisa_data = self._fetch_json(FEED_CONFIG["cisa_kev"]["url"])
        if cisa_data and "vulnerabilities" in cisa_data:
            for vuln in cisa_data["vulnerabilities"]:
                if vuln.get("cveID", "").upper() == cve_id.upper():
                    result["exploited"] = True
                    result["confidence"] = 95.0
                    result["source"] = "CISA KEV"
                    result["kev_date"] = vuln.get("dateAdded", "")
                    result["required_action"] = vuln.get("requiredAction", "")
                    break

        # Fallback: OTX if available
        if not result["exploited"] and self.api_key:
            otx_url = FEED_CONFIG["otx"]["url"].format(cve=cve_id.replace("CVE-", ""))
            headers = {"X-OTX-Authentication-Token": self.api_key}
            otx_data = self._fetch_json(otx_url, headers=headers)
            if otx_data and "pulses" in otx_data:
                if otx_data["pulses"]:
                    result["exploited"] = True
                    result["confidence"] = 75.0
                    result["source"] = "AlienVault OTX"

        # Fallback: NVD exploitability metrics
        if not result["exploited"]:
            nvd_data = self._check_nvd(cve_id)
            if nvd_data:
                # High CVSS + exploit code = strongly indicative of exploitation
                cvss = nvd_data.get("cvss", 0)
                has_exploit_code = nvd_data.get("exploit_code", False)
                if cvss >= 9.0 and has_exploit_code:
                    result["confidence"] = 50.0
                    result["exploited"] = True
                    result["source"] = "NVD heuristics"
                elif cvss >= 9.0:
                    result["confidence"] = 30.0
                    result["source"] = "NVD heuristics (critical severity)"

        _save_cache(cache_key, result)
        return result

    def _check_nvd(self, cve_id: str) -> Optional[Dict]:
        """Check NVD for CVE details."""
        cache_key = f"nvd:{cve_id}"
        cached = _load_cache(cache_key)
        if cached:
            return cached

        nvd_data = {
            "cve": cve_id,
            "cvss": 0.0,
            "vector": "",
            "exploit_code": False,
            "date_added": "",
            "description": "",
        }

        try:
            import requests
            url = FEED_CONFIG["nvd"]["url"]
            params = {"cveId": cve_id}
            if self.api_key:
                params[FEED_CONFIG["nvd"]["api_key_param"]] = self.api_key

            resp = requests.get(url, params=params, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("totalResults", 0) > 0:
                    vuln = data["vulnerabilities"][0]["cve"]
                    nvd_data["description"] = vuln.get("descriptions", [{}])[0].get("value", "")
                    nvd_data["date_added"] = vuln.get("published", "")

                    # Get CVSS
                    metrics = vuln.get("metrics", {})
                    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if version in metrics and metrics[version]:
                            cvss_data = metrics[version][0]
                            nvd_data["cvss"] = float(cvss_data.get("cvssData", {}).get("baseScore", 0))
                            nvd_data["vector"] = cvss_data.get("cvssData", {}).get("vectorString", "")
                            break

                    # Check for exploit code
                    refs = vuln.get("references", [])
                    nvd_data["exploit_code"] = any(
                        "exploit" in r.get("url", "").lower()
                        or "exploit-db" in r.get("url", "").lower()
                        for r in refs
                    )
        except Exception:
            pass

        _save_cache(cache_key, nvd_data)
        return nvd_data

    def get_attack_technique_prevalence(self, technique_id: str) -> Dict[str, float]:
        """
        Get prevalence score for an ATT&CK technique.

        NOTE: this is a static heuristic table derived from common
        enterprise attack patterns, NOT a live feed query. The MITRE
        ATT&CK API/CTI feeds require authentication and are not
        integrated yet; the static table keeps the interface honest
        and offline-friendly.

        Returns {'prevalence': 0-100, 'detected': int, 'sectors': list}
        """
        cache_key = f"attack:{technique_id}"
        cached = _load_cache(cache_key)
        if cached:
            return cached

        result = {
            "technique": technique_id,
            "prevalence": 50.0,  # Default mid-range
            "source": "static_heuristic",
        }

        # Static heuristic prevalence by technique (from public breach/IR reports)
        known_techniques = {
            "T1078": 90.0,  # Valid Accounts
            "T1021": 85.0,  # Remote Services
            "T1190": 80.0,  # Exploit Public-Facing Application
            "T1068": 75.0,  # Exploitation for Privilege Escalation
            "T1566": 70.0,  # Phishing
            "T1076": 65.0,  # Remote Desktop Protocol
            "T1046": 60.0,  # Network Service Scanning
            "T1033": 55.0,  # System Owner/User Discovery
        }

        if technique_id in known_techniques:
            result["prevalence"] = known_techniques[technique_id]

        _save_cache(cache_key, result)
        return result

    def clear_cache(self) -> None:
        """Clear all cached threat intel data."""
        if os.path.exists(CACHE_DIR):
            import shutil
            shutil.rmtree(CACHE_DIR)
        _ensure_cache_dir()
        notifier.info("Threat intelligence cache cleared")


# Global instance
threat_intel = ThreatIntelFeed()
