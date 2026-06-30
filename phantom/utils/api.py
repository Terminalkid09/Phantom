"""
api.py – Wrappers for free external APIs:
- NVD (CVE search by software/version)
- crt.sh (subdomain enumeration via SSL certificates)
- Shodan (free tier, host info)
- Local searchsploit (ExploitDB)
"""

import requests
import subprocess
import json
import time
import copy
import os
import hashlib
import threading
from typing import List, Dict, Any, Callable, Optional
from rich.console import Console

from phantom.utils.paths import cve_cache_path, cve_cache_dir

console = Console()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CRTSH_URL = "https://crt.sh/"
SHODAN_INTERNETDB = "https://internetdb.shodan.io/"

CVE_CACHE_TTL = 86400  # 24 hours
_nvd_lock = threading.Lock()
_last_nvd_request = 0.0
_github_rate_limited_until = 0.0
_cache: Dict[str, Any] = {}
_cache_loaded = False


def with_backoff(func: Callable, max_retries: int = 5, initial_delay: int = 2):
    """Wrapper for exponential backoff on API calls (429 handling)."""
    def wrapper(*args, **kwargs):
        delay = initial_delay
        for i in range(max_retries):
            try:
                resp = func(*args, **kwargs)
                if resp.status_code == 200:
                    return resp
                if resp.status_code == 429:
                    console.print(f"[yellow][!] Rate limit hit (429). Backing off for {delay}s...[/]")
                    time.sleep(delay)
                    delay = min(delay * 3, 60)
                    continue
                resp.raise_for_status()
                return resp
            except Exception as e:
                if i == max_retries - 1:
                    raise e
                time.sleep(delay)
                delay = min(delay * 2, 60)
        return None
    return wrapper


def retry_api(retries: int = 3, backoff: int = 2, return_on_fail=None):
    """Decorator factory for retrying API calls on exception."""
    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            last_exception = None
            delay = backoff
            for i in range(retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if i < retries - 1:
                        console.print(f"[yellow][!] API error: {e}. Retrying in {delay}s... (Attempt {i+1}/{retries})[/]")
                        time.sleep(delay)
                        delay = min(delay * 2, 60)
            if return_on_fail is not None:
                try:
                    if callable(return_on_fail):
                        return return_on_fail()
                    return copy.deepcopy(return_on_fail)
                except Exception:
                    return return_on_fail
            raise last_exception
        return wrapper
    return decorator


def _load_cache() -> None:
    global _cache_loaded, _cache
    if _cache_loaded:
        return
    _cache_loaded = True
    path = cve_cache_path()
    if not os.path.exists(path):
        _cache = {}
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            _cache = json.load(f)
    except (json.JSONDecodeError, OSError):
        _cache = {}


def _save_cache() -> None:
    os.makedirs(cve_cache_dir(), exist_ok=True)
    path = cve_cache_path()
    temp = path + ".tmp"
    try:
        with open(temp, "w", encoding="utf-8") as f:
            json.dump(_cache, f)
        os.replace(temp, path)
    except OSError:
        if os.path.exists(temp):
            os.remove(temp)


def _cache_key(software: str, version: str) -> str:
    return hashlib.sha256(f"{software}|{version}".lower().encode()).hexdigest()


def _wait_nvd_rate_limit() -> None:
    """Enforce NVD public rate: 1 request per 6s without API key."""
    global _last_nvd_request
    if os.getenv("NVD_API_KEY"):
        return
    with _nvd_lock:
        elapsed = time.time() - _last_nvd_request
        if elapsed < 6.0:
            time.sleep(6.0 - elapsed)
        _last_nvd_request = time.time()


def _nvd_request(params: dict) -> requests.Response:
    _wait_nvd_rate_limit()
    headers = {}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key

    def _call():
        return requests.get(NVD_URL, params=params, headers=headers, timeout=15)

    return with_backoff(_call)()


def _parse_nvd_response(data: dict) -> List[Dict[str, Any]]:
    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss = 0.0
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        desc = cve.get("descriptions", [{}])[0].get("value", "")[:200]
        desc_lower = desc.lower()
        requires_auth = any(k in desc_lower for k in ("authentication required", "requires auth", "privileged"))
        local_only = any(k in desc_lower for k in ("local ", "locally ", "adjacent"))

        results.append({
            "id": cve.get("id"),
            "cvss": cvss,
            "description": desc,
            "has_exploit": False,
            "requires_auth": requires_auth,
            "local_only": local_only,
            "recent": False,
            "exact_match": True,
        })
    return results


@retry_api(retries=2, backoff=6, return_on_fail=[])
def nvd_lookup(software: str, version: str = "", max_results: int = 20) -> List[Dict[str, Any]]:
    """
    Query NVD for CVEs matching software name and optional version.
    Results are cached for 24 hours.
    """
    query = f"{software} {version}".strip()
    if not query:
        return []

    _load_cache()
    key = _cache_key(software, version)
    entry = _cache.get(key)
    now = time.time()
    if entry and (now - entry.get("ts", 0)) < CVE_CACHE_TTL:
        return entry.get("data", [])[:max_results]

    params = {"keywordSearch": query, "resultsPerPage": max_results}
    resp = _nvd_request(params)
    if resp is None:
        return entry.get("data", [])[:max_results] if entry else []

    data = resp.json()
    results = _parse_nvd_response(data)

    _cache[key] = {"ts": now, "data": results}
    _save_cache()
    return results


def crtsh_lookup(domain: str) -> List[str]:
    """Query crt.sh for subdomains matching the given domain."""
    try:
        params = {"q": f"%.{domain}", "output": "json"}
        resp = requests.get(CRTSH_URL, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub and domain in sub:
                    subdomains.add(sub)
        return sorted(subdomains)
    except Exception as e:
        console.print(f"[yellow]crt.sh error: {e}[/]")
        return []


def shodan_lookup(ip: str, api_key: str = "") -> Dict[str, Any]:
    """Get host info from Shodan's free InternetDB."""
    try:
        if api_key:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        else:
            url = f"{SHODAN_INTERNETDB}/{ip}"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        console.print(f"[yellow]Shodan lookup error for {ip}: {e}[/]")
        return {}


def exploitdb_lookup(cve_id: str) -> bool:
    """Check if there is a public exploit for the given CVE using local searchsploit."""
    try:
        result = subprocess.run(
            ["searchsploit", "--cve", cve_id, "--json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            exploits = data.get("RESULTS_EXPLOIT", [])
            return len(exploits) > 0
    except Exception as e:
        console.print(f"[yellow]ExploitDB search error: {e}[/]")
    return False


def github_poc_lookup(cve_id: str) -> bool:
    """Check GitHub for public PoC repos related to a CVE."""
    global _github_rate_limited_until
    if time.time() < _github_rate_limited_until:
        return False

    url = "https://api.github.com/search/repositories"
    params = {"q": f"{cve_id} in:name,description,readme", "per_page": 1}
    try:
        resp = requests.get(url, params=params, timeout=10)
        if resp.status_code == 403:
            _github_rate_limited_until = time.time() + 3600
            console.print("[yellow][!] GitHub API rate limited — skipping PoC checks for 1h.[/]")
            return False
        if resp.status_code == 429:
            _github_rate_limited_until = time.time() + 600
            return False
        resp.raise_for_status()
        return resp.json().get("total_count", 0) > 0
    except Exception as e:
        console.print(f"[yellow]GitHub API error for {cve_id}: {e}[/]")
        return False


def bgp_lookup(ip_or_asn: str) -> dict:
    """Query bgpview.io for ASN, prefixes, and peers information."""
    query = ip_or_asn.strip()
    if query.upper().startswith("AS"):
        query = query[2:]

    if query.isdigit():
        url = f"https://api.bgpview.io/asn/{query}"
    else:
        url = f"https://api.bgpview.io/ip/{query}"

    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "ok":
            return {}
        return data.get("data", {})
    except Exception as e:
        console.print(f"[yellow]BGP lookup error for {ip_or_asn}: {e}[/]")
        return {}
