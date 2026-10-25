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
import re
import time
import copy
import os
import hashlib
import threading
from typing import List, Dict, Any, Callable, Optional
from rich.console import Console

from phantom.utils.paths import cve_cache_path, cve_cache_dir
from phantom.utils import provider_contract

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
    if _nvd_api_key():
        return
    with _nvd_lock:
        elapsed = time.time() - _last_nvd_request
        if elapsed < 6.0:
            time.sleep(6.0 - elapsed)
        _last_nvd_request = time.time()


def _nvd_api_key() -> str:
    """NVD key from the legacy env var first, then the config plane."""
    env = os.getenv("NVD_API_KEY", "").strip()
    if env:
        return env
    try:
        from phantom.utils import api_keys
        return api_keys.get("nvd")
    except Exception:
        return ""


def _nvd_request(params: dict) -> requests.Response:
    _wait_nvd_rate_limit()
    headers = {}
    api_key = _nvd_api_key()
    if api_key:
        headers["apiKey"] = api_key

    def _call():
        return provider_contract.http_get("nvd", NVD_URL, params=params,
                                          headers=headers, timeout=15)

    return with_backoff(_call)()


# Vendor/product hints for NVD's CPE index. Keyword search is noisy: asking
# for "Apache httpd 2.4.49" can return zero rows, while a product-level CPE
# match returns the affected CVEs and lets us do the version test ourselves.
_CPE_HINTS: Dict[str, tuple] = {
    "apache": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "apache tomcat": ("apache", "tomcat"),
    "tomcat": ("apache", "tomcat"),
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "php": ("php", "php"),
    "nginx": ("nginx", "nginx"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "iis": ("microsoft", "internet_information_services"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "gitlab": ("gitlab", "gitlab"),
    "confluence": ("atlassian", "confluence"),
    "struts2": ("apache", "struts"),
    "log4j": ("apache", "log4j"),
    "spring": ("vmware", "spring_framework"),
    "vcenter": ("vmware", "vcenter_server"),
    "fortios": ("fortinet", "fortios"),
    "cisco asa": ("cisco", "adaptive_security_appliance_software"),
    "citrix": ("citrix", "application_delivery_controller"),
    "exchange": ("microsoft", "exchange_server"),
    "sharepoint": ("microsoft", "sharepoint_server"),
}


def _version_tuple(text: str) -> tuple:
    parts = []
    for chunk in str(text or "").replace("-", ".").split("."):
        match = re.match(r"\d+", chunk)
        if not match:
            break
        parts.append(int(match.group(0)))
    return tuple(parts)


def _cpe_version_matches(criteria: str, version: str) -> Optional[bool]:
    """Whether one CPE match includes ``version``.

    Returns ``None`` when the CPE has no concrete version and no range (the
    caller can then keep the advisory but must not call it exact).
    """
    if not version:
        return None
    parts = str(criteria or "").split(":")
    cpe_version = parts[5] if len(parts) > 5 else "*"
    wanted = _version_tuple(version)
    if not wanted:
        return None
    if cpe_version not in ("*", "-", ""):
        got = _version_tuple(cpe_version)
        # A CPE version is usually exact; accept a prefix relationship for
        # callers that pass "2.4" instead of the full banner version.
        if got and (got == wanted or wanted[:len(got)] == got
                    or got[:len(wanted)] == wanted):
            return True
        return False
    return None


def _cpe_match_includes(match: dict, version: str) -> Optional[bool]:
    criteria = str(match.get("criteria") or "")
    exact = _cpe_version_matches(criteria, version)
    if exact is not None:
        return exact
    wanted = _version_tuple(version)
    if not wanted:
        return None
    starts = [
        ("versionStartIncluding", True), ("versionStartExcluding", False),
    ]
    ends = [
        ("versionEndIncluding", True), ("versionEndExcluding", False),
    ]
    checked = False
    for field, inclusive in starts:
        if match.get(field):
            checked = True
            bound = _version_tuple(str(match[field]))
            if bound and (wanted < bound or (wanted == bound and not inclusive)):
                return False
    for field, inclusive in ends:
        if match.get(field):
            checked = True
            bound = _version_tuple(str(match[field]))
            if bound and (wanted > bound or (wanted == bound and not inclusive)):
                return False
    return True if checked else None


def _nvd_version_evidence(cve: dict, version: str) -> tuple[bool, bool]:
    """Return (has_version_evidence, version_matches) for one NVD CVE."""
    if not version:
        return False, False
    seen = False
    matched = False
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if not match.get("vulnerable", True):
                    continue
                seen = True
                result = _cpe_match_includes(match, version)
                if result:
                    matched = True
    return seen, matched


def _parse_nvd_response(data: dict, version: str = "") -> List[Dict[str, Any]]:
    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss = 0.0
        if "cvssMetricV40" in metrics:
            cvss = metrics["cvssMetricV40"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        desc = cve.get("descriptions", [{}])[0].get("value", "")[:200]
        desc_lower = desc.lower()
        requires_auth = any(k in desc_lower for k in ("authentication required", "requires auth", "privileged"))
        local_only = any(k in desc_lower for k in ("local ", "locally ", "adjacent"))
        has_evidence, version_match = _nvd_version_evidence(cve, version)

        results.append({
            "id": cve.get("id"),
            "cvss": cvss,
            "description": desc,
            "has_exploit": False,
            "requires_auth": requires_auth,
            "local_only": local_only,
            "recent": False,
            "exact_match": bool(version_match),
            "version_match": bool(version_match),
            "has_version_evidence": bool(has_evidence),
        })
    return results


def _nvd_cpe_hint(software: str) -> Optional[str]:
    key = str(software or "").strip().lower()
    hint = _CPE_HINTS.get(key)
    if hint is None:
        # "Apache httpd 2.4" or "PHP 8.4.26" -> longest known prefix.
        for name, pair in sorted(_CPE_HINTS.items(), key=lambda x: -len(x[0])):
            if key.startswith(name):
                hint = pair
                break
    if hint is None:
        return None
    return f"cpe:2.3:a:{hint[0]}:{hint[1]}"


def _filter_version_matches(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop non-matching versions only when NVD gave us version evidence."""
    evidence = [r for r in results if r.get("has_version_evidence")]
    if not evidence:
        return results
    return [r for r in results if r.get("version_match")]


@retry_api(retries=2, backoff=6, return_on_fail=[])
def nvd_lookup(software: str, version: str = "", max_results: int = 20) -> List[Dict[str, Any]]:
    """Query NVD for CVEs matching a product and optional version.

    Preferred path: a product-level CPE query, which is precise and avoids
    the "Apache httpd 2.4.49" keyword dead end.  Fallback: the legacy
    keyword search (still useful for products without a CPE hint).  Results
    are cached for 24 hours and carry an honest ``exact_match`` flag.
    """
    query = f"{software} {version}".strip()
    if not query:
        return []

    _load_cache()
    cache_salt = "cpe" if _nvd_cpe_hint(software) else "kw"
    key = _cache_key(f"{cache_salt}:{software}", version)
    entry = _cache.get(key)
    now = time.time()
    if entry and (now - entry.get("ts", 0)) < CVE_CACHE_TTL:
        return entry.get("data", [])[:max_results]

    results: List[Dict[str, Any]] = []
    cpe_answered = False
    cpe = _nvd_cpe_hint(software)
    if cpe:
        params = {"virtualMatchString": cpe, "resultsPerPage": max_results}
        resp = _nvd_request(params)
        if resp is not None:
            data = resp.json()
            parsed = _parse_nvd_response(data, version)
            if parsed:
                cpe_answered = True
                results = _filter_version_matches(parsed)

    if not results and not cpe_answered:
        params = {"keywordSearch": query, "resultsPerPage": max_results}
        resp = _nvd_request(params)
        if resp is not None:
            results = _parse_nvd_response(resp.json(), version)
            # A keyword hit without CPE evidence is a lead, not an exact
            # version match. The flag is already false in that case.

    _cache[key] = {"ts": now, "data": results}
    _save_cache()
    return results[:max_results]


def crtsh_lookup(domain: str) -> List[str]:
    """Query crt.sh for subdomains matching the given domain."""
    try:
        params = {"q": f"%.{domain}", "output": "json"}
        resp = provider_contract.http_get("crtsh", CRTSH_URL, params=params,
                                          timeout=15)
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
    """Get host info from Shodan's free InternetDB (or the full API when a
    key is available). The key falls back to the config plane, so a key set
    via `config keys` / the Electron panel is honoured without passing it
    at every call site."""
    if not api_key:
        try:
            from phantom.utils import api_keys
            api_key = api_keys.get("shodan")
        except Exception:
            api_key = ""
    try:
        if api_key:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            provider = "shodan"
        else:
            # SHODAN_INTERNETDB already ends in "/": appending another one
            # produced "https://internetdb.shodan.io//1.2.3.4", which the
            # service answers with 404 — a silent "no data" for every host.
            url = f"{SHODAN_INTERNETDB}{ip}"
            provider = "shodan_internetdb"
        resp = provider_contract.http_get(provider, url, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        console.print(f"[yellow]Shodan lookup error for {ip}: {e}[/]")
        return {}


def exploitdb_lookup(cve_id: str) -> bool:
    """Check for a public exploit through native searchsploit or Kali WSL."""
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
        return False
    except FileNotFoundError:
        try:
            from phantom.utils import exploitdb
            return bool(exploitdb.by_cve(cve_id))
        except Exception:
            return False
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
    headers = {}
    try:
        from phantom.utils import api_keys
        token = api_keys.get("github")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    except Exception:
        pass
    try:
        resp = provider_contract.http_get("github", url, params=params,
                                          headers=headers, timeout=10)
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
        resp = provider_contract.http_get("bgpview", url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "ok":
            return {}
        return data.get("data", {})
    except Exception as e:
        console.print(f"[yellow]BGP lookup error for {ip_or_asn}: {e}[/]")
        return {}
