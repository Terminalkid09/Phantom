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
from typing import List, Dict, Any
from rich.console import Console

console = Console()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CRTSH_URL = "https://crt.sh/"
SHODAN_INTERNETDB = "https://internetdb.shodan.io/"

# NVD free 
def nvd_lookup(software: str, version: str = "") -> List[Dict[str, Any]]:
    """
    Query NVD for CVEs matching software name and optional version.
    Returns list of dicts with keys: id, cvss, description, has_exploit (False initially).
    """
    query = f"{software} {version}".strip()
    if not query:
        return []
    params = {
        "keywordSearch": query,
        "resultsPerPage": 20,
    }
    try:
        resp = requests.get(NVD_URL, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        results = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss = 0.0
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            results.append({
                "id": cve.get("id"),
                "cvss": cvss,
                "description": cve.get("descriptions", [{}])[0].get("value", "")[:200],
                "has_exploit": False,   # placeholder, will be updated by exploitdb_lookup
                "requires_auth": False,
                "local_only": False,
                "recent": False,
                "exact_match": True,
            })
        return results
    except Exception as e:
        console.print(f"[yellow]NVD API error: {e}[/]")
        return []

# crt.sh subdomains from certificate logs
def crtsh_lookup(domain: str) -> List[str]:
    """
    Query crt.sh for subdomains matching the given domain.
    Returns a sorted list of unique subdomains.
    """
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

# Shodan free tier
def shodan_lookup(ip: str, api_key: str = "") -> Dict[str, Any]:
    """
    Get host info from Shodan's free InternetDB.
    If api_key is provided, use the authenticated endpoint (more data).
    """
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

# ExploitDB (local searchsploit)
def exploitdb_lookup(cve_id: str) -> bool:
    """
    Check if there is a public exploit for the given CVE using local searchsploit.
    Returns True if at least one exploit is found.
    """
    try:
        # searchsploit --cve <CVE> --json
        result = subprocess.run(
            ["searchsploit", "--cve", cve_id, "--json"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            # The JSON contains a "RESULTS_EXPLOIT" list
            exploits = data.get("RESULTS_EXPLOIT", [])
            return len(exploits) > 0
    except Exception as e:
        console.print(f"[yellow]ExploitDB search error: {e}[/]")
    return False

# GitHub check for public poC repo related to a CVE
def github_poc_lookup(cve_id: str) -> bool:
    # github's search API
    url = f"https://api.github.com/search/repositories"
    params = {
        "q": f"{cve_id} in:name,description,readme",
        "per_page": 1 # only need to know if any exists
    }
    try:
        resp =  requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        total = data.get("total_count", 0)
        return total > 0
    except Exception as e:
        console.print(f"[yellow]GitHub API error for {cve_id}: {e}[/]")
        return False

# BGP lookup via bgpview.io (free, no API key)
def bgp_lookup(ip_or_asn: str) -> dict:
    """
    Query bgpview.io for ASN, prefixes, and peers information.
    Accepts an IP address or an ASN number (with or without 'AS' prefix).
    Returns a dictionary with relevant BGP data.
    """
    # Normalize ASN (remove 'AS' prefix if present)
    query = ip_or_asn.strip()
    if query.upper().startswith("AS"):
        query = query[2:]
    
    # Determine if it's an ASN or IP
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