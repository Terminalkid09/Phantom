"""knowledge.py — shared WorldModel for the MANUAL shell.

The manual modules write typed Findings into the same WorldModel the
autonomous agent uses. Every tool output becomes a belief that:

  * other modules reuse (services -> exploit, creds -> payload/pivot),
  * the reasoning engine builds senior hypotheses on (live `suggest`),
  * the report builders consume (same Raw/Client reports as auto-mode).

Kept OUTSIDE the Session dataclass so session save/load (which serializes
`__dict__`) never has to deal with a WorldModel; this is per-engagement
runtime state, reset when the target changes.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from phantom.automation.belief import WorldModel

_wm: Optional[WorldModel] = None


def session_wm() -> WorldModel:
    """The shared WorldModel of the manual engagement (lazily created)."""
    global _wm
    if _wm is None:
        _wm = WorldModel(target="", target_type="ip")
    return _wm


def reset_wm(target: str = "", target_type: str = "ip") -> WorldModel:
    """Start a fresh WorldModel for a new engagement/target."""
    global _wm
    _wm = WorldModel(target=target, target_type=target_type)
    return _wm


def set_wm(wm: WorldModel) -> WorldModel:
    """Replace the shared WorldModel (used when restoring a saved session)."""
    global _wm
    _wm = wm
    return _wm


# ── typed writers (convenience — modules may also call add_finding directly)

def add_service(port: str, service: str, product: str = "", version: str = "",
                protocol: str = "tcp", confidence: float = 0.7,
                source: str = "scan") -> Any:
    return session_wm().add_finding(
        "service", f"{protocol}/{port}",
        {"port": str(port), "protocol": protocol, "service": service,
         "product": product, "version": version},
        confidence=confidence, source=source)


def add_creds(username: str, password: str, service: str, valid: bool = True,
              confidence: float = 0.8, source: str = "brute") -> Any:
    return session_wm().add_finding(
        "creds", f"{service}:{username}",
        {"username": username, "password": password, "service": service,
         "valid": valid},
        confidence=confidence, source=source)


def add_os(os_name: str, confidence: float = 0.5, source: str = "scan") -> Any:
    return session_wm().add_finding(
        "os", "detected", {"os": os_name, "name": os_name},
        confidence=confidence, source=source)


def add_web_app(name: str, url: str = "", confidence: float = 0.6,
                source: str = "web") -> Any:
    return session_wm().add_finding(
        "web_app", name.lower(),
        {"name": name, "url": url},
        confidence=confidence, source=source)


def add_vuln(cve_id: str, detail: str, score: int = 0,
             confidence: float = 0.7, source: str = "exploit") -> Any:
    return session_wm().add_finding(
        "vuln", cve_id,
        {"cve": cve_id, "detail": detail, "score": score},
        confidence=confidence, source=source)


def knowledge_summary() -> Dict[str, int]:
    """Counts per finding kind — for `show knowledge`."""
    wm = session_wm()
    counts: Dict[str, int] = {}
    for f in wm.all_findings():
        counts[f.kind] = counts.get(f.kind, 0) + 1
    return counts
