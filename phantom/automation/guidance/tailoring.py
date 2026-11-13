"""
tailoring.py — per-target adaptation of the kill chain.

The planner is generic; the tailoring engine is not. Given the classified
target (network vs identity), it reorders fact sources, bans capabilities
that are meaningless for the target class, and surfaces the best-matching
CVE module (from the B1 registry) for whatever software the world model has
already fingerprinted. B3 (preflight) consumes these hints.

    ip / domain / url   -> network chain: local brute before breach DB,
                           Bluetooth scanning banned (nothing local to scan)
    email / username / phone -> identity chain: breach/OSINT before brute
                           on an unknown machine
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.targets import classify_target, is_identity_target

# default ordering lives in planner._FACT_SOURCES; these OVERRIDE it
_NETWORK_PREFERENCES: Dict[str, List[str]] = {
    "service": ["scan_tcp", "version_detect"],
    # web_creds is the stealth-default creds source (active, not aggressive):
    # it extracts creds via SSRF/SQLi without the brute-force fingerprint of
    # ssh_login. ssh_login is aggressive-only (online brute) so it must come
    # AFTER web_creds in the preference, or the planner dead-locks in
    # default/stealth mode (ssh_login always stealth-gated out).
    "creds": ["web_creds", "ssh_login", "breach_check"],
    # web_rce (upload→RCE) is the no-creds beacon path: preferred over
    # beacon_deploy (which needs creds) when the app has an RCE primitive.
    "rce_foothold": ["web_rce"],
    "web_app": ["http_probe"],
}

_IDENTITY_PREFERENCES: Dict[str, List[str]] = {
    "creds": ["breach_check", "ssh_login"],
    "identity": ["osint_identity", "persona_create"],
}

# capabilities that make no sense against a remote host without a beacon
_NETWORK_BANNED = ("bt_scan",)


@dataclass
class TailoringEngine:
    """Adapts planning to the target class."""

    target: str
    target_type: str = ""
    preferred_sources: Dict[str, List[str]] = field(default_factory=dict)
    banned: Tuple[str, ...] = ()

    @classmethod
    def for_target(cls, target: str, target_type: str = "") -> "TailoringEngine":
        tt = target_type or classify_target(target)
        if is_identity_target(tt):
            return cls(target=target, target_type=tt,
                       preferred_sources=dict(_IDENTITY_PREFERENCES))
        return cls(target=target, target_type=tt,
                   preferred_sources=dict(_NETWORK_PREFERENCES),
                   banned=_NETWORK_BANNED)

    @property
    def chain_label(self) -> str:
        return "identity" if is_identity_target(self.target_type) else "network"

    def source_order(self, fact: str, defaults: List[str],
                     allow_banned: bool = False) -> List[str]:
        """Preferred capability ids for a fact, defaults appended after.

        The bt_scan ban is a PRE-foothold rule (nothing local to scan
        while the target is just a remote host): once a beacon is on the
        box the proximity tooling becomes legitimate (harvest goal), so
        the planner passes allow_banned=True.
        """
        ordered = list(self.preferred_sources.get(fact, []))
        for cap_id in defaults:
            if cap_id not in ordered:
                ordered.append(cap_id)
        if allow_banned:
            return ordered
        return [c for c in ordered if c not in self.banned]

    def suggest_exploit(self, wm: WorldModel) -> Optional[dict]:
        """Best CVE module for fingerprinted software, or None.

        Consumes service/web_app findings (B1 registry); the returned dict
        is the module metadata — preflight (B3) turns it into a resource
        script. Never raises: no fingerprints means no hint.
        """
        try:
            from phantom.automation.exploit.modules import module_registry
        except Exception:
            return None
        for finding in wm.all_findings():
            if finding.kind not in ("service", "web_app"):
                continue
            val = finding.value if isinstance(finding.value, dict) else {}
            software = val.get("software") or (finding.key.split("@")[0]
                                               if "@" in finding.key else "")
            version = val.get("version") or (finding.key.split("@")[1]
                                             if "@" in finding.key else "")
            if not software:
                continue
            try:
                module = module_registry.match(software, version or None)
            except Exception:
                module = None
            if module is not None:
                return module.to_dict()
        return None
