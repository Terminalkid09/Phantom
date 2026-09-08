"""
strategy.py — declarative red-team strategy library and target profiling.

The planner's backward chain answers "how do I reach fact X". The
strategic layer answers "what SHOULD I be doing against THIS target":
it derives a TargetModel from the WorldModel findings, profiles the
engagement (identity vs network host, AD domain present, beacon foothold,
...) and picks the best applicable Strategy from a declarative library.

Strategies are STAGES of the kill chain, each tied to a planner goal:
  * identity targets      -> OSINT -> breach -> beacon (phish-converged)
  * network hosts         -> footprint -> creds -> beacon
  * once on the box       -> harvest / supply-chain / impact / lateral
  * domain environments   -> AD attack, hash cracking
  * end of engagement     -> cleanup

Planner.plan_strategic executes the library: it orders the applicable
strategies by weight, advances through them as each stage's goal facts
are satisfied, and falls back to the generic plan when no strategy fits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from phantom.automation.belief import WorldModel

_IDENTITY_TYPES = ("email", "username", "phone")
_NETWORK_TYPES = ("ip", "domain", "url")


@dataclass
class TargetModel:
    """What the world tells us about the engagement target."""
    target_type: str = "auto"
    is_identity: bool = False
    is_network: bool = False
    has_beacon: bool = False
    has_creds: bool = False
    has_ad: bool = False
    has_os: bool = False
    open_services: List[str] = field(default_factory=list)
    software: Dict[str, str] = field(default_factory=dict)

    @property
    def profile(self) -> str:
        """Short human profile: identity / network / compromised / ad."""
        if self.is_identity:
            return "identity"
        if self.has_ad:
            return "ad-domain"
        if self.has_beacon:
            return "compromised"
        return "network"


class ProfileDetector:
    """Builds the TargetModel from the WorldModel's findings."""

    @staticmethod
    def detect(wm: WorldModel) -> TargetModel:
        model = TargetModel(target_type=wm.target_type)
        model.is_identity = wm.target_type in _IDENTITY_TYPES
        model.is_network = wm.target_type in _NETWORK_TYPES
        model.has_beacon = bool(wm.find("beacon"))
        model.has_creds = bool(wm.find("creds", valid=True))
        model.has_ad = bool(wm.find("ad_domain"))
        model.has_os = bool(wm.find("os"))
        model.open_services = sorted(
            {str(f.key) for f in wm.find("service")})
        for f in wm.find("service") + wm.find("web_app"):
            software = (f.value.get("software") or f.value.get("name")
                        or f.value.get("product"))
            version = f.value.get("version")
            if software:
                model.software[str(software)] = str(version or "")
        return model


@dataclass(frozen=True)
class Strategy:
    """A declarative red-team stage: goal + when it applies + priority."""
    id: str
    name: str
    goal: str                 # planner goal of this stage
    requires: Callable[[TargetModel], bool]
    weight: int = 50          # higher = preferred earlier
    description: str = ""


def _identity(model: TargetModel) -> bool:
    return model.is_identity


def _network(model: TargetModel) -> bool:
    return model.is_network


def _beacon(model: TargetModel) -> bool:
    return model.has_beacon


def _ad(model: TargetModel) -> bool:
    return model.has_ad and model.has_beacon


def _lateral(model: TargetModel) -> bool:
    return model.has_beacon and model.has_creds


def _exploitable(model: TargetModel) -> bool:
    """Network host with at least one fingerprinted software version."""
    return model.is_network and bool(model.software)


STRATEGIES: List[Strategy] = [
    Strategy("identity_osint", "Identity OSINT discovery",
             "identity", _identity, weight=90,
             description="osint_identity / persona_create -> identity facts"),
    Strategy("identity_breach", "Identity breach-lookup",
             "creds", _identity, weight=85,
             description="breach_check first for identity targets"),
    Strategy("identity_beacon", "Identity-to-beacon convergence",
             "beacon", _identity, weight=80,
             description="phish -> victim_ip -> network chain -> beacon"),
    Strategy("ad_attack", "Active Directory attack surface",
             "ad", _ad, weight=78,
             description="ad_enum / kerberoast / as_rep / dc_sync"),
    Strategy("network_footprint", "Network footprinting",
             "footprint", _network, weight=75,
             description="scan_tcp / version_detect / os_detect"),
    Strategy("exploit_chain", "Version-matched exploitation",
             "exploit", _exploitable, weight=72,
             description="service_exploit: CVE module matched to the "
                         "fingerprinted software@version"),
    Strategy("network_creds", "Credential acquisition",
             "creds", _network, weight=70,
             description="ssh_login against found services"),
    Strategy("network_beacon", "Beacon injection",
             "beacon", _network, weight=65,
             description="beacon_deploy with verified credentials"),
    Strategy("crack_hashes", "Offline hash cracking",
             "crack", _ad, weight=60,
             description="hash_crack on kerberoast / as_rep / dc_sync hashes"),
    Strategy("harvest_intel", "Post-exploitation intelligence harvest",
             "harvest", _beacon, weight=58,
             description="cookie_stealer / bt_scan / cdp_pivot / socks_proxy"),
    Strategy("supply_chain", "Trojan supply-chain delivery",
             "trojan", _beacon, weight=52,
             description="trojan_deliver: bundle + drop on the target"),
    Strategy("impact_sim", "Impact simulation (non-destructive ransomware)",
             "impact", _beacon, weight=50,
             description="ransom_sim reversible encryption"),
    Strategy("lateral_expand", "Lateral movement to peers",
             "lateral", _lateral, weight=55,
             description="lateral_pivot / smb_pivot / winrm_pivot"),
    Strategy("cleanup_ops", "Operational cleanup",
             "cleanup", _beacon, weight=30,
             description="remove persistence and kill the beacon"),
]


def applicable_strategies(model: TargetModel) -> List[Strategy]:
    """The strategies that fit the current target profile, best first."""
    return sorted((s for s in STRATEGIES if s.requires(model)),
                  key=lambda s: (-s.weight, s.id))
