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

# tokens that mark a MOBILE surface on a host. Deliberately specific:
# "mobile"/"mdm"/vendor names/enrolment paths — NOT generic web services.
_MOBILE_HINT_TOKENS = (
    "mdm", "mobileiron", "airwatch", "intune", "jamf", "kandji",
    "simplemdm", "apns", "gcm", "fcm", "enroll", "byod", "mobile",
    "device-management", "scim",
)


def _detect_mobile_hint(wm: WorldModel) -> bool:
    """Concrete evidence that the host fronts a mobile/MDM surface.

    Looks at service names/versions and web-surface facts. A plain
    `tcp/443 http` is NOT a hint, so the MDM probe is only planned when the
    scan actually saw mobile management software.
    """
    try:
        for f in wm.find("service"):
            v = f.value if isinstance(f.value, dict) else {}
            blob = " ".join(str(v.get(k, "")) for k in
                            ("service", "version", "banner", "product"))
            blob = (blob + " " + str(f.key)).lower()
            if any(t in blob for t in _MOBILE_HINT_TOKENS):
                return True
        for kind in ("web_app", "web_header", "environment", "mobile"):
            for f in wm.find(kind):
                blob = (str(f.key) + " " + str(f.value)).lower()
                if any(t in blob for t in _MOBILE_HINT_TOKENS):
                    return True
    except Exception:
        return False
    return False


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
    # mobile surface: a device identity (phone) OR a confirmed mobile/MDM
    # fact OR a network/web host whose services are known (an MDM
    # enrollment endpoint is a web service, so it only becomes reachable
    # once services are visible)
    is_mobile: bool = False
    has_mobile: bool = False
    # a MOBILE HINT is concrete evidence that the host fronts a mobile
    # surface (an MDM/APNS/GCM/enrolment service or a mobile-web app). It is
    # deliberately narrower than "has any open port": planning the MDM probe
    # against every scanned host would hijack the chain from the beacon stage.
    mobile_hint: bool = False
    # platform branch of the mobile surface ("ios" / "android"), learned
    # from the MDM enrolment probe: the two platforms have different
    # delivery doctrine (Android sideloads, iOS needs MDM supervision)
    mobile_platforms: List[str] = field(default_factory=list)
    mobile_managed: bool = False
    open_services: List[str] = field(default_factory=list)
    software: Dict[str, str] = field(default_factory=dict)
    # I3 — identity doctrine: phishing is the LAST resort. `contact_allowed`
    # is the operator's explicit contact consent; when it is absent the
    # delivery stage (which is the phishing stage for an identity target)
    # is DEMOTED below every non-contact stage rather than removed — the
    # operator's rule is "map everything first; contact only if nothing
    # else is left", so the stage stays reachable, just last.
    contact_allowed: bool = False
    # the non-contact ladder produced what it could: an identity resolved
    # and either an address verified, breach exposure correlated, or a
    # service account mapped. Recorded so the report can say WHY contact
    # became reachable.
    identity_mapped: bool = False

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
        model.is_mobile = wm.target_type == "phone"
        model.has_mobile = bool(wm.find("mobile") or wm.find("mdm_vendor"))
        # I3: the contact consent lives on the WorldModel (stamped by the
        # agent from the dedicated flag). Absent = closed = phishing last.
        consent = getattr(wm, "identity_consent", None)
        if isinstance(consent, dict):
            model.contact_allowed = bool(consent.get("contact"))
        model.identity_mapped = bool(
            wm.find("identity")
            and (wm.find("email_verified") or wm.find("breach_exposure")
                 or wm.find("service_account")))
        for f in wm.find("mobile_platform"):
            v = f.value if isinstance(f.value, dict) else {}
            for p in (v.get("platforms") or []):
                if p not in model.mobile_platforms:
                    model.mobile_platforms.append(str(p))
            if v.get("mdm"):
                model.mobile_managed = True
        model.open_services = sorted(
            {str(f.key) for f in wm.find("service")})
        model.mobile_hint = _detect_mobile_hint(wm)
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


def _mobile_device(model: TargetModel) -> bool:
    """The TARGET is a device (phone identity) or a mobile/MDM surface is
    already confirmed: probe/expand it. Ranked ABOVE the beacon stage so a
    phone still does OSINT first, then mobile, then converges."""
    return model.is_mobile or model.has_mobile


def _mobile_host(model: TargetModel) -> bool:
    """A network/web host that shows a CONCRETE mobile/MDM hint (MDM or
    APNS/GCM service, enrolment path, mobile-web app) may front an MDM
    enrolment endpoint. Ranked BELOW the beacon stage so the mobile probe
    can never hijack the terminal stage of the chain."""
    return model.is_network and model.mobile_hint


STRATEGIES: List[Strategy] = [
    Strategy("identity_osint", "Identity OSINT discovery",
             "identity", _identity, weight=90,
             description="osint_identity / persona_create -> identity facts"),
    # I3 — the NON-CONTACT ladder, before any breach/contact move: compose
    # candidate addresses (passive), then verify them (active, consent), then
    # correlate breach exposure. Weights sit just under identity_osint so a
    # fresh identity target walks the non-contact ladder in order.
    Strategy("identity_field", "Identity field expansion (non-contact)",
             "enrich", _identity, weight=88,
             description="email_candidates -> email_verify -> "
                         "breach_correlate: widen the field, no contact"),
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
    # mobile surface: its own stage so `mobile_probe` ->
    # `mobile_mdm_fingerprint` are actually PLANNED (they were orphaned
    # capabilities before). Two entries, same goal:
    #   * device -> above the beacon stage (phone: OSINT, then mobile)
    #   * host   -> just under the footprint stage (scan, then mobile probe)
    Strategy("mobile_surface_device", "Mobile device / MDM surface",
             "mobile", _mobile_device, weight=82,
             description="mobile_probe -> mobile_mdm_fingerprint "
                         "(MDM vendor -> mobile attack tree)"),
    Strategy("mobile_surface_host", "MDM surface on host",
             "mobile", _mobile_host, weight=67,
             description="MDM enrollment probe on a host showing a "
                         "mobile/MDM hint (before the beacon stage)"),
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


# ---------------------------------------------------------------------------
# thin-surface policy (what to do when enumeration found almost nothing)
# ---------------------------------------------------------------------------
#
# The ENVIRONMENT profile owns a thin-surface policy (see
# `phantom.automation.swarm.profile_policy`): deepen_one / identity /
# control_plane. It was declared in 7.1 and consumed by nobody, so a run
# on a barren surface still reached for the generic escalation list.
#
# The policy ORDERS the capability families a recovery re-arms first — it
# does not exclude the rest (the docstrings say "before", not "instead"):
# a machine class stops DEFAULTING into active OSINT/phishing, a mobile
# class does exactly the opposite, a cloud class goes to the control
# plane rather than to more ports. The ids are capability ids, so a typo
# would silently disable a policy — the test suite pins them against the
# registry.
THIN_SURFACE_CAPS: Dict[str, tuple] = {
    # go DEEPER on the one service that is open: identify it, then use it
    "deepen_one": ("version_detect", "surface_map", "os_detect",
                   "service_exploit", "http_probe"),
    # identity/MDM/social surface BEFORE anything active (mobile: the OS
    # sandbox hides the device, so the person and the enrolment are the
    # surface that actually exists)
    "identity": ("osint_identity", "profile_recon", "deep_recon",
                 "mobile_probe", "mobile_mdm_fingerprint", "breach_check"),
    # cloud identity/config IS the surface (OIDC, IAM, tokens), not ports
    "control_plane": ("cloud_creds_harvest", "cloud_iam_enum",
                      "cloud_s3_enum", "env_probe", "env_probe_internal"),
}

# fact kinds that mean the engagement HAS A LEAD (a surface to work, a
# credential to use, a foothold). Their absence is what makes a surface
# THIN — "os"/"banner" alone deliberately do NOT count: a guess about the
# platform is not something to build a plan on.
_LEAD_FACTS = ("service", "web_app", "web_header", "creds", "ad_domain",
               "mobile", "mdm_vendor", "cloud_creds", "identity",
               "victim_ip", "beacon", "rce_foothold", "internal_host")


def surface_is_thin(wm: WorldModel) -> bool:
    """Enumeration found almost nothing to work with.

    Scarcity, not difficulty: no service, no web/app surface, no
    credential, no foothold. This is the state the thin-surface policy
    exists for — here "try the next tool" is a guess, and the profile's
    doctrine is the only informed answer available. As soon as ONE lead
    exists the policy stands down (the plan can work the lead instead of
    following a class prior), so a run with valid creds re-arms
    `beacon_deploy` rather than "deepen" a service it has not found.
    """
    try:
        return not any(wm.has_any(kind) for kind in _LEAD_FACTS)
    except Exception:
        return False


def thin_surface_caps(policy: str) -> tuple:
    """Capability ids to re-arm FIRST under a thin-surface policy."""
    return tuple(THIN_SURFACE_CAPS.get((policy or "").strip().lower(), ()))


def _demote_identity_delivery(model: TargetModel,
                              stages: List[Strategy]) -> List[Strategy]:
    """I3 — phishing is the LAST resort for an identity target.

    The operator's rule: map everything non-contact first; only when that
    is exhausted may contact be considered. So the delivery stage
    (`identity_beacon`, the stage whose capabilities are phish/DM) is
    DEMOTED to the end of the applicable list unless the operator gave
    explicit contact consent. It is never REMOVED: with the rest of the
    ladder satisfied it is still reachable, and an explicit `--goal
    beacon` still selects it directly (that is an operator choice, not an
    automatic default).
    """
    if not model.is_identity or model.contact_allowed:
        return stages
    delivery = [s for s in stages if s.id == "identity_beacon"]
    if not delivery:
        return stages
    rest = [s for s in stages if s.id != "identity_beacon"]
    return rest + delivery


def applicable_strategies(model: TargetModel) -> List[Strategy]:
    """The strategies that fit the current target profile, best first."""
    ordered = sorted((s for s in STRATEGIES if s.requires(model)),
                     key=lambda s: (-s.weight, s.id))
    return _demote_identity_delivery(model, ordered)

