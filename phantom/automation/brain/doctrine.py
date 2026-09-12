"""
phantom.automation.brain.doctrine — per-class chain doctrine.

Doctrine is HOW a kill chain flows for a target class: the stage order,
the goal per stage, and the class-specific constraints. Strategies
(guidance/strategy.py) remain the executable stage list; doctrine gives
the planner the class-correct SHAPE so a username never gets an nmap
scan and an IP never gets a breach lookup.

One file per class was the agreed layout; at this stage the class table
lives in one module to keep the import graph flat — the per-class files
land with the phases/ migration (Fase 6) which moves the stage bodies.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Tuple

from phantom.automation.brain.targets import (
    CLASS_AD, CLASS_CLOUD, CLASS_IDENTITY, CLASS_MOBILE, CLASS_NETWORK,
    CLASS_PERSON, CLASS_WEB,
)


@dataclass(frozen=True)
class Doctrine:
    """The class-level chain contract."""
    cls: str
    # ordered (strategy-goal, description) — the shape of the engagement
    stages: Tuple[Tuple[str, str], ...]
    # goals that must NEVER be planned for this class (hard doctrine)
    forbidden: Tuple[str, ...] = ()
    notes: str = ""


_DOCTRINES: Dict[str, Doctrine] = {
    # ── identity: the person is the target; machines come later ────────
    CLASS_IDENTITY: Doctrine(
        cls=CLASS_IDENTITY,
        stages=(
            ("identity", "resolve handles/emails, breach exposure"),
            ("creds", "harvested credentials from breaches"),
            ("social", "persona + lure delivery (phish/dm)"),
            ("beacon", "victim machine check-in converges the chain"),
        ),
        forbidden=("footprint",),   # NO port scan against a person
        notes="machine stages activate only after a victim_ip exists",
    ),
    # ── network: the classic footprint-first chain ─────────────────────
    CLASS_NETWORK: Doctrine(
        cls=CLASS_NETWORK,
        stages=(
            ("footprint", "scan + fingerprint + OS detect"),
            ("exploit", "version-matched exploitation / hunt"),
            ("creds", "credential acquisition on found services"),
            ("beacon", "delivery + persistence"),
        ),
        forbidden=("identity",),
        notes="no breach lookup for a bare machine",
    ),
    # ── web: surface map before touching ports ─────────────────────────
    CLASS_WEB: Doctrine(
        cls=CLASS_WEB,
        stages=(
            ("footprint", "surface map (CT/wayback) then service scan"),
            ("exploit", "web hunt + fuzz + RCE bridge"),
            ("creds", "web credential extraction"),
            ("beacon", "delivery"),
        ),
        forbidden=("identity",),
        notes="asset enumeration precedes packet-level scanning",
    ),
    # ── cloud: identity plane first, never a port scan of the tenant ───
    CLASS_CLOUD: Doctrine(
        cls=CLASS_CLOUD,
        stages=(
            ("environment", "metadata / IAM enumeration"),
            ("cloud_creds", "role assumption, key harvesting"),
            ("cloud_lateral", "cross-account / storage pivot"),
            ("beacon", "workload delivery when an endpoint exists"),
        ),
        forbidden=("footprint",),
        notes="the API is the target, the ports are noise",
    ),
    # ── mobile: sandboxed device, social-first ─────────────────────────
    # The platform branch is applied in for_class(): Android can sideload a
    # native implant, iOS only after MDM supervision + an enterprise-signed
    # app, so an unmanaged iOS target has NO beacon stage at all.
    CLASS_MOBILE: Doctrine(
        cls=CLASS_MOBILE,
        stages=(
            ("identity", "device owner OSINT + app inventory"),
            ("mobile", "MDM / device-management surface probe"),
            ("social", "lure delivery tuned for mobile click-through"),
            ("beacon", "companion-agent delivery after victim contact"),
        ),
        forbidden=("footprint",),
        notes="nmap against a phone is noise: sandbox hides the surface",
    ),
    # ── ad: directory attacks once the domain is known ─────────────────
    CLASS_AD: Doctrine(
        cls=CLASS_AD,
        stages=(
            ("footprint", "DC discovery + enum"),
            ("ad", "kerberoast / AS-REP / ACL abuse"),
            ("crack", "offline hash cracking"),
            ("beacon", "delivery via harvested creds"),
        ),
        forbidden=(),
        notes="credential attacks outrank exploit attempts",
    ),
    # ── person: pure OSINT subject (feeds identity pivots) ──────────────
    CLASS_PERSON: Doctrine(
        cls=CLASS_PERSON,
        stages=(
            ("identity", "deep OSINT only"),
            ("social", "contact when justified"),
        ),
        forbidden=("footprint", "creds", "beacon"),
        notes="no access operations against the human directly",
    ),
}

# goal -> class stages lookup ------------------------------------------------

# Platforms whose delivery doctrine we can branch on. Android installs a
# native implant directly (sideload / dropper); iOS reaches the beacon
# stage ONLY on an MDM-supervised device with an enterprise-signed app.
MOBILE_PLATFORMS = ("android", "ios")


def _mobile_extra_forbidden(platform: Optional[str],
                            managed: bool) -> Tuple[str, ...]:
    """Extra (platform-conditional) forbidden goals for CLASS_MOBILE."""
    if platform == "ios" and not managed:
        # no sideload, no supervision: the device will not run our binary
        return ("beacon",)
    return ()


def for_class(cls: str, platform: Optional[str] = None,
             managed: bool = False) -> Doctrine:
    """The doctrine for a target class (network is the default).

    For CLASS_MOBILE the stage ORDER is fixed and platform-independent, but
    the forbidden set branches on (platform, managed): an unmanaged iOS
    device never reaches the beacon stage.
    """
    base = _DOCTRINES.get(cls, _DOCTRINES[CLASS_NETWORK])
    if cls != CLASS_MOBILE:
        return base
    extra = _mobile_extra_forbidden(platform, managed)
    if not extra:
        return base
    return replace(base, forbidden=tuple(base.forbidden) + extra)


def stage_order(cls: str) -> List[str]:
    """Ordered stage goals for a class — what plan_strategic walks."""
    return [g for g, _ in for_class(cls).stages]


def forbidden_goals(cls: str, platform: Optional[str] = None,
                   managed: bool = False) -> Tuple[str, ...]:
    return for_class(cls, platform=platform, managed=managed).forbidden


def allows(cls: str, goal: str, platform: Optional[str] = None,
           managed: bool = False) -> bool:
    """Hard doctrine gate: may this class ever pursue this stage goal?

    `platform` / `managed` refine the mobile class only; other classes are
    unaffected. An unmanaged iOS target is refused the beacon stage.
    """
    return goal not in forbidden_goals(cls, platform=platform,
                                       managed=managed)


def chain_preview(cls: str) -> str:
    """Human one-liner: 'identity -> creds -> social -> beacon'."""
    return " -> ".join(g for g, _ in for_class(cls).stages)


def doctrine_report(cls: str) -> str:
    d = for_class(cls)
    lines = [f"Doctrine [{d.cls}]  {d.notes}".rstrip(),
             f"  chain   : {chain_preview(cls)}"]
    if d.forbidden:
        lines.append(f"  forbid  : {', '.join(d.forbidden)}")
    return "\n".join(lines)
