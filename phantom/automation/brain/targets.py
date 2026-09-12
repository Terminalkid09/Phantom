"""
phantom.automation.brain.targets — the target ledger.

Every input target and every target DISCOVERED during the engagement is
classified into a class, and the class decides the doctrine (the chain
shape). The ledger is the single source of truth for:

    * the ACTIVE target set (initial + pivots discovered mid-run)
    * the class of each target (identity / network / web / cloud /
      mobile / ad / person)
    * the pivot trail: WHEN and FROM WHICH fact a target was discovered
      (e.g. breach dump -> email -> victim machine IP)
    * scope: discovery alone never authorizes action — a discovered
      pivot is only ACTIVE when it is in scope or identity-class

Classes are a superset of guidance/targets.py primitives: identity
(username/email/phone), network (ip/cidr/host), web (domain/url), plus
the analyst classes cloud / mobile / ad / person that the doctrine
layer can assign from evidence (cloud tenant discovered via metadata
endpoint, DC discovered via LDAP, person behind an identity target...).

Design rules:
    * classification is DETERMINISTIC (pure syntax rules), the same
      string always lands in the same class
    * re-classification on new facts can only WIDEN knowledge
      (a "web" target that reveals a DC gains an `ad` pivot), never
      silently rewrite the original input
    * scope gating is centralized here: `activatable()` is the ONE
      place that decides whether the agent may act on a target
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ── classes ────────────────────────────────────────────────────────────────

CLASS_IDENTITY = "identity"   # username / email / phone (the subject)
CLASS_NETWORK = "network"     # ip / cidr / host
CLASS_WEB = "web"             # domain / url
CLASS_CLOUD = "cloud"         # tenant / subscription / storage endpoint
CLASS_MOBILE = "mobile"       # a device (phone target, MDM-managed host)
CLASS_AD = "ad"               # AD forest / domain controller
CLASS_PERSON = "person"       # a physical individual (OSINT subject)

ALL_CLASSES = (CLASS_IDENTITY, CLASS_NETWORK, CLASS_WEB, CLASS_CLOUD,
               CLASS_MOBILE, CLASS_AD, CLASS_PERSON)

# classes whose subject is out-of-band of machine scope gates
MACHINE_CLASSES = (CLASS_NETWORK, CLASS_WEB, CLASS_CLOUD, CLASS_AD)

# guidance/targets primitive -> brain class
_PRIMITIVE_TO_CLASS = {
    "email": CLASS_IDENTITY,
    "username": CLASS_IDENTITY,
    # a phone is a DEVICE, not a person: it takes the mobile doctrine (which
    # still starts with identity/OSINT) so the platform branch — MDM probe,
    # Android vs iOS delivery — is reachable for the primary target
    "phone": CLASS_MOBILE,
    "ip": CLASS_NETWORK,
    "cidr": CLASS_NETWORK,
    "domain": CLASS_WEB,
    "url": CLASS_WEB,
}

# network classes pivot into AD when domain-controller evidence appears
_AD_HINT_PORTS = {88, 389, 636, 3268, 3269}  # kerberos / ldap / gc


def _looks_like_tld(label: str) -> bool:
    """Heuristic TLD check mirrored from guidance/targets.py."""
    if not label or not label.isalpha():
        return False
    if len(label) <= 1:
        return False
    if label.lower() in ("corp", "local", "internal", "lan", "intranet",
                         "test", "lab", "home", "priv"):
        return True
    return len(label) >= 2


@dataclass
class TargetEntry:
    """One known target and its provenance."""
    value: str
    cls: str
    source: str = "operator"          # operator | discovered:<fact> | pivot:<kind>
    origin: str = ""                  # the target value this was pivoted from
    fact_kind: str = ""               # the finding kind that produced it
    scope_ok: bool = False            # machine classes only
    reason: str = ""                  # why it was added
    pivots: List[str] = field(default_factory=list)  # values derived from this

    def to_dict(self) -> dict:
        return {"value": self.value, "class": self.cls,
                "source": self.source, "origin": self.origin,
                "fact_kind": self.fact_kind, "scope_ok": self.scope_ok,
                "reason": self.reason, "pivots": list(self.pivots)}


class TargetLedger:
    """The active target set + classification + pivot trail.

    The agent reads `ledger.initial` for its target and queries
    `activatable()` before acting on anything discovered mid-run.
    """

    def __init__(self, target: str, scope_list: Optional[List[str]] = None,
                 scope_fn=None) -> None:
        self.scope_list = list(scope_list or [])
        self._scope_fn = scope_fn  # injected scope predicate (tests)
        self._entries: Dict[str, TargetEntry] = {}
        self.initial = self.register(target, source="operator")
        # identity-confidence gate state (set by the agent): tier map for
        # cross-platform identity candidates + whether --aggressive was
        # given (aggressive accepts the wrong-person risk explicitly).
        self.identity_tiers: Dict[str, str] = {}
        self.aggressive = False

    # ── scope ──────────────────────────────────────────────────────────
    def _in_scope(self, value: str) -> bool:
        """Machine targets must be authorized; identity subjects are the
        engagement subject by definition (same rule the agent applies)."""
        from phantom.automation.guidance.targets import (
            classify_target as _classify, is_identity_target)
        if is_identity_target(_classify(value)):
            return True
        if self._scope_fn is not None:
            return bool(self._scope_fn(value))
        if not self.scope_list:
            return True   # documented default: empty scope allows all
        from phantom.core.scope import is_in_scope
        return is_in_scope(value, self.scope_list)

    # ── registration ───────────────────────────────────────────────────
    def register(self, value: str, source: str = "operator",
                 origin: str = "", fact_kind: str = "",
                 cls: Optional[str] = None, reason: str = "",
                 inherit_scope: bool = False) -> Optional[TargetEntry]:
        """Add a target. Returns the (new or existing) entry; None when
        the value is empty or a machine target out of scope.

        ``inherit_scope=True``: a target DISCOVERED from an authorized
        origin (in-scope machine or identity subject) is part of the same
        authorized environment — e.g. the AD domain revealed by LDAP on an
        in-scope host. Operator-supplied targets never inherit: they pass
        the strict gate themselves."""
        value = (value or "").strip()
        if not value:
            return None
        entry = self._entries.get(value)
        if entry is not None:
            # known target: record the extra provenance path only
            if origin and origin not in entry.pivots:
                entry.pivots.append(origin)
            return entry
        klass = cls or classify(value)
        if klass in MACHINE_CLASSES:
            if inherit_scope and origin:
                # pivot inheritance: authorized origin authorizes the child
                origin_entry = self.get(origin)
                scope_ok = (origin_entry is None
                            or origin_entry.cls not in MACHINE_CLASSES
                            or origin_entry.scope_ok)
                if origin_entry is None:
                    scope_ok = self._in_scope(origin)
            else:
                scope_ok = self._in_scope(value)
        else:
            scope_ok = True
        if klass in MACHINE_CLASSES and not scope_ok:
            return None    # discovered but NOT authorized: recorded nowhere
        entry = TargetEntry(value=value, cls=klass, source=source,
                            origin=origin, fact_kind=fact_kind,
                            scope_ok=scope_ok, reason=reason)
        self._entries[value] = entry
        if origin and origin in self._entries:
            parent = self._entries[origin]
            if value not in parent.pivots:
                parent.pivots.append(value)
        return entry

    def get(self, value: str) -> Optional[TargetEntry]:
        return self._entries.get((value or "").strip())

    def all(self) -> List[TargetEntry]:
        return list(self._entries.values())

    def by_class(self, klass: str) -> List[TargetEntry]:
        return [e for e in self._entries.values() if e.cls == klass]

    def activatable(self, value: str) -> bool:
        """May the agent act on this target RIGHT NOW? The single gate.

        Cross-platform identity candidates additionally respect the
        identity-confidence gate: PROBABLE/UNRELATED tiers never become
        actionable pivots unless --aggressive (wrong-person risk taken
        explicitly by the operator). The PRIMARY identity target is
        always unaffected — the operator chose it deliberately.
        """
        entry = self.get(value)
        if entry is None:
            return False
        if entry.cls not in MACHINE_CLASSES:
            if entry.cls == CLASS_IDENTITY and value != self.initial.value:
                tier = self.identity_tiers.get((value or "").lower())
                if tier and not self.aggressive:
                    return False  # unconfirmed same-person claim
            return True
        return entry.scope_ok

    def set_identity_tiers(self, tiers: Dict[str, str],
                           aggressive: bool = False) -> None:
        """Load the confidence tiers discovered during OSINT (handle ->
        tier). Called by the agent when identity_conf findings arrive."""
        self.identity_tiers.update({
            (k or "").strip().lstrip("@").lower(): (v or "unrelated")
            for k, v in (tiers or {}).items()})
        self.aggressive = bool(aggressive)

    # ── doctrine-facing API ────────────────────────────────────────────
    def chain_class(self) -> str:
        """The primary class driving the initial chain."""
        return self.initial.cls if self.initial else CLASS_NETWORK

    def reclassify_on_facts(self, facts) -> List[TargetEntry]:
        """Mid-run re-classification: scan findings for NEW targets.

        Returns the list of newly registered entries. Currently detects:
          * AD surface  (kerberos/ldap/gc ports, ad_domain facts)
          * cloud surface (metadata/S3/Azure endpoints in env facts)
          * victim machines (victim_ip findings from the identity chain)
          * peer hosts (pivot findings from post-exploitation)
        """
        new: List[TargetEntry] = []
        for f in facts:
            kind = getattr(f, "kind", "")
            value = getattr(f, "value", None)
            vdict = value if isinstance(value, dict) else {}
            target_new = None

            if kind == "ad_domain":
                # the domain string can be the VALUE itself, or sit inside
                # the structured payload (ad_domain:{domain: ...}), or be
                # the finding KEY — all three shapes occur in the wild
                dom = ""
                if isinstance(value, dict):
                    dom = str(value.get("domain") or value.get("name") or "")
                elif value:
                    dom = str(value)
                dom = dom or str(getattr(f, "key", "") or "")
                target_new = self.register(
                    dom, source="discovered:ad_domain",
                    fact_kind="ad_domain", cls=CLASS_AD,
                    origin=getattr(f, "target", "") or self.initial.value,
                    reason="domain controller surface discovered",
                    inherit_scope=True) if dom else None
            elif kind == "environment" and vdict.get("cloud"):
                target_new = self.register(
                    str(vdict.get("cloud")), source="discovered:cloud_env",
                    fact_kind="environment", cls=CLASS_CLOUD,
                    origin=getattr(f, "target", "") or self.initial.value,
                    reason="cloud control plane discovered",
                    inherit_scope=True)
            elif kind == "victim_ip":
                ip = str(vdict.get("ip") or value or "").strip()
                if ip:
                    target_new = self.register(
                        ip, source="discovered:victim_ip",
                        fact_kind="victim_ip", cls=CLASS_NETWORK,
                        origin=getattr(f, "target", "") or self.initial.value,
                        reason="identity chain harvested the victim machine",
                        inherit_scope=True)
            elif kind == "pivot":
                ip = str(vdict.get("host") or vdict.get("ip") or "").strip()
                if ip:
                    target_new = self.register(
                        ip, source="discovered:pivot",
                        fact_kind="pivot", cls=CLASS_NETWORK,
                        origin=getattr(f, "target", "") or self.initial.value,
                        reason="peer host reachable via foothold",
                        inherit_scope=True)
            elif kind == "service":
                try:
                    port = int(str(vdict.get("port", "0")).split("/")[0])
                except (TypeError, ValueError):
                    port = 0
                if port in _AD_HINT_PORTS:
                    host = str(getattr(f, "target", "") or "").strip()
                    if host and host not in self._entries:
                        target_new = self.register(
                            host, source="discovered:ad_ports",
                            fact_kind="service", cls=CLASS_AD,
                            origin=self.initial.value,
                            reason=f"kerberos/ldap surface on tcp/{port}",
                            inherit_scope=True)

            if target_new is not None and target_new not in new:
                new.append(target_new)
        return new

    def to_dict(self) -> dict:
        return {"initial": self.initial.value if self.initial else None,
                "scope": list(self.scope_list),
                "identity_tiers": dict(self.identity_tiers),
                "targets": [e.to_dict() for e in self._entries.values()]}


# ── deterministic classification ───────────────────────────────────────────

_CIDR_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+/\d+$")


def classify(value: str) -> str:
    """String -> one of ALL_CLASSES. Deterministic, syntax-only.

    Extends guidance/targets.py with the analyst classes (cloud/mobile/ad)
    which are only assigned via evidence in reclassify_on_facts — from a
    bare string, cloud/mobile/ad are not distinguishable and default to
    their primitive class.
    """
    t = (value or "").strip()
    if not t:
        return CLASS_IDENTITY
    if _CIDR_RE.match(t):
        return CLASS_NETWORK
    from phantom.automation.guidance.targets import classify_target
    primitive = classify_target(t)
    return _PRIMITIVE_TO_CLASS.get(primitive, CLASS_NETWORK)
