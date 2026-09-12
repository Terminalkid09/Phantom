"""
experience.signature — the SITUATION fingerprint.

`TechniquePriors` buckets history by a coarse "fingerprint class" (a
product string or an OS). That is enough to average a success rate, but it
is not enough to say *"I have seen this exact kind of situation before"*.

The signature is that finer key: the target class, the product family, the
exposed service set and the defensive posture, plus a token bag used for
similarity. Two situations are "the same" when their token bags overlap
strongly and their class/product agree — so a case learned on one
nginx+php host with a WAF transfers to the next nginx+php host with a WAF,
without pretending a Windows DC is the same thing.

Deterministic and side-effect free: the same world model always yields the
same signature (so the store keys are stable across runs and platforms).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

# target_type -> coarse class used as the first matching dimension
_CLASS_OF_TYPE = {
    "ip": "network",
    "host": "network",
    "domain": "web",
    "url": "web",
    "subdomain": "web",
    "username": "identity",
    "handle": "identity",
    "email": "identity",
    "phone": "mobile",
    "mobile": "mobile",
    "person": "identity",
    "cloud": "cloud",
}

_GENERIC = "generic"


def _product_of(wm) -> str:
    """First known product/server family (same notion as the priors bucket,
    kept in sync deliberately so both systems key off the same world)."""
    for kind in ("fingerprint", "web_header", "banner"):
        for f in wm.find(kind):
            v = f.value if isinstance(f.value, dict) else {}
            product = str(v.get("product") or v.get("server") or "").lower()
            if product:
                return product.split("_")[0].split("/")[0][:24]
    for f in wm.find("os"):
        v = f.value if isinstance(f.value, dict) else {}
        name = str(v.get("name", "")).lower()
        if name:
            return name.split()[0][:24]
    return _GENERIC


def _services_of(wm) -> Tuple[str, ...]:
    out = set()
    for f in wm.find("service"):
        v = f.value if isinstance(f.value, dict) else {}
        name = str(v.get("service") or v.get("name") or "").lower().strip()
        if name:
            out.add(name.split("/")[0][:20])
    return tuple(sorted(out))


def _defenses_of(wm) -> Tuple[str, ...]:
    """Defensive posture tokens: what the target has that BLOCKS a move.

    Only signals that genuinely change which technique works belong here —
    a generic 'the target is up' is not a defense.
    """
    out = set()
    for kind in ("defensive_gap", "waf", "cdn", "protection"):
        for f in wm.find(kind):
            v = f.value if isinstance(f.value, dict) else {}
            for key in ("vendor", "product", "name", "type"):
                val = str(v.get(key, "")).lower().strip()
                if val and val not in ("none", "unknown", "null"):
                    out.add(val[:24])
    # a confirmed behavioural anomaly means the app reacts to probes:
    # treat it as an active-defense signal so cases do not transfer blindly
    for f in wm.find("hunt_anomaly"):
        v = f.value if isinstance(f.value, dict) else {}
        if v.get("confirmed"):
            out.add("reactive-app")
    return tuple(sorted(out))


def _class_of(wm) -> str:
    ttype = str(getattr(wm, "target_type", "") or "").lower()
    if ttype in _CLASS_OF_TYPE:
        return _CLASS_OF_TYPE[ttype]
    try:
        from phantom.automation.brain.targets import classify
        cls = classify(str(getattr(wm, "target", "") or ""))
        cls = getattr(cls, "name", cls)
        cls = str(cls or "").lower()
        if cls in ("network", "web", "identity", "mobile", "cloud"):
            return cls
    except Exception:
        pass
    return _GENERIC


@dataclass(frozen=True)
class Signature:
    """Immutable situation key + token bag."""

    cls: str = _GENERIC
    product: str = _GENERIC
    services: Tuple[str, ...] = ()
    defenses: Tuple[str, ...] = ()
    key: str = ""
    features: FrozenSet[str] = field(default_factory=frozenset)

    @classmethod
    def from_worldmodel(cls, wm) -> "Signature":
        cls_ = _class_of(wm)
        product = _product_of(wm)
        services = _services_of(wm)
        defenses = _defenses_of(wm)
        feats = set()
        feats.add(f"cls:{cls_}")
        feats.add(f"prod:{product}")
        for s in services:
            feats.add(f"svc:{s}")
        for d in defenses:
            feats.add(f"def:{d}")
        key_raw = f"{cls_}|{product}|{','.join(services)}|{','.join(defenses)}"
        digest = hashlib.sha1(key_raw.encode("utf-8")).hexdigest()[:16]
        return cls(cls=cls_, product=product, services=services,
                   defenses=defenses, key=digest,
                   features=frozenset(feats))

    # ── comparison ────────────────────────────────────────────────────
    def similarity(self, other: "Signature") -> float:
        """0..1 — how transferable a case from `other` is to `self`.

        Jaccard over the token bag, with explicit bonuses for the two
        dimensions that matter most (target class and product family)
        because those decide whether a technique even applies.
        """
        if not isinstance(other, Signature):
            return 0.0
        if self.key and self.key == other.key:
            return 1.0
        a, b = self.features, other.features
        if not a or not b:
            return 0.0
        inter = len(a & b)
        union = len(a | b)
        jac = inter / union if union else 0.0
        score = jac
        if self.cls == other.cls and self.cls != _GENERIC:
            score += 0.25
        if self.product == other.product and self.product != _GENERIC:
            score += 0.15
        return min(1.0, round(score, 4))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cls": self.cls,
            "product": self.product,
            "services": list(self.services),
            "defenses": list(self.defenses),
            "key": self.key,
            "features": sorted(self.features),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Signature":
        data = data or {}
        return cls(
            cls=str(data.get("cls", _GENERIC)),
            product=str(data.get("product", _GENERIC)),
            services=tuple(data.get("services") or ()),
            defenses=tuple(data.get("defenses") or ()),
            key=str(data.get("key", "")),
            features=frozenset(data.get("features") or ()),
        )

    def human(self) -> str:
        bits = [self.cls, self.product]
        if self.services:
            bits.append("+".join(self.services[:3]))
        if self.defenses:
            bits.append("[" + ",".join(self.defenses[:2]) + "]")
        return " ".join(b for b in bits if b and b != _GENERIC)


def similarity_bucket(a: Signature, b: Signature,
                      threshold: float = 0.55) -> bool:
    """True when two situations are close enough to share experience."""
    return a.similarity(b) >= threshold
