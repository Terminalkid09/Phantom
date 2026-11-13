"""image_reverse.py — opening a PRIVATE profile through its avatar.

A private account hides posts and bios, not its profile picture. The same
photo reused on another platform (or a public commenter's copy of it) is
the most common way back to a public surface — and the perceptual hash in
``identity_confidence`` already survives the re-encoding platforms apply.

Honest scope: this module does NOT scrape the search engines. It builds
the exact queries for the operator (who is logged in and can solve a
challenge), and it verifies a candidate avatar the operator/another probe
already fetched. Two independent signals are required before a match is
called `confirmed`; a hash alone is supporting evidence, never proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

from phantom.automation.social.identity_confidence import (
    CONFIRMED_THRESHOLD,
    DHASH_MAX_DISTANCE,
    dhash_distance,
)

CONFIRMED = "confirmed"
PROBABLE = "probable"
DIFFERENT = "different"
UNKNOWN = "unknown"

# Minimum number of INDEPENDENT signals for a confirmed same-person claim.
MIN_CONFIRMING_SIGNALS = 2

_ENGINES: Dict[str, str] = {
    "yandex": "https://yandex.com/images/search?rpt=imageview&url={url}",
    "google": "https://lens.google.com/uploadbyurl?url={url}",
    "tineye": "https://tineye.com/search?url={url}",
}


@dataclass
class Match:
    verdict: str = UNKNOWN
    distance: Optional[int] = None
    confidence: float = 0.0
    reason: str = ""

    def marker(self) -> str:
        return (f"IMAGE_MATCH: verdict={self.verdict} "
                f"distance={-1 if self.distance is None else self.distance} "
                f"confidence={self.confidence:.2f} reason={self.reason}")


@dataclass
class ReversePlan:
    platform: str = ""
    handle: str = ""
    queries: List[Tuple[str, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def markers(self) -> List[str]:
        out = [f"REVERSE_PLAN: platform={self.platform} handle={self.handle} "
               f"queries={len(self.queries)}"]
        out += [f"REVERSE_QUERY: engine={engine} url={url}"
                for engine, url in self.queries]
        out += [f"REVERSE_NOTE: {note}" for note in self.notes]
        return out


def compare_hashes(primary_hash: str, candidate_hash: str) -> Match:
    """dHash comparison: same picture survives resize/re-encode."""
    distance = dhash_distance(primary_hash, candidate_hash)
    if distance is None:
        return Match(UNKNOWN, None, 0.0, "missing or unparseable hash")
    if distance <= DHASH_MAX_DISTANCE:
        confidence = max(0.0, 1.0 - distance / max(1, DHASH_MAX_DISTANCE * 2))
        verdict = CONFIRMED if confidence >= CONFIRMED_THRESHOLD else PROBABLE
        return Match(verdict, distance, round(confidence, 3),
                     "perceptual hash within the same-picture band")
    return Match(DIFFERENT, distance, 0.0,
                 f"hash distance {distance} > {DHASH_MAX_DISTANCE}")


def combine(signals: List[Match], name_match: bool = False,
            link_match: bool = False) -> Match:
    """Two independent signals are required for `confirmed`.

    A hash match alone stays `probable`: avatars are reused by fan pages,
    impersonators and stock photos, so the operator must not treat one as
    identity proof. A name/link corroboration upgrades it.
    """
    hashes = [s for s in signals if s.verdict in (CONFIRMED, PROBABLE)]
    corroboration = int(bool(name_match)) + int(bool(link_match))
    if not hashes:
        return Match(DIFFERENT if signals else UNKNOWN, None, 0.0,
                     "no reusable avatar signal")
    best = max(hashes, key=lambda s: s.confidence)
    independent = len(hashes) + corroboration
    if best.verdict == CONFIRMED and independent >= MIN_CONFIRMING_SIGNALS:
        return Match(CONFIRMED, best.distance, best.confidence,
                     f"{independent} independent signals")
    return Match(PROBABLE, best.distance,
                 round(best.confidence * (1.0 if independent > 1 else 0.7), 3),
                 "single avatar signal — corroborate before claiming identity")


def search_urls(image_url: str, engines: Optional[List[str]] = None
                ) -> List[Tuple[str, str]]:
    """The exact reverse-image queries for a PUBLIC image URL."""
    url = str(image_url or "").strip()
    if not url.startswith(("http://", "https://")):
        return []
    encoded = quote(url, safe="")
    names = engines or list(_ENGINES)
    return [(name, _ENGINES[name].format(url=encoded)) for name in names
            if name in _ENGINES]


def reverse_plan(platform: str = "", handle: str = "",
                 avatar_url: str = "", avatar_hash: str = "") -> ReversePlan:
    """What to open, and why, for a private target. No network calls."""
    plan = ReversePlan(platform=platform, handle=str(handle or "").lstrip("@"))
    plan.queries = search_urls(avatar_url)
    if avatar_hash:
        plan.notes.append("avatar_hash_present: candidate copies can be "
                          "compared offline with compare_hashes")
    if not plan.queries:
        plan.notes.append(
            "no public avatar URL: fetch it from a cached/thumbnail copy or "
            "ask the operator for a screenshot; a private-only URL cannot be "
            "sent to an external engine")
    plan.notes.append(
        "match candidates against the same-handle public profiles and the "
        "2-hop mutual graph before claiming the same person")
    return plan
