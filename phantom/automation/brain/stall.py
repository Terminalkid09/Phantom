"""
phantom.automation.brain.stall — stall classification.

Fixed escalation lists break on targets they weren't written for. A
senior first asks WHY they're stuck:

    no_visibility  -> nothing seen on the wire: change protocol/angle
                      (surface mapping, other ports, other hosts)
    blocked        -> seen but refused: evasion/identity change, not
                      more retries of the same payload family
    wrong_model    -> facts contradict the fingerprint: re-fingerprint,
                      trust the differential, not the banner
    wrong_altitude -> machine surface exhausted: pivot boundary —
                      social, adjacent host, supply chain

The classifier reads the WorldModel (findings, failures, noise) and
names the stall class + the strategy class to try. The agent's
_recover_stall consults it BEFORE falling back to the canned moves.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# strategy classes the agent can follow per stall type
STRATEGY_CLASSES = {
    "no_visibility": ["surface_map", "full_scan", "adjacent_hosts"],
    "blocked": ["evasion_change", "identity_change", "quiet_window"],
    "wrong_model": ["refingerprint", "differential_probe"],
    "wrong_altitude": ["social_pivot", "lateral_boundary", "supply_chain"],
}


@dataclass
class StallVerdict:
    stall_class: str
    reason: str
    strategies: List[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"stall": self.stall_class, "reason": self.reason,
                "strategies": self.strategies, "evidence": self.evidence}


class StallClassifier:
    """Names WHY the agent is stuck from the WorldModel's state."""

    def __init__(self, noise_breaker_tripped: bool = False) -> None:
        self.noise_breaker_tripped = noise_breaker_tripped

    def classify(self, wm, goal: str = "beacon") -> StallVerdict:
        failures = list(getattr(wm, "failures", []) or [])
        findings = list(wm.all_findings())
        kinds = {f.kind for f in findings}
        ev: dict = {
            "services": bool("service" in kinds),
            "web": bool(kinds & {"web_app", "web_header", "web_title"}),
            "creds": bool("creds" in kinds),
            "beacon": bool("beacon" in kinds),
            "failures": len(failures),
        }

        # 1. WRONG MODEL: fingerprint contradiction signals already present
        mismatch = bool(getattr(wm, "fingerprint_mismatch", False))
        if not mismatch:
            mismatch = any("mismatch" in str(f.get("reason", "")).lower()
                           for f in failures[-6:])
        if mismatch:
            return StallVerdict(
                "wrong_model",
                "observations contradict the fingerprint (expected-vs-"
                "observed differential): re-probe, do not repeat",
                STRATEGY_CLASSES["wrong_model"], ev)

        # 2. BLOCKED: the world says we were SEEN (noise breaker) or
        #    everything reachable failed with refusal-shaped reasons
        refusal = sum(1 for f in failures[-8:]
                      if any(word in str(f.get("reason", "")).lower()
                             for word in ("denied", "forbidden", "403",
                                          "refused", "blocked", "reset")))
        if self.noise_breaker_tripped or refusal >= 3:
            return StallVerdict(
                "blocked",
                f"moves are being refused ({refusal} refusal-shaped failures"
                f"{', noise breaker tripped' if self.noise_breaker_tripped else ''})"
                ": change evasion/identity, not the payload family",
                STRATEGY_CLASSES["blocked"], ev)

        # 3. NO VISIBILITY: nothing (or almost nothing) was ever observed
        if not ev["services"] and not ev["web"]:
            return StallVerdict(
                "no_visibility",
                "no open service or web surface observed: the perimeter is "
                "blind to port scanning — enumerate assets instead",
                STRATEGY_CLASSES["no_visibility"], ev)

        # 4. WRONG ALTITUDE: machine surface mapped but dead-ended
        #    (services/creds known, no code execution, many failures)
        if ev["failures"] >= 4 and not ev["beacon"]:
            return StallVerdict(
                "wrong_altitude",
                "machine surface exhausted without code execution: pivot "
                "boundary (social, adjacent host, supply chain)",
                STRATEGY_CLASSES["wrong_altitude"], ev)

        # 5. default: bounded re-arm (the classic transient recovery)
        return StallVerdict(
            "transient",
            "failures look transient (low count, partial visibility): "
            "re-arm viable moves once",
            ["rearm"], ev)
