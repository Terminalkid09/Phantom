"""
phantom.automation.brain.tribunal — the second opinion and its adjudication (C2).

Two agents on one task are only worth their threads if they can DISAGREE and
if the disagreement is then settled by a rule. This module provides both:

    opinion()     — rate the same candidate set through ONE profile and
                    return its ranking with the driving lens per move
    adjudicate()  — rate it through the LEAD profile and the PEER profile,
                    and decide which pick stands

The adjudication rule (deterministic, no LLM):

  1. agreement      -> the lead's pick stands; nothing changes.
  2. conviction     -> the peer's pick is adopted when the peer WANTS it more
                       than the lead RESISTS it (its relative advantage,
                       under each profile's own ranking, is larger), with a
                       floor on the peer's conviction so an indifferent
                       peer never swings a decision. "If you want it more
                       than I mind it, take it."
  3. exposed veto   -> if the lead's pick is vetoed by the peer's (stricter)
                       stealth lens, the peer's pick is adopted regardless.

  else              -> different trade-off: the LEAD RETAINS COMMAND and the
                       peer's preference is recorded as a dissent.

A rule that was tried first and REMOVED because it is unreachable: "adopt
the peer's pick when it also beats the lead's pick under the lead's own
profile". That can never be true — the lead's top is BY CONSTRUCTION the
maximum of its own ranking, so the condition is vacuous. It is recorded here
because a rule that cannot fire is worse than no rule: it reads like a
safeguard while doing nothing.

Whatever loses is not thrown away: it is recorded as a DISSENT with its
reason, which is the raw material the hypothesis ledger and the learning
sandbox consume. A second opinion that leaves no trace is just a rerun.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from phantom.automation.brain.lenses import (
    Arbitrator,
    Decision,
    ReasoningProfile,
    WorldSignals,
    adversarial_profile,
    profile_for,
)

# minimum relative conviction the peer must have for its own pick before it
# can swing a decision at all (an indifferent peer never overrules)
COMPROMISE_EPS = 0.01


@dataclass
class Opinion:
    """One agent's ranking of the candidate set."""

    cell_id: str
    profile: str
    ranking: List[Tuple[str, float]] = field(default_factory=list)
    drivers: Dict[str, str] = field(default_factory=dict)
    vetoes: Dict[str, str] = field(default_factory=dict)
    search_policy: str = "adaptive"

    def top(self) -> Optional[str]:
        return self.ranking[0][0] if self.ranking else None

    def score_of(self, capability: str) -> Optional[float]:
        for cid, value in self.ranking:
            if cid == capability:
                return value
        return None

    def to_dict(self) -> dict:
        return {"cell": self.cell_id, "profile": self.profile,
                "search_policy": self.search_policy,
                "top": self.top(),
                "ranking": [(c, round(v, 4)) for c, v in self.ranking],
                "drivers": dict(self.drivers), "vetoes": dict(self.vetoes)}


@dataclass
class Dispute:
    """The outcome: who won, why, and what the loser said."""

    lead: Opinion
    peer: Opinion
    agreed: bool = True
    winner: str = "lead"                 # lead | peer
    rule: str = "agreement"
    adopted: Optional[str] = None        # the move the run should take now
    dissent: Optional[str] = None        # capability the loser preferred
    dissent_reason: str = ""
    magnitude: float = 0.0               # how far apart the two picks are

    def explain(self) -> str:
        if self.agreed:
            return (f"tribunal: {self.lead.profile} and {self.peer.profile} "
                    f"agree on {self.lead.top()}")
        return (f"tribunal: {self.lead.profile} picks {self.lead.top()}, "
                f"{self.peer.profile} picks {self.peer.top()} "
                f"(gap {self.magnitude:.2f}) -> {self.winner} "
                f"[{self.rule}] adopted={self.adopted}")

    def to_dict(self) -> dict:
        return {"agreed": self.agreed, "winner": self.winner, "rule": self.rule,
                "adopted": self.adopted, "dissent": self.dissent,
                "dissent_reason": self.dissent_reason,
                "magnitude": round(self.magnitude, 4),
                "lead": self.lead.to_dict(), "peer": self.peer.to_dict()}


class Tribunal:
    """Rates a candidate set through two profiles and settles the dispute."""

    def __init__(self, lead_profile: Optional[ReasoningProfile] = None,
                 peer_profile: Optional[ReasoningProfile] = None) -> None:
        self.lead_profile = lead_profile or profile_for("balanced")
        self.peer_profile = peer_profile or adversarial_profile(self.lead_profile)
        self._lead = Arbitrator(self.lead_profile)
        self._peer = Arbitrator(self.peer_profile)
        # a per-profile arbitrator cache: parallel reasoning rates the same
        # candidates through MANY cells' profiles, not only lead/peer
        self._arbs: Dict[str, Arbitrator] = {}
        self.history: List[Dispute] = []

    def _arb_for(self, profile: ReasoningProfile) -> Arbitrator:
        """The arbitrator for a profile (thread-safe: pure after build)."""
        if profile is self.lead_profile:
            return self._lead
        if profile is self.peer_profile:
            return self._peer
        arb = self._arbs.get(profile.name)
        if arb is None:
            arb = Arbitrator(profile)
            self._arbs[profile.name] = arb
        return arb

    # ── one opinion ────────────────────────────────────────────────────
    def opinion(self, cell_id: str, profile: ReasoningProfile,
                views: Sequence[Any], base_of: Dict[str, float],
                signals: WorldSignals) -> Opinion:
        """Rate every candidate with ONE profile. `views` are CapabilityView
        (or anything `evaluate` accepts), `base_of` maps id -> expected
        value. Pure: safe to call from several threads at once."""
        arb = self._arb_for(profile)
        op = Opinion(cell_id=cell_id, profile=profile.name,
                     search_policy=arb.search_policy(signals))
        scored: List[Tuple[str, float]] = []
        for view in views:
            cid = getattr(view, "id", "")
            decision: Decision = arb.evaluate(view, float(base_of.get(cid, 1.0)),
                                              signals)
            if decision.vetoed:
                op.vetoes[cid] = decision.veto
                continue
            scored.append((cid, decision.value))
            op.drivers[cid] = decision.driver
        scored.sort(key=lambda kv: (-kv[1], kv[0]))
        op.ranking = scored
        return op

    # ── adjudication ───────────────────────────────────────────────────
    def adjudicate(self, views: Sequence[Any], base_of: Dict[str, float],
                   signals: WorldSignals,
                   lead_cell: str = "lead",
                   peer_cell: str = "peer",
                   peer_views: Optional[Sequence[Any]] = None,
                   peer_signals: Optional[WorldSignals] = None) -> Dispute:
        # the peer rates its OWN world when one is supplied (buco 1): a peer
        # that cannot see a fact cannot let it swing the decision.
        lead = self.opinion(lead_cell, self.lead_profile, views, base_of, signals)
        peer = self.opinion(peer_cell, self.peer_profile,
                            views if peer_views is None else peer_views,
                            base_of,
                            signals if peer_signals is None else peer_signals)
        dispute = Dispute(lead=lead, peer=peer)

        if not lead.ranking and not peer.ranking:
            dispute.rule = "no viable candidate under either profile"
            dispute.adopted = None
            self.history.append(dispute)
            return dispute
        if not lead.ranking:
            dispute.agreed = False
            dispute.winner, dispute.rule = "peer", "every lead candidate vetoed"
            dispute.adopted = peer.top()
            dispute.dissent_reason = "; ".join(
                f"{cid}: {why}" for cid, why in lead.vetoes.items())
            self.history.append(dispute)
            return dispute
        if not peer.ranking:
            dispute.rule = "peer found nothing viable; lead stands"
            dispute.adopted = lead.top()
            self.history.append(dispute)
            return dispute

        lt, pt = lead.top(), peer.top()
        if lt == pt:
            dispute.adopted = lt
            self.history.append(dispute)
            return dispute

        dispute.agreed = False
        dispute.dissent = pt
        lead_score = lead.score_of(lt) or 0.0
        peer_score = lead.score_of(pt)             # under the LEAD's profile
        dispute.magnitude = abs(lead_score - (peer_score or 0.0))

        # 3. the lead's own pick is vetoed by the stricter peer profile
        if lt in peer.vetoes:
            dispute.winner, dispute.rule = "peer", "lead pick vetoed by the peer"
            dispute.adopted = pt
            # `dissent` is what the LOSER preferred: when the peer wins, the
            # loser is the lead, so the dissent is the lead's pick.
            dispute.dissent = lt
            dispute.dissent_reason = peer.vetoes[lt]
            self.history.append(dispute)
            return dispute
        # 2. the peer wants its pick more than the lead resists it
        lead_pref, peer_pref = self._intensities(lead, peer, lt, pt)
        if peer_pref > max(lead_pref, COMPROMISE_EPS):
            dispute.winner = "peer"
            dispute.rule = ("peer conviction exceeds the lead's cost "
                            f"({peer_pref:.1%} vs {lead_pref:.1%})")
            dispute.adopted = pt
            dispute.dissent = lt                    # the lead is the loser here
            dispute.dissent_reason = (
                f"{peer.profile} wants {pt} by {peer_pref:.1%}; "
                f"{lead.profile} would give up {lt} by {lead_pref:.1%}")
            self.history.append(dispute)
            return dispute

        dispute.winner = "lead"
        dispute.rule = "different trade-off, lead retains command"
        dispute.adopted = lt
        dispute.dissent_reason = (
            f"{peer.profile} prefers {pt} "
            f"({peer.score_of(pt):.2f}) over {lt} "
            f"({peer.score_of(lt):.2f})")
        self.history.append(dispute)
        return dispute

    @staticmethod
    def _intensities(lead: Opinion, peer: Opinion,
                     lt: str, pt: str) -> Tuple[float, float]:
        """How much each side cares, as a RELATIVE gap inside its own
        ranking. Scale-free on purpose: the two profiles score on the same
        scale, but their gap sizes mean different things, and an absolute
        threshold would make the rule fire on noise.

        Returns (lead_cost, peer_conviction): what the lead gives up by
        switching, and what the peer gains by switching.
        """
        lead_top = lead.score_of(lt) or 0.0
        lead_cand = lead.score_of(pt)
        peer_top = peer.score_of(pt) or 0.0
        peer_lt = peer.score_of(lt) or 0.0
        if lead_cand is None or lead_top <= 0 or peer_top <= 0:
            return 0.0, 0.0
        lead_cost = max(0.0, (lead_top - lead_cand) / abs(lead_top))
        peer_conv = max(0.0, (peer_top - peer_lt) / abs(peer_top))
        return lead_cost, peer_conv

    # ── introspection ──────────────────────────────────────────────────
    def disagreements(self) -> List[Dispute]:
        return [d for d in self.history if not d.agreed]

    def stats(self) -> dict:
        return {
            "lead": self.lead_profile.name,
            "peer": self.peer_profile.name,
            "rounds": len(self.history),
            "disagreements": len(self.disagreements()),
            "peer_wins": sum(1 for d in self.history if d.winner == "peer"),
        }
