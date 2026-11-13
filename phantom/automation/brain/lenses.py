"""
phantom.automation.brain.lenses — the reasoning core (R1/R2/R3).

Before this module the agent decided with ONE formula:

    priority = (1 - risk) / opsec_cost   x   success_prior

That is a *fixed* function: the same two terms at second 1 and at minute 40,
on a quiet recon and on an engagement that already tripped the noise
breaker. It cannot be wrong in the small — it can only be context-blind.

This module replaces it with an explicit, auditable arbitration:

    SIGNALS  — what is happening to the engagement RIGHT NOW: visibility,
               noise budget, foothold, stall class, stage, goal. Recomputed
               at EVENTS, never continuously: a decision must be
               reproducible from a STATE, not from a stopwatch.
    LENSES   — five independent readings of one capability: progress,
               success, evidence, stealth, collateral.
    WEIGHTS  — how much each lens counts right now, as a function of the
               signals: stealth weighs more when the noise breaker trips,
               evidence weighs more when nothing has been seen yet.
    ARBITER  — combines lenses x weights into one value, RECORDS why (the
               driving lens and the runner-up), and can HARD-VETO a loud
               move once the stealth lens says the budget is gone.

Diversity (the sub-agent design): a ReasoningProfile is a named weight
vector + search policy + seed. Two profiles on the SAME task disagree
PRODUCTIVELY — "balanced" maximizes expected success, "evidence_first"
buys discriminating information. Same engine, same rules, different
objective, so a second opinion is never a duplicate execution.

Info-gain discipline (R3): the evidence lens rewards a capability that is
named by an OPEN hypothesis, but the reward is bounded (<= 0.15) so it can
only reorder moves that were already within ~15% of each other — i.e.
exactly "when the hypotheses are uncertain". When one path is clearly
ahead, the run goes straight at it.

Learning discipline (bandit): within a run the weights move only through
these EVENTS; the outcome feedback (cross-engagement priors) may nudge a
weight by a bounded amount and never inside the run.

Discipline: every Decision carries its own explanation. A dynamic reasoner
that cannot name the lens that drove it is just a different black box.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ── the five lenses ────────────────────────────────────────────────────────

LENSES: Tuple[str, ...] = ("progress", "success", "evidence", "stealth",
                           "collateral")

# how far the arbitration may move a move's value: a BOUNDED modulation, so
# a state signal can reorder near-ties but can never silently overturn the
# kill-chain ordering (the pre-service scan keeps its dominance) or turn a
# forbidden move into an affordable one. Read it as the arbiter's JURISDICTION:
# two moves within a factor 1.40/0.60 = 2.33 of each other are decided by the
# lenses; anything further apart is decided by the expected value, and the
# lenses can only shade it.
MODULATION_FLOOR = 0.60
MODULATION_CEIL = 1.40

# info-gain can only matter inside this band (R3 decision: "solo a ipotesi
# incerte"). It is a multiplier on the move's OWN value, so a bounded reward
# can, by construction, only overturn a gap narrower than the band itself:
# 15% for a balanced operator, wider for an investigator profile that has
# explicitly accepted a slower chain.
INFO_GAIN_MAX = 0.15
INFO_GAIN_CEIL = 0.30


@dataclass(frozen=True)
class ReasoningProfile:
    """A named objective: which lenses an agent cares about, and how.

    `weights` are the BASE weights (before signal adaptation) and are
    normalised on construction. `search_policy` names the search MODE the
    cell runs in (breadth = widen the surface, depth = finish a promising
    thread, identity = change who we are). `seed` only breaks exact ties,
    so two profiles differ by objective and not by dice.
    """

    name: str
    weights: Tuple[Tuple[str, float], ...]
    search_policy: str = "adaptive"
    info_gain_bias: float = 1.0
    seed: int = 0
    # noise ratio (noise_score / NOISE_LIMIT) at which the stealth lens gets
    # a HARD veto on loud moves. 1.0 = only once the breaker tripped.
    veto_above: float = 1.0

    def __post_init__(self) -> None:
        total = sum(max(0.0, w) for _n, w in self.weights)
        if total <= 0:
            object.__setattr__(self, "weights", ((LENSES[0], 1.0),))
            return
        object.__setattr__(self, "weights",
                           tuple((n, max(0.0, w) / total)
                                 for n, w in self.weights))

    def weight_of(self, lens: str) -> float:
        for name, w in self.weights:
            if name == lens:
                return w
        return 0.0

    def to_dict(self) -> dict:
        return {"profile": self.name, "weights": dict(self.weights),
                "search_policy": self.search_policy,
                "info_gain_bias": self.info_gain_bias, "seed": self.seed,
                "veto_above": self.veto_above}


# The catalogue. `balanced` and `evidence_first` are deliberately
# complementary: pairing them is what makes a second advisory agent worth
# its thread instead of a duplicate.
PROFILES: Dict[str, ReasoningProfile] = {
    "balanced": ReasoningProfile(
        "balanced",
        (("progress", 0.30), ("success", 0.25), ("evidence", 0.20),
         ("stealth", 0.20), ("collateral", 0.05)),
        search_policy="adaptive"),
    # the quiet operator: same target, much lower tolerance for noise. The
    # veto fires earlier because `veto_above` is below the trip point.
    "stealth_first": ReasoningProfile(
        "stealth_first",
        (("progress", 0.18), ("success", 0.18), ("evidence", 0.12),
         ("stealth", 0.44), ("collateral", 0.08)),
        search_policy="depth", veto_above=0.70),
    # the investigator: buys information first, accepts a slower chain.
    "evidence_first": ReasoningProfile(
        "evidence_first",
        (("progress", 0.16), ("success", 0.16), ("evidence", 0.42),
         ("stealth", 0.20), ("collateral", 0.06)),
        search_policy="breadth", info_gain_bias=1.6),
    # the loud one: only ever selected with --aggressive.
    "force_first": ReasoningProfile(
        "force_first",
        (("progress", 0.34), ("success", 0.30), ("evidence", 0.16),
         ("stealth", 0.06), ("collateral", 0.14)),
        search_policy="adaptive", veto_above=1.6),
}

# the complementary pair used when the orchestrator puts a SECOND agent on
# the same task (advisory): it must reason differently by construction.
ADVERSARIAL_PAIR: Dict[str, str] = {
    "balanced": "evidence_first",
    "evidence_first": "balanced",
    "stealth_first": "evidence_first",
    "force_first": "balanced",
}


def profile_for(name: str) -> ReasoningProfile:
    return PROFILES.get(name, PROFILES["balanced"])


def choose_profile(profile: str = "enterprise", paranoid: bool = False,
                   aggressive: bool = False, speed: bool = False,
                   explicit: str = "") -> ReasoningProfile:
    """The run's profile from the operator's flags (deterministic order).

    An explicit `--reason` wins; otherwise aggressive runs take force_first
    and paranoid runs take stealth_first, and everything else gets
    balanced. Speed does NOT lower stealth tolerance: fast is a timing
    choice, not a licence to be loud.
    """
    if explicit and explicit in PROFILES:
        return PROFILES[explicit]
    if aggressive:
        return PROFILES["force_first"]
    if paranoid:
        return PROFILES["stealth_first"]
    return PROFILES["balanced"]


def adversarial_profile(base: ReasoningProfile) -> ReasoningProfile:
    """The profile a second agent on the SAME task should reason with."""
    name = ADVERSARIAL_PAIR.get(base.name, "evidence_first")
    other = profile_for(name)
    if other.name == base.name:                      # degenerate: flip seed
        return ReasoningProfile(
            base.name + "+", base.weights, base.search_policy,
            base.info_gain_bias * 1.4, seed=(base.seed ^ 0x5F3759DF),
            veto_above=base.veto_above)
    return other


# ── signals: the event-driven state the weights adapt to ───────────────────

@dataclass
class WorldSignals:
    """What the engagement looks like at THIS decision point.

    Every field is derived from state (findings, noise score, stall class,
    stage) and never from elapsed time, so two runs in the same state
    arbitrate identically.
    """

    visibility: bool = False          # any service/web surface observed
    noise_ratio: float = 0.0          # noise_score / NOISE_LIMIT
    breaker_tripped: bool = False
    foothold: bool = False            # a beacon is already up
    creds: bool = False
    stall_class: str = ""             # brain/stall.py verdict, "" if none
    stage: str = ""                   # current kill-chain stage
    threat_intel_hot: bool = False    # a matched CVE is exploited in the wild

    def to_dict(self) -> dict:
        return {"visibility": self.visibility,
                "noise_ratio": round(self.noise_ratio, 3),
                "breaker_tripped": self.breaker_tripped,
                "foothold": self.foothold, "creds": self.creds,
                "stall": self.stall_class, "stage": self.stage,
                "threat_intel_hot": self.threat_intel_hot}


def signals_from(wm: Any, stage: str = "", stall_class: str = "",
                 threat_intel_hot: bool = False) -> WorldSignals:
    """Build the signal set from a WorldModel. Never raises: a missing
    attribute means "unknown", which adapts to the neutral value."""
    sig = WorldSignals(stage=stage, stall_class=stall_class,
                       threat_intel_hot=threat_intel_hot)
    try:
        findings = list(wm.all_findings())
        kinds = {f.kind for f in findings}
        sig.visibility = bool(kinds & {"service", "web_app", "web_header",
                                       "banner", "os"})
        sig.foothold = "beacon" in kinds
        sig.creds = bool(wm.find("creds", valid=True))
    except Exception:
        pass
    try:
        limit = float(getattr(wm, "NOISE_LIMIT", 10.0) or 10.0)
        score = float(getattr(wm, "noise_score", 0.0) or 0.0)
        sig.noise_ratio = score / limit if limit > 0 else 0.0
        sig.breaker_tripped = bool(wm.noise_breaker_tripped())
    except Exception:
        sig.breaker_tripped = False
    return sig


# ── weights: signals -> how much each lens counts now ──────────────────────

# (condition, lens, multiplier). The table IS the adaptation policy: reading
# it tells you exactly when the agent changes its mind, which is the whole
# point of doing this in events rather than continuously.
_ADAPTATIONS: Tuple[Tuple[str, str, float], ...] = (
    # the engagement is already loud: buy quiet, stop widening
    ("breaker_tripped", "stealth", 2.20),
    ("breaker_tripped", "collateral", 1.60),
    ("breaker_tripped", "evidence", 0.70),
    ("breaker_tripped", "progress", 0.60),
    # approaching the breaker: lean quiet before we trip it
    ("noise_high", "stealth", 1.40),
    ("noise_high", "evidence", 0.85),
    # nothing seen yet: information first, noise is worthless if blind
    ("blind", "evidence", 1.55),
    ("blind", "progress", 0.90),
    # we already own a foothold: do not gamble it away
    ("foothold", "collateral", 1.55),
    ("foothold", "stealth", 1.30),
    ("foothold", "progress", 0.70),
    # stall classes (brain/stall.py) each bias a different lens
    ("stall_blocked", "stealth", 1.55),
    ("stall_blocked", "evidence", 1.15),
    ("stall_visibility", "evidence", 1.60),
    ("stall_model", "evidence", 1.40),
    ("stall_altitude", "evidence", 1.20),
    ("stall_altitude", "collateral", 1.20),
    # post-exploitation touches the client's real systems: weigh blast radius
    ("stage_post", "collateral", 1.30),
    # threat intel: a matched, actively-exploited CVE is a narrow window
    ("threat_hot", "progress", 1.20),
)


def _conditions(sig: WorldSignals) -> set:
    conds = set()
    if sig.breaker_tripped:
        conds.add("breaker_tripped")
    if sig.noise_ratio >= 0.60:
        conds.add("noise_high")
    if not sig.visibility:
        conds.add("blind")
    if sig.foothold:
        conds.add("foothold")
    if sig.stall_class == "blocked":
        conds.add("stall_blocked")
    if sig.stall_class == "no_visibility":
        conds.add("stall_visibility")
    if sig.stall_class == "wrong_model":
        conds.add("stall_model")
    if sig.stall_class == "wrong_altitude":
        conds.add("stall_altitude")
    if sig.stage in ("post_exploit", "expand", "ad", "lateral", "crack"):
        conds.add("stage_post")
    if sig.threat_intel_hot:
        conds.add("threat_hot")
    return conds


def adapt_weights(profile: ReasoningProfile,
                  sig: WorldSignals) -> Dict[str, float]:
    """Base weights -> weights for THIS state. Deterministic, normalised."""
    raw = {lens: max(1e-6, profile.weight_of(lens)) for lens in LENSES}
    conds = _conditions(sig)
    for cond, lens, factor in _ADAPTATIONS:
        if cond in conds:
            raw[lens] = raw.get(lens, 0.0) * factor
    total = sum(raw.values()) or 1.0
    return {lens: raw[lens] / total for lens in LENSES}


def nudge_from_priors(weights: Dict[str, float],
                      stealth_success: Optional[float] = None,
                      loud_success: Optional[float] = None) -> Dict[str, float]:
    """Learning discipline (bandit): cross-engagement outcome feedback may
    move the stealth weight by a BOUNDED amount, and only BETWEEN runs.

    `stealth_success` / `loud_success` are the historical success rates of
    quiet vs loud moves against this target class. The nudge is capped at
    +/-25% of the stealth weight so a small sample can never rewrite the
    policy, and a missing sample means no movement at all.
    """
    if stealth_success is None or loud_success is None:
        return dict(weights)
    out = dict(weights)
    try:
        s = max(0.0, min(1.0, float(stealth_success)))
        l = max(0.0, min(1.0, float(loud_success)))
    except (TypeError, ValueError):
        return out
    edge = s - l                                   # >0: quiet pays off
    factor = 1.0 + max(-0.25, min(0.25, edge * 0.25))
    out["stealth"] = out.get("stealth", 0.0) * factor
    total = sum(out.values()) or 1.0
    return {k: v / total for k, v in out.items()}


# ── the decision record ────────────────────────────────────────────────────

@dataclass
class Decision:
    """One arbitrated move, with the reason attached.

    `driver` is the lens that contributed most relative to its weight (the
    one that MADE the decision), `runner_up` the second. `veto` is set when
    the stealth lens refuses the move outright.
    """

    capability: str
    base: float
    value: float
    lens_scores: Dict[str, float] = field(default_factory=dict)
    weights: Dict[str, float] = field(default_factory=dict)
    driver: str = ""
    runner_up: str = ""
    contributions: Dict[str, float] = field(default_factory=dict)
    profile: str = ""
    search_policy: str = "adaptive"
    signals: Dict[str, Any] = field(default_factory=dict)
    veto: str = ""
    notes: List[str] = field(default_factory=list)

    @property
    def vetoed(self) -> bool:
        return bool(self.veto)

    def explain(self) -> str:
        """One auditable line: what drove it, how much, and why."""
        if self.veto:
            return (f"{self.capability}: VETOED by the stealth lens "
                    f"({self.veto})")
        top = ", ".join(f"{k}={v:.2f}"
                        for k, v in sorted(self.contributions.items(),
                                           key=lambda kv: -kv[1])[:2])
        band = f"x{self.value / self.base:.2f}" if self.base else "n/a"
        extra = f" [{'; '.join(self.notes)}]" if self.notes else ""
        return (f"{self.capability}: {self.base:.2f} -> {self.value:.2f} "
                f"({band}) driven by {self.driver}"
                f"{f' (runner-up {self.runner_up})' if self.runner_up else ''}"
                f" [{top}] profile={self.profile}{extra}")

    def to_dict(self) -> dict:
        return {"capability": self.capability, "base": round(self.base, 4),
                "value": round(self.value, 4), "driver": self.driver,
                "runner_up": self.runner_up,
                "lens_scores": {k: round(v, 4)
                                for k, v in self.lens_scores.items()},
                "weights": {k: round(v, 4) for k, v in self.weights.items()},
                "contributions": {k: round(v, 4)
                                  for k, v in self.contributions.items()},
                "profile": self.profile, "search_policy": self.search_policy,
                "signals": self.signals, "veto": self.veto,
                "notes": list(self.notes)}


# ── capability view: the lens inputs ───────────────────────────────────────

# kill-chain position per capability category: the progress lens measures
# how close a move is to the stage the run is actually in.
_CATEGORY_RANK = {
    "recon": 0, "scan": 0, "osint": 0, "social": 0, "identity": 0,
    "web": 1, "hunt": 1,
    "exploit": 2, "brute": 3, "access": 3,
    "post": 4, "ad": 4, "cloud": 4, "mobile": 4, "payload": 2,
}
_STAGE_RANK = {
    "": 0, "identity": 0, "footprint": 0, "environment": 0, "cloud_creds": 3,
    "exploit": 2, "beacon": 3, "deliver": 3, "post_exploit": 4, "expand": 4,
    "ad": 4, "crack": 4, "lateral": 4, "cloud": 4, "mobile": 4,
    "complete_kill_chain": 3, "harvest": 4, "evasion": 4,
}

# categories whose blast radius reaches past the target itself
_WIDE_BLAST = {"brute": 0.35, "scan": 0.55, "exploit": 0.45, "ad": 0.35,
               "hunt": 0.5, "payload": 0.4, "social": 0.6}
_QUIET_BLAST = 0.95


@dataclass
class CapabilityView:
    """The lens-facing view of a capability (no command strings involved)."""

    id: str
    category: str = "recon"
    opsec_cost: float = 1.0
    detection_risk: float = 0.2
    stealth_level: str = "active"
    forceful: bool = False
    effects: Tuple[str, ...] = ()
    goal_facts: Tuple[str, ...] = ()
    success_prior: float = 1.0        # ~0.5..1.5 multiplier from the priors
    in_open_hypothesis: bool = False  # named by an unresolved hypothesis


def view_of(step: Any, goal_facts: Sequence[str] = (),
            success_prior: float = 1.0,
            open_hypothesis_caps: Sequence[str] = ()) -> CapabilityView:
    """Build the view from a PlanStep (or anything with `.capability`)."""
    cap = getattr(step, "capability", step)
    cid = str(getattr(cap, "id", "") or "")
    return CapabilityView(
        id=cid,
        category=str(getattr(cap, "category", "recon") or "recon"),
        opsec_cost=float(getattr(cap, "opsec_cost", 1.0) or 1.0),
        detection_risk=float(getattr(cap, "detection_risk", 0.2) or 0.0),
        stealth_level=str(getattr(cap, "stealth_level", "active") or "active"),
        forceful=bool(getattr(cap, "forceful", False)),
        effects=tuple(str(e) for e in (getattr(cap, "effects", ()) or ())),
        goal_facts=tuple(str(g) for g in (goal_facts or ())),
        success_prior=float(success_prior or 1.0),
        in_open_hypothesis=cid in set(open_hypothesis_caps or ()),
    )


def lens_scores(view: CapabilityView,
                sig: WorldSignals) -> Dict[str, float]:
    """The five readings of one capability in this world state (each 0..1).

    progress   — does this move advance the stage the run is in
    success    — the learned/historical probability it works here
    evidence   — how much discriminating information it buys
    stealth    — how quiet it is against the detection model
    collateral — one minus the blast radius (does it touch only the target)
    """
    # progress: distance between the capability's chain position and the
    # stage we are in, plus a bonus when it can produce the goal fact itself
    rank = _CATEGORY_RANK.get(view.category, 2)
    stage_rank = _STAGE_RANK.get(sig.stage, 0)
    progress = 1.0 - min(1.0, abs(rank - stage_rank) / 4.0)
    if view.goal_facts and set(view.effects) & set(view.goal_facts):
        progress = min(1.0, progress + 0.30)
    if not sig.visibility and "service" in view.effects:
        progress = 1.0                      # the scan that opens the chain

    # success: the prior multiplier mapped onto 0..1 (0.5x -> 0.33, 1.5x -> 1)
    success = max(0.0, min(1.0, (view.success_prior - 0.25) / 1.25))

    # evidence: does this move produce information we do not have. The
    # DISCRIMINATION bonus for an open hypothesis is NOT here on purpose —
    # it lives in the arbiter as one bounded multiplier, so the info-gain
    # effect has exactly one source (and one test).
    evidence = 0.45
    if view.effects:
        evidence += 0.15
    if not sig.visibility and view.category in ("recon", "identity", "osint"):
        evidence = min(1.0, evidence + 0.15)

    # stealth: the detection model, plus the opsec the move spends
    stealth = 1.0 - max(0.0, min(1.0, view.detection_risk))
    stealth -= max(0.0, min(0.5, (view.opsec_cost - 1.0) / 20.0))
    if view.stealth_level == "aggressive":
        stealth -= 0.20
    if view.forceful:
        stealth -= 0.15
    stealth = max(0.05, min(1.0, stealth))

    # collateral: how much of the world outside the target this move touches
    collateral = _WIDE_BLAST.get(view.category, _QUIET_BLAST)
    if not view.forceful and view.stealth_level == "passive":
        collateral = min(1.0, collateral + 0.10)
    if view.forceful:
        collateral = max(0.05, collateral - 0.20)

    return {"progress": round(progress, 4), "success": round(success, 4),
            "evidence": round(evidence, 4), "stealth": round(stealth, 4),
            "collateral": round(collateral, 4)}


# ── the arbiter ────────────────────────────────────────────────────────────

class Arbitrator:
    """Scores a capability with lenses x weights, and says WHY.

    `base` is the legacy expected-value number (kept as the *scale* so the
    kill-chain ordering and the post-exploitation penalty survive); the
    arbitration applies a BOUNDED, state-dependent modulation on top and can
    refuse the move outright.
    """

    def __init__(self, profile: Optional[ReasoningProfile] = None,
                 enabled: bool = True) -> None:
        self.profile = profile or profile_for("balanced")
        self.enabled = enabled
        self._count = 0
        self._vetoes = 0

    # -- weights ---------------------------------------------------------
    def weights_for(self, sig: WorldSignals) -> Dict[str, float]:
        """Adapted weights for this state. Cached per signal signature so a
        planning pass that scores 40 candidates computes the vector once."""
        key = hashlib.sha256(repr(sorted(sig.to_dict().items()))
                             .encode("utf-8", "replace")).hexdigest()[:16]
        cached = getattr(self, "_cache", None)
        if cached and cached[0] == key:
            return cached[1]
        w = adapt_weights(self.profile, sig)
        self._cache = (key, w)
        return w

    # -- veto ------------------------------------------------------------
    def hard_veto(self, view: CapabilityView,
                  sig: WorldSignals) -> str:
        """The stealth lens' HARD veto: returns the reason, or "".

        Fires only when the engagement is at/over the profile's noise
        threshold AND the move is genuinely loud (aggressive or forceful, or
        a detection risk the detection model already rates high). It is
        deliberately narrow: the point is to stop the engagement from
        spending the last of its quiet on a marginal move, not to freeze a
        run that has no other path.
        """
        if not self.enabled:
            return ""
        if sig.noise_ratio < self.profile.veto_above:
            return ""
        loud = (view.stealth_level == "aggressive" or view.forceful
                or view.detection_risk >= 0.60)
        if not loud:
            return ""
        return (f"engagement noise at {sig.noise_ratio:.2f} of budget "
                f"(profile {self.profile.name} vetoes above "
                f"{self.profile.veto_above:.2f})")

    # -- evaluate --------------------------------------------------------
    def evaluate(self, view: CapabilityView, base: float,
                 sig: WorldSignals) -> Decision:
        """One arbitrated value + its explanation."""
        weights = self.weights_for(sig)
        scores = lens_scores(view, sig)
        contrib = {lens: weights.get(lens, 0.0) * scores.get(lens, 0.0)
                   for lens in LENSES}
        ordered = sorted(contrib.items(), key=lambda kv: (-kv[1], kv[0]))
        driver = ordered[0][0] if ordered else ""
        runner = ordered[1][0] if len(ordered) > 1 else ""

        decision = Decision(
            capability=view.id, base=base, value=base,
            lens_scores=scores, weights=weights, driver=driver,
            runner_up=runner, contributions=contrib,
            profile=self.profile.name, search_policy=self.profile.search_policy,
            signals=sig.to_dict(),
        )

        veto = self.hard_veto(view, sig)
        if veto:
            decision.veto = veto
            # sink it so a scheduler that ignores the veto still deprioritises
            decision.value = min(0.0, base) - 1.0 if base >= 0 else base
            self._vetoes += 1
            return decision

        if not self.enabled:
            return decision

        # bounded modulation: `mod` is the weighted quality of the move
        mod = sum(contrib.values())
        factor = MODULATION_FLOOR + (MODULATION_CEIL - MODULATION_FLOOR) * \
            max(0.0, min(1.0, mod))
        decision.value = base * factor
        if view.in_open_hypothesis:
            # R3: a probe that DISCRIMINATES between live beliefs is worth
            # more. The reward is bounded by the profile's own tolerance, so
            # it can only overturn a gap narrower than the band —
            # "solo a ipotesi incerte", enforced by construction rather than
            # by a comparison against a leader the arbiter cannot see.
            band = min(INFO_GAIN_CEIL, INFO_GAIN_MAX * self.profile.info_gain_bias)
            decision.value *= (1.0 + band)
            decision.notes.append(
                f"info-gain +{band * 100:.0f}%: discriminates an open "
                "hypothesis")
        self._count += 1
        return decision

    # -- search policy ---------------------------------------------------
    def search_policy(self, sig: WorldSignals) -> str:
        """The search MODE for this state (R1: stall-driven, from
        brain/stall.py's own vocabulary, promoted from "canned moves" to the
        cell's mode)."""
        if sig.stall_class == "no_visibility":
            return "breadth"
        if sig.stall_class == "wrong_model":
            return "depth"          # re-probe the thing we mis-modelled
        if sig.stall_class == "blocked":
            return "identity"       # change who we are, not what we send
        if sig.stall_class == "wrong_altitude":
            return "breadth"        # widen to adjacent surface
        if not sig.visibility:
            return "breadth"
        return self.profile.search_policy

    def stats(self) -> dict:
        return {"profile": self.profile.name, "decisions": self._count,
                "vetoes": self._vetoes}
