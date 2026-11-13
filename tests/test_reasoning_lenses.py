"""R1/R2/R3 acceptance tests — the adaptive reasoning core.

The claims under test are the design ones, not tautologies:

  R1  weights ADAPT to the engagement state (events, not a clock) and are
      reproducible for the same state
  R2  the arbitration is a BOUNDED modulation (it reorders near-ties and
      never overturns the kill-chain ordering) plus a NARROW hard veto once
      the noise budget is spent
  R3  the info-gain reward for a discriminating probe can only flip
      near-ties ("solo a ipotesi incerte"), never a clearly-beaten move
  D   two profiles on the same move disagree by construction (the diversity
      the sub-agent design needs), and the search MODE follows the stall
      class instead of a canned move list
"""

import pytest

from phantom.automation.brain.lenses import (
    INFO_GAIN_MAX,
    LENSES,
    MODULATION_CEIL,
    MODULATION_FLOOR,
    Arbitrator,
    CapabilityView,
    ReasoningProfile,
    WorldSignals,
    adapt_weights,
    adversarial_profile,
    choose_profile,
    lens_scores,
    nudge_from_priors,
    profile_for,
    signals_from,
    view_of,
)


def _view(cid="scan_tcp", category="recon", **kw):
    base = dict(id=cid, category=category, opsec_cost=1.0,
                detection_risk=0.2, stealth_level="active", effects=("service",))
    base.update(kw)
    return CapabilityView(**base)


# ── R1: adaptation ─────────────────────────────────────────────────────────

def test_weights_sum_to_one_and_cover_every_lens():
    for name in ("balanced", "stealth_first", "evidence_first", "force_first"):
        w = adapt_weights(profile_for(name), WorldSignals())
        assert set(w) == set(LENSES)
        assert abs(sum(w.values()) - 1.0) < 1e-9


def test_blind_engagement_raises_the_evidence_weight():
    p = profile_for("balanced")
    calm = adapt_weights(p, WorldSignals(visibility=True))
    blind = adapt_weights(p, WorldSignals(visibility=False))
    assert blind["evidence"] > calm["evidence"]
    assert blind["progress"] <= calm["progress"]


def test_noise_breaker_tripped_raises_stealth_and_lowers_progress():
    p = profile_for("balanced")
    quiet = adapt_weights(p, WorldSignals(visibility=True, noise_ratio=0.0))
    loud = adapt_weights(p, WorldSignals(visibility=True, noise_ratio=1.2,
                                         breaker_tripped=True))
    assert loud["stealth"] > quiet["stealth"] * 2
    assert loud["progress"] < quiet["progress"]


def test_foothold_makes_collateral_count_more_than_progress():
    p = profile_for("balanced")
    before = adapt_weights(p, WorldSignals(visibility=True))
    after = adapt_weights(p, WorldSignals(visibility=True, foothold=True))
    assert after["collateral"] > before["collateral"]
    assert after["progress"] < before["progress"]


def test_stall_class_moves_the_weight_vector():
    p = profile_for("balanced")
    vis = adapt_weights(p, WorldSignals(visibility=True))
    no_vis = adapt_weights(p, WorldSignals(visibility=True,
                                           stall_class="no_visibility"))
    blocked = adapt_weights(p, WorldSignals(visibility=True,
                                            stall_class="blocked"))
    assert no_vis["evidence"] > vis["evidence"]
    assert blocked["stealth"] > vis["stealth"]


def test_weights_are_reproducible_for_the_same_state():
    a = Arbitrator(profile_for("balanced"))
    sig = WorldSignals(visibility=True, noise_ratio=0.7)
    assert a.weights_for(sig) == a.weights_for(WorldSignals(visibility=True,
                                                            noise_ratio=0.7))


def test_signals_read_the_world_model_state():
    class _WM:
        noise_score = 5.0
        NOISE_LIMIT = 10.0

        def all_findings(self):
            class F:
                kind = "service"
            return [F()]

        def noise_breaker_tripped(self):
            return False

        def find(self, kind, **kw):
            return []

    sig = signals_from(_WM())
    assert sig.visibility is True
    assert abs(sig.noise_ratio - 0.5) < 1e-9
    assert sig.breaker_tripped is False


def test_signals_survive_a_hostile_world_model():
    class _Broken:
        def all_findings(self):
            raise RuntimeError("boom")

        def noise_breaker_tripped(self):
            raise RuntimeError("boom")

        def find(self, *a, **k):
            raise RuntimeError("boom")

    sig = signals_from(_Broken())          # must not raise
    assert sig.visibility is False
    assert sig.noise_ratio == 0.0


# ── R2: bounded modulation + narrow veto ───────────────────────────────────

def test_modulation_stays_inside_the_declared_band():
    arb = Arbitrator(profile_for("balanced"))
    sig = WorldSignals(visibility=True)
    for base in (0.5, 1.0, 3.0, 12.0):
        d = arb.evaluate(_view(), base, sig)
        assert base * MODULATION_FLOOR - 1e-9 <= d.value <= base * MODULATION_CEIL + 1e-9


def test_the_kill_chain_ordering_survives_any_modulation():
    """The pre-service scan keeps its dominance: the band is narrower than
    the gap the planner uses to put the footprint scan first."""
    arb = Arbitrator(profile_for("balanced"))
    sig = WorldSignals(visibility=False)
    scan = arb.evaluate(_view("scan_tcp"), 100.0, sig)
    other = arb.evaluate(_view("http_probe", detection_risk=0.05,
                               opsec_cost=0.5), 2.0, sig)
    assert scan.value > other.value


def test_quiet_move_is_not_vetoed_even_with_the_breaker_tripped():
    arb = Arbitrator(profile_for("balanced"))
    sig = WorldSignals(visibility=True, noise_ratio=1.5, breaker_tripped=True)
    quiet = arb.evaluate(_view("http_probe", detection_risk=0.05), 3.0, sig)
    assert quiet.vetoed is False


def test_loud_move_is_vetoed_once_the_budget_is_spent():
    arb = Arbitrator(profile_for("balanced"))
    sig = WorldSignals(visibility=True, noise_ratio=1.5, breaker_tripped=True)
    loud = arb.evaluate(_view("cred_spray", category="brute",
                              stealth_level="aggressive",
                              detection_risk=0.9), 3.0, sig)
    assert loud.vetoed is True
    assert "noise" in loud.veto
    assert loud.value < 0                       # sunk out of the queue


def test_veto_is_narrow_below_the_threshold():
    arb = Arbitrator(profile_for("balanced"))
    sig = WorldSignals(visibility=True, noise_ratio=0.5)
    loud = arb.evaluate(_view("cred_spray", category="brute",
                              stealth_level="aggressive",
                              detection_risk=0.9), 3.0, sig)
    assert loud.vetoed is False


def test_stealth_first_profile_vetoes_earlier_than_balanced():
    view = _view("weird_probe", category="hunt", detection_risk=0.65)
    sig = WorldSignals(visibility=True, noise_ratio=0.80)
    assert Arbitrator(profile_for("stealth_first")).evaluate(
        view, 2.0, sig).vetoed is True
    assert Arbitrator(profile_for("balanced")).evaluate(
        view, 2.0, sig).vetoed is False


def test_decision_explains_itself():
    arb = Arbitrator(profile_for("balanced"))
    d = arb.evaluate(_view(), 2.0, WorldSignals(visibility=True))
    assert d.driver in LENSES
    assert d.runner_up in LENSES
    assert d.driver != d.runner_up
    line = d.explain()
    assert "scan_tcp" in line and d.driver in line
    as_dict = d.to_dict()
    assert as_dict["driver"] == d.driver
    assert set(as_dict["weights"]) == set(LENSES)


# ── R3: info-gain only inside the uncertain band ──────────────────────────

def test_discriminating_probe_wins_a_near_tie():
    arb = Arbitrator(profile_for("balanced"))
    sig = WorldSignals(visibility=True)
    # 5% apart: the arbiter may reorder these (they are a near-tie)
    strong = arb.evaluate(_view("a-strong", detection_risk=0.20), 1.05, sig)
    disc = arb.evaluate(_view("b-disc", detection_risk=0.22,
                              in_open_hypothesis=True), 1.00, sig)
    assert disc.value > strong.value


def test_discriminating_probe_cannot_overturn_a_clear_leader():
    arb = Arbitrator(profile_for("balanced"))
    sig = WorldSignals(visibility=True)
    strong = arb.evaluate(_view("a-strong", detection_risk=0.20), 2.00, sig)
    disc = arb.evaluate(_view("b-disc", detection_risk=0.22,
                              in_open_hypothesis=True), 1.00, sig)
    assert strong.value > disc.value


def test_info_gain_reward_is_bounded_by_the_declared_band():
    """The reward is a fraction of the move's OWN value, and cannot exceed
    the profile's tolerance — which is what makes "only near-ties" a
    property of the code rather than of a comment."""
    arb = Arbitrator(profile_for("balanced"))
    sig = WorldSignals(visibility=True)
    plain = arb.evaluate(_view("x"), 1.0, sig).value
    disc = arb.evaluate(_view("x", in_open_hypothesis=True), 1.0, sig).value
    assert disc > plain
    assert disc / plain <= 1.0 + INFO_GAIN_MAX + 1e-9


def test_info_gain_band_is_wider_for_the_investigator_profile():
    sig = WorldSignals(visibility=True)
    bal = Arbitrator(profile_for("balanced"))
    inv = Arbitrator(profile_for("evidence_first"))
    v = _view("x")
    hot = _view("x", in_open_hypothesis=True)
    bal_band = bal.evaluate(hot, 1.0, sig).value / bal.evaluate(v, 1.0, sig).value
    inv_band = inv.evaluate(hot, 1.0, sig).value / inv.evaluate(v, 1.0, sig).value
    assert inv_band > bal_band


# ── diversity (the sub-agent second opinion) ──────────────────────────────

def test_two_profiles_disagree_about_the_same_move():
    sig = WorldSignals(visibility=True)
    view = _view("service_exploit", category="exploit",
                 detection_risk=0.8, opsec_cost=6.0)
    balanced = Arbitrator(profile_for("balanced")).evaluate(view, 1.0, sig)
    secretive = Arbitrator(profile_for("stealth_first")).evaluate(view, 1.0, sig)
    assert balanced.value != secretive.value
    assert secretive.value < balanced.value          # quieter objective


def test_adversarial_profile_differs_from_its_base():
    base = profile_for("balanced")
    other = adversarial_profile(base)
    assert other.name != base.name
    assert other.weights != base.weights


def test_adversarial_profile_never_returns_the_same_profile():
    for name in ("balanced", "evidence_first", "stealth_first", "force_first"):
        base = profile_for(name)
        assert adversarial_profile(base).name != base.name


def test_choose_profile_follows_the_operator_flags():
    assert choose_profile(aggressive=True).name == "force_first"
    assert choose_profile(paranoid=True).name == "stealth_first"
    assert choose_profile().name == "balanced"
    assert choose_profile(explicit="evidence_first").name == "evidence_first"
    # speed is a timing choice, not a licence to be loud
    assert choose_profile(speed=True).name == "balanced"


# ── search mode from the stall class ─────────────────────────────────────

def test_search_mode_follows_the_stall_class():
    arb = Arbitrator(profile_for("balanced"))
    assert arb.search_policy(WorldSignals(visibility=True,
                                          stall_class="no_visibility")) == "breadth"
    assert arb.search_policy(WorldSignals(visibility=True,
                                          stall_class="wrong_model")) == "depth"
    assert arb.search_policy(WorldSignals(visibility=True,
                                          stall_class="blocked")) == "identity"
    assert arb.search_policy(WorldSignals(visibility=True,
                                          stall_class="wrong_altitude")) == "breadth"
    # no stall: the profile's own policy applies
    assert arb.search_policy(WorldSignals(visibility=True)) == "adaptive"


# ── learning discipline (bandit: bounded, cross-run only) ─────────────────

def test_prior_nudge_is_bounded_and_needs_both_samples():
    w = adapt_weights(profile_for("balanced"), WorldSignals(visibility=True))
    assert nudge_from_priors(w) == w                 # no samples: no movement
    up = nudge_from_priors(w, stealth_success=1.0, loud_success=0.0)
    assert up["stealth"] <= w["stealth"] * 1.26
    down = nudge_from_priors(w, stealth_success=0.0, loud_success=1.0)
    assert down["stealth"] >= w["stealth"] * 0.74
    assert abs(sum(up.values()) - 1.0) < 1e-9


# ── lens readings ─────────────────────────────────────────────────────────

def test_lens_readings_are_distinguishable():
    quiet = lens_scores(_view("http_probe", detection_risk=0.05),
                        WorldSignals(visibility=True))
    loud = lens_scores(_view("cred_spray", category="brute",
                             detection_risk=0.9, forceful=True),
                       WorldSignals(visibility=True))
    assert quiet["stealth"] > loud["stealth"]
    assert quiet["collateral"] > loud["collateral"]


def test_view_of_reads_a_plan_step():
    class Cap:
        id = "scan_tcp"
        category = "recon"
        opsec_cost = 1.0
        detection_risk = 0.2
        stealth_level = "active"
        forceful = False
        effects = ("service",)

    class Step:
        capability = Cap()

    v = view_of(Step(), goal_facts=("service",), success_prior=1.2,
                open_hypothesis_caps=("scan_tcp",))
    assert v.id == "scan_tcp"
    assert v.in_open_hypothesis is True
    assert v.success_prior == 1.2


# ── integration with the agent (R1 wiring) ────────────────────────────────

def test_agent_exposes_the_reasoning_core():
    from phantom.automation.agent import AutonomousAgent

    agent = AutonomousAgent("10.0.0.5", registry=None)
    try:
        assert agent.arbiter is not None
        assert agent.reasoning_profile.name == "balanced"
        assert agent.search_policy() in ("adaptive", "breadth", "depth",
                                         "identity")
        agent._last_stall = "blocked"
        assert agent.search_policy() == "identity"
    finally:
        agent.close() if hasattr(agent, "close") else None


def test_agent_veto_blocks_a_loud_move_when_the_budget_is_spent():
    from phantom.automation.agent import AutonomousAgent

    agent = AutonomousAgent("10.0.0.5", registry=None)
    try:
        class Cap:
            id = "cred_spray"
            category = "brute"
            opsec_cost = 8.0
            detection_risk = 0.9
            stealth_level = "aggressive"
            forceful = True
            effects = ("creds",)

        # calm engagement: the veto stays silent
        assert agent._stealth_veto(Cap()) == ""
        # budget spent: the stealth lens refuses it
        agent.wm.noise_score = 999.0
        assert agent._stealth_veto(Cap()) != ""
    finally:
        pass


def test_agent_priority_keeps_the_kill_chain_ordering():
    """The R1 retrofit must not disturb the pre-service scan dominance."""
    from phantom.automation.agent import AutonomousAgent
    from phantom.automation.planner import PlanStep

    agent = AutonomousAgent("10.0.0.5", registry=None)
    cap = agent.registry.get("scan_tcp")
    assert cap is not None
    step = PlanStep(capability=cap, slot_values={})
    assert agent._priority(step) == 100.0
