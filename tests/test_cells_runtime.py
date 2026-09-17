"""C2 acceptance tests — the cell runtime: bus, tribunal, permit, agent wiring.

The claims under test:

  * the bus carries QUESTIONS (not just broadcasts) between cells, and the
    knowledge scope survives the trip: a recon cell cannot answer about a
    kind it is not allowed to see, and a denial carries its reason;
  * the tribunal makes the second opinion USEFUL: it adjudicates by a rule
    (the peer wins only when it is right under the lead's own profile, or
    when the lead's pick is vetoed) and the loser is recorded as a dissent;
  * the run routes each action to its cell, serialises contact through the
    egress permit, and the strict (C4) mode refuses what no cell owns.
"""

import pytest

from phantom.automation.brain.bus import CellBus
from phantom.automation.brain.cells import (
    CELL_LIBRARY,
    MIGRATED_STAGES,
    Cell,
    CellTeam,
)
from phantom.automation.brain.cell_runtime import CellRuntime
from phantom.automation.brain.lenses import (
    CapabilityView,
    WorldSignals,
    adversarial_profile,
    profile_for,
)
from phantom.automation.brain.tribunal import Tribunal


class F:
    """A stand-in finding (kind/key/value, like belief.Finding)."""

    def __init__(self, kind, key, value):
        self.kind, self.key, self.value = kind, key, value


def _view(cid, **kw):
    base = dict(id=cid, category="recon", opsec_cost=1.0, detection_risk=0.2,
                stealth_level="active", effects=("service",))
    base.update(kw)
    return CapabilityView(**base)


def _recon() -> Cell:
    return Cell("c1-recon", CELL_LIBRARY["recon"], profile_for("balanced"))


def _exploit() -> Cell:
    return Cell("c3-exploit", CELL_LIBRARY["exploit"], profile_for("balanced"))


# ── the bus ───────────────────────────────────────────────────────────────

def test_bus_answers_inside_the_answering_cells_scope():
    bus = CellBus([_recon(), _exploit()])
    qid = bus.ask("c3-exploit", "recon", "service", key="tcp/8080")
    answers = bus.answer_all([F("service", "tcp/8080", {"port": "8080",
                                                       "version": "2.4.49"})])
    assert len(answers) == 1
    a = answers[0]
    assert a.qid == qid
    assert a.answered is True
    assert a.value["version"] == "2.4.49"
    assert a.from_cell == "c1-recon"


def test_bus_denies_a_kind_the_answering_role_cannot_see():
    """The exploit cell asks the recon cell for credentials it does not
    have: the scope is what denies it, and the reason says so."""
    bus = CellBus([_recon(), _exploit()])
    bus.ask("c3-exploit", "recon", "creds", key="ssh")
    answers = bus.answer_all([F("creds", "ssh", {"user": "root"})])
    assert answers[0].answered is False
    assert "may not see kind 'creds'" in answers[0].reason


def test_bus_denies_when_no_cell_carries_the_role():
    bus = CellBus([_recon()])
    bus.ask("c1-recon", "cloud", "cloud_access")
    answers = bus.answer_all([])
    assert answers[0].answered is False
    assert "no cell with role 'cloud'" in answers[0].reason


def test_bus_reports_a_miss_without_pretending_it_answered():
    bus = CellBus([_recon(), _exploit()])
    bus.ask("c3-exploit", "recon", "service", key="tcp/22")
    answers = bus.answer_all([F("service", "tcp/8080", {})])
    assert answers[0].answered is False
    assert "not in the shared map" in answers[0].reason


def test_bus_clears_pending_after_answering():
    bus = CellBus([_recon(), _exploit()])
    bus.ask("c3-exploit", "recon", "service")
    bus.answer_all([])
    assert bus.pending() == []
    assert bus.stats()["denied"] == 1


def test_bus_transcript_is_bounded():
    from phantom.automation.brain.bus import MAX_TRANSCRIPT
    bus = CellBus([_recon()])
    for _ in range(MAX_TRANSCRIPT + 25):
        bus.ask("x", "recon", "service")
        bus.answer_all([])
    assert len(bus.transcript()) <= MAX_TRANSCRIPT


# ── the tribunal ──────────────────────────────────────────────────────────

def _signals(vis=True):
    return WorldSignals(visibility=vis)


def test_tribunal_agreement_changes_nothing():
    t = Tribunal(profile_for("balanced"), profile_for("evidence_first"))
    views = [_view("scan_tcp")]
    d = t.adjudicate(views, {"scan_tcp": 2.0}, _signals())
    assert d.agreed is True
    assert d.adopted == "scan_tcp"
    assert d.rule == "agreement"


# the pair used to exercise the two reachable dissent outcomes: the same two
# moves, 2% apart in expected value. This is where a second opinion is worth
# paying for, and it is exactly the band the two profiles disagree inside.
def _contested_pair():
    return ([_view("loud_exploit", category="exploit", detection_risk=0.70,
                   opsec_cost=3.0),
             _view("quiet_recon", category="recon", detection_risk=0.10,
                   opsec_cost=0.6)],)


def test_tribunal_lead_keeps_command_on_a_mere_trade_off():
    """The peer prefers the loud exploit and the lead prefers the quiet
    recon: the lead resists the switch MORE than the peer wants it, so the
    lead stands and the dissent is recorded rather than obeyed."""
    t = Tribunal(profile_for("balanced"), profile_for("evidence_first"))
    views, = _contested_pair()
    d = t.adjudicate(views, {"loud_exploit": 1.22, "quiet_recon": 1.0},
                     _signals())
    assert d.agreed is False
    assert d.winner == "lead"
    assert d.adopted == "quiet_recon"
    assert "lead retains command" in d.rule
    assert d.dissent == "loud_exploit"                # the peer was heard
    assert d.dissent_reason


def test_tribunal_peer_wins_when_its_conviction_exceeds_the_leads_cost():
    """2% more expected value for the loud move: the lead barely minds the
    switch and the peer clearly wants it, so the peer takes it."""
    t = Tribunal(profile_for("balanced"), profile_for("evidence_first"))
    views, = _contested_pair()
    d = t.adjudicate(views, {"loud_exploit": 1.24, "quiet_recon": 1.0},
                     _signals())
    assert d.agreed is False
    assert d.winner == "peer"
    assert d.adopted == "loud_exploit"
    assert "conviction exceeds" in d.rule
    assert d.dissent == "quiet_recon"
    assert d.dissent_reason


def test_tribunal_never_overturns_when_the_peer_is_indifferent():
    """The compromise floor: a peer whose own ranking barely separates the
    two moves must not swing a decision."""
    t = Tribunal(profile_for("balanced"), profile_for("evidence_first"))
    views, = _contested_pair()
    # bases far apart: the lead's gap is large and the peer's is tiny
    d = t.adjudicate(views, {"loud_exploit": 3.0, "quiet_recon": 1.0},
                     _signals())
    assert d.agreed is True
    assert d.adopted == "loud_exploit"


def test_tribunal_peer_wins_when_the_leads_pick_is_vetoed():
    t = Tribunal(profile_for("balanced"), profile_for("stealth_first"))
    t.peer_profile = profile_for("stealth_first")
    views = [_view("loud", category="brute", detection_risk=0.95,
                   stealth_level="aggressive", forceful=True),
             _view("quiet", category="recon", detection_risk=0.05)]
    sig = WorldSignals(visibility=True, noise_ratio=0.9, breaker_tripped=False)
    d = t.adjudicate(views, {"loud": 5.0, "quiet": 0.4}, sig)
    # the lead ranks the loud move first; the peer vetos it (0.70 threshold)
    assert d.adopted == "quiet"
    assert d.winner == "peer"
    assert "veto" in d.rule


def test_tribunal_reports_when_nothing_is_viable():
    t = Tribunal(profile_for("balanced"), profile_for("stealth_first"))
    sig = WorldSignals(visibility=True, noise_ratio=2.0, breaker_tripped=True)
    views = [_view("loud", category="brute", detection_risk=0.95,
                   stealth_level="aggressive", forceful=True)]
    d = t.adjudicate(views, {"loud": 5.0}, sig)
    assert d.adopted is None
    assert d.rule


def test_tribunal_history_and_stats_are_inspectable():
    t = Tribunal(profile_for("balanced"), profile_for("evidence_first"))
    t.adjudicate([_view("a")], {"a": 1.0}, _signals())
    t.adjudicate([_view("a"), _view("b", category="osint")],
                 {"a": 3.0, "b": 0.5}, _signals())
    st = t.stats()
    assert st["rounds"] == 2
    assert st["lead"] == "balanced"
    assert st["peer"] == "evidence_first"
    assert isinstance(t.disagreements(), list)


def test_dispute_explains_itself():
    t = Tribunal(profile_for("balanced"), profile_for("evidence_first"))
    d = t.adjudicate([_view("a"), _view("b", category="osint")],
                     {"a": 3.0, "b": 0.4}, _signals())
    assert "tribunal:" in d.explain()
    as_dict = d.to_dict()
    assert set(as_dict) >= {"agreed", "winner", "rule", "adopted", "lead",
                            "peer"}


# ── the runtime ───────────────────────────────────────────────────────────

def test_runtime_roster_follows_the_doctrine_chain():
    """The coverage starts from the doctrine chain and then joins the run's
    own GOAL: the roster has to cover what this run will actually walk, not
    just what the target class is willing to do."""
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network")
    assert rt.stages[:4] == ("footprint", "exploit", "creds", "beacon")
    assert "deliver" in rt.stages
    roles = [c.spec.role for c in rt.team.cells]
    assert "recon" in roles and "foothold" in roles


def test_a_deep_run_covers_the_whole_ladder():
    """A roster built from the doctrine chain alone has no `post` cell for a
    network target, so the post-exploitation half of a deep run would have
    no owner at all."""
    rt = CellRuntime(goal="deep", target_type="ip", cls="network")
    roles = {c.spec.role for c in rt.team.cells}
    assert {"recon", "web", "exploit", "foothold", "post"} <= roles


def test_runtime_cap_follows_the_active_stage():
    """The operator's rule: identity/social run wide, a target-touching
    stage collapses to one acting cell."""
    rt = CellRuntime(goal="identity", target_type="username", cls="identity")
    rt.set_stage("identity")
    wide = rt.team.permit.acting_cap
    rt.set_stage("beacon")
    narrow = rt.team.permit.acting_cap
    assert wide > narrow == 1


def test_runtime_refuses_a_capability_no_cell_owns_in_strict_mode():
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network",
                     strict=True)
    rt.set_stage("footprint")

    class Cap:
        id = "cloud_iam_enum"
        category = "cloud"

    assert rt.cell_for(Cap(), "footprint") is None
    assert rt.owns(Cap(), "footprint") is False


def test_runtime_routes_a_capability_to_its_cell():
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network")
    rt.set_stage("footprint")

    class Cap:
        id = "scan_tcp"
        category = "recon"

    cell = rt.cell_for(Cap(), "footprint")
    assert cell is not None
    assert cell.spec.role == "recon"


def test_runtime_egress_is_serialised_per_stage():
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network")
    rt.set_stage("exploit")
    rt.permit_wait = 0.0
    a = rt.team.cells[0]
    b = rt.team.cells[1]
    assert rt.admit(a) is True
    assert rt.admit(b) is False              # one contact at a time
    rt.release(a)
    assert rt.admit(b) is True
    rt.release(b)


def test_runtime_never_admits_an_advisory_cell():
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network")
    peer = rt.team.escalate(rt.team.cells[0], reason="stalled")
    assert peer is not None and peer.advisory is True
    assert rt.admit(peer) is False


def test_runtime_stall_escalates_and_switches_the_peer_objective():
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network")
    rt.set_stage("footprint")

    class Cap:
        id = "scan_tcp"
        category = "recon"

    before = rt.tribunal.peer_profile.name
    peer = rt.on_stall("no_visibility", Cap(), "footprint")
    assert peer is not None
    assert rt.tribunal.peer_profile.name == peer.profile.name
    assert rt.team.escalations, "the escalation must be on the record"
    assert rt.tribunal.peer_profile.name != before or peer.profile.name == before


def test_runtime_second_opinion_rates_the_same_candidates():
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network")
    views = [_view("strong", category="exploit", detection_risk=0.7),
             _view("curious", category="osint", detection_risk=0.2)]
    d = rt.second_opinion(views, {"strong": 3.0, "curious": 0.6}, _signals())
    assert d is not None
    assert d.adopted in ("strong", "curious")
    assert rt.tribunal.stats()["rounds"] == 1


def test_runtime_emits_the_roster_and_the_stage_scope():
    events = []
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network",
                     emit=lambda k, d: events.append((k, d)))
    rt.start()
    rt.set_stage("footprint")
    kinds = [k for k, _ in events]
    assert "roster" in kinds
    assert "stage_scope" in kinds


def test_runtime_stats_and_dict_are_complete():
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network")
    rt.start()
    st = rt.stats()
    assert set(st) >= {"team", "bus", "tribunal", "routed", "unrouted",
                       "deferred", "refused", "strict", "chain"}
    assert rt.to_dict()["cells"]


# ── agent wiring ──────────────────────────────────────────────────────────

def _agent(**kw):
    from phantom.automation.agent import AutonomousAgent
    a = AutonomousAgent("10.0.0.5")
    a.goal = kw.pop("goal", "deliver")
    for k, v in kw.items():
        setattr(a, k, v)
    return a


def test_agent_builds_the_roster_once_and_emits_it():
    a = _agent()
    a._ensure_cells("deliver")
    assert a.cells is not None
    first = a.cells
    a._ensure_cells("deliver")
    assert a.cells is first                  # built once per run
    assert a.sink.by_kind("roster")


def test_agent_routes_and_releases_the_permit_around_an_action():
    from phantom.automation.planner import PlanStep

    a = _agent()
    a._ensure_cells("footprint")
    a._current_stage = "footprint"
    calls = []
    a._execute_capability = lambda step: calls.append(step.capability.id) or True
    cap = a.registry.get("scan_tcp")
    assert a._exec_with_permit(PlanStep(capability=cap, slot_values={})) is True
    assert calls == ["scan_tcp"]
    assert a.cells.team.permit.holders == []          # always released
    assert a.cells.routed == 1


def test_agent_defers_when_the_egress_permit_is_taken():
    from phantom.automation.planner import PlanStep

    a = _agent()
    a._ensure_cells("footprint")
    a._current_stage = "footprint"
    a.cells.permit_wait = 0.0
    # hold the permit as ANOTHER cell: a cell re-acquiring its own permit is
    # reentrant by design, so the deferral must be provoked by a real rival
    assert a.cells.team.permit.acquire("rival-cell", timeout=0.1) is True
    try:
        ran = []
        a._execute_capability = lambda step: ran.append(1) or True
        cap = a.registry.get("scan_tcp")
        ok = a._exec_with_permit(PlanStep(capability=cap, slot_values={}))
        assert ok is False                   # deferred, not failed
        assert ran == []                     # nothing touched the target
        assert a.cells.deferred == 1
        assert "scan_tcp" not in a._failed_caps, "deferral is not a failure"
    finally:
        a.cells.team.permit.release("rival-cell")


def _unowned_capability(a):
    """A REAL capability whose category no cell in this roster may use.

    Discovered from the registry rather than hardcoded: a capability's
    category is a property of the kit, and a test that assumes one (e.g.
    that `cloud_iam_enum` is category `cloud` when it is `post`) tests the
    assumption instead of the code.
    """
    owned = set()
    for cell in a.cells.team.cells:
        owned |= set(cell.spec.uses_categories)
    for cap in a.registry.all():
        if cap.category not in owned:
            return cap
    return None


def test_the_roster_does_not_own_every_category():
    """The strict test below is only meaningful while some capability sits
    outside every role's hands. If that stops being true, this fails loudly
    instead of letting the other test pass vacuously."""
    a = _agent()
    a._ensure_cells("footprint")
    assert _unowned_capability(a) is not None


def test_agent_strict_mode_refuses_what_no_cell_owns():
    from phantom.automation.planner import PlanStep

    a = _agent()
    a.cell_loop = True
    a.cell_stages = ("footprint",)
    a._ensure_cells("footprint")
    a._current_stage = "footprint"
    a.cells.strict = True
    ran = []
    a._execute_capability = lambda step: ran.append(1) or True
    cap = _unowned_capability(a)
    assert cap is not None
    ok = a._exec_with_permit(PlanStep(capability=cap, slot_values={}))
    assert ok is False
    assert ran == []
    assert a.cells.refused == 1
    assert a.sink.by_kind("blocked")


def test_agent_lenient_mode_lets_an_unowned_capability_through():
    from phantom.automation.planner import PlanStep

    a = _agent()
    a._ensure_cells("footprint")
    a._current_stage = "footprint"
    ran = []
    a._execute_capability = lambda step: ran.append(1) or True
    cap = _unowned_capability(a)
    assert cap is not None
    assert a.cells.cell_for(cap, "footprint") is None
    assert a._exec_with_permit(PlanStep(capability=cap, slot_values={})) is True
    assert ran == [1]
    assert a.cells.unrouted == 1


def test_agent_never_routes_to_an_advisory_cell():
    """An advisory cell is a second opinion, never a worker: the router
    must not hand it an action, and the guard refuses it if it does."""
    from phantom.automation.planner import PlanStep

    a = _agent()
    a._ensure_cells("footprint")
    a._current_stage = "footprint"
    peer = a.cells.team.escalate(a.cells.team.cells[0], reason="stalled")
    assert peer.advisory is True
    # 1. the router skips it
    assert a.cells.cell_for(a.registry.get("scan_tcp"), "footprint") is not None
    assert a.cells.cell_for(a.registry.get("scan_tcp"), "footprint").advisory is False
    # 2. and if it ever got routed there, the guard refuses it
    a.cells.cell_for = lambda cap, stage="", stage_scoped=False: peer
    ran = []
    a._execute_capability = lambda step: ran.append(1) or True
    cap = a.registry.get("scan_tcp")
    assert a._exec_with_permit(PlanStep(capability=cap, slot_values={})) is False
    assert ran == []
    assert "advisory" in str(a.sink.by_kind("blocked")[-1])


def test_agent_finalize_carries_the_cell_telemetry():
    a = _agent()
    a._ensure_cells("deliver")
    result = a._finalize()
    assert result["cells"]
    assert "team" in result["cell_stats"]


def test_migrated_stages_is_a_real_ledger():
    assert isinstance(MIGRATED_STAGES, tuple)
    assert all(isinstance(s, str) for s in MIGRATED_STAGES)
