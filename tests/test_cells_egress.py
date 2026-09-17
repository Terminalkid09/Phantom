"""C1 acceptance tests — cells, the egress permit, and knowledge scoping.

The claims under test are the ones the operator approved:

  * concurrency is a property of the ACTION, not of the run: a sandbox role
    (OSINT, correlation, reverse engineering) parallelises freely, a role
    that TOUCHES the target is serialised, and only --aggressive pays for a
    second acting cell;
  * a second agent on the same task is ADVISORY when the role touches the
    target, so the second opinion costs no extra noise;
  * knowledge scoping is real: the cell that found the version may REPORT a
    vulnerability class and still be unable to see, plan with, or pick any
    exploit capability.
"""

import pytest

from phantom.automation.brain.cells import (
    ACTING_CAP,
    ACTING_CAP_AGGRESSIVE,
    ADVISORY_CAP,
    CELL_LIBRARY,
    CONTACT_EXPLOIT,
    CONTACT_NONE,
    CONTACT_RECON,
    Cell,
    CellTeam,
    EgressPermit,
    STAGE_ROLES,
    team_for_goal,
)
from phantom.automation.brain.lenses import profile_for


# ── roster construction ───────────────────────────────────────────────────

def test_deliver_roster_carries_the_machine_roles():
    team = team_for_goal("deliver", "ip")
    roles = [c.spec.role for c in team.cells]
    assert "recon" in roles
    assert "foothold" in roles


def test_identity_roster_never_opens_with_a_scan():
    team = team_for_goal("identity", "username")
    roles = [c.spec.role for c in team.cells]
    assert "recon" not in roles
    assert "identity" in roles


def test_identity_roster_gets_a_parallel_sandbox_role():
    """More ANONYMOUS eyes on the same subject is free (no target contact)."""
    team = team_for_goal("identity", "username",
                         explicit_profile="evidence_first")
    assert any("sandboxed" in n for c in team.cells for n in c.notes) is not None


def test_roster_is_deterministic():
    a = team_for_goal("deep", "ip")
    b = team_for_goal("deep", "ip")
    assert [c.cell_id for c in a.cells] == [c.cell_id for c in b.cells]
    assert [c.profile.name for c in a.cells] == [c.profile.name for c in b.cells]


# ── the contact model (the operator's rule) ───────────────────────────────

def test_sandbox_only_roster_allows_many_acting_cells():
    team = CellTeam([Cell("c1", CELL_LIBRARY["identity"], profile_for("balanced")),
                     Cell("c2", CELL_LIBRARY["osint"], profile_for("balanced"))])
    assert team.acting_cap() == ACTING_CAP[CONTACT_NONE]


def test_target_touching_roster_serialises_to_one():
    team = team_for_goal("deliver", "ip")
    assert team.acting_cap() == 1


def test_aggressive_only_buys_a_second_acting_cell():
    calm = team_for_goal("deliver", "ip")
    loud = team_for_goal("deliver", "ip", aggressive=True)
    assert calm.acting_cap() == 1
    assert loud.acting_cap() == ACTING_CAP_AGGRESSIVE[CONTACT_RECON]


def test_the_quietest_acting_cell_does_not_raise_the_cap():
    """A report role (no contact) in a team alongside a recon role must not
    let the recon role run two-at-a-time: the LOUDEST class present bounds
    the whole team, because noise adds up across classes."""
    team = CellTeam([Cell("c1", CELL_LIBRARY["recon"], profile_for("balanced")),
                     Cell("c2", CELL_LIBRARY["report"], profile_for("balanced"))])
    assert team.acting_cap() == 1


# ── the egress permit ─────────────────────────────────────────────────────

def test_permit_serialises_two_acting_cells():
    permit = EgressPermit(1)
    assert permit.acquire("c1") is True
    assert permit.acquire("c2") is False
    assert permit.holders == ["c1"]
    permit.release("c1")
    assert permit.acquire("c2") is True


def test_permit_is_idempotent_for_the_same_cell():
    permit = EgressPermit(1)
    assert permit.acquire("c1") is True
    assert permit.acquire("c1") is True
    assert permit.holders == ["c1"]


def test_team_admission_follows_the_permit():
    team = CellTeam([Cell("c1", CELL_LIBRARY["recon"], profile_for("balanced")),
                     Cell("c2", CELL_LIBRARY["web"], profile_for("balanced"))])
    first, second = team.cells
    assert team.admit(first) is True
    assert team.admit(second) is False          # one contact at a time
    team.release(first)
    assert team.admit(second) is True


def test_advisory_cell_never_holds_a_permit():
    team = CellTeam([Cell("c1", CELL_LIBRARY["exploit"], profile_for("balanced"))])
    peer = team.escalate(team.cells[0], reason="no path")
    assert peer is not None
    assert peer.advisory is True
    assert team.admit(peer) is False
    assert team.permit.holders == []


# ── escalation ────────────────────────────────────────────────────────────

def test_escalating_a_target_touching_role_spawns_an_advisory_peer():
    team = CellTeam([Cell("c1", CELL_LIBRARY["exploit"], profile_for("balanced"))])
    peer = team.escalate(team.cells[0], reason="wrong_model")
    assert peer.advisory is True
    assert "wrong_model" in peer.objective


def test_escalating_a_sandbox_role_spawns_an_acting_peer():
    """No contact: the peer can act, and the team's cap allows it."""
    team = CellTeam([Cell("c1", CELL_LIBRARY["osint"], profile_for("balanced"))])
    peer = team.escalate(team.cells[0], reason="identity unresolved")
    assert peer.advisory is False
    assert team.acting_cap() == ACTING_CAP[CONTACT_NONE]


def test_the_escalated_peer_reasons_differently_by_construction():
    base = profile_for("balanced")
    team = CellTeam([Cell("c1", CELL_LIBRARY["recon"], base)])
    peer = team.escalate(team.cells[0])
    assert peer.profile.name != base.name
    assert peer.profile.weights != base.weights
    assert peer.seed != team.cells[0].seed


def test_escalation_is_recorded_for_the_trail():
    team = CellTeam([Cell("c1", CELL_LIBRARY["recon"], profile_for("balanced"))])
    team.escalate(team.cells[0], reason="no_visibility")
    assert team.escalations
    entry = team.escalations[0]
    assert entry["from"] == "c1"
    assert entry["reason"] == "no_visibility"
    assert entry["profile"] != "balanced"


def test_escalation_is_bounded_no_peer_storm():
    team = CellTeam([Cell("c1", CELL_LIBRARY["recon"], profile_for("balanced"))])
    assert team.escalate(team.cells[0]) is not None
    assert team.escalate(team.cells[0]) is not None
    assert team.escalate(team.cells[0]) is None     # two peers is the cap


def test_report_role_is_not_escalated():
    team = CellTeam([Cell("c1", CELL_LIBRARY["report"], profile_for("balanced"))])
    assert team.escalate(team.cells[0]) is None


# ── knowledge scoping (the operator's example, as a system property) ──────

def test_recon_cell_can_report_a_vulnerability_it_cannot_exploit():
    recon = CELL_LIBRARY["recon"]
    assert recon.reports_kinds >= {"vuln_class", "attack_path"}
    assert "rce_foothold" not in recon.reports_kinds
    assert "creds" not in recon.reports_kinds


def test_recon_cell_does_not_SEE_exploitation_facts():
    recon = CELL_LIBRARY["recon"]
    assert "rce_foothold" not in recon.sees_kinds
    assert "exploit_plan" not in recon.sees_kinds
    assert "creds" not in recon.sees_kinds
    assert "beacon" not in recon.sees_kinds


def test_recon_cell_cannot_plan_with_exploit_capabilities():
    from phantom.automation.guidance.commands import make_registry
    registry = make_registry()
    exploit_ids = {c.id for c in registry.all()
                   if getattr(c, "category", "") == "exploit"}
    assert exploit_ids, "the registry must actually contain exploit capabilities"
    cell = Cell("c1", CELL_LIBRARY["recon"], profile_for("balanced"))
    ids = set(cell.capability_ids(registry))
    assert ids, "the recon cell must still see its own capabilities"
    assert "scan_tcp" in ids
    assert ids & exploit_ids == set()


def test_cell_view_filters_the_shared_map_by_role():
    class F:
        def __init__(self, kind):
            self.kind = kind

    findings = [F("service"), F("vuln_class"), F("rce_foothold"),
                F("beacon"), F("creds")]
    recon = Cell("c1", CELL_LIBRARY["recon"], profile_for("balanced"))
    seen = {f.kind for f in recon.view_of(findings)}
    assert seen == {"service", "vuln_class"}

    post = Cell("c2", CELL_LIBRARY["post"], profile_for("balanced"))
    post_seen = {f.kind for f in post.view_of(findings)}
    assert {"beacon", "creds", "rce_foothold"} <= post_seen


def test_the_report_role_sees_everything():
    cell = Cell("c1", CELL_LIBRARY["report"], profile_for("balanced"))
    assert cell.sees("beacon") is True
    assert cell.sees("anything_at_all") is True


def test_every_library_role_declares_a_scope():
    for name, spec in CELL_LIBRARY.items():
        assert spec.uses_categories, name
        assert spec.sees_kinds, name
        assert spec.contact in (CONTACT_NONE, CONTACT_RECON, CONTACT_EXPLOIT)


def test_stage_roles_reference_real_roles():
    for stage, roles in STAGE_ROLES.items():
        for role in roles:
            assert role in CELL_LIBRARY, f"{stage} -> {role}"


# ── budget and halt conditions ────────────────────────────────────────────

def test_cell_budget_is_enforced():
    cell = Cell("c1", CELL_LIBRARY["recon"], profile_for("balanced"), budget=2)
    assert cell.spend() is True
    assert cell.spend() is True
    assert cell.spend() is False
    assert cell.exhausted() is True


def test_zero_budget_means_unlimited():
    cell = Cell("c1", CELL_LIBRARY["recon"], profile_for("balanced"), budget=0)
    for _ in range(50):
        assert cell.spend() is True
    assert cell.exhausted() is False


def test_exhausted_cell_is_never_admitted():
    team = CellTeam([Cell("c1", CELL_LIBRARY["recon"], profile_for("balanced"),
                          budget=1)])
    assert team.admit(team.cells[0]) is True
    team.cells[0].spend()
    assert team.admit(team.cells[0]) is False


def test_halt_fact_matches_the_stage():
    team = team_for_goal("deliver", "ip")
    foothold = [c for c in team.cells if c.spec.role == "foothold"][0]
    assert foothold.halt == "beacon"
    recon = [c for c in team.cells if c.spec.role == "recon"][0]
    assert recon.halt == "service"


def test_team_stats_are_inspectable():
    team = team_for_goal("deep", "ip")
    stats = team.stats()
    assert stats["cells"] == len(team.cells)
    assert stats["acting"] + stats["advisory"] == stats["cells"]
    assert stats["acting_cap"] >= 1
