"""Buco 1 — every cell reasons over its OWN view of the world.

Before this, the roster differed only in the capabilities a cell may USE
(`may_use`). The knowledge scope existed (`Cell.sees`, `Cell.view_of`) but
the *planning and the second opinion* still read the whole shared map, so a
cell could not actually be said to "not see" a fact.

The claims under test:

  * `Cell.view` projects the shared map onto the cell's scope and counts
    what it excludes;
  * two cells on one run therefore do NOT see the same world;
  * the runtime reports that scope (`cell_scope` event) — isolation is
    auditable, not a claim;
  * the tribunal's second opinion is rateable over the peer's OWN candidate
    set: a peer unaware of a move cannot pick it, and an empty peer world
    leaves the lead in command.
"""

from phantom.automation.brain.cells import CELL_LIBRARY, Cell
from phantom.automation.brain.cell_runtime import CellRuntime
from phantom.automation.brain.lenses import (
    CapabilityView,
    WorldSignals,
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


def _signals(vis=True):
    return WorldSignals(visibility=vis)


FINDINGS = [
    F("service", "tcp/22", {"port": 22}),
    F("rce_foothold", "web", {"host": "h"}),
    F("beacon", "b1", {"id": "b1"}),
    F("creds", "root", {"user": "root"}),
    F("identity", "bob", {"handle": "bob"}),
]


def _recon():
    return Cell("c-recon", CELL_LIBRARY["recon"], profile_for("balanced"))


def _exploit():
    return Cell("c-exploit", CELL_LIBRARY["exploit"], profile_for("balanced"))


def _identity():
    return Cell("c-identity", CELL_LIBRARY["identity"], profile_for("balanced"))


# ── the projection ────────────────────────────────────────────────────────

def test_a_cell_view_is_its_own_projection_of_the_map():
    v = _recon().view(FINDINGS)
    assert v.cell_id == "c-recon" and v.role == "recon"
    assert {f.kind for f in v.visible} == {"service"}
    assert v.has_any("service") is True
    assert v.has_any("rce_foothold") is False
    # what it cannot see is COUNTED, not silently dropped
    assert v.hidden == len(FINDINGS) - len(v.visible)
    assert v.to_dict()["visible"] == len(v.visible)


def test_two_cells_on_one_run_do_not_see_the_same_world():
    recon = {f.kind for f in _recon().view(FINDINGS).visible}
    exploit = {f.kind for f in _exploit().view(FINDINGS).visible}
    identity = {f.kind for f in _identity().view(FINDINGS).visible}
    assert "rce_foothold" in exploit and "rce_foothold" not in recon
    assert "identity" in identity and "identity" not in recon
    assert recon != exploit and exploit != identity


# ── the runtime reports it ────────────────────────────────────────────────

def test_runtime_reports_the_scope_of_every_cell():
    events = []
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network",
                     emit=lambda k, d: events.append((k, d)))
    payload = rt.report_scope(FINDINGS)
    assert payload["shared_facts"] == len(FINDINGS)
    assert events and events[-1][0] == "cell_scope"
    cells = payload["cells"]
    assert cells, "the roster must be reported"
    for entry in cells.values():
        assert "visible" in entry and "hidden" in entry and "kinds" in entry
    # at least one cell hides something on this map, or the test is vacuous
    assert any(e["hidden"] > 0 for e in cells.values())


def test_views_for_returns_one_view_per_cell():
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network")
    views = rt.views_for(FINDINGS)
    assert set(views) == {c.cell_id for c in rt.team.cells}
    assert all(v.cell_id == cid for cid, v in views.items())


# ── the second opinion reasons over the peer's world ──────────────────────

def test_a_peer_aware_of_one_move_cannot_pick_the_other():
    t = Tribunal(profile_for("balanced"), profile_for("evidence_first"))
    views = [_view("strong", category="exploit", detection_risk=0.7),
             _view("curious", category="osint", detection_risk=0.2)]
    base = {"strong": 3.0, "curious": 0.6}
    d = t.adjudicate(views, base, _signals(), peer_views=[views[1]])
    assert [cid for cid, _ in d.peer.ranking] == ["curious"]
    assert d.peer.top() == "curious"


def test_an_empty_peer_world_leaves_the_lead_in_command():
    t = Tribunal(profile_for("balanced"), profile_for("evidence_first"))
    views = [_view("strong", category="exploit", detection_risk=0.7),
             _view("curious", category="osint", detection_risk=0.2)]
    d = t.adjudicate(views, {"strong": 3.0, "curious": 0.6}, _signals(),
                     peer_views=[])
    assert d.peer.ranking == []
    assert d.adopted == d.lead.top()
    assert "peer found nothing viable" in d.rule


def test_second_opinion_accepts_the_peers_own_candidate_set():
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network")
    views = [_view("strong", category="exploit", detection_risk=0.7),
             _view("curious", category="osint", detection_risk=0.2)]
    d = rt.second_opinion(views, {"strong": 3.0, "curious": 0.6}, _signals(),
                          peer_views=[views[0]])
    assert d is not None
    assert [cid for cid, _ in d.peer.ranking] == ["strong"]


def test_peer_signals_are_the_peers_not_the_runs():
    """A peer with no visibility of its own must not be handed the run's."""
    t = Tribunal(profile_for("balanced"), profile_for("evidence_first"))
    views = [_view("scan_tcp"), _view("http_probe", category="web")]
    base = {"scan_tcp": 1.0, "http_probe": 0.9}
    blind = _signals(vis=False)
    d = t.adjudicate(views, base, _signals(vis=True), peer_signals=blind)
    assert d.peer.ranking, "the peer still rates its own candidates"
    # the two sides were given different worlds; the dispute is still settled
    assert d.adopted in ("scan_tcp", "http_probe")
