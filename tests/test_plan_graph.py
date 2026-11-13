"""Buco 3 — the plan as an explicit DAG (the run's mental model).

The planner returns an ordered list. This file pins the other reading of the
SAME plan: a graph whose edges only ever climb the kill-chain ladder, whose
layers expose what depends on what, and whose critical path is the chain to
the goal. The beacon is a node; the goal is the sink.
"""

from phantom.automation.brain.plan_graph import GOAL_NODE, PlanGraph


class _Cap:
    def __init__(self, cid, category, effects=(), contact=""):
        self.id, self.category = cid, category
        self.effects, self.contact = tuple(effects), contact


class _Step:
    def __init__(self, cap):
        self.capability = cap


class _Plan:
    def __init__(self, caps):
        self.steps = [_Step(c) for c in caps]


def _sample():
    return _Plan([
        _Cap("osint_identity", "osint", ("identity",), "none"),
        _Cap("scan_tcp", "recon", ("service",), "recon"),
        _Cap("http_probe", "web", ("web_app",), "recon"),
        _Cap("beacon_via_rce", "beacon", ("beacon",), "exploit"),
        _Cap("persist", "post", ("persistence",), "exploit"),
    ])


# ── structure ─────────────────────────────────────────────────────────────

def test_nodes_take_their_layer_from_the_chain_rank():
    g = PlanGraph.from_plan(_sample(), goal_facts=("beacon",))
    ranks = {n.capability: n.rank for n in g.nodes}
    assert ranks["osint_identity"] == 0
    assert ranks["scan_tcp"] == 1
    assert ranks["http_probe"] == 2
    assert ranks["beacon_via_rce"] == 4
    assert ranks["persist"] == 5
    assert len(g.layers()) == 5


def test_edges_only_climb_the_ladder_so_the_graph_is_always_a_dag():
    g = PlanGraph.from_plan(_sample(), goal_facts=("beacon",))
    assert g.is_dag()
    for a, b in g.edges:
        if b == GOAL_NODE:
            continue
        assert g._rank_of(a) < g._rank_of(b), (a, b)


def test_the_terminal_layer_points_at_the_goal():
    g = PlanGraph.from_plan(_sample(), goal_facts=("beacon",))
    into_goal = [a for a, b in g.edges if b == GOAL_NODE]
    assert into_goal == ["persist"]


def test_the_critical_path_visits_every_layer_then_the_goal():
    g = PlanGraph.from_plan(_sample(), goal_facts=("beacon",))
    path = g.critical_path()
    assert path[-1] == GOAL_NODE
    assert len(path) == len(g.layers()) + 1
    assert g.critical_ids() <= {n.node_id for n in g.nodes}


def test_an_empty_plan_is_an_empty_graph_not_a_crash():
    g = PlanGraph.from_plan(_Plan([]))
    assert g.nodes == [] and g.edges == ()
    assert g.is_dag() is True
    assert g.critical_path() == []
    assert g.to_dict()["layers"] == []


def test_to_dict_is_complete():
    d = PlanGraph.from_plan(_sample(), goal_facts=("beacon",)).to_dict()
    for key in ("nodes", "edges", "layers", "critical_path", "critical",
                "goal_facts", "dag"):
        assert key in d
    assert d["goal_facts"] == ["beacon"]
    assert d["dag"] is True


# ── the runtime emits it ──────────────────────────────────────────────────

def test_the_runtime_emits_the_plan_graph():
    from phantom.automation.brain.cell_runtime import CellRuntime
    events = []
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network",
                     emit=lambda k, d: events.append((k, d)))
    payload = rt.plan_graph(_sample(), goal_facts=("beacon",))
    assert payload is not None
    kinds = [k for k, _ in events]
    assert "plan_graph" in kinds
    emitted = [d for k, d in events if k == "plan_graph"][-1]
    assert emitted["critical_path"]


# ── the REAL planner produces a DAG ───────────────────────────────────────

def test_the_real_planner_yields_a_valid_dag():
    from phantom.automation.agent import AutonomousAgent
    a = AutonomousAgent("10.0.0.5", target_type="ip")
    plan = a.planner.plan_strategic(a.wm, goal="deliver")
    g = PlanGraph.from_plan(plan, goal_facts=a._goal_facts())
    assert g.is_dag()
    if g.nodes:
        assert g.critical_path()[-1] == GOAL_NODE
