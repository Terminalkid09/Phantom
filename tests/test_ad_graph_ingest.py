"""Extra coverage for the AD-graph ingest bridge: the finding kinds the
agent ACTUALLY emits (ad_users, ad_weakness, ad_creds, creds
service=domain) must land in the graph — the earlier ingest only read
ad_user/ad_edge shapes nothing produced, so auto-mode AD data never
reached the manual core's graph."""
import pytest

from phantom.core.ad_graph import ADGraph, ingest_from_wm
from phantom.core.knowledge import reset_wm


@pytest.fixture(autouse=True)
def _clean_state(tmp_path, monkeypatch):
    """Isolate persistence: the graph file lives under data/."""
    from phantom.core import ad_graph as m
    monkeypatch.setattr(m, "STATE_PATH", tmp_path / "ad_graph.json")
    yield


def _wm(*findings):
    wm = reset_wm("10.0.0.5")
    for kind, key, value in findings:
        wm.add_finding(kind, key, value)
    return wm


def test_ad_users_list_becomes_user_nodes():
    wm = _wm(("ad_users", "users", {"users": ["alice", "bob", "svc-x"]}))
    g = ingest_from_wm(wm)
    for u in ("alice", "bob", "svc-x"):
        assert u in g.nodes and g.nodes[u].type == "user"


def test_ad_weakness_attaches_to_host():
    wm = _wm(("ad_weakness", "ldap_anon:DC01",
              {"type": "anonymous_bind", "host": "DC01"}))
    g = ingest_from_wm(wm)
    assert "DC01" in g.nodes
    assert "anonymous_bind" in g.nodes["DC01"].props.get("weaknesses", [])


def test_domain_creds_link_user_to_domain():
    wm = _wm(
        ("ad_domain", "ACME.LOCAL",
         {"domain": "acme.local", "dc_host": "DC01"}),
        ("ad_users", "users", {"users": ["alice"]}),
        ("creds", "domain:alice",
         {"username": "alice", "password": "x", "valid": True,
          "service": "domain", "domain": "acme.local"}),
    )
    g = ingest_from_wm(wm)
    # the edge exists EVEN THOUGH alice already appeared via ad_users
    # (regression: the earlier skip-on-existing-node lost the credential)
    assert ("alice", "member_of", "acme.local") in \
        [(e.src, e.type, e.dst) for e in g.edges]


def test_ad_user_enriches_existing_node():
    wm = _wm(
        ("ad_users", "users", {"users": ["alice"]}),
        ("ad_user", "alice", {"admin_to": "DC01", "session_on": "WS01"}),
    )
    g = ingest_from_wm(wm)
    types = {(e.src, e.type, e.dst) for e in g.edges}
    assert ("alice", "admin_to", "DC01") in types
    assert ("alice", "session", "WS01") in types


def test_paths_to_da_still_bfs_safe():
    """Flags stay node props — no self-loop edges to corrupt BFS."""
    wm = _wm(
        ("ad_domain", "ACME.LOCAL", {"domain": "acme.local",
                                     "dc_host": "DC01"}),
        ("ad_user", "svc", {"kerberoastable": True, "admin_to": "DC01"}),
    )
    g = ingest_from_wm(wm)
    assert g.nodes["svc"].props.get("kerberoastable") is True
    for e in g.edges:
        assert e.src != e.dst


# ── transitive group nesting (BloodHound-grade path expansion) ───────────

def _nested_graph():
    g = ADGraph()
    for nid, t in (("DA", "group"), ("G1", "group"), ("G2", "group"),
                   ("alice", "user"), ("svc", "user"), ("DC01", "computer")):
        g.add_node(nid, t, label="Domain Admins" if nid == "DA" else nid)
    g.add_edge("alice", "G1", "member_of")
    g.add_edge("G1", "G2", "member_of")
    g.add_edge("G2", "DA", "member_of")
    g.add_edge("svc", "G2", "member_of")
    g.add_edge("G2", "DC01", "admin_to")
    return g


def test_nested_group_path_found():
    """user -> G1 -> G2 -> DA is a REAL path BloodHound would report;
    direct-edge BFS misses it entirely."""
    g = _nested_graph()
    chains = [tuple(p) for p in g.paths_to("DA")]
    assert any(c == (("alice", "member_of", "G1"),
                     ("G1", "member_of", "G2"),
                     ("G2", "member_of", "DA")) for c in chains)


def test_group_power_inherited_by_members():
    """G2 has admin_to DC01 ⇒ alice (member of G2 via G1) can reach DC01
    through the inherited power edge."""
    g = _nested_graph()
    chains = [tuple(p) for p in g.paths_to("DC01")]
    assert any(c[0] == ("alice", "admin_to", "DC01") for c in chains)


def test_nesting_depth_guard_no_hang():
    """A member_of cycle must not hang the expansion."""
    g = ADGraph()
    for nid, t in (("A", "group"), ("B", "group"), ("u", "user"),
                   ("DC01", "computer")):
        g.add_node(nid, t)
    g.add_edge("u", "A", "member_of")
    g.add_edge("A", "B", "member_of")
    g.add_edge("B", "A", "member_of")   # cycle
    g.add_edge("B", "DC01", "admin_to")
    chains = [tuple(p) for p in g.paths_to("DC01")]
    assert any(c[0] == ("u", "admin_to", "DC01") for c in chains)
