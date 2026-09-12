"""Tests for the manual-core AD attack graph (BloodHound-style).

Acceptance criteria:
  * ingest_from_wm folds ad_domain/ad_user/ad_edge findings into nodes
    and edges (idempotent);
  * flags (kerberoastable / as_rep / cracked) are node PROPS, never
    self-loop edges (self-loops corrupt shortest-path BFS);
  * paths_to('DA') returns shortest chains; an uncracked kerberoastable
    user is NOT a path until cracking is recorded;
  * the graph persists to data/ad_graph.json (survives sessions);
  * ascii_tree and to_json agree on the same model (CLI == Electron).
"""
import json

import pytest

from phantom.core import ad_graph as AG
from phantom.core.ad_graph import ADGraph, ingest_from_wm


@pytest.fixture(autouse=True)
def _clean_state(tmp_path, monkeypatch):
    monkeypatch.setattr(AG, "STATE_PATH", tmp_path / "ad_graph.json")
    yield


def _wm_with_ad():
    from phantom.core.knowledge import reset_wm
    wm = reset_wm("acme.local", target_type="domain")
    wm.add_finding(kind="ad_domain", key="acme.local",
                   value={"domain": "acme.local", "dc_host": "DC01"},
                   target="acme.local")
    wm.add_finding(kind="ad_user", key="svc_backup",
                   value={"kerberoastable": True, "session_on": ["DC01"]},
                   target="acme.local")
    wm.add_finding(kind="ad_user", key="jsmith",
                   value={"cracked": True, "admin_to": ["DC01"]},
                   target="acme.local")
    return wm


class TestIngest:
    def test_domain_dc_users_ingested(self):
        g = ingest_from_wm(_wm_with_ad())
        assert g.domain == "acme.local"
        assert "DC01" in g.nodes and g.nodes["DC01"].type == "dc"
        assert "svc_backup" in g.nodes and g.nodes["svc_backup"].type == "user"
        assert g.nodes["svc_backup"].props.get("kerberoastable") is True
        assert g.nodes["jsmith"].props.get("cracked") is True

    def test_flags_are_props_not_self_loops(self):
        g = ingest_from_wm(_wm_with_ad())
        for e in g.edges:
            assert e.src != e.dst, "self-loop edges break path BFS"

    def test_session_and_admin_edges_created(self):
        g = ingest_from_wm(_wm_with_ad())
        assert any(e.src == "svc_backup" and e.dst == "DC01"
                   and e.type == "session" for e in g.edges)
        assert any(e.src == "jsmith" and e.dst == "DC01"
                   and e.type == "admin_to" for e in g.edges)

    def test_idempotent(self):
        wm = _wm_with_ad()
        g1 = ingest_from_wm(wm)
        n = len(g1.nodes)
        g2 = ingest_from_wm(wm)
        assert len(g2.nodes) == n
        assert len(g2.edges) == len(g1.edges)


class TestPaths:
    def _full_graph(self) -> ADGraph:
        g = ingest_from_wm(_wm_with_ad())
        g.add_node("Domain Admins", "group", label="Domain Admins")
        g.add_edge("jsmith", "Domain Admins", "member_of")
        g.add_edge("Domain Admins", "DC01", "admin_to")
        return g

    def test_path_via_member_of(self):
        g = self._full_graph()
        paths = g.paths_to("DA")
        assert paths, "cracked jsmith member_of Domain Admins must be a path"
        chain = paths[0]
        assert chain[0][0] == "jsmith"
        assert any(t == "member_of" for _, t, _ in chain)

    def test_uncracked_kerberoastable_is_not_a_path(self):
        g = self._full_graph()
        # svc_backup: kerberoastable + session on DC, but NOT cracked and
        # NOT member of anything — must not yield a path on its own
        # (remove jsmith to prove svc_backup alone doesn't count)
        del g.nodes["jsmith"]
        g.edges = [e for e in g.edges if "jsmith" not in (e.src, e.dst)]
        assert g.paths_to("DA") == []

    def test_da_alias_resolves(self):
        g = self._full_graph()
        # 'DA' alias resolves to the node labelled 'Domain Admins'
        assert g._da_id() == "Domain Admins"


class TestPersistence:
    def test_survives_reload(self):
        g = ingest_from_wm(_wm_with_ad())
        g.add_node("extra", "user")
        g2 = ADGraph()
        assert "extra" in g2.nodes
        assert g2.domain == "acme.local"

    def test_json_matches_model(self):
        g = ingest_from_wm(_wm_with_ad())
        g.add_node("Domain Admins", "group", label="Domain Admins")
        g.add_edge("jsmith", "Domain Admins", "member_of")
        j = g.to_json()
        ids = {n["id"] for n in j["nodes"]}
        assert ids == set(g.nodes.keys())
        assert len(j["edges"]) == len(g.edges)
        # CLI tree and JSON render the same domain
        assert any("acme.local" in l for l in g.ascii_tree())


class TestCliWiring:
    def test_shell_has_ad_command(self):
        from phantom.core.shell import PhantomShell
        assert hasattr(PhantomShell, "do_ad")

    def test_api_routes_registered(self):
        from phantom.api.server import routes
        rendered = "\n".join(str(r) for r in routes)
        assert "/api/ad/graph" in rendered
        assert "/api/ad/mutate" in rendered
