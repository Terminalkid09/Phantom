"""Tests for the identity social graph (`automation/social/social_graph.py`).

Everything here is offline: the graph and the post miner take already-fetched
data, so the whole thing is verifiable without a network call — which is the
claim the module makes about itself.
"""
import json
import xml.etree.ElementTree as ET

import pytest

from phantom.automation.social import social_graph as SG


class TestGraphBasics:
    def test_nodes_are_kind_prefixed_so_kinds_cannot_collide(self):
        g = SG.SocialGraph()
        g.add_handle("jane")
        g.add_node(SG.node_key("domain", "jane"), "domain")
        assert set(g.nodes) == {"handle:jane", "domain:jane"}

    def test_a_second_sighting_merges_instead_of_duplicating(self):
        g = SG.SocialGraph()
        g.add_handle("Jane", platform="x", source="recon:x", confidence=0.4)
        g.add_handle("jane", platform="", source="recon:github", confidence=0.9)
        assert len(g.nodes) == 1
        node = g.nodes["handle:jane"]
        assert node.confidence == 0.9
        assert node.sources == ["recon:x", "recon:github"]
        assert node.platform == "x"

    def test_the_same_proof_twice_is_one_edge_with_two_sources(self):
        g = SG.SocialGraph()
        a = g.add_handle("a")
        b = g.add_handle("b")
        g.add_edge(a.key, b.key, "comments_on", evidence="graph:instagram",
                   source="recon:instagram")
        g.add_edge(a.key, b.key, "comments_on", evidence="graph:instagram",
                   source="post-mining")
        assert len(g.edges) == 1
        edge = next(iter(g.edges.values()))
        assert edge.sources == ["recon:instagram", "post-mining"]
        assert g.evidence_count(a.key, b.key) == 1

    def test_unknown_kinds_are_refused_not_invented(self):
        g = SG.SocialGraph()
        a = g.add_handle("a")
        b = g.add_handle("b")
        assert g.add_edge(a.key, b.key, "dunno") is None
        assert g.add_node("x:y", "not_a_kind") is None
        assert g.edges == {}

    def test_edges_need_both_endpoints_to_exist(self):
        g = SG.SocialGraph()
        a = g.add_handle("a")
        assert g.add_edge(a.key, "handle:ghost", "follows") is None

    def test_self_loops_are_dropped(self):
        g = SG.SocialGraph()
        a = g.add_handle("a")
        assert g.add_edge(a.key, a.key, "follows") is None

    def test_the_graph_is_bounded_and_says_what_it_dropped(self):
        g = SG.SocialGraph(max_nodes=2)
        g.add_handle("a")
        g.add_handle("b")
        assert g.add_handle("c") is None
        assert g.stats()["dropped_nodes"] == 1


class TestWalks:
    def _chain(self, n=4):
        g = SG.SocialGraph()
        for i in range(n):
            g.add_handle(f"u{i}")
        for i in range(n - 1):
            g.add_edge(f"handle:u{i}", f"handle:u{i+1}", "follows")
        return g

    def test_bfs_respects_depth_and_never_loops(self):
        g = self._chain(5)
        assert g.bfs("handle:u0", depth=1) == ["handle:u0", "handle:u1"]
        assert g.bfs("handle:u0", depth=99) == [
            "handle:u0", "handle:u1", "handle:u2", "handle:u3", "handle:u4"]

    def test_bfs_is_bounded_by_max_nodes(self):
        g = self._chain(5)
        assert len(g.bfs("handle:u0", depth=99, max_nodes=3)) == 3

    def test_bfs_kind_filter_walks_only_that_proof(self):
        g = SG.SocialGraph()
        for name in ("a", "b", "c"):
            g.add_handle(name)
        g.add_edge("handle:a", "handle:b", "follows")
        g.add_edge("handle:a", "handle:c", "tagged_in")
        assert g.bfs("handle:a", depth=1, kinds=["tagged_in"]) == [
            "handle:a", "handle:c"]

    def test_bfs_of_an_unknown_node_is_empty(self):
        assert SG.SocialGraph().bfs("handle:nope") == []

    def test_clusters_group_connected_pieces(self):
        g = self._chain(3)
        g.add_handle("lonely")
        clusters = g.clusters()
        assert ["handle:lonely"] in clusters
        assert max(len(c) for c in clusters) == 3


class TestSamePersonProofs:
    def test_shared_avatar_and_email_make_a_same_person_edge(self):
        g = SG.SocialGraph()
        ig = g.add_handle("jane", platform="instagram")
        gh = g.add_handle("jdoe", platform="github")
        email = g.add_node(SG.node_key("email", "j@x.com"), "email")
        g.add_edge(ig.key, email.key, "email_match", evidence="bio")
        g.add_edge(gh.key, email.key, "email_match", evidence="commit")
        SG._link_shared_emails(g)
        assert ("handle:jane", "handle:jdoe", "same_person") in g.edges
        assert g.same_person_groups() == [["handle:jane", "handle:jdoe"]]

    def test_weak_edges_do_not_confirm_an_identity(self):
        g = SG.SocialGraph()
        a = g.add_handle("a")
        b = g.add_handle("b")
        g.add_edge(a.key, b.key, "tagged_in", evidence="post:1")
        assert g.same_person_groups() == []

    def test_pivot_leads_are_ranked_by_confidence(self):
        g = SG.SocialGraph()
        g.add_handle("weak", confidence=0.2)
        g.add_handle("strong", confidence=0.9)
        assert [n.label for n in g.pivot_leads()] == ["strong", "weak"]


class TestExports:
    def test_to_dict_round_trips_through_json(self):
        g = SG.SocialGraph()
        a = g.add_handle("a", platform="x")
        b = g.add_handle("b")
        g.add_edge(a.key, b.key, "follows", evidence="graph:x", confidence=0.5)
        payload = json.loads(SG.to_json(g))
        assert len(payload["nodes"]) == 2 and len(payload["edges"]) == 1
        assert payload["edges"][0]["kind"] == "follows"
        assert payload["stats"]["nodes"] == 2

    def test_graphml_is_valid_xml_with_every_node_and_edge(self):
        g = SG.SocialGraph()
        a = g.add_handle("a & b", platform="x")   # escaping must hold
        b = g.add_handle("b")
        g.add_edge(a.key, b.key, "follows", evidence="<graph>", confidence=0.5)
        root = ET.fromstring(g.to_graphml())
        ns = "{http://graphml.graphdrawing.org/xmlns}"
        graph = root.find(f"{ns}graph")
        assert len(graph.findall(f"{ns}node")) == 2
        assert len(graph.findall(f"{ns}edge")) == 1

    def test_render_prints_nodes_proofs_and_groups(self):
        g = SG.SocialGraph()
        a = g.add_handle("jane", platform="instagram")
        b = g.add_handle("jdoe")
        g.add_edge(a.key, b.key, "same_person", evidence="shared-email")
        text = g.render()
        assert "2 nodes" in text and "same-person groups" in text
        assert "jane" in text and "jdoe" in text

    def test_an_empty_graph_says_so(self):
        assert SG.SocialGraph().render() == "social graph: empty"


class TestGraphFromTheSession:
    """`social graph` shows what the engagement knows, with no network call."""

    class _Finding:
        def __init__(self, kind, value, confidence=0.5, key=""):
            self.kind, self.value, self.confidence, self.key = (
                kind, value, confidence, key)

    class _WM:
        def __init__(self, findings):
            self._findings = findings

        def find(self, kind):
            return [f for f in self._findings if f.kind == kind]

    def _wm(self):
        return self._WM([
            self._Finding("profile", {"username": "jane", "platform": "instagram",
                                      "state": "private", "private": True,
                                      "followers": "342",
                                      "full_name": "Jane Doe"},
                          confidence=0.9),
            self._Finding("account_link", {"handle": "sara", "platform": "instagram",
                                           "relation": "commenter", "on": "jane",
                                           "evidence": "graph:instagram"},
                          confidence=0.55),
            self._Finding("account_link", {"handle": "luca", "platform": "instagram",
                                           "relation": "tagged", "on": "jane",
                                           "evidence": "graph:instagram"},
                          confidence=0.45),
            self._Finding("account_link", {"handle": "ghost", "platform": "instagram",
                                           "relation": "weird"},
                          confidence=0.3),
            self._Finding("identity", {"email": "jane@example.com"},
                          confidence=0.8),
            self._Finding("identity_conf", {"handle": "sara", "tier": "likely",
                                            "score": 0.66}),
            self._Finding("profile", {"junk": True}),
        ])

    def test_it_rebuilds_the_circle_offline(self):
        g = SG.graph_from_wm(self._wm())
        assert "handle:jane" in g.nodes and "handle:sara" in g.nodes
        assert g.nodes["handle:jane"].attrs["state"] == "private"
        assert ("handle:jane", "handle:sara", "comments_on") in g.edges
        assert ("handle:jane", "handle:luca", "tagged_in") in g.edges
        assert g.edges[("handle:jane", "handle:sara", "comments_on")].evidence \
            == "graph:instagram"

    def test_an_unknown_relation_becomes_a_weak_second_hop(self):
        g = SG.graph_from_wm(self._wm())
        assert ("handle:jane", "handle:ghost", "second_hop") in g.edges

    def test_emails_from_identity_findings_link_to_the_subject(self):
        g = SG.graph_from_wm(self._wm())
        assert ("handle:jane", "email:jane@example.com", "email_match") \
            in g.edges

    def test_the_confirmed_tier_raises_the_node_confidence(self):
        g = SG.graph_from_wm(self._wm())
        assert g.nodes["handle:sara"].confidence == 0.66
        assert g.nodes["handle:sara"].attrs["tier"] == "likely"

    def test_a_malformed_or_empty_session_yields_an_empty_graph(self):
        assert SG.graph_from_wm(self._WM([])).stats()["nodes"] == 0
        assert SG.graph_from_wm(object()).stats()["nodes"] == 0


class TestPostMining:
    """Per-post intelligence: topics, mentions, places, links."""

    BLOB = {
        "data": {"user": {"edge_owner_to_timeline_media": {"edges": [
            {"node": {
                "id": "111", "shortcode": "abc",
                "taken_at_timestamp": 1712345678,
                "edge_media_to_caption": {"edges": [{"node": {
                    "text": "Climbing in Torino with @mario_rossi #boulder "
                            "#torino see https://climb.example.org/x"}}]},
                "location": {"name": "Torino", "slug": "torino"},
                "edge_liked_by": {"count": 42},
                "edge_media_to_comment": {"count": 7},
                "edge_media_to_tagged_user": {"edges": [{"node": {"user": {
                    "username": "giulia_b"}}}]}}},
            {"node": {
                "id": "222", "shortcode": "def", "taken_at_timestamp": 1712400000,
                "edge_media_to_caption": {"edges": [{"node": {
                    "text": "no mentions here"}}]}}},
        ]}}}}

    def test_it_mines_caption_mentions_hashtags_places_and_links(self):
        posts = SG.mine_posts([self.BLOB], author="jane")
        assert len(posts) == 2
        first = posts[0]
        assert first.post_id == "abc"
        assert first.mentions == ["mario_rossi", "giulia_b"]
        assert first.hashtags == ["boulder", "torino"]
        assert first.places == ["Torino"]
        assert first.links == ["climb.example.org"]
        assert first.taken_at == "1712345678"
        assert first.likes == "42" and first.comments == "7"

    def test_the_author_is_never_their_own_mention(self):
        blob = json.loads(json.dumps(self.BLOB))
        blob["data"]["user"]["edge_owner_to_timeline_media"]["edges"][0][
            "node"]["edge_media_to_caption"]["edges"][0]["node"]["text"] = \
            "me @jane_doe and @other"
        posts = SG.mine_posts([blob], author="jane_doe")
        assert "jane_doe" not in posts[0].mentions
        assert "other" in posts[0].mentions

    def test_it_never_raises_on_junk(self):
        assert SG.mine_posts(None) == []
        assert SG.mine_posts([None, 3, "x", {}]) == []
        assert SG.mine_posts(object()) == []

    def test_it_accepts_a_raw_json_document_as_well_as_html(self):
        assert SG.mine_posts(json.dumps(self.BLOB), author="jane")[0].post_id \
            == "abc"
        html = ('<html><script type="application/json">'
                + json.dumps(self.BLOB) + "</script></html>")
        assert SG.mine_posts(html, author="jane")[0].hashtags == [
            "boulder", "torino"]

    def test_posts_become_interest_and_tagged_in_edges(self):
        posts = SG.mine_posts([self.BLOB], author="jane")
        g = SG.graph_from_posts(posts, author="jane", platform="instagram")
        interests = dict(g.interests("handle:jane"))
        assert interests["torino"] == 2      # hashtag #torino + place Torino
        assert interests["boulder"] == 1
        kinds = {e.kind for e in g.proofs("handle:jane")}
        assert "tagged_in" in kinds and "interest" in kinds

    def test_a_post_with_no_analysis_still_exists_as_a_node(self):
        posts = SG.mine_posts([self.BLOB], author="jane")
        g = SG.graph_from_posts([p for p in posts if p.post_id == "def"],
                                author="jane")
        assert any(n.kind == "post" for n in g.nodes.values())


class TestReconIngest:
    """`recon.ReconResult` -> graph, including the free corroboration."""

    @staticmethod
    def _result(username, platform, leads, **kw):
        from phantom.automation.social.recon import Lead, ReconResult
        res = ReconResult(username=username, platform=platform, **kw)
        res.leads = [Lead(*l) if isinstance(l, tuple) else l for l in leads]
        return res

    def test_leads_become_typed_edges_with_evidence(self):
        r = self._result("jane", "instagram", [
            ("commenter", "mario", "instagram", "graph:instagram", 0.5),
            ("tagged", "giulia", "instagram", "graph:instagram", 0.45),
            ("identity", "j@x.com", "instagram", "bio:email", 0.8),
        ])
        g = SG.correlate([r])
        assert ("handle:jane", "handle:mario", "comments_on") in g.edges
        assert ("handle:jane", "handle:giulia", "tagged_in") in g.edges
        assert ("handle:jane", "email:j@x.com", "email_match") in g.edges
        assert g.edges[("handle:jane", "handle:mario", "comments_on")].evidence \
            == "graph:instagram"

    def test_the_same_handle_on_two_platforms_is_corroborated(self):
        r1 = self._result("jane", "instagram", [])
        r2 = self._result("jane", "github", [])
        g = SG.correlate([r1, r2])
        assert len([n for n in g.nodes.values() if n.kind == "handle"]) == 1
        node = g.nodes["handle:jane"]
        assert len(node.sources) == 2

    def test_an_avatar_hash_match_confirms_one_person(self):
        r1 = self._result("jane", "instagram", [
            ("account_link", "jdoe", "instagram", "cross", 0.6)],
            avatar_dhash="deadbeef")
        r2 = self._result("jdoe", "github", [], avatar_dhash="deadbeef")
        g = SG.correlate([r1, r2])
        assert ("handle:jane", "handle:jdoe", "same_person") in g.edges
        assert g.same_person_groups() == [["handle:jane", "handle:jdoe"]]

    def test_search_hits_are_kept_as_urls_not_fake_handles(self):
        r = self._result("jane", "instagram", [
            ("search_hit", "https://news.example.com/jane", "", "ddg", 0.3)])
        g = SG.correlate([r])
        assert not [n for n in g.nodes.values() if n.kind == "handle"
                    and n.label == "https://news.example.com/jane"]
        assert [n for n in g.nodes.values() if n.kind == "url"]

    def test_deep_recon_emits_the_graph_markers_and_fills_the_graph(self):
        """The wiring: recon's flat markers now carry a walkable summary."""
        from phantom.automation.social import recon as R

        html = ('<html><script type="application/json">' + json.dumps({
            "data": {"user": {
            "edge_followed_by": {"count": 342},
            "edge_owner_to_timeline_media": {"count": 12, "edges": [
                {"node": {"id": "9", "shortcode": "p1", "taken_at": 171,
                          "edge_media_to_caption": {"edges": [{"node": {
                              "text": "#torino #boulder with @mario"}}]},
                          "location": {"name": "Torino"}}}]},
            "edge_media_to_parent_comment": {"edges": [
                {"node": {"user": {"username": "sara"}}}]},
        }}}) + "</script></html>")

        def fake_vote(username, platform, jar=None):
            if platform == "instagram":
                return "public", 0.9, html
            return "missing", 0.0, ""

        R._state_vote = fake_vote
        graph = SG.SocialGraph()
        ok, lines = R.deep_recon("jane", "instagram", variants=False,
                                 wayback=False, search=False,
                                 second_hop=False, graph=graph)
        assert ok
        summary = [l for l in lines if l.startswith("SOCIAL_GRAPH:")]
        assert summary and "nodes=" in summary[0]
        assert any(l.startswith("GRAPH_PIVOT:") and "mario" in l
                   for l in lines)
        assert any(l.startswith("POST_TOPIC:") and "torino" in l
                   for l in lines)
        # the caller's graph really was filled in (CLI/API render it)
        assert "handle:jane" in graph.nodes and "handle:mario" in graph.nodes
        assert graph.interests("handle:jane")
        assert graph.stats()["nodes"] > 2

    def test_a_failing_graph_step_never_breaks_the_recon(self):
        from phantom.automation.social import recon as R

        def fake_vote(username, platform, jar=None):
            return ("public", 0.9, "<html></html>") if platform == "instagram" \
                else ("missing", 0.0, "")

        def boom(*_a, **_k):
            raise RuntimeError("graph exploded")

        R._state_vote = fake_vote
        original = SG.graph_from_recon
        try:
            SG.graph_from_recon = boom
            ok, lines = R.deep_recon("jane", "instagram", variants=False,
                                     wayback=False, search=False,
                                     second_hop=False)
        finally:
            SG.graph_from_recon = original
        assert ok and any(l.startswith("RECON_STATE:") for l in lines)

    def test_merging_two_graphs_keeps_edges_and_raises_confidence(self):
        a = SG.SocialGraph()
        a.add_handle("x", confidence=0.3)
        b = SG.SocialGraph()
        b.add_handle("x", confidence=0.8)
        b.add_handle("y")
        b.add_edge("handle:x", "handle:y", "follows")
        counts = a.merge(b)
        assert counts == {"nodes": 1, "edges": 1}
        assert a.nodes["handle:x"].confidence == 0.8
