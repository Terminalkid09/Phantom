"""Cross-platform correlation tests for `automation/social/social_graph.py`.

Every test is offline: the graph ingests already-computed `ReconResult`-shaped
objects, so what is verified here is the REASONING, not the network.

The three defects these tests pin down are the ones the report used to get
wrong in a way an operator could act on:

  * the same picture served under two CDN URLs never linked (the query string
    and the `_s150x150` size suffix were treated as part of the identity);
  * an email probed as a social handle lived next to its own `email:` node, so
    a shared email could not connect the profiles that exposed it;
  * nothing RANKED the clusters, so a commenter chain and a confirmed
    same-person pair read the same in the JSON.
"""
from types import SimpleNamespace

from phantom.automation.social import social_graph as SG


def _result(username, platform="instagram", *, state="public", leads=(),
            avatar_url="", avatar_hash=""):
    return SimpleNamespace(
        username=username, platform=platform, state=state, full_name="",
        bio="", avatar_url=avatar_url, avatar_hash=avatar_hash,
        avatar_dhash="", leads=list(leads),
    )


def _lead(kind, value, evidence="recon", confidence=0.6, platform=""):
    return SimpleNamespace(kind=kind, value=value, evidence=evidence,
                           confidence=confidence, platform=platform)


class TestAvatarNormalisation:
    def test_the_same_picture_under_two_cdn_urls_is_one_avatar(self):
        # same file, different cache-buster + size suffix (what Instagram
        # actually serves on the profile page vs the /embed/ page)
        first = _result(
            "jane.doe", avatar_url=(
                "https://scontent-mxp1-1.cdninstagram.com/v/t51.2885-19/"
                "abc123/x.jpg?stp=dst-jpg_s150x150&_nc_ht=scontent-mxp1-1"))
        second = _result(
            "janedoe", platform="tiktok", avatar_url=(
                "http://SCONTENT-MXP1-1.cdninstagram.com/v/t51.2885-19/"
                "abc123/x_s150x150.jpg"))
        graph = SG.correlate([first, second])
        avatars = [k for k, n in graph.nodes.items()
                   if n.kind == "url" and "avatar" in k]
        assert len(avatars) == 1, avatars
        report = SG.correlation_report(graph)
        assert report, "a shared avatar must produce a cluster"
        assert set(report[0]["handles"]) == {"jane.doe", "janedoe"}
        assert "same_avatar" in report[0]["why"]

    def test_a_different_host_is_a_different_picture(self):
        a = _result("a", avatar_url="https://cdn.one.example/x.jpg")
        b = _result("b", avatar_url="https://cdn.two.example/x.jpg")
        graph = SG.correlate([a, b])
        assert SG.correlation_report(graph) == []

    def test_exact_hash_linking_still_works(self):
        a = _result("a", avatar_hash="deadbeef00112233")
        b = _result("b", avatar_hash="DEADBEEF00112233")
        graph = SG.correlate([a, b])
        assert graph.same_person_groups() == [["handle:a", "handle:b"]]


class TestAliasMerge:
    def test_an_email_probed_as_a_handle_folds_into_its_email_node(self):
        # the live case: the recon engine probes the address as a username
        # because that is a legal handle, and keeps both nodes
        probed = _result("mail@example.com", state="missing")
        profile = _result("jane", leads=[
            _lead("identity", "mail@example.com", evidence="bio"),
        ])
        graph = SG.correlate([probed, profile])
        assert "handle:mail@example.com" not in graph.nodes
        email = graph.nodes["email:mail@example.com"]
        # the "missing" outcome travels with the identity; it must not turn
        # into a confirmed email just because the node was renamed
        assert email.attrs.get("state") == "missing"
        report = SG.correlation_report(graph)
        assert len(report) == 1
        assert report[0]["handles"] == ["jane"]

    def test_a_phone_handle_folds_into_a_phone_node(self):
        graph = SG.graph_from_recon([_result("+39 333 123 4567")])
        assert "handle:+393331234567" not in graph.nodes
        assert "phone:+393331234567" in graph.nodes


class TestCorrelationReport:
    def _graph(self):
        g = SG.SocialGraph()
        a = g.add_handle("a", platform="instagram", state="public")
        b = g.add_handle("b", platform="tiktok", state="public")
        g.add_edge(a.key, b.key, "same_person", evidence="shared-email")
        c = g.add_handle("c", platform="x", state="public")
        d = g.add_handle("d", platform="github", state="public")
        g.add_edge(c.key, d.key, "same_avatar", evidence="avatar")
        return g

    def test_a_confirming_proof_outranks_a_weak_one(self):
        report = SG.correlation_report(self._graph())
        assert [row["handles"] for row in report] == [["a", "b"], ["c", "d"]]
        assert report[0]["score"] > report[1]["score"]

    def test_weak_edges_alone_are_not_a_cluster(self):
        g = SG.SocialGraph()
        a = g.add_handle("a")
        b = g.add_handle("b")
        g.add_edge(a.key, b.key, "comments_on", confidence=0.5)
        assert SG.correlation_report(g) == []

    def test_missing_or_unknown_only_clusters_are_flagged(self):
        g = SG.SocialGraph()
        a = g.add_handle("a", state="unknown")
        b = g.add_handle("b", state="missing")
        g.add_edge(a.key, b.key, "same_avatar", evidence="avatar")
        report = SG.correlation_report(g)
        assert report[0]["unconfirmed"] is True

        g2 = SG.SocialGraph()
        c = g2.add_handle("c", state="public")
        d = g2.add_handle("d", state="unknown")
        g2.add_edge(c.key, d.key, "same_avatar", evidence="avatar")
        assert SG.correlation_report(g2)[0]["unconfirmed"] is False

    def test_no_cluster_ever_reaches_certainty(self):
        g = SG.SocialGraph()
        keys = [g.add_handle(name).key for name in "abcdef"]
        for i, first in enumerate(keys):
            for second in keys[i + 1:]:
                g.add_edge(first, second, "same_person", evidence="manual")
                g.add_edge(first, second, "reset_flow_match", evidence="reset")
        report = SG.correlation_report(g)
        assert report[0]["score"] < 1.0
        assert report[0]["why"] == ["reset_flow_match", "same_person"]

    def test_the_report_is_deterministic(self):
        graph = self._graph()
        first = SG.correlation_report(graph)
        second = SG.correlation_report(graph)
        assert first == second
        assert [row["id"] for row in first] == [row["id"] for row in second]

    def test_a_cluster_carries_its_platforms(self):
        report = SG.correlation_report(self._graph())
        assert report[0]["platforms"] == ["instagram", "tiktok"]
