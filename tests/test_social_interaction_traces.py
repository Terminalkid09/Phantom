"""Interaction traces: authors, mentions, co-commenters and secondary handles.

The old recon mined `@handles` out of comment TEXT. That found people a
commenter mentioned, never the commenter, and a target's own comment under
somebody else's post left no trace at all. These tests pin the structured
author path and the dork -> account candidate extraction.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.kit import _social_interp
from phantom.automation.social import recon as R
from phantom.automation.social import social_graph as SG
from phantom.automation.social.identity_confidence import (
    _handle_variant, score_lead)


def _page(comments, post_author="friend"):
    blob = json.dumps({"commentList": comments})
    return ('<html><script type="application/ld+json">'
            + blob + "</script></html>")


def test_status_marker_is_not_read_as_a_curl_format_file(monkeypatch):
    """`curl -w @file` reads a file; the sentinel must not start with `@`.

    Measured live: the old `@@PHANTOM_STATUS@@` made every fetch exit 26
    with no body, so a real GitHub profile was classified `unknown`.
    """
    captured = {}

    def fake_execute(cmd, timeout=None):
        captured["cmd"] = cmd
        return SimpleNamespace(
            stdout="HTTP/1.1 200 OK\r\n\r\nREAL BODY" + R._STATUS_MARK + "200",
            stderr="", returncode=0)

    monkeypatch.setattr("phantom.core.executor.execute_quiet", fake_execute)
    result = R._fetch_ex("https://example.com/profile")
    assert not R._STATUS_MARK.startswith("@")
    assert ' -w "@' not in captured["cmd"]
    assert result.status == 200
    assert result.body == "REAL BODY"


def test_comment_author_is_extracted_from_structured_json():
    comments = [
        {"owner": {"username": "target"}, "text": "great post @friend",
         "id": "c1"},
        {"user": {"unique_id": "observer"}, "text": "@target look"},
        {"author": "[deleted]", "body": "gone"},
    ]
    traces = R._comment_traces(
        [json.loads(json.dumps({"commentList": comments}))],
        post_author="friend")
    assert [(t.actor, t.text) for t in traces] == [
        ("target", "great post @friend"),
        ("observer", "@target look"),
    ]


def test_platform_chrome_and_hex_ids_are_not_people():
    assert not R._is_real_handle("github")
    assert not R._is_real_handle("d5750093facf")
    assert R._is_real_handle("torvalds")


def test_an_avatar_body_is_hashed_without_aborting_the_pass(monkeypatch):
    html = ('<html><meta property="og:image" '
            'content="https://cdn.example/avatar.jpg"></html>')
    monkeypatch.setattr(R, "_fetch", lambda *a, **k: "not-real-image-bytes")
    result = R.ReconResult(username="target", platform="github")
    R._mine_graph("target", "github", html, result)
    assert result.avatar_hash


def test_a_caption_is_not_a_comment():
    blob = {"edge_media_to_caption": {"edges": [
        {"node": {"text": "holiday #torino"}}]}}
    assert R._comment_traces([blob]) == []


def test_target_comment_mention_and_co_commenter_are_distinct_leads():
    html = _page([
        {"owner": {"username": "target"}, "text": "nice one @friend"},
        {"user": {"unique_id": "observer"}, "text": "@target see this"},
        {"user": {"unique_id": "stranger"}, "text": "hello"},
    ])
    leads = R._trace_leads("target", "instagram", html, "friend",
                           {"observer"})
    kinds = {(l.kind, l.value) for l in leads}
    assert ("trace", "friend") in kinds
    assert ("mention", "observer") in kinds
    assert ("co_commenter", "observer") in kinds
    assert all("stranger" not in value for _kind, value in kinds)


def test_profile_url_extraction_rejects_content_paths():
    assert R._profile_handle("https://www.linkedin.com/in/mario-rossi") \
        == ("linkedin", "mario-rossi")
    assert R._profile_handle("reddit.com/user/mrossi") == ("reddit", "mrossi")
    assert R._profile_handle("github.com/mrossi/repo") == ("github", "mrossi")
    assert R._profile_handle("instagram.com/p/abc")[1] == ""
    assert R._profile_handle("instagram.com/popular/linus-torvalds/")[1] == ""
    assert R._profile_handle("tiktok.com/@user/video/123")[1] == ""
    assert R._profile_handle("tiktok.com/@user") == ("tiktok", "user")
    assert R._profile_handle("x.com/status/1")[1] == ""
    assert R._profile_handle("github.com/orgs/acme")[1] == ""
    assert R._profile_handle("t.me/joinchat/abc")[1] == ""


def test_a_dork_profile_url_becomes_an_account_candidate(monkeypatch):
    page = ('<a class="result__url" href="x">'
            'linkedin.com/in/mario-rossi</a>')
    monkeypatch.setattr(R, "_fetch", lambda *a, **k: page)
    monkeypatch.setattr(R.time, "sleep", lambda *_: None)
    leads = R._search_dorks("target", "Mario Rossi")
    assert any(l.kind == "account_link" and l.value == "mario-rossi"
               and l.platform == "linkedin" for l in leads)
    assert any(l.kind == "search_hit" for l in leads)


def test_handle_variant_is_a_weak_signal_not_identity_proof():
    assert _handle_variant("mario.rossi", "mario_rossi")
    assert _handle_variant("mario.rossi", "mario.rossi1")
    assert not _handle_variant("marco", "mario")
    lead = score_lead("instagram", {"username": "mario.rossi"},
                      {"username": "mario_rossi"})
    assert "handle_variant" in {k for k, _ in lead.signals}
    assert lead.score < 0.55


def test_trace_markers_reach_the_identity_graph():
    output = "\n".join([
        "PROFILE: username=target platform=instagram private=0 bio=x link=",
        "TRACE: handle=friend platform=instagram on=friend "
        "evidence=comment_on:friend:post:1",
        "MENTION: handle=observer platform=instagram mentions=target "
        "evidence=mentions:target:on:friend",
        "CO_COMMENTER: handle=observer platform=instagram "
        "evidence=co_comment_with:friend",
    ])
    wm = WorldModel(target="target", target_type="username")
    findings = _social_interp(output, wm, {})
    for finding in findings:
        wm.add_finding(finding.kind, finding.key, finding.value,
                       confidence=finding.confidence, source=finding.source)
    graph = SG.graph_from_wm(wm)
    assert ("handle:target", "handle:friend", "commented_on") in graph.edges
    assert ("handle:target", "handle:observer", "mentioned_by") in graph.edges
    assert ("handle:target", "handle:observer", "co_commented") in graph.edges
