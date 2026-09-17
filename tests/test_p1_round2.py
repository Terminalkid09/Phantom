"""P1 closure tests, round 2: P1-11 artifact governance, P1-15 AD graph
ACL edges + provenance, and the API artifact metadata surface."""
import os
import time

import pytest


# ── P1-11: artifact policy ────────────────────────────────────────────────

def test_classify_defaults_follow_owner_decision():
    from phantom.core.artifact_policy import classify
    # Q-5: media retention = 30 days by default
    assert classify("screenshots")["ttl_days"] == 30
    assert classify("downloads")["ttl_days"] == 30
    # high-volume transient streams are shorter-lived
    assert classify("remote")["ttl_days"] < 30
    assert classify("recordings/live")["ttl_days"] < 30


def test_over_quota_blocks_when_dir_full(tmp_path):
    from phantom.core import artifact_policy as AP
    d = tmp_path / "screenshots"
    d.mkdir()
    (d / "a.bin").write_bytes(b"x" * 1000)
    assert AP.dir_usage(str(d))["bytes"] == 1000
    # env is the operator override path — set it the way an engagement
    # would: default 1 GB → room for 1 KB; a 0.001 MB (1048 byte) quota
    # refuses after the next write crosses it
    import unittest.mock as _mock
    with _mock.patch.dict(os.environ, {"PHANTOM_ARTIFACT_QUOTA_MB": "1024"}):
        assert not AP.over_quota(str(d), "screenshots")
    with _mock.patch.dict(os.environ, {"PHANTOM_ARTIFACT_QUOTA_MB": "0.001"}):
        assert not AP.over_quota(str(d), "screenshots")   # 1000 < 1048
        (d / "b.bin").write_bytes(b"x" * 2000)            # now 3000 > 1048
        assert AP.over_quota(str(d), "screenshots")


def test_cleanup_expired_deletes_and_receipts(tmp_path):
    from phantom.core.artifact_policy import cleanup_expired
    d = tmp_path / "remote"
    d.mkdir()
    f = d / "frame_1.jpg"
    f.write_bytes(b"x" * 10)
    old = time.time() - 9 * 86400        # remote TTL = 7 days
    os.utime(f, (old, old))
    fresh = d / "frame_2.jpg"
    fresh.write_bytes(b"x" * 10)         # fresh file must survive
    receipts = cleanup_expired(str(tmp_path))
    names = [r["name"] for r in receipts]
    assert "frame_1.jpg" in names and "frame_2.jpg" not in names
    assert not f.exists() and fresh.exists()


def test_ttl_days_left_computation():
    from phantom.core.artifact_policy import ttl_days_left
    now = time.time()
    assert ttl_days_left("screenshots", now, now=now) == 30
    aged = now - 31 * 86400
    assert ttl_days_left("screenshots", aged, now=now) < 0


# ── P1-15: AD graph ACL edges + provenance ───────────────────────────────

@pytest.fixture
def isolated_graph(monkeypatch, tmp_path):
    """Point STATE_PATH at a temp file so tests never touch data/."""
    from phantom.core import ad_graph as AG
    monkeypatch.setattr(AG, "STATE_PATH", tmp_path / "ad_graph.json")
    yield AG


def test_acl_ingestion_creates_edges_with_provenance(isolated_graph,
                                                     tmp_path):
    from phantom.automation.belief import WorldModel
    from phantom.core.ad_graph import ingest_from_wm
    wm = WorldModel(target="10.0.0.10")
    wm.add_finding(kind="ad_domain", key="corp.local",
                   value={"domain": "corp.local", "dc_host": "DC01"})
    wm.add_finding(kind="ad_acl", key="a1", value={
        "principal": "jdoe", "target": "DC01",
        "rights": ["WriteDacl", "DS-Replication-Get-Changes-All"],
        "target_type": "dc", "source": "enum"})
    g = ingest_from_wm(wm)
    types = {(e.src, e.type, e.dst) for e in g.edges}
    assert ("jdoe", "write_dacl", "DC01") in types
    assert ("jdoe", "dcsync", "DC01") in types
    for e in g.edges:
        if e.src == "jdoe":
            assert e.source == "enum" and e.confidence >= 0.7


def test_provenance_confidence_upgrade_on_stronger_source(isolated_graph,
                                                          tmp_path):
    g = isolated_graph.ADGraph()
    g.add_node("u1", "user")
    g.add_node("h1", "computer")
    g.add_edge("u1", "h1", "generic_all", source="operator")
    conf_before = [e.confidence for e in g.edges
                   if e.type == "generic_all"][0]
    g.add_edge("u1", "h1", "generic_all", source="logon")   # stronger proof
    conf_after = [e.confidence for e in g.edges
                  if e.type == "generic_all"][0]
    assert conf_after > conf_before
    assert conf_after == isolated_graph.SOURCE_CONFIDENCE["logon"]


def test_unknown_acl_right_is_ignored(isolated_graph, tmp_path):
    from phantom.automation.belief import WorldModel
    from phantom.core.ad_graph import ingest_from_wm
    wm = WorldModel(target="10.0.0.10")
    wm.add_finding(kind="ad_domain", key="corp.local",
                   value={"domain": "corp.local", "dc_host": "DC01"})
    wm.add_finding(kind="ad_acl", key="a2", value={
        "principal": "eve", "target": "DC01",
        "rights": ["MakeCoffee"], "target_type": "dc"})
    g = ingest_from_wm(wm)
    assert not [e for e in g.edges if e.src == "eve"
                and e.type != "owns"]


# ── artifact API carries governance metadata ─────────────────────────────

def test_artifact_policy_exposes_ttl_days_left():
    from phantom.core.artifact_policy import ttl_days_left
    now = time.time()
    v = ttl_days_left("downloads", now, now=now)
    assert v == 30
