"""Reverse-image planning: queries only, and two signals for a confirmed match."""
from __future__ import annotations

from phantom.automation.social import image_reverse as ir


def test_a_public_avatar_becomes_real_reverse_queries():
    plan = ir.reverse_plan("instagram", "mario.rossi",
                           avatar_url="https://cdn.example.com/a.jpg")
    engines = {e for e, _u in plan.queries}
    assert {"yandex", "google", "tineye"} <= engines
    assert all("cdn.example.com" in u for _e, u in plan.queries)


def test_no_public_url_means_no_query_and_an_honest_note():
    plan = ir.reverse_plan("instagram", "mario.rossi", avatar_url="")
    assert plan.queries == []
    assert any("no public avatar URL" in n for n in plan.notes)


def test_the_same_picture_survives_reencoding_but_a_different_one_does_not():
    same = ir.compare_hashes("f0e1d2c3b4a59687", "f0e1d2c3b4a59687")
    assert same.verdict in (ir.CONFIRMED, ir.PROBABLE)
    assert same.distance == 0
    different = ir.compare_hashes("f0e1d2c3b4a59687", "0f1e2d3c4b5a6978")
    assert different.verdict == ir.DIFFERENT


def test_one_avatar_signal_alone_is_never_confirmed():
    m = ir.compare_hashes("f0e1d2c3b4a59687", "f0e1d2c3b4a59687")
    combined = ir.combine([m])
    assert combined.verdict == ir.PROBABLE
    assert "corroborate" in combined.reason


def test_two_independent_signals_can_confirm():
    m = ir.compare_hashes("f0e1d2c3b4a59687", "f0e1d2c3b4a59687")
    assert ir.combine([m, m], name_match=True).verdict == ir.CONFIRMED


def test_missing_hashes_are_unknown_not_a_match():
    m = ir.compare_hashes("", "")
    assert m.verdict == ir.UNKNOWN
    assert "missing" in m.reason


def test_markers_never_claim_more_than_the_evidence():
    plan = ir.reverse_plan("x", "handle", avatar_url="https://e/x.png")
    assert any(m.startswith("REVERSE_PLAN") for m in plan.markers())
    assert any("REVERSE_QUERY" in m for m in plan.markers())
