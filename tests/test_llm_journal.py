"""Tests: the LLM proposal journal (phantom/automation/llm_journal.py).

The advisor is non-gating by design, which made one question unanswerable: when
the planner ignored the model, WHY? A dropped proposal left no trace, so a
hallucinated capability id looked identical to a move this engagement needed and
a gate refused. These tests pin the trace that fixes it — every proposal, its
verdict, and the deterministic reason — plus the two invariants that keep it
safe: the journal can never break a run, and it stores a request DIGEST rather
than the prompt text.
"""
from __future__ import annotations

import json
import os

import pytest

from phantom.automation import llm_journal as lj


@pytest.fixture()
def journal(tmp_path):
    return lj.Journal(path=str(tmp_path / "llm_journal.jsonl"))


def _prop(cid, verdict="accepted", drop="", reason="because"):
    return {"capability_id": cid, "reason": reason,
            "verdict": verdict, "drop_reason": drop}


# ── recording ────────────────────────────────────────────────────────────────

def test_a_recorded_call_keeps_the_proposals_and_their_verdicts(journal):
    entry = journal.record("suggest", request="10.0.0.5",
                           raw="[{\"capability_id\": \"ssh_login\"}]",
                           proposals=[_prop("ssh_login"),
                                      _prop("made_up", "dropped",
                                            "not-whitelisted")])
    assert entry.seq == 1
    assert entry.accepted == ["ssh_login"]
    assert [p["capability_id"] for p in entry.dropped] == ["made_up"]
    assert journal.entries()[0].to_dict()["dropped"] == ["made_up"]


def test_the_request_is_stored_as_a_digest_not_as_text(journal):
    journal.record("suggest", request="secret-target.internal")
    entry = journal.entries()[0]
    assert "secret-target.internal" not in json.dumps(entry.to_dict())
    assert entry.request_digest and len(entry.request_digest) == 16


def test_the_ring_is_bounded(journal):
    for i in range(lj.MAX_ENTRIES + 25):
        journal.record("suggest", request=f"t{i}")
    assert len(journal.entries()) == lj.MAX_ENTRIES
    assert journal.entries()[-1].request_digest          # newest kept


def test_a_broken_file_path_is_reported_never_raised(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")                    # a FILE where a dir must be
    broken = lj.Journal(path=str(blocker / "nested" / "journal.jsonl"))
    entry = broken.record("suggest", request="t")
    assert entry.wrote is False                # reported on the entry
    assert broken.entries()                    # and it still kept the data
    assert broken.render().count("#1") == 1


def test_clear_empties_the_ring(journal):
    journal.record("suggest", request="t")
    assert journal.clear() == 1
    assert journal.entries() == []


# ── the operator view ────────────────────────────────────────────────────────

def test_refusals_lists_only_calls_the_algorithm_overruled(journal):
    journal.record("suggest", request="a", proposals=[_prop("ssh_login")])
    journal.record("suggest", request="b",
                   proposals=[_prop("http_probe", "dropped",
                                    "unknown-capability")])
    journal.record("classify", request="c", error="boom")
    refusals = journal.refusals()
    assert len(refusals) == 2                  # the dropped one AND the error
    assert [e.kind for e in refusals] == ["suggest", "classify"]


def test_render_shows_what_the_model_wanted_and_why_it_was_dropped(journal):
    journal.record("suggest", request="a",
                   proposals=[_prop("ssh_login", reason="creds available"),
                              _prop("made_up", "dropped", "not-whitelisted",
                                    reason="hallucinated")])
    text = journal.render()
    assert "ACCEPTED" in text and "ssh_login" in text
    assert "DROPPED" in text and "made_up" in text
    assert "not-whitelisted" in text and "hallucinated" in text


def test_render_says_so_when_there_is_nothing_to_show(journal):
    assert "no model proposals" in journal.render()
    assert "refusals" in journal.render(refused_only=True)


def test_stats_count_calls_proposals_and_refusals(journal):
    journal.record("suggest", request="a",
                   proposals=[_prop("ssh_login"),
                              _prop("made_up", "dropped", "not-whitelisted")])
    journal.record("classify", request="b", error="boom")
    stats = journal.stats()
    assert stats == {"calls": 2, "proposals": 2, "accepted": 1,
                     "dropped": 1, "errors": 1, "refusals": 2}


# ── the advisor actually feeds it ────────────────────────────────────────────

class _Wm:
    target = "10.0.0.5"


class _Registry:
    """Knows ssh_login only; http_probe is whitelisted but not registered."""

    def get(self, cid):
        return object() if cid == "ssh_login" else None


def test_the_advisor_records_every_proposal_with_its_drop_reason(monkeypatch,
                                                                journal):
    from phantom.automation.llm_advisor import LLMAdvisor

    monkeypatch.setattr(lj, "journal", journal)
    advisor = LLMAdvisor(enabled=True)
    monkeypatch.setattr(advisor, "available", lambda: True)
    monkeypatch.setattr(advisor, "_generate", lambda wm: json.dumps([
        {"capability_id": "ssh_login", "reason": "creds in the world model"},
        {"capability_id": "http_probe", "reason": "web service seen"},
        {"capability_id": "made_up", "reason": "hallucinated"},
    ]))

    prefs = advisor.suggest(_Wm(), _Registry())
    assert prefs == ["ssh_login"]

    entry = journal.entries()[-1]
    by_id = {p["capability_id"]: p for p in entry.proposals}
    assert by_id["ssh_login"]["verdict"] == "accepted"
    assert by_id["http_probe"]["drop_reason"] == "unknown-capability"
    assert by_id["made_up"]["drop_reason"] == "not-whitelisted"
    # the model's own words survive, so a human can judge them later
    assert by_id["http_probe"]["reason"] == "web service seen"
    assert journal.refusals()[-1].seq == entry.seq


def test_a_failing_model_call_is_recorded_as_an_error(monkeypatch, journal):
    from phantom.automation.llm_advisor import LLMAdvisor

    monkeypatch.setattr(lj, "journal", journal)
    advisor = LLMAdvisor(enabled=True)
    monkeypatch.setattr(advisor, "available", lambda: True)

    def boom(wm):
        raise RuntimeError("model exploded")

    monkeypatch.setattr(advisor, "_generate", boom)
    assert advisor.suggest(_Wm(), _Registry()) == []
    entry = journal.entries()[-1]
    assert "model exploded" in entry.error


def test_a_broken_journal_never_breaks_the_advisor(monkeypatch):
    from phantom.automation.llm_advisor import LLMAdvisor

    class _Broken:
        @staticmethod
        def record(*a, **k):
            raise RuntimeError("journal unavailable")

    monkeypatch.setattr(lj, "journal", _Broken)
    advisor = LLMAdvisor(enabled=True)
    monkeypatch.setattr(advisor, "available", lambda: True)
    monkeypatch.setattr(advisor, "_generate", lambda wm: json.dumps(
        [{"capability_id": "ssh_login", "reason": "r"}]))
    assert advisor.suggest(_Wm(), _Registry()) == ["ssh_login"]
