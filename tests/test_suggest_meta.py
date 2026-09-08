"""Tests for the trust-earned suggestion layer (evidence tags + preflight)."""
import pytest

from phantom.core.suggest_meta import (
    TaggedSuggestion, preflight, score_trust, tag_suggestions,
)


@pytest.fixture(autouse=True)
def _clean_session(monkeypatch):
    from phantom.core.session import session
    monkeypatch.setattr(session, "target", "10.0.0.5", raising=False)
    monkeypatch.setattr(session, "scope", [], raising=False)
    monkeypatch.setattr(session, "results", {}, raising=False)
    kb = dict(session.knowledge_base or {})
    kb.pop("services", None)
    kb.pop("creds_found", None)
    monkeypatch.setattr(session, "knowledge_base", kb, raising=False)
    yield


def test_trust_bounds_and_monotonicity():
    for n in (1, 2, 3, 5):
        t = score_trust(n)
        assert 0.0 <= t <= 1.0
    assert score_trust(3) >= score_trust(1)


def test_preflight_missing_tool():
    pf = preflight("definitely_missing_tool_xyz --help")
    assert pf["missing"] is True
    assert pf["tool"] == "definitely_missing_tool_xyz"


def test_preflight_present_tool():
    pf = preflight("python --version")
    assert pf["missing"] is False


def test_tagging_attaches_evidence_from_kb():
    from phantom.core.session import session
    session.knowledge_base["services"] = [
        {"proto": "tcp", "port": 445, "service": "microsoft-ds"}]
    groups = {"SUGGESTED (smb:445)": ["enum4linux -a 10.0.0.5"]}
    tagged = tag_suggestions(groups)
    assert len(tagged) == 1
    t = tagged[0]
    assert "service:tcp/445" in t.why
    assert t.tool == "enum4linux"
    assert t.trust > 0.3


def test_missing_tool_sinks_in_ranking():
    groups = {
        "A": ["python -c 'present tool'"],
        "B": ["definitely_missing_tool_xyz --help"],
    }
    tagged = tag_suggestions(groups)
    assert tagged[0].tool != "definitely_missing_tool_xyz"


def test_dedup_marks_already_ok():
    from phantom.core.session import session
    cmd = "nmap -sS -p- 10.0.0.5"
    session.results["scan"] = f"{cmd} ok"
    tagged = tag_suggestions({"G": [cmd]})
    assert tagged[0].already_ok is True


def test_empty_groups_safe():
    assert tag_suggestions({}) == []
    assert tag_suggestions({"G": []}) == []
