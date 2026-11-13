"""AI advisors: bounded influence, closed ids, no execution authority."""
from __future__ import annotations

from phantom.automation.ai.advisors import exploit as advisor
from phantom.automation.ai.advisors import finding as finder
from phantom.automation.ai.router import AIResult
from phantom.automation.ai.trust import Trust
from phantom.automation.exploit.access import AccessCandidate


#: The rerank tests exercise the CONTRACT, not the repository's current
#: model state: passing the ladder explicitly keeps them green when no
#: manifest is promoted (2026-11-02) and still bounds the influence.
NUDGE = Trust(phase="exploit", level="nudge", bound=0.12,
              max_steps=2, gap=0.15)


def _cand(cid: str, score: float, *, actionable: bool = True,
          auto: bool = True, access: str = "exec",
          complexity: float = 0.3, noise: float = 0.3) -> AccessCandidate:
    return AccessCandidate(
        id=cid, target="10.0.0.5", cve="", access=access,
        actionable=actionable, auto_execute=auto, score=score,
        complexity=complexity, noise=noise, success=0.7)


def _ok(ids, model="test-model"):
    return AIResult(ok=True, model=model,
                    data={"ranked": [{"id": i} for i in ids]})


def test_an_unknown_id_is_dropped_and_the_order_is_unchanged(monkeypatch):
    a, b = _cand("a", 60), _cand("b", 50)
    monkeypatch.setattr(
        advisor, "ask",
        lambda *a, **k: AIResult(ok=True, model="m",
                                 data={"ranked": [{"id": "ghost"},
                                                  {"id": "a"}]}))
    result = advisor.rerank([a, b], "balanced")
    assert [c.id for c in result.ordered] == ["a", "b"]
    assert "ghost" not in [c.id for c in result.ordered]
    assert result.applied is False


def test_a_close_pair_can_be_reordered_and_is_recorded(monkeypatch):
    a, b = _cand("a", 60.0), _cand("b", 59.0)
    monkeypatch.setattr(advisor, "ask", lambda *a, **k: _ok(["b", "a"]))
    result = advisor.rerank([a, b], "balanced", trust=NUDGE)
    assert [c.id for c in result.ordered] == ["b", "a"]
    assert result.applied is True
    assert result.changed


def test_a_big_score_gap_cannot_be_inverted(monkeypatch):
    strong, weak = _cand("strong", 90.0), _cand("weak", 40.0)
    monkeypatch.setattr(advisor, "ask",
                        lambda *a, **k: _ok(["weak", "strong"]))
    result = advisor.rerank([strong, weak], "balanced")
    assert [c.id for c in result.ordered] == ["strong", "weak"]
    assert result.applied is False


def test_actionability_and_execution_flags_are_never_changed(monkeypatch):
    a = _cand("a", 10.0, actionable=True)
    b = _cand("b", 99.0, actionable=False)
    monkeypatch.setattr(advisor, "ask", lambda *a, **k: _ok(["a"]))
    result = advisor.rerank([a, b], "balanced")
    assert [c.id for c in result.ordered] == ["a", "b"]
    assert a.actionable and b.actionable is False
    assert b.auto_execute is True


def test_a_failed_model_leaves_the_order_untouched(monkeypatch):
    """No model AT ALL: the deterministic order stands and says why.

    The promoted CPU ranker is a fallback ON PURPOSE (see the module docstring:
    "the LLM is not the only model"), so this test removes it explicitly — the
    property under test is what happens when nothing can answer.
    """
    from phantom.automation.ai import linear

    monkeypatch.setattr(linear, "promoted", lambda *_a, **_k: None)
    a, b = _cand("a", 60.0), _cand("b", 10.0)
    monkeypatch.setattr(
        advisor, "ask",
        lambda *a, **k: AIResult(ok=False, error="timeout"))
    result = advisor.rerank([a, b], "balanced", trust=NUDGE)
    assert [c.id for c in result.ordered] == ["a", "b"]
    assert result.applied is False and "timeout" in result.reason


def test_an_unreachable_llm_falls_back_to_the_promoted_cpu_ranker(monkeypatch):
    """A measured CPU ranker answers when the endpoint does not."""
    from phantom.automation.ai import linear

    class _Ranker:
        version = "test-ranker"

        def rank(self, ids, context=None, contexts=None):
            assert contexts is not None, (
                "the runtime must pass per-candidate contexts, or the "
                "trained is_cve interaction is dead")
            return sorted(ids, reverse=True)

    monkeypatch.setattr(linear, "promoted", lambda *_a, **_k: _Ranker())
    monkeypatch.setattr(
        advisor, "ask",
        lambda *a, **k: AIResult(ok=False, error="timeout"))
    # a SMALL gap (the trust cap refuses an inversion across 30 points, which
    # is the whole point of the ladder — see `test_nudge_cannot_invert_...`)
    a, b = _cand("a", 60.0), _cand("b", 55.0)
    result = advisor.rerank([a, b], "balanced", trust=NUDGE)
    assert result.model == "test-ranker"
    assert result.applied is True
    assert [c.id for c in result.ordered] == ["b", "a"]


def test_the_payload_never_carries_a_command(monkeypatch):
    seen = {}

    def fake_ask(phase, payload, **_kwargs):
        seen["payload"] = payload
        return _ok(["a"])

    a = _cand("a", 60.0)
    a.action = {"command": "id", "shell": "bash"}
    monkeypatch.setattr(advisor, "ask", fake_ask)
    advisor.rerank([a], "balanced", trust=NUDGE)
    row = seen["payload"]["candidates"][0]
    assert row["id"] == "a"
    assert {"action", "command", "shell", "cmd"} & set(row) == set()


def test_finding_advice_is_off_or_empty_when_the_model_fails(monkeypatch):
    class F:
        kind, key, value, confidence = "service", "tcp/22", {"port": "22"}, 0.9

    monkeypatch.setattr(
        finder, "ask",
        lambda *a, **k: AIResult(ok=False, error="disabled"))
    advice = finder.advise([F()])
    assert advice.ok is False
    assert advice.anomalies == [] and advice.next_checks == []


def test_finding_advice_drops_invented_findings(monkeypatch):
    class F:
        kind, key, value, confidence = "service", "tcp/22", {"port": "22"}, 0.9

    monkeypatch.setattr(
        finder, "ask",
        lambda *a, **k: AIResult(ok=True, model="m", data={
            "findings": [
                {"kind": "service", "key": "tcp/22", "note": "odd banner"},
                {"kind": "service", "key": "tcp/9999", "note": "invented"},
            ],
            "next": ["banner grab on 22"],
        }))
    advice = finder.advise([F()])
    assert advice.ok is True
    assert [a["key"] for a in advice.anomalies] == ["tcp/22"]
    assert advice.next_checks == ["banner grab on 22"]


def test_the_schema_refuses_execution_keys():
    from phantom.automation.ai.schemas import validate_exploit
    errors = validate_exploit({"ranked": [{"id": "a", "command": "id"}]})
    assert errors


def test_sweep_adds_no_ai_key_when_disabled(monkeypatch):
    from phantom.automation.belief import WorldModel
    from phantom.automation.exploit import sweep
    wm = WorldModel(target="10.0.0.5")
    monkeypatch.setattr(
        sweep, "collect_candidates",
        lambda **kw: [_cand("a", 60.0, actionable=False)])
    monkeypatch.setattr(sweep, "_ai_enabled", lambda phase: False)
    summary = sweep.exploit_worldmodel(wm)
    assert "ai_rerank" not in summary
    assert "ai_findings" not in summary


def test_sweep_uses_the_bounded_order_when_ai_is_on(monkeypatch):
    from phantom.automation.belief import WorldModel
    from phantom.automation.exploit import sweep
    wm = WorldModel(target="10.0.0.5")
    a, b = _cand("a", 60.0), _cand("b", 59.0)
    monkeypatch.setattr(sweep, "collect_candidates", lambda **kw: [a, b])
    monkeypatch.setattr(sweep, "_ai_enabled",
                        lambda phase: phase == "exploit")
    # ``goal``/``profile`` travel with the call now: the ranker's context is
    # trained on them, so the sweep is expected to forward them.
    monkeypatch.setattr(
        "phantom.automation.ai.advisors.exploit.rerank",
        lambda cands, mode, **kw: advisor.RerankResult(
            [b, a], True, "test", [("b", "0->1")], "m"))
    summary = sweep.exploit_worldmodel(wm)
    assert summary["ai_rerank"]["applied"] is True
    assert [row["id"] for row in summary["selected"]] == ["b", "a"]
