"""The measured model inside the ONE decision engine (next_moves).

Measured 2026-11-03: `rank_next_moves` is what `run <n>`, `suggest` and the
auto-mode move order all read, and it contained no AI code — the trained
advisor was reachable only from `exploit sweep`. That is why `--ai
integrated` produced the same lab outcome as no AI at all: the model was not
in the loop. These tests pin the contract of the bridge:

  * at `observe` (the default: nothing measured has been promoted) the
    advisor is NOT called and the order is byte-identical;
  * an applied order is recorded, so a report can tell a rule-made decision
    from a model-made one;
  * an advisor failure leaves the deterministic order untouched;
  * the model can only REORDER: a move that cannot run stays where the
    rules put it, and a list with duplicate ids is refused outright.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from phantom.core import next_moves as nm


def _moves():
    """Three runnable moves + one that cannot run here (the tail)."""
    return [
        nm.Move(title="nmap -sV 10.0.0.5", command="nmap -sV 10.0.0.5",
                module="scan", trust=0.9, why="services unknown"),
        nm.Move(title="gobuster dir", command="gobuster dir -u http://10.0.0.5",
                module="web", trust=0.7, why="web surface found"),
        nm.Move(title="hydra ssh", command="hydra -L users -P pass ssh://10.0.0.5",
                module="brute", trust=0.5, why="ssh exposed"),
        nm.Move(title="use exploit", command="", module="exploit",
                blockers=["no-auto-command"]),
    ]


def _trust(level: str):
    return SimpleNamespace(level=level, reason=f"{level} (test)")


class _Result:
    def __init__(self, ordered, *, applied=True, level="decide",
                 model="ranker-test", changed=(), reason="model rerank"):
        self.ordered = ordered
        self.applied = applied
        self.level = level
        self.model = model
        self.changed = list(changed)
        self.reason = reason


def _forbid_advisor(monkeypatch):
    """Make any call to the advisor a test failure."""
    def _boom(*_a, **_k):
        raise AssertionError("the advisor must not be called at observe")

    monkeypatch.setattr("phantom.automation.ai.advisors.exploit.rerank", _boom)


def test_observe_never_calls_the_model(monkeypatch):
    """No promoted model = no call, no latency, identical order."""
    _forbid_advisor(monkeypatch)
    monkeypatch.setattr("phantom.automation.ai.trust.trust_for",
                        lambda *_a, **_k: _trust("observe"))
    moves = _moves()
    before = [m.title for m in moves]

    ordered, record = nm._ai_order(moves, goal="beacon")

    assert [m.title for m in ordered] == before
    assert record == {}


def test_applied_order_is_recorded_and_used(monkeypatch):
    moves = _moves()
    # Only the RUNNABLE moves may be reordered. Reversing the whole list puts
    # the blocked `use exploit` row first, which the bridge refuses on purpose
    # (see test_applied_order_cannot_promote_a_blocked_move) — so the model's
    # order here is what an honest model would return: the candidates it was
    # allowed to touch, reversed, with the tail exactly where the rules put it.
    runnable = [m for m in moves if m.runnable()]
    tail = [m for m in moves if not m.runnable()]
    reversed_order = list(reversed(runnable)) + tail
    monkeypatch.setattr("phantom.automation.ai.trust.trust_for",
                        lambda *_a, **_k: _trust("decide"))
    monkeypatch.setattr(
        "phantom.automation.ai.advisors.exploit.rerank",
        lambda cands, mode="balanced", **kw: _Result(
            reversed_order, changed=[("web:gobuster dir", "1->0")]))

    ordered, record = nm._ai_order(moves, goal="beacon")

    assert [m.title for m in ordered] == [m.title for m in reversed_order]
    assert record["applied"] is True
    assert record["level"] == "decide"
    assert record["model"] == "ranker-test"
    assert record["changed"] == ["web:gobuster dir:1->0"]


def test_advisor_failure_keeps_the_deterministic_order(monkeypatch):
    monkeypatch.setattr("phantom.automation.ai.trust.trust_for",
                        lambda *_a, **_k: _trust("nudge"))

    def _explode(*_a, **_k):
        raise RuntimeError("model exploded")

    monkeypatch.setattr("phantom.automation.ai.advisors.exploit.rerank",
                        _explode)
    moves = _moves()
    before = [m.title for m in moves]

    ordered, record = nm._ai_order(moves, goal="beacon")

    assert [m.title for m in ordered] == before
    assert record == {}


def test_model_cannot_promote_a_move_that_cannot_run(monkeypatch):
    """The advisor keeps the ineligible tail; the bridge keeps it too."""
    moves = _moves()
    eligible = [m for m in moves if m.runnable()]
    tail = [m for m in moves if not m.runnable()]
    model_order = list(reversed(eligible)) + tail
    monkeypatch.setattr("phantom.automation.ai.trust.trust_for",
                        lambda *_a, **_k: _trust("decide"))
    monkeypatch.setattr(
        "phantom.automation.ai.advisors.exploit.rerank",
        lambda cands, mode="balanced", **kw: _Result(model_order))

    ordered, record = nm._ai_order(moves, goal="beacon")

    assert ordered[-1].title == "use exploit"
    assert ordered[-1] not in eligible
    assert record["applied"] is True


def test_an_order_that_promotes_a_blocked_move_is_refused(monkeypatch):
    """A model order that puts a non-runnable move first is not applied."""
    moves = _moves()
    blocked = [m for m in moves if not m.runnable()]
    runnable = [m for m in moves if m.runnable()]
    monkeypatch.setattr("phantom.automation.ai.trust.trust_for",
                        lambda *_a, **_k: _trust("decide"))
    monkeypatch.setattr(
        "phantom.automation.ai.advisors.exploit.rerank",
        lambda cands, mode="balanced", **kw: _Result(blocked + runnable))
    before = [m.title for m in moves]

    ordered, record = nm._ai_order(moves, goal="beacon")

    assert [m.title for m in ordered] == before
    assert record == {}


def test_duplicate_ids_are_refused_without_calling_the_model(monkeypatch):
    """Two moves with one id is an ambiguous order: nothing is applied."""
    _forbid_advisor(monkeypatch)
    monkeypatch.setattr("phantom.automation.ai.trust.trust_for",
                        lambda *_a, **_k: _trust("decide"))
    twin = nm.Move(title="nmap again", command="nmap -sV 10.0.0.5",
                   module="scan", trust=0.4, why="services unknown")
    moves = [nm.Move(title="nmap -sV 10.0.0.5",
                     command="nmap -sV 10.0.0.5", module="scan",
                     trust=0.9, why="services unknown"), twin]
    assert moves[0].id == twin.id

    ordered, record = nm._ai_order(moves, goal="beacon")

    assert ordered == moves
    assert record == {}


def test_rank_next_moves_carries_the_ai_record(monkeypatch):
    """The public entry point exposes what the model did to the ranking."""
    moves = _moves()
    eligible = [m for m in moves if m.runnable()]
    tail = [m for m in moves if not m.runnable()]
    reversed_order = list(reversed(eligible)) + tail
    monkeypatch.setattr(nm, "_plan_signals", lambda: ("beacon", [], []))
    monkeypatch.setattr(nm, "base_move", lambda: None)
    monkeypatch.setattr(nm, "_command_moves", lambda shell, chain: list(moves))
    monkeypatch.setattr(nm, "_chain_steps", lambda shell, steps, got: [])
    monkeypatch.setattr(nm.session, "target", "10.0.0.5", raising=False)
    monkeypatch.setattr("phantom.automation.ai.trust.trust_for",
                        lambda *_a, **_k: _trust("decide"))
    monkeypatch.setattr(
        "phantom.automation.ai.advisors.exploit.rerank",
        lambda cands, mode="balanced", **kw: _Result(reversed_order))

    ranked = nm.rank_next_moves(shell=None, limit=9, remember=False)

    assert ranked.ai.get("applied") is True
    assert [m.title for m in ranked.moves] == [m.title for m in reversed_order]
    assert [m.index for m in ranked.moves] == [1, 2, 3, 4]


@pytest.mark.parametrize("level", ["observe"])
def test_rank_next_moves_records_nothing_at_observe(monkeypatch, level):
    _forbid_advisor(monkeypatch)
    monkeypatch.setattr("phantom.automation.ai.trust.trust_for",
                        lambda *_a, **_k: _trust(level))
    monkeypatch.setattr(nm, "_plan_signals", lambda: ("beacon", [], []))
    monkeypatch.setattr(nm, "base_move", lambda: None)
    monkeypatch.setattr(nm, "_command_moves",
                        lambda shell, chain: list(_moves()))
    monkeypatch.setattr(nm, "_chain_steps", lambda shell, steps, got: [])
    monkeypatch.setattr(nm.session, "target", "10.0.0.5", raising=False)

    ranked = nm.rank_next_moves(shell=None, limit=9, remember=False)

    assert ranked.ai == {}
