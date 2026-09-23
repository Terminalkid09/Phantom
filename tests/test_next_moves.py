"""Tests for the ranked next-move engine (suggest + run in one decision).

Covers the behaviours the manual core now depends on:
  * the target-type-first decision (once, shared with the adaptive `run`);
  * one deterministic ranked list with a planner chain bonus;
  * chain steps that no command covers still get an executable row;
  * the rejected paths ("why not X") reach the renderer;
  * `run <n>` executes the remembered move, out-of-range is safe;
  * the AGGRESSIVE marker survives into execution (OPSEC confirmation);
  * `run <module> <args>` reaches the module (the `--quiet` fast path).
"""
import io
import sys

import pytest

from phantom.core import next_moves as nm
from phantom.core.session import session


class _StubModule:
    def __init__(self, groups):
        self._groups = groups

    def suggest_commands(self):
        return self._groups


class _StubShell:
    """A shell whose module lookup is fixed, so ranking is hermetic."""

    def __init__(self, mapping):
        self._mapping = mapping

    def _instantiate_module(self, name):
        return self._mapping.get(name)


@pytest.fixture(autouse=True)
def _clean_session(monkeypatch):
    monkeypatch.setattr(session, "target", "", raising=False)
    monkeypatch.setattr(session, "scope", [], raising=False)
    monkeypatch.setattr(session, "results", {}, raising=False)
    monkeypatch.setattr(session, "pending_moves", [], raising=False)
    yield


# ── the shared target-type-first decision ────────────────────────────────

def test_base_move_identity_target_is_osint():
    session.target = "mario.rossi@acme.it"
    move = nm.base_move()
    assert move is not None
    assert move.module == "osint"
    assert "identity" in move.why.lower()


def test_base_move_blind_network_target_is_scan():
    session.target = "10.0.0.5"
    from phantom.core.knowledge import reset_wm
    reset_wm(target="10.0.0.5")
    move = nm.base_move()
    assert move is not None
    assert move.module == "scan"


def test_base_move_is_none_with_services_present():
    session.target = "10.0.0.5"
    from phantom.core.knowledge import reset_wm, session_wm
    wm = reset_wm(target="10.0.0.5")
    wm.add_finding("service", "tcp/22", {"port": "22", "service": "ssh"},
                   confidence=0.9, source="test")
    assert nm.base_move() is None


# ── ranking ──────────────────────────────────────────────────────────────

def _rank_with(monkeypatch, shell, steps):
    monkeypatch.setattr(
        nm, "_plan_signals",
        lambda: (nm.engagement_goal(), steps, []))
    return nm.rank_next_moves(shell)


def test_ranking_is_numbered_and_remembered(monkeypatch):
    shell = _StubShell({"scan": _StubModule({"G": ["nmap -sV 10.0.0.5"]})})
    ranked = _rank_with(monkeypatch, shell, [])
    assert ranked.moves
    assert [m.index for m in ranked.moves] == list(
        range(1, len(ranked.moves) + 1))
    assert nm.pending() == ranked.moves


def test_ranking_is_deterministic(monkeypatch):
    shell = _StubShell({
        "scan": _StubModule({"G": ["nmap -sV 10.0.0.5"]}),
        "web": _StubModule({"G": ["curl -s -I http://10.0.0.5"]}),
    })
    first = _rank_with(monkeypatch, shell, [])
    second = _rank_with(monkeypatch, shell, [])
    assert [m.title for m in first.moves] == [m.title for m in second.moves]


def test_remember_false_does_not_clobber_pending(monkeypatch):
    shell = _StubShell({"scan": _StubModule({"G": ["nmap -sV 10.0.0.5"]})})
    ranked = _rank_with(monkeypatch, shell, [])
    saved = list(ranked.moves)
    monkeypatch.setattr(nm, "_plan_signals",
                        lambda: (nm.engagement_goal(), [], []))
    nm.rank_next_moves(shell, remember=False)
    assert nm.pending() == saved


def test_chain_step_outranks_equal_evidence_command(monkeypatch):
    """The planner's next step lifts its module's commands above a peer with
    identical evidence — the chain orders, it never invents entries."""
    shell = _StubShell({
        "web": _StubModule({"G": ["toolalpha -x"]}),
        "scan": _StubModule({"G": ["toolbeta -y"]}),
    })
    session.target = "10.0.0.5"
    steps = [{"capability": "http_probe", "reason": "web step first",
              "exec_class": "shell_command"}]
    ranked = _rank_with(monkeypatch, shell, steps)
    by_module = {m.module: m for m in ranked.moves}
    assert by_module["web"].chain is True
    assert by_module["scan"].chain is False
    assert by_module["web"].trust > by_module["scan"].trust
    assert ranked.moves[0].module == "web"


def test_chain_step_without_command_gets_an_executable_row(monkeypatch):
    """A chain step whose module offers nothing yet is still a row — and it
    says so instead of pretending it can run."""
    shell = _StubShell({"pivot": _StubModule({})})
    steps = [{"capability": "lateral_pivot", "reason": "pivot with creds",
              "exec_class": "shell_command"}]
    ranked = _rank_with(monkeypatch, shell, steps)
    row = next(m for m in ranked.moves if m.capability == "lateral_pivot")
    assert row.chain is True
    assert row.command == ""
    assert "no-auto-command" in row.blockers
    assert row.runnable() is False


def test_capability_without_module_is_flagged_not_runnable(monkeypatch):
    shell = _StubShell({})
    steps = [{"capability": "some_future_capability", "reason": "future",
              "exec_class": "in_process_engine"}]
    ranked = _rank_with(monkeypatch, shell, steps)
    row = next(m for m in ranked.moves
               if m.capability == "some_future_capability")
    assert "no-direct-runner" in row.blockers
    assert row.runnable() is False


def test_wifi_recipes_are_not_ranked_moves(monkeypatch):
    """wifi's suggestions are unconditional interface setup: they answer no
    finding, so they must not occupy the ranked list."""
    shell = _StubShell({
        "wifi": _StubModule({"SUGGESTED (wifi)": ["sudo airmon-ng check kill"]}),
        "scan": _StubModule({"G": ["nmap -sV 10.0.0.5"]}),
    })
    ranked = _rank_with(monkeypatch, shell, [])
    assert not any(m.module == "wifi" for m in ranked.moves)
    assert "wifi" not in nm.SUGGEST_MODULES


def test_unevidenced_catalogue_is_capped(monkeypatch):
    """Recipe-book commands with nothing behind them may fill the gaps, but
    they must never dominate the list."""
    shell = _StubShell({
        "wordlist": _StubModule({"G": ["genA", "genB"]}),
        "osint": _StubModule({"G": ["genC", "genD"]}),
    })
    ranked = _rank_with(monkeypatch, shell, [])
    unevidenced = [m for m in ranked.moves
                   if not m.why and m.runnable()]
    assert len(unevidenced) <= 3


def test_evidence_backed_moves_are_never_capped(monkeypatch):
    """The cap applies to the filler only: commands that answer a finding
    always keep their place, however many there are."""
    monkeypatch.setattr(session, "target", "10.0.0.5", raising=False)
    monkeypatch.setattr(
        session, "knowledge_base",
        {"services": [{"proto": "tcp", "port": 445,
                        "service": "microsoft-ds"}],
         "creds_found": []}, raising=False)
    shell = _StubShell({
        "scan": _StubModule({"SUGGESTED (smb:445)": [
            "enum4linux -a 10.0.0.5", "smbclient -L //10.0.0.5"]}),
        "wordlist": _StubModule({"G": ["genA", "genB"]}),
        "osint": _StubModule({"G": ["genC", "genD"]}),
    })
    ranked = _rank_with(monkeypatch, shell, [])
    titles = {m.title for m in ranked.moves}
    assert {"enum4linux -a 10.0.0.5", "smbclient -L //10.0.0.5"} <= titles
    assert all(m.why for m in ranked.moves
               if m.title in ("enum4linux -a 10.0.0.5",
                              "smbclient -L //10.0.0.5"))


def test_rejected_paths_are_carried_through(monkeypatch):
    rejected = [{"fact": "ad_domain", "capability": "kerberoast",
                 "reason": "no SPN evidence", "hint": "alternative"}]
    monkeypatch.setattr(
        nm, "_plan_signals",
        lambda: (nm.engagement_goal(), [], rejected))
    ranked = nm.rank_next_moves(_StubShell({}))
    assert ranked.rejected == rejected


def test_render_shows_why_not_section(monkeypatch):
    from rich.console import Console
    rejected = [{"fact": "ad_domain", "capability": "kerberoast",
                 "reason": "no SPN evidence"}]
    monkeypatch.setattr(
        nm, "_plan_signals",
        lambda: (nm.engagement_goal(), [], rejected))
    shell = _StubShell({"scan": _StubModule({"G": ["nmap -sV 10.0.0.5"]})})
    ranked = nm.rank_next_moves(shell)
    buf = io.StringIO()
    nm.render_moves(ranked, console=Console(file=buf, width=200))
    out = buf.getvalue()
    assert "WHY NOT" in out
    assert "kerberoast" in out


# ── execution ────────────────────────────────────────────────────────────

def test_aggressive_marker_survives_into_execution(monkeypatch):
    """The display form drops AGGRESSIVE; the executed form must keep it or
    the OPSEC confirmation never fires."""
    from phantom.core.suggest_meta import tag_suggestions
    tagged = tag_suggestions({"G": ["hydra -l admin AGGRESSIVE"]})
    assert tagged[0].command == "hydra -l admin"
    assert "AGGRESSIVE" in tagged[0].metadata["raw"]

    seen = {}

    def _fake_filter(commands):
        seen["filtered"] = list(commands)
        return commands

    def _fake_run(commands, target_ip=""):
        seen["ran"] = list(commands)
        return {c: "ok" for c in commands}

    from phantom.core import executor
    monkeypatch.setattr("phantom.utils.aggressive.filter_aggressive_commands",
                        _fake_filter)
    monkeypatch.setattr(executor, "run_commands", _fake_run)
    move = nm.Move(title="hydra -l admin", command="hydra -l admin AGGRESSIVE",
                   module="brute", trust=0.5)
    assert nm.execute_move(None, move) is True
    assert "AGGRESSIVE" in seen["filtered"][0]
    assert seen["ran"] == ["hydra -l admin AGGRESSIVE"]


def test_execute_move_skipped_when_aggressive_refused(monkeypatch):
    monkeypatch.setattr("phantom.utils.aggressive.filter_aggressive_commands",
                        lambda commands: [])
    move = nm.Move(title="hydra", command="hydra -l a AGGRESSIVE",
                   module="brute")
    assert nm.execute_move(None, move) is False


def test_execute_move_without_runner_is_a_noop(monkeypatch):
    move = nm.Move(title="use pivot", module="pivot",
                   blockers=["no-auto-command"])
    assert nm.execute_move(_StubShell({"pivot": _StubModule({})}), move) is False


# ── the shell commands ───────────────────────────────────────────────────

def test_run_number_executes_remembered_move(monkeypatch):
    from phantom.core.shell import PhantomShell
    from phantom.core.shell.commands.run import cmd_run
    from phantom.core import executor
    session.target = "10.0.0.5"
    session.pending_moves = [nm.Move(index=1, title="nmap -sV 10.0.0.5",
                                     command="nmap -sV 10.0.0.5",
                                     module="scan")]
    ran = {}
    monkeypatch.setattr(
        executor, "run_commands",
        lambda commands, target_ip="": ran.setdefault("cmds", list(commands)) or {})
    cmd_run(PhantomShell(), "1")
    assert ran["cmds"] == ["nmap -sV 10.0.0.5"]


def test_run_number_out_of_range_is_safe():
    from phantom.core.shell import PhantomShell
    from phantom.core.shell.commands.run import cmd_run
    session.target = "10.0.0.5"
    session.pending_moves = [nm.Move(index=1, title="x", command="x -y")]
    cmd_run(PhantomShell(), "9")  # must not raise, must not execute


def test_run_module_receives_extra_args(monkeypatch):
    """`run scan --quiet` reaches the module (the fast path used to be
    unreachable from the top-level shell)."""
    from phantom.core.shell import PhantomShell
    from phantom.core.shell.commands.run import cmd_run

    class _Recorder(_StubModule):
        def __init__(self):
            super().__init__({})
            self.args = None

        def do_run(self, arg):
            self.args = arg

    recorder = _Recorder()
    shell = PhantomShell()
    monkeypatch.setattr(shell, "_instantiate_module",
                        lambda name: recorder if name == "scan" else None)
    monkeypatch.setattr(shell, "_warn_identity_target", lambda name: False)
    session.target = "10.0.0.5"
    cmd_run(shell, "scan --quiet")
    assert recorder.args == "--quiet"


def test_run_module_aliases_resolve(monkeypatch):
    from phantom.core.shell import PhantomShell
    from phantom.core.shell.commands.run import cmd_run

    class _Recorder(_StubModule):
        def __init__(self):
            super().__init__({})
            self.called = False

        def do_run(self, arg):
            self.called = True

    recorder = _Recorder()
    shell = PhantomShell()
    monkeypatch.setattr(shell, "_instantiate_module",
                        lambda name: recorder if name == "scan" else None)
    monkeypatch.setattr(shell, "_warn_identity_target", lambda name: False)
    session.target = "10.0.0.5"
    cmd_run(shell, "s")
    assert recorder.called is True
