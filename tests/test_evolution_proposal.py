"""C3 acceptance tests — the triage cell and the markdown-only learning mode.

The claims:

  * triage decides WHETHER a failure deserves a proposal at all, and only a
    stable, uncovered, capability-shaped cause earns one;
  * `--oM` needs neither an LLM nor the lab (the dossier is deterministic),
    and spends a budget SEPARATE from the authored-capability one;
  * the dossier is complete about the situation and silent about the code,
    and it is publishable through the existing PR machinery unchanged.
"""

import pathlib

import pytest

from phantom.automation.brain.triage import (
    MIN_OCCURRENCES,
    Triage,
    FailureCase,
)
from phantom.automation.evolution import loop as evo_loop
from phantom.automation.evolution import proposal as proposal_mod


PAT_GAP = dict(technique="sqlmap-union", cause="waf_blocked",
               missing_fact="web_creds", n=4, phase="exploit",
               signature_summary="cls=waf product=cloudflare services=443",
               evidence="403 on union select", remedy="tautology",
               sig_hash="aaa")
PAT_ENV = dict(technique="ssh_login", cause="tool_missing",
               missing_fact="creds", n=9, phase="creds",
               signature_summary="cls=ssh", evidence="sshpass not found",
               sig_hash="bbb")
PAT_OPS = dict(technique="web_rce", cause="stealth_veto",
               missing_fact="rce_foothold", n=6, phase="exploit",
               signature_summary="cls=web", evidence="vetoed", sig_hash="ccc")
PAT_THIN = dict(technique="nmap", cause="not_found", missing_fact="service",
                n=2, phase="footprint", signature_summary="cls=net",
                evidence="x", sig_hash="ddd")


def _registry():
    from phantom.automation.guidance.commands import make_registry
    return make_registry()


# ── triage verdicts ───────────────────────────────────────────────────────

def test_capability_shaped_gap_earns_a_proposal():
    tri = Triage(_registry())
    case = tri.package(PAT_GAP)
    assert case.verdict == "capability_gap"
    assert case.proposes_code is True
    assert "exactly the class" in case.verdict_reason


def test_environmental_cause_is_not_a_capability_problem():
    case = Triage(_registry()).package(PAT_ENV)
    assert case.verdict == "environmental"
    assert case.proposes_code is False
    assert "setup or tooling" in case.verdict_reason


def test_policy_outcome_is_not_a_capability_problem():
    """A stealth veto (or a deferral, a scope block) means the chain was
    told to stop on purpose — writing offensive code would be the wrong
    lesson to learn."""
    case = Triage(_registry()).package(PAT_OPS)
    assert case.verdict == "operational"
    assert case.proposes_code is False
    assert "POLICY outcome" in case.verdict_reason


def test_too_few_occurrences_is_not_a_finding():
    case = Triage(_registry()).package(PAT_THIN)
    assert case.verdict == "unstable"
    assert str(MIN_OCCURRENCES) in case.verdict_reason


def test_an_already_covered_fact_is_not_a_gap():
    """`service` is produced by the existing scan capabilities: the gap is
    elsewhere (planning or preconditions), so no proposal is earned."""
    pat = dict(PAT_GAP)
    pat["missing_fact"] = "service"
    case = Triage(_registry()).package(pat)
    assert case.verdict == "covered"
    assert case.covered_by
    assert case.proposes_code is False


def test_proposable_filters_the_set():
    tri = Triage(_registry())
    cases = tri.package_all([PAT_GAP, PAT_ENV, PAT_OPS, PAT_THIN])
    assert [c.sig_hash for c in Triage.proposable(cases)] == ["aaa"]


def test_triage_records_the_roster_and_the_dissent():
    from phantom.automation.brain.cell_runtime import CellRuntime

    rt = CellRuntime(goal="deliver", target_type="ip", cls="network")
    rt.start()
    rt.set_stage("exploit")
    case = Triage(_registry()).package(
        PAT_GAP, case_id="aaa", roster=rt, stall_class="blocked",
        dissent={"adopted": "web_rce", "dissent_reason": "peer wanted the RCE"})
    assert case.cells, "the acting cells must be on the record"
    assert case.active_stage == "exploit"
    assert case.stall_class == "blocked"
    assert case.dissent == "web_rce"
    assert "peer wanted the RCE" in case.dissent_reason


# ── the dossier ───────────────────────────────────────────────────────────

def test_dossier_carries_the_situation_and_no_code():
    case = Triage(_registry()).package(PAT_GAP, case_id="20260914-aaa")
    md = case.to_markdown()
    assert "Failure case `20260914-aaa`" in md
    assert "sqlmap-union" in md
    assert "waf_blocked" in md
    assert "web_creds" in md
    assert "## What a capability would have to do" in md
    assert "## Acceptance checklist" in md
    assert "No code is included on purpose" in md
    # it must not pretend to be a patch
    assert "```python" not in md


def test_dossier_is_rebuilt_from_a_plain_dict():
    as_dict = Triage(_registry()).package(PAT_GAP).to_dict()
    assert "Failure case" in proposal_mod.build_dossier(as_dict)


def test_proposal_is_written_atomically_under_the_root(tmp_path):
    case = Triage(_registry()).package(PAT_GAP, case_id="pid-1")
    res = proposal_mod.write_proposal("pid-1", case, root=tmp_path)
    assert res.ok is True
    written = tmp_path / "pid-1.md"
    assert written.exists()
    assert written.read_text(encoding="utf-8") == res.markdown
    # no temp litter left behind
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".proposal-")]


def test_proposal_result_is_publish_compatible():
    """`publish()` collects cap/test/proposal paths and skips the empty
    ones: a proposal-only result must therefore leave cap and test EMPTY."""
    case = Triage(_registry()).package(PAT_GAP, case_id="pid-2")
    res = proposal_mod.write_proposal("pid-2", case,
                                      root=pathlib.Path("/tmp/nonexistent-ph"))
    assert res.ok is True
    ar = proposal_mod.as_author_result(res)
    assert ar.ok is True
    assert ar.proposal_relpath == res.relpath
    assert ar.cap_relpath == ""
    assert ar.test_relpath == ""


# ── the separate budget ───────────────────────────────────────────────────

def test_proposal_budget_is_separate_from_the_capability_budget(tmp_path):
    st = evo_loop.EvolutionState(tmp_path / "state.json")
    # exhaust the CAPABILITY budgets
    for _ in range(evo_loop.MAX_GATE_RUNS_PER_DAY):
        assert st.reserve_gate_slot() is True
    for _ in range(evo_loop.MAX_PRS_PER_DAY):
        assert st.reserve_pr_slot() is True
    assert st.reserve_gate_slot() is False
    assert st.reserve_pr_slot() is False
    # ...and the PROPOSAL budget is untouched
    assert st.reserve_proposal_slot() is True
    assert st.proposals_today() == 1


def test_proposal_budget_is_enforced(tmp_path):
    st = evo_loop.EvolutionState(tmp_path / "state.json")
    for _ in range(evo_loop.MAX_PROPOSALS_PER_DAY):
        assert st.reserve_proposal_slot() is True
    assert st.reserve_proposal_slot() is False


# ── the loop wiring ───────────────────────────────────────────────────────

def test_proposal_worker_writes_and_publishes(monkeypatch, tmp_path):
    case = Triage(_registry()).package(PAT_GAP, case_id="pid-3")
    written = {}
    published = {}

    def fake_write(pid, c, emit=None, root=None):
        written["pid"] = pid
        written["case"] = c
        return proposal_mod.ProposalResult(True, relpath=f"docs/evolution/{pid}.md",
                                           markdown=c.to_markdown(),
                                           case=c.to_dict())

    def fake_publish(pid, ar, state, run_git=None):
        published["pid"] = pid
        published["relpath"] = ar.proposal_relpath
        return type("P", (), {"ok": True, "detail": "PR opened",
                              "branch": "auto-evolution/x"})()

    monkeypatch.setattr(proposal_mod, "write_proposal", fake_write)
    from phantom.automation.evolution import publish as publish_mod
    monkeypatch.setattr(publish_mod, "publish", fake_publish)

    st = evo_loop.EvolutionState(tmp_path / "state.json")
    notes = []
    # the loop's emit convention is emit(kind, **data) — the same shape the
    # agent's _emit has
    evo_loop._worker_proposal("pid-3", PAT_GAP, st,
                              lambda kind, **kw: notes.append(kw),
                              roster=None, case=case)
    assert written["pid"] == "pid-3"
    assert published["relpath"].endswith("pid-3.md")
    assert any("PR opened" in n.get("detail", "") for n in notes)


def test_proposal_worker_skips_a_case_the_triage_rejected(monkeypatch, tmp_path):
    case = Triage(_registry()).package(PAT_OPS, case_id="pid-4")
    called = []
    monkeypatch.setattr(proposal_mod, "write_proposal",
                        lambda *a, **k: called.append(1))
    st = evo_loop.EvolutionState(tmp_path / "state.json")
    st.mark_authored(case.sig_hash or "pid-4", "pid-4")
    notes = []
    evo_loop._worker_proposal("pid-4", PAT_OPS, st,
                              lambda kind, **kw: notes.append(kw),
                              case=case)
    assert called == []
    assert st.authored() == {}                       # reservation released
    assert any("no proposal" in n.get("detail", "") for n in notes)


def test_maybe_spawn_in_proposal_mode_needs_no_lab_and_no_llm(monkeypatch,
                                                              tmp_path):
    """The whole point of `--oM`: neither the LLM transport nor the lab is
    required, so a team with neither can still accumulate learning."""
    spawned_threads = []

    class FakeThread:
        def __init__(self, target=None, args=(), kwargs=None, **kw):
            spawned_threads.append({"target": target, "args": args,
                                    "kwargs": kwargs or {}})

        def start(self):
            pass

    monkeypatch.setattr(evo_loop.threading, "Thread", FakeThread)
    st = evo_loop.EvolutionState(tmp_path / "state.json")
    out = evo_loop.maybe_spawn([dict(PAT_GAP)], advisor=None, wm=None,
                               emit=lambda k, d: None, state=st, lab_ok=False,
                               mode="proposal")
    assert out, "proposal mode must spawn even with no lab and no advisor"
    assert spawned_threads[0]["kwargs"]["mode"] == "proposal"
    assert st.proposals_today() == 1
    assert st._d["gate_runs"] == 0                   # capability budget untouched


def test_maybe_spawn_in_code_mode_still_requires_the_lab(monkeypatch, tmp_path):
    spawned = []
    monkeypatch.setattr(evo_loop.threading, "Thread",
                        lambda **kw: type("T", (), {"start": lambda self: spawned.append(1)})())
    st = evo_loop.EvolutionState(tmp_path / "state.json")
    out = evo_loop.maybe_spawn([dict(PAT_GAP)], advisor=None, wm=None,
                               emit=lambda k, d: None, state=st, lab_ok=False,
                               mode="code")
    assert out == []
    assert spawned == []


def test_mode_is_validated():
    assert "proposal" in evo_loop.MODES
    assert "code" in evo_loop.MODES


# ── agent wiring ──────────────────────────────────────────────────────────

class _Exp:
    def __init__(self, patterns):
        self._p = patterns

    def authorable_patterns(self):
        return [dict(p) for p in self._p]


def _agent(**kw):
    from phantom.automation.agent import AutonomousAgent
    a = AutonomousAgent("10.0.0.5", **kw)
    return a


def test_agent_proposal_mode_runs_without_llm_or_lab(monkeypatch):
    a = _agent()
    a.evolution = True
    a.evolution_mode = "proposal"
    a.experience = _Exp([PAT_GAP])
    a.llm_advisor.enabled = False
    seen = {}

    def fake_spawn(patterns, advisor, wm, **kw):
        seen["patterns"] = patterns
        seen["kw"] = kw
        return []

    import phantom.automation.evolution.loop as loop_mod
    monkeypatch.setattr(loop_mod, "maybe_spawn", fake_spawn)
    a._spawn_evolution()
    assert seen.get("kw", {}).get("mode") == "proposal"
    assert seen["patterns"], "the capability-shaped pattern must survive triage"
    assert seen["kw"]["cases"], "the triaged cases travel with the spawn"


def test_agent_proposal_mode_reports_when_triage_rejects_everything():
    a = _agent()
    a.evolution = True
    a.evolution_mode = "proposal"
    a.experience = _Exp([PAT_ENV, PAT_OPS])
    a._spawn_evolution()
    notes = [e for e in a.sink.events if e["kind"] == "note"]
    assert any("triaged out" in e.get("detail", "") for e in notes)


def test_agent_code_mode_still_requires_the_llm():
    a = _agent()
    a.evolution = True
    a.experience = _Exp([PAT_GAP])
    a.llm_advisor.enabled = False
    a._spawn_evolution()                     # must return quietly, not raise
    assert a._evolution_spawned is True
    assert not [e for e in a.sink.events if e["kind"] == "triage"]


def test_agent_emits_the_triage_event_in_proposal_mode(monkeypatch):
    a = _agent()
    a.evolution = True
    a.evolution_mode = "proposal"
    a.experience = _Exp([PAT_GAP, PAT_THIN])
    import phantom.automation.evolution.loop as loop_mod
    monkeypatch.setattr(loop_mod, "maybe_spawn",
                        lambda *args, **kw: [])
    a._spawn_evolution()
    triage = a.sink.by_kind("triage")
    assert triage
    assert triage[0]["patterns"] == 2
    assert len(triage[0]["cases"]) == 1      # only the capability-shaped one
