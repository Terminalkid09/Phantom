"""The five LLM gates, exercised on real objects.

`phantom/automation/brain/llm/gates.py` is the boundary that stops a language
model from turning a plausible sentence into an action: the model proposes, the
gates decide. Nothing tested it, and a broken gate is invisible — it either
lets a hallucinated chain through or blocks every legitimate one, and both look
like "the model is being unhelpful".

Everything here is the real code: a real `OperatorRegistry` with real
`Operator` dataclasses, a real `WorldModel`, a real `TargetLedger` (scope law),
and the real `ValidationGates`. No mocks: a mocked registry would pass whether
or not the gate reads it.
"""
import pytest

from phantom.automation.belief import WorldModel
from phantom.automation.brain.llm.gates import (
    ProposedChain,
    ValidationGates,
)
from phantom.automation.brain.operators import Operator, OperatorRegistry
from phantom.automation.brain.targets import TargetLedger

TARGET = "10.0.0.5"


@pytest.fixture
def registry():
    """A small, real operator pack: a quiet recon move and a loud exploit."""
    reg = OperatorRegistry()
    reg.register_all([
        Operator(op_id="quiet_probe", requires=("service",),
                 produces=("banner",), noise=0.1),
        Operator(op_id="loud_exploit", requires=("banner",),
                 produces=("shell",), noise=0.9),
    ])
    return reg


@pytest.fixture
def wm():
    """A real world model that knows one thing: the target speaks http."""
    model = WorldModel(target=TARGET)
    model.add_finding("service", "tcp/80",
                      {"port": "80", "service": "http", "class": "web"},
                      source="scan_tcp")
    return model


def _proposal(operators=("quiet_probe",), facts=(), goal="foothold"):
    return ProposedChain(operators=list(operators), goal=goal,
                         rationale="because the model said so",
                         referenced_facts=list(facts))


def _chain(registry, wm, proposal, **kwargs):
    return ValidationGates(registry, **kwargs).validate(proposal, wm)


# ── G1 registry ────────────────────────────────────────────────────────────

def test_g1_refuses_an_operator_that_does_not_exist(registry, wm):
    chain = _chain(registry, wm,
                   _proposal(operators=("quiet_probe", "teleport")))
    assert chain.approved is False
    assert chain.failed_gate() == "registry"
    assert "teleport" in chain.results[-1].detail
    # it stops AT the first failure: the later gates are not consulted, so a
    # rejected chain cannot report a "budget ok" it never checked
    assert len(chain.results) == 1


# ── G2 scope ───────────────────────────────────────────────────────────────

def test_g2_refuses_a_target_the_ledger_does_not_authorize(registry, wm):
    ledger = TargetLedger(TARGET, scope_list=["10.0.0.0/24"])
    wm.target = "192.168.1.5"                 # not in the engagement
    chain = _chain(registry, wm, _proposal(), ledger=ledger)
    assert chain.failed_gate() == "scope"
    assert "not activatable" in chain.results[-1].detail


def test_g2_accepts_the_authorized_target(registry, wm):
    ledger = TargetLedger(TARGET, scope_list=["10.0.0.0/24"])
    chain = _chain(registry, wm, _proposal(), ledger=ledger)
    assert chain.approved is True, chain.results
    assert [r.gate for r in chain.results] == [
        "registry", "scope", "policy", "evidence", "budget"]


# ── G3 policy ──────────────────────────────────────────────────────────────

def test_g3_refuses_loud_moves_in_paranoid_mode(registry, wm):
    chain = _chain(registry, wm, _proposal(operators=("loud_exploit",)),
                   paranoid=True)
    assert chain.failed_gate() == "policy"
    assert "loud_exploit" in chain.results[-1].detail


def test_g3_lets_a_quiet_move_through_paranoid_mode(registry, wm):
    chain = _chain(registry, wm, _proposal(), paranoid=True)
    assert chain.approved is True, chain.results


# ── G4 evidence ────────────────────────────────────────────────────────────

def test_g4_refuses_a_chain_grounded_in_nothing_real(registry, wm):
    chain = _chain(registry, wm,
                   _proposal(facts=["admin_credentials", "domain_admin"]))
    assert chain.failed_gate() == "evidence"
    assert "none of the referenced facts exist" in chain.results[-1].detail


def test_g4_accepts_a_chain_grounded_in_a_real_finding(registry, wm):
    # `http` comes from the finding's own `service` value — the gate reads what
    # the WORLD MODEL observed, not what the proposal claims
    chain = _chain(registry, wm, _proposal(facts=["http", "made_up"]))
    assert chain.approved is True, chain.results
    evidence = next(r for r in chain.results if r.gate == "evidence")
    assert "grounded in 1 observed fact" in evidence.detail


def test_g4_allows_a_chain_that_references_no_fact_at_all(registry, wm):
    """A proposal that claims no grounding is not claiming a false one: the
    gate is about hallucinated PREREQUISITES, and it says so."""
    chain = _chain(registry, wm, _proposal(facts=()))
    assert chain.approved is True, chain.results


# ── G5 budget ──────────────────────────────────────────────────────────────

def test_g5_refuses_a_chain_that_costs_more_noise_than_is_left(registry, wm):
    chain = _chain(registry, wm, _proposal(operators=("quiet_probe",
                                                      "loud_exploit")),
                   noise_budget_remaining=0.5)
    assert chain.failed_gate() == "budget"
    assert "exceeds remaining" in chain.results[-1].detail


def test_g5_allows_a_chain_that_fits_the_budget_exactly(registry, wm):
    chain = _chain(registry, wm, _proposal(), noise_budget_remaining=0.1)
    assert chain.approved is True, chain.results


# ── the order, and what "approved" means ───────────────────────────────────

def test_the_cheapest_gate_decides_first(registry, wm):
    """A chain that is wrong in two ways reports the FIRST one: the detail is
    what the operator reads, and it must point at the real reason."""
    chain = _chain(registry, wm,
                   _proposal(operators=("teleport",), facts=["hallucinated"]))
    assert chain.failed_gate() == "registry"
    assert not any(r.gate == "evidence" for r in chain.results)


def test_an_approved_chain_records_every_gate_it_passed(registry, wm):
    chain = _chain(registry, wm, _proposal(facts=["http"]))
    assert chain.approved is True
    assert chain.failed_gate() is None
    assert all(r.passed for r in chain.results)
    assert all(r.detail for r in chain.results), "a pass must say why"


def test_the_gates_never_mutate_what_the_model_proposed(registry, wm):
    """The model's proposal is evidence of what it asked for: validation
    annotates it, it does not rewrite it."""
    proposal = _proposal(operators=("quiet_probe",), facts=["http"])
    before = (list(proposal.operators), list(proposal.referenced_facts))
    _chain(registry, wm, proposal)
    assert (proposal.operators, proposal.referenced_facts) == before
