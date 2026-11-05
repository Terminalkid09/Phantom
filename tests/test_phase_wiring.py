"""The phase vocabulary must point at real code, and interfaces must say so.

Measured 2026-11-05: the phase packages read like an orphan layer because
nothing recorded where each phase is actually implemented. They are declarative
facades (capability ids + re-exported adapters) over ``agent.py`` / ``kit.py``,
which is fine — what was missing is the mapping that makes the difference
visible. This test pins it, and pins that an interface error is not empty.
"""
import importlib
import pathlib

from phantom.automation.phases import (
    IMPLEMENTATIONS,
    PHASE_ORDER,
    implementation_for,
    unimplemented_phases,
)


def test_every_mapped_phase_resolves_to_a_real_module():
    for phase, target in IMPLEMENTATIONS.items():
        assert phase in PHASE_ORDER, f"{phase} is not a declared phase"
        module = importlib.import_module(target)
        assert module is not None, target


def test_every_declared_phase_has_an_entry_or_is_reported_as_missing():
    known = set(PHASE_ORDER) - set(unimplemented_phases())
    assert known == set(IMPLEMENTATIONS)
    # A phase may legitimately have no implementation; the contract is that
    # the two sets together cover the vocabulary, never that a phase silently
    # disappears from both.
    assert set(IMPLEMENTATIONS) | set(unimplemented_phases()) == set(PHASE_ORDER)


def test_an_unknown_phase_has_no_implementation():
    assert implementation_for("reconn") is None
    assert implementation_for("") is None


def test_interface_errors_carry_a_message():
    root = pathlib.Path(__file__).resolve().parents[1]
    for rel in ("phantom/automation/social/persona.py",
                "phantom/automation/social/social_dm.py"):
        src = (root / rel).read_text(encoding="utf-8")
        # A bare `raise NotImplementedError` reaches the operator as a
        # traceback with no channel/method in it.
        assert "raise NotImplementedError\n" not in src, rel
        assert "is an interface" in src, rel
