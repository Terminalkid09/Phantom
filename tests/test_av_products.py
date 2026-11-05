"""The antivirus STACK, not one product.

Measured 2026-11-03 on the operator's Windows 11 box: SecurityCenter2 reported
``Windows Defender`` and ``McAfee`` while ``WinDefend`` was stopped and only
``McAfee WebAdvisor`` ran. A Defender-only probe answered the wrong question
twice: it could stay silent on a machine with a live product, and it could
never name the product that was actually installed.

These tests pin the two claims a report depends on: WHICH products were seen,
and that "could not be read" is never reported as "clean".
"""
from __future__ import annotations

import pytest

from phantom.utils import defender_check as dc


def _products(*rows):
    return [{"name": name, "state": state,
             "enabled": enabled, "up_to_date": up_to_date}
            for name, state, enabled, up_to_date in rows]


# ── the note names the product that is there ────────────────────────────────

def test_mcafee_is_named_and_defender_is_not_claimed():
    note = dc.av_note("windows", products=_products(("McAfee", 0x41000, True, True)),
                      local_present=False)
    assert "mcafee" in note.lower()
    assert "windows defender" not in note.lower()
    assert "quarantin" in note.lower()
    assert "not proof the payload failed" in note.lower()


def test_every_registered_product_is_named():
    note = dc.av_note(
        "Windows",
        products=_products(("Windows Defender", 0x60100, None, True),
                           ("McAfee", 0x41000, True, True)),
        local_present=True)
    low = note.lower()
    assert "windows defender" in low and "mcafee" in low
    # order is the enumeration's order, so a report matches the machine
    assert low.index("windows defender") < low.index("mcafee")


def test_an_unreadable_enumeration_is_unknown_not_clean():
    note = dc.av_note("windows", products=[], local_present=False).lower()
    # The claim under test is the MEANING: something was asked and nothing
    # came back, so protection is unknown. Pinning the exact sentence would
    # fail on a rewording that says the same thing.
    assert "no antivirus product could be read" in note
    assert "unknown" in note
    # the one reading that must never appear is "nothing is installed"
    assert "no antivirus is installed" not in note


def test_a_non_windows_target_gets_nothing():
    assert dc.av_note("linux", products=_products(("McAfee", 0x41000, True, True))) == ""
    assert dc.av_note("macos", products=[]) == ""
    assert dc.av_note("", products=[]) == ""


def test_the_note_stays_a_warning():
    """No exit path: it returns text and touches nothing else."""
    note = dc.av_note("windows", products=[], local_present=True)
    assert isinstance(note, str) and note
    assert "disabled" not in note.lower().replace("nothing is disabled", "")


# ── productState decoding, documented values only ───────────────────────────

@pytest.mark.parametrize("state,enabled,up_to_date", [
    (0x41000, True, True),    # McAfee, measured: scanner 0x10, signature 0x00
    (0x60100, None, True),    # Defender, measured: provider 0x06, scanner 0x01
    (0x40010, False, False),  # scanner 0x00 (off), signature 0x10 (outdated)
])
def test_documented_product_states_decode(state, enabled, up_to_date):
    got = dc.decode_product_state(state)
    assert got["state"] == state
    assert got["enabled"] is enabled
    assert got["up_to_date"] is up_to_date


def test_an_undecodable_state_is_unknown_not_a_guess():
    got = dc.decode_product_state(0x060700)      # scanner 0x07: no known meaning
    assert got["enabled"] is None
    assert got["state"] == 0x060700


def test_a_missing_state_is_unknown():
    assert dc.decode_product_state(None)["enabled"] is None
    assert dc.decode_product_state("nonsense")["up_to_date"] is None


# ── the enumeration itself, injected ────────────────────────────────────────

def test_av_products_shapes_rows_and_skips_unnamed_ones():
    rows = [{"displayName": "McAfee", "productState": 0x41000},
            {"displayName": "", "productState": 0x41000},
            {"productState": 0x41000}]
    got = dc.av_products(lambda: rows)
    assert [p["name"] for p in got] == ["McAfee"]
    assert got[0]["enabled"] is True


def test_av_products_never_raises_on_a_broken_reader():
    """A probe that dies must not kill a deploy — and must not read as clean."""
    def _boom():
        raise RuntimeError("CIM exploded")

    assert dc.av_products(_boom) == []
    assert "no antivirus product could be read" in dc.av_note(
        "windows", products=[], local_present=False).lower()
