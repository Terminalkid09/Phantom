"""Candidate emails: generation is offline, verification is consent-gated."""
from __future__ import annotations

from phantom.automation.social import email_candidates as ec
from phantom.automation.social.email_enum import EXISTS, UNKNOWN


def test_common_patterns_are_generated_for_a_full_name():
    cands = ec.generate("Mario", "Rossi", "mrossi", "acme.it")
    corporate = [c for c in cands if c.email.endswith("@acme.it")]
    locals_ = {c.email.split("@")[0] for c in corporate}
    assert {"mario.rossi", "mariorossi", "m.rossi", "mario.r"} <= locals_
    # the free-mail variants exist but rank below the corporate ones
    assert any(c.email.endswith("@gmail.com") for c in cands)
    assert corporate[0].score > cands[-1].score


def test_corporate_domain_outranks_free_mail_for_the_same_pattern():
    cands = ec.generate("Mario", "Rossi", domain="acme.it")
    by_local = {c.email.split("@")[0]: c for c in cands}
    assert by_local["mario.rossi"].score > 0.5
    corp = [c for c in cands if c.email == "mario.rossi@acme.it"][0]
    free = [c for c in cands if c.email == "mario.rossi@gmail.com"][0]
    assert corp.score > free.score


def test_a_breach_hit_is_evidence_and_raises_the_score():
    plain = ec.generate("Mario", "Rossi", domain="acme.it")
    hit = ec.generate("Mario", "Rossi", domain="acme.it",
                      breaches=["mario.rossi@acme.it"])
    p = [c for c in plain if c.email == "mario.rossi@acme.it"][0]
    h = [c for c in hit if c.email == "mario.rossi@acme.it"][0]
    assert h.score > p.score
    assert "breach_hit" in h.reasons


def test_markers_never_print_the_full_address():
    cands = ec.generate("Mario", "Rossi", domain="acme.it")
    for marker in (c.markers() for c in cands):
        assert "@acme.it" not in marker or "*" in marker
        assert "mario.rossi@acme.it" != marker


def test_generation_does_not_touch_the_network(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("generation must stay offline")
    monkeypatch.setattr(ec, "reset_oracle", boom)
    ec.generate("Mario", "Rossi", domain="acme.it")


def test_verification_without_confirmation_sends_nothing():
    cands = ec.generate("Mario", "Rossi", domain="acme.it")
    out = ec.verify(cands, confirm=None, max_candidates=2)
    assert len(out) == 2
    assert all(v.verdict == UNKNOWN for v in out)
    assert all("confirmation" in v.evidence for v in out)


def test_verification_uses_the_oracle_and_reports_the_confirmation():
    cands = ec.generate("Mario", "Rossi", domain="acme.it")
    asked = []

    def fake_oracle(email, **_kwargs):
        asked.append(email)
        return [type("V", (), {"verdict": EXISTS,
                               "evidence": "reset accepted"})()]

    out = ec.verify(cands, confirm=lambda *_a: True, oracle=fake_oracle,
                    max_candidates=2)
    assert len(asked) == 2
    assert all(v.verdict == EXISTS for v in out)
    assert all("reset" in v.marker() for v in out)


def test_a_broken_oracle_is_unknown_never_a_guess():
    cands = ec.generate("Mario", "Rossi", domain="acme.it")[:1]

    def boom(*_a, **_k):
        raise RuntimeError("network down")

    out = ec.verify(cands, confirm=lambda *_a: True, oracle=boom)
    assert out[0].verdict == UNKNOWN
    assert "oracle-error" in out[0].evidence
