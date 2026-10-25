"""Domain readiness: the sending domain is scored from records, offline."""
from __future__ import annotations

from phantom.automation.social.domain_readiness import check_domain


def test_a_correct_domain_is_ready():
    rep = check_domain(
        "azienda.it",
        spf="v=spf1 include:_spf.google.com -all",
        dmarc="v=DMARC1; p=reject; rua=mailto:dmarc@azienda.it",
        dkim=["google"], mx=["mx1.azienda.it"])
    assert rep.ready is True
    assert rep.blocking is False
    assert rep.grade in ("A", "B")


def test_missing_spf_and_dkim_are_blocking_and_explained():
    rep = check_domain("lookalike.com", spf="", dmarc="", dkim=(), mx=())
    assert rep.blocking is True
    assert rep.ready is False
    assert "no_spf" in rep.codes("critical")
    assert {"no_dkim", "no_dmarc", "no_mx"} & set(rep.codes())
    assert rep.top_fix()


def test_permissive_spf_is_critical():
    rep = check_domain(
        "open.com", spf="v=spf1 +all", dmarc="v=DMARC1; p=quarantine",
        dkim=["s1"], mx=["mx.open.com"])
    assert "permissive_spf" in rep.codes("critical")
    assert rep.ready is False


def test_two_spf_records_are_a_permerror():
    rep = check_domain(
        "two.com", spf="v=spf1 include:a -all; v=spf1 include:b -all",
        dmarc="v=DMARC1; p=reject", dkim=["s1"], mx=["mx.two.com"])
    assert "multiple_spf" in rep.codes("high")


def test_dmarc_none_is_a_warning_not_a_block():
    rep = check_domain(
        "soft.com", spf="v=spf1 ip4:1.2.3.4 -all",
        dmarc="v=DMARC1; p=none", dkim=["s1"], mx=["mx.soft.com"])
    assert "dmarc_none" in rep.codes("medium")
    assert rep.blocking is False


def test_no_domain_scores_zero():
    rep = check_domain("")
    assert rep.score == 0
    assert "no_domain" in rep.codes("critical")
