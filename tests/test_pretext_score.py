"""Pretext quality: the tells that get a message reported, before sending."""
from __future__ import annotations

from phantom.automation.social.pretext_score import score_pretext


def test_a_specific_personal_message_is_ready():
    rep = score_pretext(
        "Ordine 4482 — conferma indirizzo",
        "Ciao Mario, sono Luca del negozio di Via Roma. Il corriere ha "
        "segnato il tuo pacco come fermo in giacenza: puoi confermare "
        "l'indirizzo dalla pagina del tuo ordine? Grazie, Luca",
        brand="gls", sender="luca@gls-italia.it",
        link="https://gls-italia.it/ordine/4482", target_name="Mario",
        channel="email")
    assert rep.value >= 60
    assert rep.ready is True
    assert rep.blocking is False


def test_the_classic_scam_is_blocked_with_named_reasons():
    rep = score_pretext(
        "URGENT: your account will be closed",
        "DEAR CUSTOMER, we detected unusual activity. Kindly verify your "
        "identity and enter your password immediately by clicking here!!!",
        channel="email", brand="paypal", sender="security@paypa1.com",
        link="http://bit.ly/x", target_name="Mario")
    assert rep.blocking is True
    assert rep.ready is False
    assert "credential_request" in rep.codes("critical")
    assert {"generic_greeting", "urgency"} & set(rep.codes())
    assert rep.value < 40
    assert rep.top_fix()


def test_brand_sender_and_link_mismatch_are_high_severity():
    rep = score_pretext(
        "Verifica il tuo account",
        "Ciao Mario, controlla la tua casella dall'area riservata.",
        brand="unicredit", sender="noreply@contoso-mail.com",
        link="https://contoso-mail.com/login", target_name="Mario")
    assert "brand_sender_mismatch" in rep.codes("high")
    assert "brand_link_mismatch" in rep.codes("high")


def test_a_one_liner_and_a_pasted_email_as_dm_are_flagged():
    short = score_pretext("", "ciao", channel="dm")
    assert "too_short" in short.codes()
    long_dm = score_pretext("", "Ciao, " + ("parola " * 300), channel="dm")
    assert "dm_too_long" in long_dm.codes()


def test_personalisation_is_only_judged_when_the_name_is_known():
    with_name = score_pretext("Ciao", "Ciao Mario, ti scrivo per il pacco.",
                              target_name="Mario", channel="dm")
    assert "no_personalisation" not in with_name.codes()
    without = score_pretext("Ciao", "Ciao, ti scrivo per il pacco.",
                            target_name="Mario", channel="dm")
    assert "no_personalisation" in without.codes()


def test_a_body_mentioning_another_host_than_the_link_is_a_tell():
    rep = score_pretext(
        "Accesso", "Ciao Mario, accedi da banca.example per confermare.",
        link="https://altro.example/login", target_name="Mario")
    assert "link_host_mismatch" in rep.codes("high")


def test_score_never_goes_below_zero_or_above_hundred():
    bad = score_pretext(
        "URGENT!!!", "DEAR CUSTOMER " + "click here verify your password " * 50,
        channel="email", brand="x", sender="a@b.com", link="http://c.d")
    assert 0 <= bad.value <= 100
    good = score_pretext("Ciao", "Ciao Mario, tutto bene?",
                         target_name="Mario", channel="dm")
    assert good.value <= 100
