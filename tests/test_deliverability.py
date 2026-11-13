"""Tests for the pre-send deliverability preflight (the email hop fails
silently, so it is scored before relay)."""
import unittest

from phantom.automation.social.deliverability import deliverability_report


def _clean(**kw):
    args = dict(
        subject="Your session summary is ready",
        body_text=("Hi Mario, the summary of your last session is ready in "
                   "your dashboard. You can review it whenever you have a "
                   "moment.\n\nThanks,\nThe team"),
        html="<html><body><p>body</p></body></html>",
        link="https://notify.acme.it/v/abc123",
        sender="Acme Notifications <no-reply@acme.it>",
    )
    args.update(kw)
    return deliverability_report(**args)


class TestCleanMessage(unittest.TestCase):

    def test_clean_message_scores_high(self):
        rep = _clean()
        self.assertFalse(rep.blocking)
        self.assertEqual(rep.codes(), [])
        self.assertEqual(rep.score, 100)
        self.assertEqual(rep.grade, "A")

    def test_marker_shape(self):
        rep = _clean()
        self.assertEqual(rep.marker(),
                         "DELIVERABILITY: score=100 grade=A issues=none")


class TestIdentity(unittest.TestCase):

    def test_no_sender_is_critical(self):
        rep = _clean(sender="someone with no address")
        self.assertTrue(rep.blocking)
        self.assertIn("no_sender", rep.codes("critical"))

    def test_free_mail_sender_is_medium(self):
        rep = _clean(sender="IT Support <persona@grr.la>".replace(
            "grr.la", "gmail.com"))
        self.assertIn("free_mail_sender", rep.codes("medium"))

    def test_mixed_script_is_flagged(self):
        # Cyrillic homoglyphs are a heavy filter signal
        rep = _clean(subject="Verify your \u0430ccount")
        self.assertIn("mixed_script", rep.codes("high"))


class TestDomainAndLink(unittest.TestCase):

    def test_bare_ip_link_is_critical(self):
        rep = _clean(link="http://203.0.113.9/v/abc")
        self.assertTrue(rep.blocking)
        self.assertIn("ip_link", rep.codes("critical"))
        self.assertIn("insecure_link", rep.codes("high"))

    def test_loopback_link_is_critical(self):
        rep = _clean(link="http://127.0.0.1:8081/v/abc")
        self.assertTrue(rep.blocking)
        self.assertIn("loopback_link", rep.codes("critical"))

    def test_ephemeral_tunnel_host_is_high(self):
        rep = _clean(link="https://odd-words.trycloudflare.com/v/abc")
        self.assertIn("ephemeral_host", rep.codes("high"))

    def test_shortener_is_medium(self):
        rep = _clean(link="https://is.gd/xY3k")
        self.assertIn("shortener", rep.codes("medium"))

    def test_link_domain_mismatch_is_high(self):
        rep = _clean(link="https://tracker-xyz.example/v/abc")
        self.assertIn("link_domain_mismatch", rep.codes("high"))

    def test_subdomain_of_sender_is_not_a_mismatch(self):
        rep = _clean(link="https://cdn.acme.it/v/abc")
        self.assertNotIn("link_domain_mismatch", rep.codes())

    def test_plain_http_link_is_high(self):
        rep = _clean(link="http://notify.acme.it/v/abc")
        self.assertIn("insecure_link", rep.codes("high"))
        self.assertNotIn("link_domain_mismatch", rep.codes())


class TestContent(unittest.TestCase):

    def test_hidden_pixel_is_flagged(self):
        rep = _clean(html='<html><body><img src="https://x/p.png" '
                          'width="1" height="1" style="display:none"></body></html>')
        self.assertIn("hidden_pixel", rep.codes("high"))

    def test_image_only_is_critical(self):
        rep = _clean(body_text="", html='<html><img src="a"><img src="b">'
                                       '</html>')
        self.assertTrue(rep.blocking)
        self.assertIn("image_only", rep.codes("critical"))

    def test_low_text_ratio_is_high(self):
        # enough text to avoid the image_only verdict, not enough to be sane
        rep = _clean(body_text="Hi Mario, a quick note about the summary of "
                               "your last session and the export you asked "
                               "for. Let me know if it looks right to you.",
                     html='<html><img src="a"><img src="b"></html>')
        self.assertIn("low_text_ratio", rep.codes("high"))
        self.assertNotIn("image_only", rep.codes())

    def test_spam_phrases_are_scored(self):
        rep = _clean(body_text="Please verify your account and click here now")
        self.assertIn("spam_phrases", rep.codes("high"))

    def test_shouty_and_empty_subject(self):
        self.assertIn("shouty_subject", _clean(subject="ACT NOW PLEASE").codes())
        self.assertIn("no_subject", _clean(subject="").codes("high"))

    def test_no_plaintext_alternative(self):
        rep = _clean(body_text="", html="<html><body><p>hi</p></body></html>")
        self.assertIn("no_plaintext", rep.codes("medium"))

    def test_bulk_without_unsubscribe(self):
        rep = _clean(is_bulk=True)
        self.assertIn("no_unsubscribe", rep.codes("medium"))
        rep2 = _clean(is_bulk=True,
                      html="<html><body><p>hi</p>"
                           "<a href='#'>Unsubscribe</a></body></html>")
        self.assertNotIn("no_unsubscribe", rep2.codes())


class TestRecommendations(unittest.TestCase):

    def test_top_fix_picks_worst_severity_first(self):
        rep = _clean(link="http://203.0.113.9/v/abc",
                     html='<img src="a" style="display:none">')
        self.assertTrue(rep.top_fix().startswith("ip_link"))

    def test_report_lists_issues_sorted(self):
        rep = _clean(link="http://203.0.113.9/v/abc")
        out = rep.report()
        self.assertTrue(out[0].startswith("DELIVERABILITY: "))
        self.assertIn("[critical]", out[1])

    def test_score_never_negative(self):
        rep = _clean(subject="", body_text="", sender="",
                     link="http://127.0.0.1/x",
                     html='<img style="display:none"><img src="a">')
        self.assertEqual(rep.score, 0)
        self.assertEqual(rep.grade, "F")


class TestTemplatesIntegration(unittest.TestCase):
    """The HTML builder must NOT ship the classic hidden-pixel marker."""

    def test_build_html_body_pixel_is_not_hidden(self):
        from phantom.automation.social.templates import build_html_body
        html = build_html_body("Subject", "Body text here.\n\nRegards",
                              "https://x.acme.it/v/1", "Continue",
                              tracking_pixel="https://x.acme.it/px/1")
        self.assertNotIn("display:none", html)
        self.assertIn("https://x.acme.it/px/1", html)

    def test_preflight_accepts_the_built_html(self):
        from phantom.automation.social.templates import build_html_body
        html = build_html_body("Your session summary",
                              "Hi Mario, your summary is ready in the "
                              "dashboard whenever you need it.\n\nThanks",
                              "https://notify.acme.it/v/1", "Continue",
                              tracking_pixel="https://notify.acme.it/px/1")
        rep = deliverability_report(
            subject="Your session summary",
            body_text="Hi Mario, your summary is ready in the dashboard "
                      "whenever you need it.\n\nThanks",
            html=html, link="https://notify.acme.it/v/1",
            sender="Acme <no-reply@acme.it>",
            tracking_pixel="https://notify.acme.it/px/1")
        self.assertNotIn("hidden_pixel", rep.codes())


if __name__ == "__main__":
    unittest.main()
