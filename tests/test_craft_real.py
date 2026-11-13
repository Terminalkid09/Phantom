"""Tests for the REAL first hop: a genuine high-reputation URL in the message
with the capture link inside the content (the answer to "the link must not
look like the operator's")."""
import unittest

from phantom.modules.craft import (
    channel_matrix,
    craft_pixel,
    craft_real,
    host_supports_anchor,
    idn_verdict,
    is_real_host,
)


class TestRealHostDetection(unittest.TestCase):

    def test_accepts_hosts_you_can_publish_on(self):
        for url in ("https://www.youtube.com/watch?v=abc",
                    "https://youtu.be/abc",
                    "https://drive.google.com/file/d/1/view",
                    "https://docs.google.com/document/d/1/edit",
                    "https://sub.sites.google.com/view/x",
                    "https://my.notion.site/page",
                    "https://user.github.io/site"):
            self.assertIsNotNone(is_real_host(url), url)

    def test_refuses_a_platform_url_that_is_not_ours(self):
        # a URL we invent on instagram.com is answered by Instagram, not by
        # the tracker: the capture would simply never happen
        for url in ("https://www.instagram.com/reel/abc",
                    "https://instagram.com/reel/abc",
                    "https://tiktok.com/@u/video/1",
                    "https://evil.example/reel/abc",
                    "", "not a url"):
            self.assertIsNone(is_real_host(url), url)

    def test_subdomain_of_a_real_host_is_accepted(self):
        self.assertIsNotNone(is_real_host("https://cdn.drive.google.com/x"))


class TestCraftReal(unittest.TestCase):

    _REAL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

    def test_rejects_a_non_real_outer_url(self):
        out = craft_real(outer_url="https://www.instagram.com/reel/abc")
        self.assertIn("error", out)
        self.assertIn("not_a_real_first_hop", out["error"])
        self.assertIn("hint", out)

    def test_usage_error_without_a_url(self):
        for bad in ("", "youtube.com/watch?v=x"):
            out = craft_real(outer_url=bad)
            self.assertIn("error", out)
            self.assertIn("Usage", out["error"])

    def test_kit_shape_and_the_message_carries_only_the_real_url(self):
        out = craft_real(outer_url=self._REAL, inner="ipgrab")
        self.assertNotIn("error", out)
        self.assertEqual(out["kind"], "real_first_hop")
        self.assertEqual(out["outer_url"], self._REAL)
        self.assertEqual(out["outer_host"], "www.youtube.com")
        self.assertTrue(out["inner_url"])
        self.assertTrue(out["inner_code"])
        # the whole point: no operator URL reaches the target's message
        self.assertIn(self._REAL, out["dm_text"])
        self.assertNotIn(out["inner_url"], out["dm_text"])
        self.assertIn(self._REAL, out["email_body"])
        self.assertNotIn(out["inner_url"], out["email_body"])
        # and the kit says WHERE the inner link has to be placed
        self.assertIn("description", out["placement"].lower())
        self.assertIn("first hop is authentic", out["note"])

    def test_inner_beacon_player_needs_the_c2(self):
        out = craft_real(outer_url=self._REAL, inner="beacon-player")
        # no C2 listener in a unit test -> the inner build fails cleanly and
        # the failure is propagated instead of silently degrading
        self.assertIn("error", out)

    def test_unknown_inner_kind_degrades_to_ipgrab(self):
        out = craft_real(outer_url=self._REAL, inner="whatever")
        self.assertEqual(out["inner"], "ipgrab")


class TestAnchorCapability(unittest.TestCase):
    """Hiding the destination is a RENDERER capability: a raw tracker URL in
    a YouTube description is as visible as a raw tracker URL in a DM."""

    def test_host_supports_anchor(self):
        for url in ("https://sites.google.com/view/x",
                    "https://my.notion.site/page",
                    "https://user.github.io/x",
                    "https://docs.google.com/document/d/1/edit"):
            self.assertTrue(host_supports_anchor(url), url)
        for url in ("https://www.youtube.com/watch?v=a",
                    "https://youtu.be/a", "https://forms.gle/x", ""):
            self.assertFalse(host_supports_anchor(url), url)

    def test_youtube_placement_warns_that_the_domain_is_visible(self):
        out = craft_real(outer_url="https://www.youtube.com/watch?v=a",
                         inner="ipgrab")
        self.assertFalse(out["supports_anchor"])
        self.assertIn("destination_visible_on_www.youtube.com", out["warning"])
        # what to paste is the RAW tracker url here — and the kit says so
        self.assertEqual(out["inner_paste"], out["inner_url"])
        self.assertEqual(out["inner_anchor_html"], "")
        self.assertIn("sites.google.com", out["recommended_middle_hops"])
        self.assertIn("CANNOT hide", out["note"])

    def test_anchor_capable_placement_hides_the_destination(self):
        out = craft_real(outer_url="https://sites.google.com/view/mine",
                         inner="ipgrab")
        self.assertTrue(out["supports_anchor"])
        self.assertEqual(out["warning"], "")
        self.assertEqual(out["inner_paste"], out["inner_anchor_html"])
        self.assertIn(out["inner_url"], out["inner_anchor_html"])
        self.assertIn(out["inner_display"], out["inner_anchor_html"])
        self.assertIn("instagram.com/reel/", out["inner_display"])
        self.assertIn("hide the destination", out["note"])


class TestChannelMatrix(unittest.TestCase):

    def test_hideable_and_visible_channels(self):
        m = channel_matrix(url="https://t.example/reel/abc")
        for name in ("email_html", "telegram_html", "discord_markdown",
                     "your_page"):
            self.assertTrue(m["channels"][name]["hides_destination"], name)
        for name in ("whatsapp", "sms", "instagram",
                     "youtube_description"):
            self.assertFalse(m["channels"][name]["hides_destination"], name)
        self.assertIn("email_html", m["hideable"])
        self.assertIn("whatsapp", m["visible"])

    def test_paste_strings(self):
        m = channel_matrix(url="https://t.example/reel/abc", code="reel-abc")
        self.assertEqual(m["channels"]["telegram_html"]["paste"],
                         '<a href="https://t.example/reel/abc">'
                         'instagram.com/reel/abc</a>')
        self.assertEqual(m["channels"]["discord_markdown"]["paste"],
                         "[instagram.com/reel/abc]"
                         "(https://t.example/reel/abc)")
        # a channel that renders the raw URL gets the raw URL, not a fake
        self.assertEqual(m["channels"]["whatsapp"]["paste"],
                         "https://t.example/reel/abc")

    def test_truth_statement(self):
        m = channel_matrix(url="https://t.example/reel/abc")
        self.assertIn("two mechanisms", m["truth"])
        # neither mechanism fakes a domain, and the address bar is never
        # controllable after the click
        self.assertIn("neither fakes a domain", m["truth"])
        self.assertIn("after the click", m["truth"])

    def test_two_mechanisms_are_reported(self):
        m = channel_matrix(url="https://t.example/reel/abc")
        anchor = m["mechanisms"]["anchor"]
        rdr = m["mechanisms"]["middle_hop_redirect"]
        # A: only the channels that render link text
        self.assertIn("email_html", anchor["works_on"])
        self.assertIn("whatsapp", anchor["fails_on"])
        self.assertNotIn("whatsapp", anchor["works_on"])
        # B: works everywhere, including the ones where A fails
        self.assertEqual(rdr["works_on"][:12], "every channe")
        self.assertIn("is.gd", rdr["paste"])
        self.assertIn("https://t.example/reel/abc", rdr["paste"])
        self.assertIn("CARD is lost", rdr["cost"])

    def test_redirect_works_on_every_channel(self):
        m = channel_matrix(url="https://t.example/reel/abc")
        for name, row in m["channels"].items():
            self.assertTrue(row["redirect_works"], name)


class TestIDNHomograph(unittest.TestCase):
    """The Cyrillic-homograph idea, answered with evidence."""

    # Cyrillic dotted i (U+0456) in place of the Latin 'i'
    _HOMOGRAPH = "\u0456nstagram.com"

    def test_mixed_script_is_forced_to_punycode(self):
        out = idn_verdict(self._HOMOGRAPH)
        self.assertTrue(out["mixed_scripts"])
        self.assertIn("CYRILLIC", out["scripts"])
        self.assertIn("LATIN", out["scripts"])
        # the browser shows the ASCII form, NOT the brand
        self.assertEqual(out["punycode"], "xn--nstagram-shh.com")
        self.assertEqual(out["displayed_in_address_bar"],
                         "xn--nstagram-shh.com")
        self.assertIn("BLOCKED BY THE BROWSER", out["verdict"])

    def test_pure_latin_domain_is_honest(self):
        out = idn_verdict("instagram.com")
        self.assertTrue(out["ascii_only"])
        self.assertEqual(out["punycode"], "instagram.com")
        self.assertEqual(out["displayed_in_address_bar"], "instagram.com")
        self.assertIn("exactly as written", out["verdict"])

    def test_single_non_latin_script_does_not_imitate_the_brand(self):
        # a fully Cyrillic label is not mixed, so browsers DO render the
        # Unicode form — but that reads as Cyrillic letters, not as
        # `instagram.com`, so it imitates nothing (and costs money)
        out = idn_verdict("\u0438\u043d\u0441\u0442\u0430.com")
        self.assertFalse(out["mixed_scripts"])
        self.assertEqual(out["mixed_label"], "")
        self.assertEqual(out["displayed_in_address_bar"],
                         "\u0438\u043d\u0441\u0442\u0430.com")
        self.assertTrue(out["punycode"].startswith("xn--"))
        self.assertIn("imitates nothing", out["verdict"])
        self.assertIn("registered", out["verdict"])

    def test_ascii_tld_is_not_counted_as_a_second_script(self):
        # judging the whole domain would wrongly flag every IDN just because
        # it ends in .com: the policy is per label
        out = idn_verdict("\u0438\u043d\u0441\u0442\u0430.com")
        self.assertFalse(out["mixed_scripts"])
        self.assertEqual(out["mixed_label"], "")
        mixed = idn_verdict(self._HOMOGRAPH)
        self.assertEqual(mixed["mixed_label"], "\u0456nstagram")

    def test_the_free_alternative_is_always_offered(self):
        out = idn_verdict(self._HOMOGRAPH)
        self.assertIn("ANCHOR", out["free_alternative"])
        self.assertIn("TEXT, not a domain", out["free_alternative"])

    def test_usage_error(self):
        self.assertIn("error", idn_verdict(""))


class TestPixelEvasion(unittest.TestCase):

    def test_pixel_is_not_a_hidden_image(self):
        # display:none is a spam marker AND gets stripped by mail providers,
        # which kills the capture too
        out = craft_pixel()
        self.assertNotIn("display:none", out["html"])
        self.assertIn("<img", out["html"])


if __name__ == "__main__":
    unittest.main()
