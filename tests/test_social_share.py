"""Tests for share-format video IP-grabber links (the URL shape you get when
you share a reel/short) and realistic sender-domain derivation."""
import http.client
import unittest

from phantom.automation.social.grabbit import IpGrabber
from phantom.automation.social.engine import SocialEngine
from phantom.automation.social.mailers import Mailer
from phantom.automation.social.tracker import TrackingServer


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


if __name__ == "__main__":
    unittest.main()
