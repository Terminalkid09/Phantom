"""Tests for the video-lure IP grabber: /v/<code> routes with IG/TikTok/YT
skins, hit recording on page load, and the grabbit factory."""
import http.client
import unittest

from phantom.automation.social.grabbit import IpGrabber
from phantom.automation.social.tracker import TrackingServer


class TestVideoLureRoutes(unittest.TestCase):

    def _server(self, skin="youtube"):
        return TrackingServer(host="127.0.0.1", port=0, skin=skin,
                              video_id="dQw4w9WgXcQ")

    def test_youtube_skin_serves_page_and_records_hit(self):
        server = self._server("youtube")
        server.start()
        try:
            self.assertTrue(server.running, server.bind_error)
            port = server._httpd.server_address[1]
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/v/abc")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            body = resp.read().decode("utf-8", "ignore")
            conn.close()
            self.assertIn("YouTube", body)
            self.assertIn("dQw4w9WgXcQ", body)  # embedded player
            # page load IS the click: hit captured without any redirect
            hits = server.store.hits("abc")
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].ip, "127.0.0.1")
        finally:
            server.stop()

    def test_instagram_skin(self):
        server = self._server("instagram")
        server.start()
        try:
            port = server._httpd.server_address[1]
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/v/insta1")
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "ignore")
            conn.close()
            self.assertEqual(resp.status, 200)
            self.assertIn("Instagram", body)
            self.assertIn("Reels", body)
            self.assertEqual(len(server.store.hits("insta1")), 1)
        finally:
            server.stop()

    def test_tiktok_skin(self):
        server = self._server("tiktok")
        server.start()
        try:
            port = server._httpd.server_address[1]
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/v/tok1")
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "ignore")
            conn.close()
            self.assertEqual(resp.status, 200)
            self.assertIn("TikTok", body)
            self.assertEqual(len(server.store.hits("tok1")), 1)
        finally:
            server.stop()

    def test_unknown_skin_falls_back_to_youtube(self):
        server = TrackingServer(host="127.0.0.1", port=0, skin="weird",
                                video_id="")
        server.start()
        try:
            port = server._httpd.server_address[1]
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/v/x1")
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "ignore")
            conn.close()
            self.assertEqual(resp.status, 200)
            self.assertIn("YouTube", body)
            # no video id configured -> static player, still records
            self.assertEqual(len(server.store.hits("x1")), 1)
        finally:
            server.stop()

    def test_login_and_click_routes_still_work(self):
        server = self._server("youtube")
        server.start()
        try:
            port = server._httpd.server_address[1]
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/l/c1")
            self.assertEqual(conn.getresponse().status, 200)
            conn.close()
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/c1")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 302)  # click route still redirects
            conn.close()
            self.assertEqual(len(server.store.hits("c1")), 1)
        finally:
            server.stop()


class TestVideoLinkFactory(unittest.TestCase):

    def test_create_video_link_prefix(self):
        # default provider (real in-process server on an ephemeral port)
        from phantom.automation.social.tracker import TrackingServer
        g = IpGrabber(server=TrackingServer(host="127.0.0.1", port=0))
        link = g.create_video_link(label="vid")
        self.assertIn("/v/", link.short_url, link)
        self.assertIn("vid-", link.code)
        g._default_server.stop()

    def test_create_video_link_code_unique_per_call(self):
        g = IpGrabber(creator=lambda code: f"http://t/{code}",
                      fetcher=lambda code: [])
        a = g.create_video_link(label="vid")
        b = g.create_video_link(label="vid")
        self.assertNotEqual(a.code, b.code)


if __name__ == "__main__":
    unittest.main()
