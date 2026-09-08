"""Tests for encrypted .pm bundles + automatic session persistence."""
import gzip
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from phantom.core.knowledge import reset_wm, session_wm
from phantom.core.session import session
from phantom.utils.session_bundle import _MAGIC, export_session, read_bundle
import phantom.utils.auto_session as AS


class TestEncryptedBundle(unittest.TestCase):

    def _export(self, tmp, name="s.pm", **kw):
        return export_session(out_path=os.path.join(tmp, name), **kw)

    def test_export_encrypted_by_default_no_plaintext_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._export(tmp)
            raw = gzip.open(path, "rb").read().decode()
            self.assertNotIn("bob@corp.com", raw)
            self.assertNotIn("tcp/443", raw)
            top = json.loads(raw)
            self.assertEqual(top["enc"], 1)
            self.assertTrue(top["payload"])

    def test_encrypted_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._export(tmp)
            data = read_bundle(path)
            self.assertEqual(data["session"]["target"], session.target)
            self.assertTrue(data.get("engagement_id"))

    def test_tampered_bundle_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._export(tmp)
            with gzip.open(path, "rb") as f:
                top = json.loads(f.read().decode())
            top["payload"] = top["payload"][:-4] + "AAAA"
            bad = os.path.join(tmp, "bad.pm")
            with gzip.open(bad, "wb") as f:
                f.write(json.dumps(top).encode())
            with self.assertRaises(ValueError):
                read_bundle(bad)

    def test_legacy_plaintext_still_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._export(tmp, encrypt=False)
            with gzip.open(path, "rb") as f:
                raw = json.loads(f.read().decode())
            self.assertNotIn("enc", raw)
            self.assertEqual(read_bundle(path)["session"]["target"], session.target)

    def test_foreign_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "x.pm")
            with open(p, "wb") as f:
                f.write(b"not a bundle at all")
            with self.assertRaises(ValueError):
                read_bundle(p)


class TestAutoExport(unittest.TestCase):

    def setUp(self):
        self._old = (session.target, list(session.notes or []),
                     getattr(session, "engagement_started", None))
        reset_wm(target="")
        session.notes = []
        session.target = ""
        session.engagement_started = "2026-08-26T10:00:00"

    def tearDown(self):
        session.target, session.notes, session.engagement_started = self._old
        reset_wm(target="")

    def _run(self, fn):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(AS, "sessions_dir", lambda: tmp):
                return fn(tmp)

    def test_export_writes_latest_and_dated(self):
        def check(tmp):
            session.target = "bob@corp.com"
            reset_wm(target="bob@corp.com")
            session_wm().add_finding("service", "tcp/443", {}, source="scan")
            AS.auto_export()
            files = sorted(os.listdir(tmp))
            self.assertIn("latest.pm", files)
            self.assertTrue(any(f.startswith("auto_") and f.endswith(".pm") for f in files))
        self._run(check)

    def test_same_engagement_overwrites(self):
        def check(tmp):
            session.target = "bob@corp.com"
            reset_wm(target="bob@corp.com")
            AS.auto_export()
            files1 = sorted(os.listdir(tmp))
            AS.auto_export()
            self.assertEqual(sorted(os.listdir(tmp)), files1)
        self._run(check)

    def test_new_engagement_gets_new_file(self):
        def check(tmp):
            session.target = "bob@corp.com"
            reset_wm(target="bob@corp.com")
            AS.auto_export()
            session.target = "alice@corp.com"
            session.engagement_started = "2026-08-26T12:00:00"
            reset_wm(target="alice@corp.com")
            AS.auto_export()
            dated = [f for f in os.listdir(tmp)
                     if f.startswith("auto_") and f.endswith(".pm")]
            self.assertGreaterEqual(len(dated), 2)
        self._run(check)

    def test_empty_session_writes_nothing(self):
        def check(tmp):
            self.assertIsNone(AS.auto_export())
            self.assertEqual(os.listdir(tmp), [])
        self._run(check)

    def test_list_auto_metadata(self):
        def check(tmp):
            session.target = "bob@corp.com"
            reset_wm(target="bob@corp.com")
            session_wm().add_finding("service", "tcp/443", {}, source="scan")
            AS.auto_export()
            items = AS.list_auto()
            self.assertTrue(any(a["name"] == "latest.pm" for a in items))
            latest = next(a for a in items if a["name"] == "latest.pm")
            self.assertEqual(latest["target"], "bob@corp.com")
            self.assertEqual(latest["findings"], 1)
        self._run(check)


class TestResumePrompt(unittest.TestCase):

    def setUp(self):
        self._old = (session.target, list(session.notes or []),
                     getattr(session, "engagement_started", None))
        reset_wm(target="")
        session.notes = []
        session.target = ""
        session.engagement_started = "2026-08-26T10:00:00"

    def tearDown(self):
        session.target, session.notes, session.engagement_started = self._old
        reset_wm(target="")

    def test_offer_resume_accepts(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(AS, "sessions_dir", lambda: tmp), \
                 patch.object(AS.sys, "stdin") as stdin, \
                 patch("builtins.input", return_value="y"):
                stdin.isatty.return_value = True
                session.target = "bob@corp.com"
                reset_wm(target="bob@corp.com")
                session_wm().add_finding("service", "tcp/443", {}, source="scan")
                AS.auto_export()
                reset_wm(target="")
                session.target = ""
                ok = AS.offer_resume()
                self.assertTrue(ok)
                self.assertEqual(session.target, "bob@corp.com")
                self.assertEqual(len(session_wm().all_findings()), 1)

    def test_offer_resume_declines(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(AS, "sessions_dir", lambda: tmp), \
                 patch.object(AS.sys, "stdin") as stdin, \
                 patch("builtins.input", return_value="n"):
                stdin.isatty.return_value = True
                session.target = "bob@corp.com"
                reset_wm(target="bob@corp.com")
                AS.auto_export()
                reset_wm(target="")
                session.target = ""
                self.assertFalse(AS.offer_resume())
                self.assertEqual(session.target, "")

    def test_offer_resume_skips_non_tty(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(AS, "sessions_dir", lambda: tmp), \
                 patch.object(AS.sys, "stdin") as stdin:
                stdin.isatty.return_value = False
                self.assertFalse(AS.offer_resume())

    def test_register_open_appends_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(AS, "sessions_dir", lambda: tmp):
                AS.register_open()
                AS.register_open()
                with open(os.path.join(tmp, "index.json"), encoding="utf-8") as f:
                    idx = json.load(f)
                self.assertEqual(len(idx), 2)
                self.assertIn("opened_at", idx[0])


class TestShellListSessions(unittest.TestCase):

    def test_list_sessions_does_not_crash(self):
        from phantom.core.shell import PhantomShell
        sh = PhantomShell()
        sh.do_list_sessions("")  # must not raise


if __name__ == "__main__":
    unittest.main()
