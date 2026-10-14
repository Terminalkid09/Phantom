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


class TestNoSilentLoss(unittest.TestCase):
    """The engagement is the one thing that must not vanish quietly.

    Every failure on these paths used to be an unannounced `None`/`False`:
    the operator closed the shell believing the run was saved.
    """

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

    def test_export_is_atomic_and_leaves_no_half_written_file(self):
        def check(tmp):
            session.target = "bob@corp.com"
            reset_wm(target="bob@corp.com")
            session_wm().add_finding("service", "tcp/443", {}, source="scan")
            AS.auto_export()
            self.assertEqual([f for f in os.listdir(tmp)
                              if f.endswith(".tmp")], [])
            data = read_bundle(os.path.join(tmp, "latest.pm"))
            self.assertEqual(data["session"]["target"], "bob@corp.com")
        self._run(check)

    def test_a_results_only_engagement_is_persisted(self):
        """`session.results` is durable output too (audit §6.5.4).

        The gate used to look at target + notes + findings only, so an
        engagement whose single result was, say, a scan was NOT written: the
        operator closed the shell and it was gone.
        """
        def check(tmp):
            session.target = ""
            reset_wm(target="")
            session.results = {"scan": {"open_ports": [22, 443]}}
            try:
                written = AS.auto_export()
            finally:
                session.results = {}
            self.assertIsNotNone(written, "results-only engagement was dropped")
            self.assertIn("latest.pm", os.listdir(tmp))
            data = read_bundle(os.path.join(tmp, "latest.pm"))
            self.assertIn("scan", data["session"]["results"])
        self._run(check)

    def test_history_alone_is_not_content(self):
        """Every typed command lands in history; it must not force a bundle."""
        def check(tmp):
            session.history = ["[10:00:00] show session"]
            try:
                self.assertIsNone(AS.auto_export())
            finally:
                session.history = []
            self.assertEqual(os.listdir(tmp), [])
        self._run(check)

    def test_a_failed_export_is_announced_not_swallowed(self):
        def check(tmp):
            session.target = "bob@corp.com"
            reset_wm(target="bob@corp.com")
            with patch.object(AS, "export_session",
                              side_effect=OSError("disk full")), \
                 patch.object(AS, "_warn") as warn:
                self.assertIsNone(AS.auto_export())
                self.assertTrue(warn.called)
                self.assertIn("auto-save FAILED", warn.call_args[0][0])
        self._run(check)

    def test_list_auto_tells_corrupt_from_wrong_key(self):
        def check(tmp):
            with open(os.path.join(tmp, "latest.pm"), "wb") as f:
                f.write(b"not a bundle at all")
            corrupt = next(a for a in AS.list_auto()
                           if a["name"] == "latest.pm")
            self.assertIn("corrupt", corrupt["target"])

            good = os.path.join(tmp, "auto_2026-08-26.pm")
            export_session(out_path=good)
            with patch("phantom.utils.session_bundle._pm_key",
                       return_value=b"\x01" * 32):
                foreign = next(a for a in AS.list_auto()
                               if a["name"] == "auto_2026-08-26.pm")
            self.assertIn("key", foreign["target"])
        self._run(check)

    def test_offer_resume_warns_when_latest_pm_is_unreadable(self):
        def check(tmp):
            with open(os.path.join(tmp, "latest.pm"), "wb") as f:
                f.write(b"truncated")
            with patch.object(AS.sys, "stdin") as stdin, \
                 patch.object(AS, "_warn") as warn:
                stdin.isatty.return_value = True
                self.assertFalse(AS.offer_resume())
                self.assertTrue(warn.called)
                self.assertIn("unreadable", warn.call_args[0][0])
        self._run(check)


class TestAutoShellPersistsOnExit(unittest.TestCase):
    """The AUTO-MODE shell is the surface that runs kill chains.

    It used to write no `.pm` at all: the C2 intel and the reasoning state
    lived only in memory and were gone at the next open.
    """

    def _run(self, side_effect, expect_raise=False):
        from phantom.core import auto_shell as SH
        with patch.object(SH, "AutoShell") as shell_cls, \
             patch("phantom.utils.auto_session.auto_export",
                   return_value="latest.pm") as export:
            shell_cls.return_value.cmdloop.side_effect = side_effect
            if expect_raise:
                with self.assertRaises(type(side_effect)):
                    SH.run_auto_shell()
            else:
                SH.run_auto_shell()
            return export

    def test_back_exit_persists(self):
        self._run(None).assert_called_once()

    def test_ctrl_c_persists(self):
        # a Ctrl+C is swallowed by design, but the export must still happen
        self._run(KeyboardInterrupt()).assert_called_once()

    def test_a_crash_inside_a_command_still_persists(self):
        self._run(RuntimeError("boom"), expect_raise=True).assert_called_once()


class TestShellListSessions(unittest.TestCase):

    def test_list_sessions_does_not_crash(self):
        from phantom.core.shell import PhantomShell
        sh = PhantomShell()
        sh.do_list_sessions("")  # must not raise


if __name__ == "__main__":
    unittest.main()
