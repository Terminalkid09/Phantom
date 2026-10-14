"""Tests for portable .pm session bundles (export/import/handoff) and the
identity-target scope discipline."""
import gzip
import json
import os
import tempfile
import unittest

from phantom.automation.agent import AutonomousAgent
from phantom.automation.belief import WorldModel
from phantom.core.session import session
from phantom.utils.session_bundle import (
    _MAGIC,
    export_session,
    import_session,
    latest_checkpoint,
    read_bundle,
)

FAKE_PM = {
    "magic": _MAGIC,
    "format": "phantom.pm",
    "version": 1,
    "exported_at": "2026-08-26T00:00:00Z",
    "session": {
        "target": "mario.rossi@acme.it",
        "mode": "recon",
        "scope": ["acme.it"],
        "notes": [{"text": "first contact"}],
        "history": ["set target", "run scan"],
        "knowledge_base": {"creds_found": [{"u": "u", "p": "p"}]},
    },
    "checkpoint_source": "checkpoint.json",
    "checkpoint": {"wm": {"target": "mario.rossi@acme.it"}, "dead": []},
    "reports": [{"dir": "auto_1", "file": "report_raw.md",
                 "path": "/x/auto_1/report_raw.md"}],
}


def _write_bundle(path, payload, *, encrypted=False):
    """A .pm on disk, optionally through the encrypted envelope path."""
    if encrypted:
        from phantom.utils.session_bundle import _encrypt_payload
        block = {"magic": _MAGIC, "format": "phantom.pm",
                 "version": payload.get("version", 1), "enc": 1,
                 "exported_at": "2026-08-26T00:00:00Z",
                 "payload": _encrypt_payload(payload)}
    else:
        block = payload
    with gzip.open(path, "wb") as fh:
        fh.write(json.dumps(block).encode("utf-8"))
    return path


class TestVersionIsValidatedOnRead(unittest.TestCase):
    """The audit: `version` was written and never read.

    A future build can reshape a field; parsing it best-effort restores a
    session that LOOKS complete and is not. The gate has to be explicit in
    both directions of the envelope.
    """

    def test_a_bundle_from_a_newer_build_is_refused_with_both_numbers(self):
        from phantom.utils.session_bundle import _VERSION
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_bundle(os.path.join(tmp, "future.pm"),
                                 dict(FAKE_PM, version=_VERSION + 1))
            with self.assertRaises(ValueError) as ctx:
                read_bundle(path)
            message = str(ctx.exception)
            self.assertIn(f"version {_VERSION + 1}", message)
            self.assertIn(f"up to {_VERSION}", message)

    def test_the_refusal_is_not_reported_as_a_key_mismatch(self):
        """Different problem, different words: this is not a wrong key."""
        from phantom.utils.session_bundle import _VERSION, is_key_mismatch
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_bundle(os.path.join(tmp, "future.pm"),
                                 dict(FAKE_PM, version=_VERSION + 5))
            try:
                read_bundle(path)
                self.fail("a newer bundle must be refused")
            except ValueError as exc:
                self.assertFalse(is_key_mismatch(exc))
                self.assertIn("NEWER Phantom", str(exc))

    def test_the_encrypted_envelope_is_gated_too(self):
        """The OUTER version, and the payload's, are both checked."""
        from phantom.utils.session_bundle import _VERSION
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_bundle(os.path.join(tmp, "future.pm"),
                                 dict(FAKE_PM, version=1),
                                 encrypted=True)
            # envelope claiming a future format
            with gzip.open(path, "rb") as fh:
                block = json.loads(fh.read().decode("utf-8"))
            block["version"] = _VERSION + 1
            with gzip.open(path, "wb") as fh:
                fh.write(json.dumps(block).encode("utf-8"))
            with self.assertRaises(ValueError) as ctx:
                read_bundle(path)
            self.assertIn("bundle", str(ctx.exception))

    def test_a_payload_from_a_future_build_is_refused(self):
        """A current envelope carrying a future PAYLOAD is refused by name."""
        from phantom.utils.session_bundle import _VERSION
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_bundle(os.path.join(tmp, "future.pm"),
                                 dict(FAKE_PM, version=_VERSION + 1),
                                 encrypted=True)
            # leave the envelope at the CURRENT version, so only the payload
            # is newer — the case an attacker or a partial upgrade produces
            with gzip.open(path, "rb") as fh:
                block = json.loads(fh.read().decode("utf-8"))
            block["version"] = _VERSION
            with gzip.open(path, "wb") as fh:
                fh.write(json.dumps(block).encode("utf-8"))
            with self.assertRaises(ValueError) as ctx:
                read_bundle(path)
            self.assertIn("payload", str(ctx.exception))

    def test_the_current_version_still_reads(self):
        from phantom.utils.session_bundle import _VERSION
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_bundle(os.path.join(tmp, "now.pm"),
                                 dict(FAKE_PM, version=_VERSION))
            self.assertEqual(read_bundle(path)["magic"], _MAGIC)

    def test_a_bundle_without_a_version_is_the_legacy_format(self):
        """Written before the field existed => version 1, still readable."""
        legacy = {k: v for k, v in FAKE_PM.items() if k != "version"}
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_bundle(os.path.join(tmp, "legacy.pm"), legacy)
            self.assertEqual(read_bundle(path)["session"]["target"],
                             "mario.rossi@acme.it")

    def test_a_malformed_version_is_refused(self):
        for bad in ("two", 0, -3, 1.5, True):
            with self.subTest(version=bad):
                with tempfile.TemporaryDirectory() as tmp:
                    path = _write_bundle(os.path.join(tmp, "bad.pm"),
                                         dict(FAKE_PM, version=bad))
                    with self.assertRaises(ValueError):
                        read_bundle(path)

    def test_check_version_names_the_case(self):
        from phantom.utils.session_bundle import check_version
        self.assertEqual(check_version(None), 1)
        self.assertEqual(check_version(1), 1)
        with self.assertRaises(ValueError) as ctx:
            check_version(99)
        self.assertIn("99", str(ctx.exception))


class TestBundleRoundTrip(unittest.TestCase):

    def test_export_writes_valid_pm(self):
        old_target = session.target
        session.target = "bob@corp.com"
        session.mode = "stealth"
        session.scope = ["corp.com"]
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = export_session(out_path=os.path.join(tmp, "sess.pm"))
                self.assertTrue(os.path.isfile(path))
                data = read_bundle(path)
                self.assertEqual(data["magic"], _MAGIC)
                self.assertEqual(data["format"], "phantom.pm")
                self.assertEqual(data["session"]["target"], "bob@corp.com")
                self.assertIn("reports", data)
        finally:
            session.target = old_target
            session.mode = ""
            session.scope = []

    def test_foreign_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "evil.pm")
            with open(p, "w", encoding="utf-8") as f:
                f.write("not a bundle")
            with self.assertRaises(ValueError):
                read_bundle(p)

    def test_import_applies_session_and_stages_checkpoint(self):
        old_target, old_scope = session.target, list(session.scope)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                pm = os.path.join(tmp, "sess.pm")
                with open(pm, "wb") as f:
                    import gzip
                    f.write(gzip.compress(
                        json.dumps(FAKE_PM).encode("utf-8")))
                data = import_session(pm, resume_dir=tmp)
                self.assertEqual(data["target"], "mario.rossi@acme.it")
                self.assertEqual(session.target, "mario.rossi@acme.it")
                self.assertEqual(session.scope, ["acme.it"])
                self.assertEqual(len(session.notes), 1)
                self.assertTrue(data["resume_path"])
                self.assertTrue(os.path.isfile(data["resume_path"]))
                with open(data["resume_path"], encoding="utf-8") as f:
                    cp = json.load(f)
                self.assertEqual(cp["wm"]["target"], "mario.rossi@acme.it")
        finally:
            session.target = old_target
            session.scope = list(old_scope)

    def test_import_hydrates_world_model(self):
        """A .pm import must restore the reasoning state, not just the
        session scalars: checkpoint WM findings land in the live WM."""
        from phantom.core.knowledge import reset_wm, session_wm
        reset_wm(target="x")
        self.assertEqual(len(session_wm().all_findings()), 0)
        pm = dict(FAKE_PM)
        pm["checkpoint"] = {"wm": {
            "target": "mario.rossi@acme.it",
            "findings": [{"kind": "service", "key": "tcp/443",
                           "value": {"port": "443"}, "confidence": 0.9,
                           "source": "scan"}],
        }}
        old_target, old_scope = session.target, list(session.scope)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                pm_path = os.path.join(tmp, "sess.pm")
                import gzip
                with open(pm_path, "wb") as f:
                    f.write(gzip.compress(json.dumps(pm).encode("utf-8")))
                data = import_session(pm_path, resume_dir=tmp)
                self.assertEqual(data["findings"], 1)
                self.assertEqual(len(session_wm().all_findings()), 1)
                self.assertEqual(session_wm().target, "mario.rossi@acme.it")
        finally:
            session.target = old_target
            session.scope = list(old_scope)
            reset_wm(target="x")

    def test_import_falls_back_to_session_wm_without_checkpoint(self):
        """No checkpoint in the bundle -> the manual session `_wm` hydrates."""
        from phantom.core.knowledge import reset_wm, session_wm
        reset_wm(target="x")
        pm = dict(FAKE_PM)
        pm["checkpoint"] = None
        pm["session"] = dict(pm["session"])
        pm["session"]["_wm"] = {"target": "mario.rossi@acme.it",
                                  "findings": [
                                      {"kind": "creds", "key": "ssh/root",
                                       "value": {"user": "root"},
                                       "confidence": 0.8, "source": "brute"}]}
        old_target, old_scope = session.target, list(session.scope)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                pm_path = os.path.join(tmp, "sess.pm")
                import gzip
                with open(pm_path, "wb") as f:
                    f.write(gzip.compress(json.dumps(pm).encode("utf-8")))
                data = import_session(pm_path, resume_dir=tmp)
                self.assertEqual(data["findings"], 1)
                self.assertEqual(len(session_wm().all_findings()), 1)
        finally:
            session.target = old_target
            session.scope = list(old_scope)
            reset_wm(target="x")

    def test_importing_two_bundles_keeps_both_staged_checkpoints(self):
        """A fixed `imported_checkpoint.json` clobbered A with B, silently.

        A later `resume imported_checkpoint.json` then continued the WRONG
        engagement — and no `latest_checkpoint` scan can even see that file.
        """
        old_target, old_scope = session.target, list(session.scope)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                staged = os.path.join(tmp, "staged")
                written = []
                for i, target in enumerate(("a@x.com", "b@x.com"), start=1):
                    pm = dict(FAKE_PM)
                    pm["session"] = dict(FAKE_PM["session"], target=target)
                    pm["checkpoint"] = {"wm": {"target": target}, "n": i}
                    path = os.path.join(tmp, f"sess{i}.pm")
                    with open(path, "wb") as f:
                        f.write(gzip.compress(
                            json.dumps(pm).encode("utf-8")))
                    written.append(import_session(path,
                                                  resume_dir=staged)["resume_path"])
                self.assertNotEqual(written[0], written[1])
                for path in written:
                    self.assertTrue(os.path.isfile(path))
                with open(written[0], encoding="utf-8") as f:
                    self.assertEqual(json.load(f)["n"], 1)
        finally:
            session.target = old_target
            session.scope = list(old_scope)

    def test_reimporting_the_same_bundle_is_idempotent(self):
        old_target, old_scope = session.target, list(session.scope)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                pm = os.path.join(tmp, "sess.pm")
                with open(pm, "wb") as f:
                    f.write(gzip.compress(json.dumps(FAKE_PM).encode("utf-8")))
                first = import_session(pm, resume_dir=tmp)["resume_path"]
                second = import_session(pm, resume_dir=tmp)["resume_path"]
                self.assertEqual(first, second)
        finally:
            session.target = old_target
            session.scope = list(old_scope)

    def test_import_warns_when_no_scope_was_restored(self):
        """An empty scope is not "no restriction": auto-mode refuses it."""
        old_target, old_scope = session.target, list(session.scope)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                pm = dict(FAKE_PM)
                pm["session"] = dict(FAKE_PM["session"], scope=[])
                pm["checkpoint"] = None
                path = os.path.join(tmp, "sess.pm")
                with open(path, "wb") as f:
                    f.write(gzip.compress(json.dumps(pm).encode("utf-8")))
                data = import_session(path, resume_dir=tmp)
                self.assertEqual(data["scope"], [])
                self.assertTrue(any("scope" in w for w in data["warnings"]))
                from phantom.utils.session_bundle import summarize
                self.assertIn("WARNING", summarize(data))
        finally:
            session.target = old_target
            session.scope = list(old_scope)

    def test_latest_checkpoint_discovers_newest(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "auto_1"))
            os.makedirs(os.path.join(tmp, "auto_2"))
            p1 = os.path.join(tmp, "auto_1", "checkpoint.json")
            p2 = os.path.join(tmp, "auto_2", "checkpoint.json")
            for p in (p1, p2):
                with open(p, "w", encoding="utf-8") as f:
                    json.dump({"x": 1}, f)
            # newest mtime wins
            os.utime(p1, (0, 100))
            os.utime(p2, (0, 200))
            self.assertEqual(latest_checkpoint(root=tmp), p2)


class TestManualReportsAreIndexed(unittest.TestCase):
    """Audit §6.5.5: the index walked only `auto_*`/`agent_*` run dirs.

    So an engagement whose reports came from the MANUAL generator
    (`report` / `export all` → `data/reports/report_*`, `engagement_*`)
    travelled as a bundle with an EMPTY report index: the artifacts the
    operator most often hands to somebody else were the ones it did not
    mention. Both trees are indexed now, and the manual entries are tagged
    so a reader can tell them from the run dirs.
    """

    def _layout(self, tmp):
        sessions = os.path.join(tmp, "sessions")
        reports = os.path.join(tmp, "reports")
        os.makedirs(os.path.join(sessions, "auto_2026-01-01"))
        os.makedirs(os.path.join(sessions, "not_an_engagement"))
        os.makedirs(os.path.join(reports, "report_10.0.0.5_2026-01-01"))
        os.makedirs(os.path.join(reports, "engagement_2026-01-01"))

        def touch(*parts):
            path = os.path.join(*parts)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{}")

        touch(sessions, "auto_2026-01-01", "raw_report.json")
        touch(sessions, "not_an_engagement", "raw_report.json")
        touch(reports, "report_10.0.0.5_2026-01-01", "raw_audit.json")
        touch(reports, "report_10.0.0.5_2026-01-01", "client_report.pdf")
        touch(reports, "engagement_2026-01-01", "client_report.md")
        return sessions, reports

    def _index(self, sessions, reports):
        from unittest.mock import patch as _patch

        from phantom.utils.session_bundle import _report_index
        with _patch("phantom.utils.paths.reports_dir", lambda: reports):
            return _report_index(root=sessions)

    def test_a_manual_report_set_is_indexed(self):
        with tempfile.TemporaryDirectory() as tmp:
            sessions, reports = self._layout(tmp)
            entries = self._index(sessions, reports)
        dirs = {e["dir"] for e in entries}
        self.assertIn("auto_2026-01-01", dirs)
        self.assertIn("reports/report_10.0.0.5_2026-01-01", dirs)
        self.assertIn("reports/engagement_2026-01-01", dirs)

    def test_the_manual_entries_are_tagged_not_confusable_with_run_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            sessions, reports = self._layout(tmp)
            entries = self._index(sessions, reports)
        auto = [e for e in entries if e["dir"].startswith("auto_")]
        manual = [e for e in entries if e["dir"].startswith("reports/")]
        self.assertTrue(auto and manual)
        self.assertFalse(any(e["dir"].startswith("reports/") for e in auto))

    def test_only_report_files_are_indexed(self):
        with tempfile.TemporaryDirectory() as tmp:
            sessions, reports = self._layout(tmp)
            entries = self._index(sessions, reports)
        files = {e["file"] for e in entries}
        self.assertIn("raw_audit.json", files)
        self.assertNotIn("client_report.pdf", files)

    def test_an_unrelated_sessions_directory_is_not_indexed(self):
        with tempfile.TemporaryDirectory() as tmp:
            sessions, reports = self._layout(tmp)
            entries = self._index(sessions, reports)
        self.assertNotIn("not_an_engagement",
                         {e["dir"] for e in entries})

    def test_a_missing_reports_tree_still_indexes_the_run_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            sessions, reports = self._layout(tmp)
            import shutil
            shutil.rmtree(reports)
            entries = self._index(sessions, reports)
        self.assertEqual([e["dir"] for e in entries], ["auto_2026-01-01"])


class TestIdentityScope(unittest.TestCase):

    def _agent(self, target, ttype, scope):
        return AutonomousAgent(target=target, target_type=ttype, scope_list=scope)

    def test_identity_target_always_in_scope(self):
        agent = self._agent("mario.rossi@gmail.com", "email", ["10.0.0.0/8"])
        self.assertTrue(agent._scope_ok())

    def test_ip_in_scope(self):
        agent = self._agent("10.0.0.5", "ip", ["10.0.0.0/8"])
        self.assertTrue(agent._scope_ok())

    def test_ip_out_of_scope(self):
        agent = self._agent("203.0.113.9", "ip", ["10.0.0.0/8"])
        self.assertFalse(agent._scope_ok())

    def test_empty_scope_allows_all(self):
        agent = self._agent("203.0.113.9", "ip", [])
        self.assertTrue(agent._scope_ok())

    def test_expand_targets_keeps_identity_with_scope(self):
        from phantom.core.automode import _expand_targets
        out = _expand_targets(["mario.rossi@gmail.com"],
                              scope_list=["10.0.0.0/8"])
        self.assertIn("mario.rossi@gmail.com", out)

    def test_expand_targets_drops_out_of_scope_ip(self):
        from phantom.core.automode import _expand_targets
        out = _expand_targets(["203.0.113.9"], scope_list=["10.0.0.0/8"])
        self.assertNotIn("203.0.113.9", out)

    def test_expand_targets_keeps_in_scope_ip(self):
        from phantom.core.automode import _expand_targets
        out = _expand_targets(["10.0.0.7"], scope_list=["10.0.0.0/8"])
        self.assertIn("10.0.0.7", out)


class TestAutoCheckpoint(unittest.TestCase):

    def test_run_writes_checkpoint_when_state_path_given(self):
        from unittest.mock import Mock as _Mock
        from phantom.automation.agent import run_autonomous

        def runner(cmd, timeout=None):
            res = _Mock()
            res.ok = False
            res.stdout = ""
            res.stderr = ""
            return res

        with tempfile.TemporaryDirectory() as tmp:
            cp = os.path.join(tmp, "checkpoint.json")
            result = run_autonomous(
                target="10.0.0.1", target_type="ip", goal="beacon",
                max_iterations=3, state_path=cp,
                runner=runner,
                beacon_builder=lambda *a: "beacon-1")
            self.assertIsInstance(result, dict)
            self.assertTrue(os.path.exists(cp),
                            "checkpoint should be written each wave")


if __name__ == "__main__":
    unittest.main()
