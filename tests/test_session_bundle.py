"""Tests for portable .pm session bundles (export/import/handoff) and the
identity-target scope discipline."""
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
