"""Tests for the unattended resume policy (phantom/utils/auto_resume.py).

The property under test is not "resume works" but "resume cannot loop
forever, and never blocks waiting for a human": the crash budget is
persisted next to the checkpoint, a foreign checkpoint schema is refused
while nobody is watching, and no code path may call ``input()``.
"""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import phantom.utils.auto_resume as AR


def _checkpoint(tmp, name="checkpoint.json", schema=1, extra=None):
    """A minimal on-disk checkpoint in the shape the agent writes."""
    path = os.path.join(tmp, name)
    data = {"target": "10.0.0.5", "wm": {"findings": []}, "saved_at": 1.0}
    if schema is not None:
        data["schema"] = schema
    if extra:
        data.update(extra)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path


class TestResumePolicy(unittest.TestCase):

    def test_first_crash_resumes_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = _checkpoint(tmp)
            with patch.object(AR, "_expected_schema", lambda: (1, "")):
                d = AR.plan_resume(ckpt, max_restarts=3)
            self.assertTrue(d.ok, d.reason)
            self.assertEqual(d.attempt, 1)
            self.assertEqual(d.checkpoint, ckpt)
            # the budget is PERSISTED, not in-memory: a relaunched process
            # must see the previous attempt
            counter = os.path.join(tmp, AR._COUNTER_NAME)
            self.assertTrue(os.path.isfile(counter))
            with open(counter, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["restarts"], 1)

    def test_counter_past_max_refuses_with_the_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = _checkpoint(tmp)
            with patch.object(AR, "_expected_schema", lambda: (1, "")):
                for expected in (1, 2, 3):
                    d = AR.plan_resume(ckpt, max_restarts=3)
                    self.assertTrue(d.ok, d.reason)
                    self.assertEqual(d.attempt, expected)
                last = AR.plan_resume(ckpt, max_restarts=3)
            self.assertFalse(last.ok)
            self.assertEqual(last.attempt, 3)
            self.assertIn("3/3", last.reason)
            self.assertIn("relaunch by hand", last.reason)

    def test_restart_budget_is_per_directory(self):
        """Two engagements in two report dirs never share a budget: one
        spent budget must not block the other engagement."""
        with tempfile.TemporaryDirectory() as one, \
                tempfile.TemporaryDirectory() as two:
            a = _checkpoint(one, name="checkpoint.json")
            b = _checkpoint(two, name="checkpoint.json")
            with patch.object(AR, "_expected_schema", lambda: (1, "")):
                AR.plan_resume(a, max_restarts=1)
                a_spent = AR.plan_resume(a, max_restarts=1)
                first_b = AR.plan_resume(b, max_restarts=1)
            self.assertFalse(a_spent.ok)
            self.assertTrue(first_b.ok, first_b.reason)
            self.assertEqual(first_b.attempt, 1)

    def test_zero_budget_refuses_every_automatic_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = _checkpoint(tmp)
            with patch.object(AR, "_expected_schema", lambda: (1, "")):
                d = AR.plan_resume(ckpt, max_restarts=0)
            self.assertFalse(d.ok)
            self.assertIn("0/0", d.reason)

    def test_missing_checkpoint_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.json")
            d = AR.plan_resume(missing)
            self.assertFalse(d.ok)
            self.assertIn("not found", d.reason)
            self.assertEqual(d.attempt, 0)

    def test_empty_checkpoint_name_refuses_without_raising(self):
        d = AR.plan_resume("")
        self.assertFalse(d.ok)
        self.assertIn("no checkpoint", d.reason)
        d2 = AR.plan_resume(None)          # type: ignore[arg-type]
        self.assertFalse(d2.ok, "None must be a refusal, not a crash")

    def test_unreadable_checkpoint_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "garbage.json")
            with open(path, "wb") as fh:
                fh.write(b"not a checkpoint at all")
            d = AR.plan_resume(path)
            self.assertFalse(d.ok)
            self.assertIn("unreadable", d.reason)

    def test_non_object_checkpoint_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "list.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(["not", "a", "checkpoint"], fh)
            d = AR.plan_resume(path)
            self.assertFalse(d.ok)
            self.assertIn("not a JSON object", d.reason)

    def test_schema_mismatch_refuses_while_nobody_watches(self):
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = _checkpoint(tmp, schema=99)
            with patch.object(AR, "_expected_schema", lambda: (1, "")):
                d = AR.plan_resume(ckpt, max_restarts=3)
            self.assertFalse(d.ok)
            self.assertIn("99", d.reason)
            self.assertIn("relaunch by hand", d.reason)
            # a refused schema must NOT spend restart budget
            self.assertFalse(
                os.path.isfile(os.path.join(tmp, AR._COUNTER_NAME)))

    def test_missing_schema_field_is_a_mismatch(self):
        """`from_state` warns and resumes best-effort; unattended there is
        nobody to warn, so the policy refuses."""
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = _checkpoint(tmp, schema=None)
            with patch.object(AR, "_expected_schema", lambda: (1, "")):
                d = AR.plan_resume(ckpt)
            self.assertFalse(d.ok)
            self.assertIn("schema", d.reason)

    def test_unavailable_schema_gate_degrades_to_a_noted_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = _checkpoint(tmp)
            with patch.object(AR, "_expected_schema",
                              lambda: (-1, "schema gate unavailable (X)")):
                d = AR.plan_resume(ckpt)
            self.assertTrue(d.ok, d.reason)
            self.assertIn("best-effort", d.reason)

    def test_note_success_resets_the_counter(self):
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = _checkpoint(tmp)
            counter = AR.counter_path_for(ckpt)
            with patch.object(AR, "_expected_schema", lambda: (1, "")):
                AR.plan_resume(ckpt, max_restarts=1)
                spent = AR.plan_resume(ckpt, max_restarts=1)
            self.assertFalse(spent.ok)
            AR.note_success(counter)
            with patch.object(AR, "_expected_schema", lambda: (1, "")):
                after = AR.plan_resume(ckpt, max_restarts=1)
            self.assertTrue(after.ok, after.reason)
            self.assertEqual(after.attempt, 1)

    def test_note_success_without_a_path_is_a_no_op(self):
        AR.note_success("")            # must not raise

    def test_counter_path_prefers_state_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = _checkpoint(tmp, name="checkpoint.json")
            state_dir = os.path.join(tmp, "run")
            os.makedirs(state_dir)
            state = os.path.join(state_dir, "checkpoint.json")
            self.assertEqual(AR.counter_path_for(ckpt, state),
                             os.path.join(state_dir, AR._COUNTER_NAME))

    def test_corrupt_counter_is_treated_as_a_clean_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = _checkpoint(tmp)
            with open(os.path.join(tmp, AR._COUNTER_NAME), "wb") as fh:
                fh.write(b"{ not json")
            with patch.object(AR, "_expected_schema", lambda: (1, "")):
                d = AR.plan_resume(ckpt, max_restarts=1)
            self.assertTrue(d.ok, d.reason)

    def test_never_calls_input(self):
        """The whole point: a resume decision must not need a terminal."""
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = _checkpoint(tmp)
            with patch("builtins.input",
                       side_effect=AssertionError("input() was called")):
                with patch.object(AR, "_expected_schema", lambda: (1, "")):
                    self.assertTrue(AR.plan_resume(ckpt).ok)
                    self.assertFalse(AR.plan_resume("").ok)
                    AR.note_success(AR.counter_path_for(ckpt))

    def test_decision_is_serialisable_for_the_event_stream(self):
        """The caller emits the decision on the run stream; it must not
        require a custom encoder."""
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = _checkpoint(tmp)
            with patch.object(AR, "_expected_schema", lambda: (1, "")):
                d = AR.plan_resume(ckpt)
            blob = json.dumps(d.__dict__)
            self.assertIn("checkpoint", blob)


if __name__ == "__main__":          # pragma: no cover
    unittest.main()
