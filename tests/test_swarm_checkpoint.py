"""Tests: the swarm checkpoint (phantom/automation/swarm/checkpoint.py).

What is being pinned here is the property that makes a MULTI-DAY swarm
operation survivable: the board and the DAG state come back from disk, a
task whose facts are already committed is never re-run (no budget re-spent
to rediscover a known fact), the per-target allowance is preserved, and a
checkpoint written by another schema is REFUSED instead of interpreted.

Everything is offline: no runner ever reaches the network. Where a run is
exercised, the board is pre-seeded so nothing needs to execute.
"""

import json
import os
import tempfile
import threading
import unittest

from phantom.automation.swarm import Board, build_tasks, run_swarm
from phantom.automation.swarm.checkpoint import (
    SWARM_CHECKPOINT_SCHEMA,
    CheckpointSchemaError,
    load_swarm_checkpoint,
    save_swarm_checkpoint,
)
from phantom.automation.swarm.idempotency import IdempotencyRegistry


def _service_staged():
    return {"kind": "service", "key": "tcp:22",
            "value": {"service": "ssh", "port": 22}, "confidence": 0.9,
            "source": "seed"}


def _creds_staged():
    return {"kind": "creds", "key": "creds:root",
            "value": {"user": "root", "password": "x", "valid": True},
            "confidence": 0.9, "source": "seed"}


def _satisfied_board(target="10.0.0.5"):
    """A board where the whole `creds` chain is already delivered."""
    board = Board([target])
    board.commit("seed", target, [_service_staged(), _creds_staged()])
    return board


def _boom(cmd, timeout=None):
    """A runner that must never be reached (resume re-ran a task)."""
    raise AssertionError("a satisfied task was re-run on resume")


class TestBoardRoundTrip(unittest.TestCase):
    def test_findings_revisions_hypotheses_and_budgets_survive(self):
        board = Board(["10.0.0.5", "10.0.0.6"])
        # a weaker observation first, then a stronger one for the SAME
        # (kind, key): the merge revises the belief instead of overwriting it
        board.commit("t1", "10.0.0.5", [dict(_service_staged(),
                                             confidence=0.4)])
        board.commit("t2", "10.0.0.5", [dict(_service_staged(),
                                             confidence=0.95)])
        board.commit("t3", "10.0.0.6", [_creds_staged()])
        wm5 = board.worldmodel("10.0.0.5")
        wm5.add_hypothesis("ssh_login", "found ssh", cost=0.4, priority=0.8)
        board.budgets.set_limit("10.0.0.5", max_actions=10, max_noise=2.5)
        board.budgets.spend("10.0.0.5", actions=4, noise=1.0)

        restored = Board.from_dict(board.to_dict())

        self.assertEqual(sorted(restored.targets()),
                         sorted(board.targets()))
        before = wm5.to_dict()
        after = restored.worldmodel("10.0.0.5").to_dict()
        self.assertEqual([f["key"] for f in before["findings"]],
                         [f["key"] for f in after["findings"]])
        self.assertEqual(before["findings"][0]["confidence"],
                         after["findings"][0]["confidence"])
        # belief revision is not decoration: a resumed run must still know
        # which beliefs were contested
        self.assertEqual(before["revisions"], after["revisions"])
        self.assertEqual(len(before["hypotheses"]), len(after["hypotheses"]))
        self.assertEqual(before["hypotheses"][0]["capability_id"],
                         after["hypotheses"][0]["capability_id"])
        # the other target's facts came back too, unchanged
        self.assertTrue(restored.has("10.0.0.6", "creds"))

    def test_budget_allowance_is_preserved_not_reset(self):
        board = Board(["10.0.0.5"])
        board.budgets.set_limit("10.0.0.5", max_actions=10)
        board.budgets.spend("10.0.0.5", actions=4)

        restored = Board.from_dict(board.to_dict())

        self.assertEqual(restored.budgets.remaining("10.0.0.5")["actions"], 6)
        self.assertFalse(restored.budgets.exhausted("10.0.0.5"))

    def test_restored_board_has_a_free_lease_table(self):
        """A lease is ownership of an IN-FLIGHT run with a monotonic TTL:
        it must not come back, or a dead owner would wedge a task."""
        board = Board(["10.0.0.5"])
        board.leases.claim("creds-1", "10.0.0.5", "old-owner")

        restored = Board.from_dict(board.to_dict())

        self.assertIsNone(restored.leases.owner_of("creds-1", "10.0.0.5"))
        self.assertTrue(restored.leases.claim("creds-1", "10.0.0.5",
                                              "fresh-owner"))

    def test_counters_survive(self):
        board = Board(["10.0.0.5"])
        board.commit("t1", "10.0.0.5", [_service_staged()])
        board.commit("t1", "10.0.0.5", [_service_staged()])
        restored = Board.from_dict(board.to_dict())
        self.assertEqual(restored.added, board.added)
        self.assertEqual(restored.skipped, board.skipped)
        self.assertGreater(restored.added, 0)
        self.assertGreater(restored.skipped, 0)


class TestCheckpointFile(unittest.TestCase):
    def test_board_tasks_sink_and_idempotency_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "nested", "swarm.json")
            board = _satisfied_board()
            tasks = build_tasks("creds", ["10.0.0.5"], seed=7)
            tasks[0].status = "done"
            tasks[0].done_targets.add("10.0.0.5")
            tasks[1].status = "failed"
            tasks[1].failure_kind = "task"
            tasks[1].attempts = 2
            tasks[1].profile = "stealth_first"
            tasks[1].helper_used = True
            tasks[1].note = "requeue profile=evidence_first"
            tasks[1].tried[("creds-1", "10.0.0.5")] = ["web_creds", "ssh_login"]
            sink = {"failures": [{"task": "creds-1", "kind": "agent"}],
                    "cases": [{"technique": "ssh_login"}],
                    "actions": 7,
                    "tried": {("creds-1", "10.0.0.5"): {"web_creds"}},
                    "lock": threading.Lock()}
            idem = IdempotencyRegistry()
            idem.begin(IdempotencyRegistry.key_for("creds-1", "10.0.0.5"))
            idem.complete(IdempotencyRegistry.key_for("creds-1", "10.0.0.5"))

            written = save_swarm_checkpoint(path, board, tasks, sink=sink,
                                            idempotency=idem)
            self.assertEqual(written, path)
            with open(path, encoding="utf-8") as fh:
                raw = json.load(fh)
            self.assertEqual(raw["schema"], SWARM_CHECKPOINT_SCHEMA)

            loaded = load_swarm_checkpoint(path)

        self.assertEqual(loaded["schema"], SWARM_CHECKPOINT_SCHEMA)
        self.assertTrue(loaded["board"].has("10.0.0.5", "creds"))
        out = loaded["tasks"]
        self.assertEqual(len(out), len(tasks))
        self.assertEqual(out[0].status, "done")
        self.assertEqual(out[0].done_targets, {"10.0.0.5"})
        self.assertEqual(out[1].status, "failed")
        self.assertEqual(out[1].failure_kind, "task")
        self.assertEqual(out[1].attempts, 2)
        self.assertEqual(out[1].profile, "stealth_first")
        self.assertTrue(out[1].helper_used)
        self.assertEqual(out[1].note, "requeue profile=evidence_first")
        # the tried keys must come back as TUPLES: the dispatcher looks
        # them up by (task_id, target), a plain string would never match
        self.assertEqual(out[1].tried[("creds-1", "10.0.0.5")],
                         ["web_creds", "ssh_login"])
        # DAG identity is preserved, not rebuilt from the chain template
        self.assertEqual(out[1].needs, tasks[1].needs)
        self.assertEqual(out[1].provides, tasks[1].provides)
        self.assertEqual(out[1].seed, tasks[1].seed)

        self.assertEqual(loaded["sink"]["actions"], 7)
        self.assertEqual(len(loaded["sink"]["failures"]), 1)
        self.assertEqual(len(loaded["sink"]["cases"]), 1)
        self.assertEqual(loaded["sink"]["tried"][("creds-1", "10.0.0.5")],
                         {"web_creds"})
        # the lock is execution-only state: it must not be serialized, and
        # it must exist again on the restored sink
        self.assertNotIn("lock", raw["sink"])
        self.assertIsInstance(loaded["sink"]["lock"], type(threading.Lock()))
        # a completed unit stays completed: begin() refuses a re-run
        key = IdempotencyRegistry.key_for("creds-1", "10.0.0.5")
        self.assertTrue(loaded["idempotency"].completed(key))
        self.assertFalse(loaded["idempotency"].begin(key))

    def test_schema_mismatch_is_refused_not_interpreted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "other.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"schema": SWARM_CHECKPOINT_SCHEMA + 999,
                           "board": {"targets": [], "wms": {}}}, fh)
            with self.assertRaises(CheckpointSchemaError) as ctx:
                load_swarm_checkpoint(path)
        self.assertIn("schema", str(ctx.exception).lower())


class TestResumeSemantics(unittest.TestCase):
    def test_resume_marks_satisfied_tasks_done_and_runs_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = save_swarm_checkpoint(
                os.path.join(tmp, "sw.json"), _satisfied_board(),
                build_tasks("creds", ["10.0.0.5"]),
                sink={"failures": [], "cases": [], "actions": 0})
            # the caller passes NO targets: a resumed run knows its own
            summary = run_swarm([], resume=path, runner=_boom,
                                drain_timeout=5.0)

        self.assertEqual([t["status"] for t in summary["tasks"]],
                         ["done"] * len(summary["tasks"]))
        self.assertTrue(all("resumed" in t["note"]
                            for t in summary["tasks"]))

    def test_run_swarm_writes_a_checkpoint_when_asked(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = save_swarm_checkpoint(
                os.path.join(tmp, "base.json"), _satisfied_board(),
                build_tasks("creds", ["10.0.0.5"]),
                sink={"failures": [], "cases": [], "actions": 0})
            out = os.path.join(tmp, "out.json")
            run_swarm([], resume=base, checkpoint_path=out, runner=_boom,
                      drain_timeout=5.0)
            self.assertTrue(os.path.exists(out))
            with open(out, encoding="utf-8") as fh:
                data = json.load(fh)

        self.assertEqual(data["schema"], SWARM_CHECKPOINT_SCHEMA)
        self.assertIn("10.0.0.5", data["board"]["wms"])
        self.assertTrue(data["board"]["wms"]["10.0.0.5"]["findings"])
        self.assertTrue(all(t["status"] == "done" for t in data["tasks"]))
        # and the file it wrote is itself loadable
        with tempfile.TemporaryDirectory() as tmp2:
            with open(os.path.join(tmp2, "x.json"), "w") as fh:
                json.dump(data, fh)
            reloaded = load_swarm_checkpoint(os.path.join(tmp2, "x.json"))
        self.assertTrue(reloaded["board"].has("10.0.0.5", "service"))

    def test_the_new_keywords_default_to_the_old_behaviour(self):
        import inspect
        params = inspect.signature(run_swarm).parameters
        self.assertEqual(params["resume"].default, "")
        self.assertEqual(params["checkpoint_path"].default, "")


if __name__ == "__main__":
    unittest.main()
