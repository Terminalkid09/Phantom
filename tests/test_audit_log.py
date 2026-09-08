"""Tests for the immutable hash-chained audit log + .pm C2 intel export."""
import json

import pytest

from phantom.utils.audit_log import AuditLog


@pytest.fixture
def log(tmp_path):
    return AuditLog(path=str(tmp_path / "audit.log"))


def test_append_creates_chain(log):
    log.append("beacon_registered", beacon_id="b1", ip="10.0.0.9")
    log.append("task_queued", beacon_id="b1", task_id="t1", command="whoami")
    ok, count, bad = log.verify()
    assert ok is True
    assert count == 2
    assert bad is None


def test_tampering_detected(log):
    log.append("task_queued", beacon_id="b1", command="whoami")
    log.append("task_queued", beacon_id="b1", command="cat /etc/shadow")
    # rewrite the second record's command (in-place tamper)
    lines = open(log.path, encoding="utf-8").read().splitlines()
    rec = json.loads(lines[1])
    rec["command"] = "rm -rf /"
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    with open(log.path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    ok, count, bad = log.verify()
    assert ok is False
    assert bad is not None


def test_deletion_detected(log):
    log.append("e1", x=1)
    log.append("e2", x=2)
    log.append("e3", x=3)
    lines = open(log.path, encoding="utf-8").read().splitlines()
    del lines[1]  # remove middle record: seq + prev chain break
    with open(log.path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    ok, count, bad = log.verify()
    assert ok is False


def test_tail(log):
    for i in range(30):
        log.append("evt", i=i)
    tail = log.tail(5)
    assert len(tail) == 5
    assert tail[-1]["i"] == 29
    assert [r["seq"] for r in tail] == [26, 27, 28, 29, 30]


def test_empty_log(log):
    ok, count, bad = log.verify()
    assert ok is True and count == 0


def test_corrupt_line_flagged(log):
    log.append("e1")
    with open(log.path, "a", encoding="utf-8") as f:
        f.write("NOT JSON AT ALL\n")
    ok, count, bad = log.verify()
    assert ok is False and "_corrupt" in bad
