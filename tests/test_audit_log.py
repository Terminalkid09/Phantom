"""Tests for the HMAC-authenticated hash-chained audit log."""
import hashlib
import json
import os

import pytest

from phantom.utils.audit_log import AuditLog, _body, _canonical


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


def test_each_record_is_hmac_signed(log):
    record = log.append("task_queued", beacon_id="b1")
    assert record["hmac"]
    assert os.path.exists(log.path + ".key")
    assert os.path.exists(log.path + ".head")
    assert log.verify() == (True, 1, None)


def test_mac_tampering_detected(log):
    """A re-hashed record is still rejected: the HMAC is the boundary."""
    log.append("e1")
    log.append("e2")
    lines = open(log.path, encoding="utf-8").read().splitlines()
    rec = json.loads(lines[1])
    rec["event"] = "forged"
    rec["hash"] = hashlib.sha256(
        _canonical(_body(rec)).encode("utf-8")).hexdigest()
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    with open(log.path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    ok, count, bad = log.verify()
    assert ok is False
    assert count == 2
    assert bad is not None


def test_tail_truncation_detected_by_signed_head(log):
    log.append("e1")
    log.append("e2")
    log.append("e3")
    lines = open(log.path, encoding="utf-8").read().splitlines()
    with open(log.path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines[:-1]) + "\n")
    ok, count, bad = log.verify()
    assert ok is False
    assert bad is not None


def test_legacy_hash_only_log_is_sealed(log):
    record = {
        "seq": 1,
        "ts": "2026-01-01T00:00:00Z",
        "event": "beacon_registered",
        "beacon_id": "b1",
        "prev": "0" * 64,
    }
    record["hash"] = hashlib.sha256(
        _canonical(_body(record)).encode("utf-8")).hexdigest()
    with open(log.path, "w", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    ok, count, bad = log.verify()
    assert ok is True and count == 1 and bad is None
    sealed = log.tail(1)[0]
    assert sealed["hmac"]
    assert os.path.exists(log.path + ".head")


def test_losing_the_key_invalidates_the_chain(log):
    log.append("e1")
    os.replace(log.path + ".key", log.path + ".key.old")
    rotated = AuditLog(path=log.path)
    ok, count, bad = rotated.verify()
    assert ok is False
    assert count == 1
    assert bad is not None
