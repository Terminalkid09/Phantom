"""The .pm lifecycle: an engagement that is opened, closed, pruned, shared.

Four defects this file pins down, each of which lost data silently:

* `index.json` was written in place — two shells opening at once (Electron +
  terminal) could truncate it, and the next open replaced the broken file with
  `[]`, erasing the whole history with no trace;
* the index grew forever and nothing recorded that an engagement had CLOSED,
  so a crash and a clean exit looked identical;
* dated `auto_*.pm` copies were never pruned;
* an unserialisable payload was written anyway, producing a bundle that
  restores a session that looks complete and is not.
"""
import json
import os

import pytest

import phantom.utils.auto_session as AS
import phantom.utils.session_bundle as SB
from phantom.core.session import session


@pytest.fixture
def store(tmp_path, monkeypatch):
    """An isolated sessions dir: no real checkpoints, no real C2 state."""
    monkeypatch.setattr(AS, "_root", lambda: str(tmp_path))
    monkeypatch.setattr(SB, "latest_checkpoint", lambda *a, **k: None)
    monkeypatch.setattr(SB, "_c2_payload", lambda: {})
    yield tmp_path


@pytest.fixture
def sess():
    """Restore the global session after the test (import mutates it)."""
    saved = {k: getattr(session, k, None) for k in
             ("target", "notes", "scope", "results", "knowledge_base")}
    saved["knowledge_base"] = json.loads(json.dumps(
        getattr(session, "knowledge_base", {}) or {}))
    yield session
    for key, value in saved.items():
        setattr(session, key, value)


def _export(store, name, **kw):
    return SB.export_session(out_path=str(store / name), **kw)


class TestIndexIsDurable:
    def test_double_registration_is_one_row(self, store):
        AS.register_open()
        AS.register_open()
        rows = json.loads((store / "index.json").read_text(encoding="utf-8"))
        assert len(rows) == 1
        assert rows[0]["engagement_id"] == SB._engagement_id()

    def test_corrupt_index_is_preserved_not_overwritten(self, store):
        (store / "index.json").write_text('{"half": ', encoding="utf-8")
        AS.register_open()

        aside = list(store.glob("index.json.corrupt-*"))
        assert len(aside) == 1, "the unreadable index must survive somewhere"
        assert aside[0].read_text(encoding="utf-8") == '{"half": '

        rows = json.loads((store / "index.json").read_text(encoding="utf-8"))
        assert len(rows) == 1
        assert not list(store.glob("index.json.tmp")), "temp file left behind"

    def test_non_list_index_is_quarantined(self, store):
        (store / "index.json").write_text('"nope"', encoding="utf-8")
        AS.register_open()
        assert list(store.glob("index.json.corrupt-*"))
        assert len(json.loads((store / "index.json").read_text())) == 1


class TestCloseStamping:
    def test_close_writes_closed_at_after_both_bundles(self, store, sess):
        sess.target = "10.0.0.9"
        sess.notes = ["a note"]
        AS.register_open()

        latest = AS.auto_export()

        assert latest and os.path.isfile(latest)
        assert os.path.isfile(store / AS._LATEST)
        assert list(store.glob("auto_*.pm")), "dated copy missing"
        rows = json.loads((store / "index.json").read_text(encoding="utf-8"))
        assert rows[-1].get("closed_at"), "a closed engagement must say so"
        assert rows[-1].get("engagement_id") == SB._engagement_id()

    def test_empty_engagement_is_not_exported(self, store, sess, monkeypatch):
        class _EmptyWM:
            def all_findings(self):
                return []

        monkeypatch.setattr("phantom.core.knowledge.session_wm",
                            lambda: _EmptyWM())
        sess.target = ""
        sess.notes = []
        sess.results = {}
        assert AS.auto_export() is None
        assert not os.path.isfile(store / AS._LATEST)


class TestRetention:
    def _dated(self, store, index, mtime):
        path = store / f"auto_2020-01-01_{index}.pm"
        SB.export_session(out_path=str(path))
        os.utime(path, (mtime, mtime))
        return path

    def test_keeps_newest_copies_and_latest(self, store, sess):
        sess.target = "t"
        SB.export_session(out_path=str(store / AS._LATEST), checkpoint=str(
            store / "missing.json"))
        made = [self._dated(store, i, 1_000_000 + i) for i in range(1, 24)]

        removed = AS._prune_dated()

        left = sorted((store / ("auto_2020-01-01_%d.pm" % i)).name
                      for i in range(1, 24)
                      if (store / ("auto_2020-01-01_%d.pm" % i)).is_file())
        assert len(left) == AS.AUTO_KEEP
        assert removed, "pruning must report what it deleted"
        # the three OLDEST are the ones that go
        assert not made[0].is_file() and not made[1].is_file()
        assert made[-1].is_file()
        assert (store / AS._LATEST).is_file(), "latest.pm is never a candidate"

    def test_never_deletes_what_it_cannot_read(self, store):
        for i in range(1, 23):
            self._dated(store, i, 1_000_000 + i)
        unreadable = store / "auto_2020-01-01_0.pm"
        unreadable.write_bytes(b"\x1f\x8bnotgzip")
        os.utime(unreadable, (1_000_000, 1_000_000))

        AS._prune_dated()

        assert unreadable.is_file(), (
            "a corrupt bundle is the operator's only copy of that engagement")


class TestImportRestoresC2Intel:
    def test_round_trip_carries_findings_and_beacon_count(self, store, sess):
        sess.target = "lab.local"
        sess.scope = ["lab.local"]
        sess.knowledge_base = {}
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(SB, "_c2_payload", lambda: {
                "beacons": {"b1": {"host": "10.0.0.5"}},
                "tasks": {"b1": [{"id": "t1"}]},
                "results": {"b1": [{"stdout": "x"}]},
                "listener": {"host": "1.2.3.4", "port": 443, "ssl": True}})
            path = _export(store, "handoff.pm", checkpoint=str(
                store / "missing.json"))
            data = SB.import_session(path)

        assert data["target"] == "lab.local"
        assert data["beacons_imported"] == 1
        assert data["c2_intel"]["beacons"] == 1
        assert data["c2_intel"]["tasks"] == 1
        assert data["c2_intel"]["results"] == 1
        assert session.knowledge_base["c2_intel"]["listener"]["port"] == 443


class TestExportRefusesHalfAnEngagement:
    def test_unserialisable_payload_names_the_field(self, store, monkeypatch):
        cyclic = {}
        cyclic["self"] = cyclic
        monkeypatch.setattr(SB, "_session_payload",
                            lambda: {"target": "t", "weird": cyclic})

        target = str(store / "bad.pm")
        with pytest.raises(ValueError) as excinfo:
            SB.export_session(out_path=target, checkpoint=str(
                store / "missing.json"))

        # the top-level field that CONTAINS the bad value is the one named
        assert "'session'" in str(excinfo.value), (
            "the failing field must be named")
        assert not os.path.isfile(target), "nothing may be written"

    def test_write_blockers_lists_each_bad_field(self):
        cyclic = {}
        cyclic["self"] = cyclic
        blockers = SB._write_blockers({"ok": 1, "bad": cyclic})
        assert len(blockers) == 1
        assert blockers[0].startswith("'bad'")
        assert SB._write_blockers({"ok": 1}) == []


class TestTheIndexDoesNotLeakTheTarget:
    """The `.pm` is encrypted; the bookkeeping around it used to not be.

    `engagement_id` was `<target>|<started>` and it is written to
    `data/sessions/index.json` (plaintext) — a readable list of client
    hostnames next to timestamps, while the bundle itself was AES-GCM.
    """

    def test_the_engagement_id_does_not_contain_the_target(self, store, sess):
        sess.target = "cristian.homenet.telecomitalia.it"
        eid = SB._engagement_id()
        assert "cristian" not in eid and "telecomitalia" not in eid
        assert eid.endswith("|" + (getattr(sess, "engagement_started", "") or ""))

    def test_the_index_file_is_not_searchable_for_the_target(self, store, sess):
        sess.target = "192.168.1.18"
        AS.register_open()
        raw = (store / "index.json").read_text(encoding="utf-8")
        assert "192.168.1.18" not in raw

    def test_two_targets_still_get_different_ids(self, store, sess):
        seen = set()
        for target in ("10.0.0.5", "10.0.0.6"):
            sess.target = target
            seen.add(SB._engagement_id())
        assert len(seen) == 2
