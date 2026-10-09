"""Section B3 — a handoff must EXPIRE.

`Handoff` has had an `expired` state since the record was introduced and
nothing ever set it (`electron/src/store/index.ts` declares the union, no code
assigns the value): a beacon handed over yesterday is still `ready` today, and
`handoff` in the AutoShell keeps offering a C2 context that may not exist any
more. This is the policy half — the criterion, the window, and the two ways a
handoff goes stale — plus the CLI contract it has to feed.

`auto_shell.py` is no longer out of perimeter: the wiring has landed, so the
CLI contracts originally pinned as `xfail(strict=True)` now run as ordinary
tests — the shell no longer offers an expired handoff, `run` is not an alias
of the whole chain, and the scope flags are reachable from the REPL.
"""
import io
import time
from unittest import mock

import pytest
from rich.console import Console

from phantom.core import auto_shell
from phantom.core.auto_shell import AutoShell
from phantom.utils import handoff_ttl as ttl

NOW = 1_800_000_000.0          # a fixed clock: no test depends on wall time


def _record(**over):
    record = {"beacon_id": "b-1", "kind": "beacon_established",
              "target": "10.0.0.9", "created_at": NOW - 30}
    record.update(over)
    return record


class _Captured:
    """A console stand-in that renders to text.

    The earlier shim read ``Table.rows`` and iterated each row's cells; the
    installed rich version keeps the cells on the Table, not the Row, so that
    iteration raised ``TypeError`` and the test never verified what it claimed
    to. Rendering through a real Console is what the operator actually sees.
    """

    def __init__(self):
        self._buf = io.StringIO()
        self._console = Console(file=self._buf, width=200,
                                force_terminal=False, no_color=True)

    def print(self, *args, **_kw):
        for arg in args:
            self._console.print(arg)

    @property
    def text(self):
        return self._buf.getvalue()


class TestTheWindow:
    def test_the_default_is_an_hour(self):
        assert ttl.ttl_minutes({}) == 60
        assert ttl.ttl_seconds({}) == 3600

    def test_the_engagement_can_state_its_own_window(self):
        assert ttl.ttl_minutes({"PHANTOM_HANDOFF_TTL_MINUTES": "5"}) == 5.0

    @pytest.mark.parametrize("value", ["", "abc", "0", "-3", "  "])
    def test_a_bad_window_falls_back_instead_of_disabling_the_policy(
            self, value):
        assert ttl.ttl_minutes({"PHANTOM_HANDOFF_TTL_MINUTES": value}) == 60


class TestTheAgeCriterion:
    def test_a_fresh_handoff_is_offerable(self):
        assert ttl.expiry_reason(_record(), now=NOW) is None
        assert not ttl.is_expired(_record(), now=NOW)

    def test_an_old_handoff_says_how_old_it_is(self):
        reason = ttl.expiry_reason(_record(created_at=NOW - 2 * 3600), now=NOW)
        assert reason and "120 minute(s) old" in reason
        assert "limit 60" in reason

    def test_exactly_at_the_limit_it_is_still_offerable(self):
        # the comparison is `>`, so the boundary belongs to the operator
        assert ttl.expiry_reason(_record(created_at=NOW - 3600), now=NOW) is None

    def test_the_rule_is_dateable_from_either_shape(self):
        # server.py records use `created_at`; the shell's own events use `at`
        assert ttl.expiry_reason(_record(at=NOW - 10), now=NOW) is None
        assert ttl.expiry_reason(_record(created_at=None, at=NOW - 7200),
                                 now=NOW)

    def test_milliseconds_are_understood(self):
        # the UI stores JS timestamps (Date.now()), i.e. milliseconds
        record = _record(created_at=(NOW - 30) * 1000)
        assert ttl.expiry_reason(record, now=NOW) is None

    def test_an_iso_timestamp_is_understood(self):
        from datetime import datetime, timezone
        stamp = datetime.fromtimestamp(NOW - 30, tz=timezone.utc).isoformat()
        assert ttl.expiry_reason(_record(created_at=stamp), now=NOW) is None
        old = datetime.fromtimestamp(NOW - 4 * 3600,
                                     tz=timezone.utc).isoformat()
        assert ttl.is_expired(_record(created_at=old), now=NOW)

    def test_an_undateable_handoff_is_not_offered(self):
        # fail closed, like TypedTask.is_expired on an unparsable deadline
        reason = ttl.expiry_reason(_record(created_at="not a date"), now=NOW)
        assert reason and "no readable timestamp" in reason

    def test_a_record_with_no_time_at_all_is_not_offered(self):
        record = {"beacon_id": "b-1", "kind": "beacon_established"}
        assert ttl.is_expired(record, now=NOW)


class TestTheLivenessCriterion:
    def _beacons(self, *entries):
        return list(entries)

    def test_a_beacon_the_c2_does_not_know_is_expired(self):
        reason = ttl.expiry_reason(_record(), beacons=self._beacons(
            {"id": "other"}), now=NOW)
        assert reason and "no longer known to the C2" in reason

    def test_a_beacon_that_stopped_checking_in_is_expired(self):
        reason = ttl.expiry_reason(
            _record(), beacons=self._beacons(
                {"id": "b-1", "last_seen": NOW - 4 * 3600}), now=NOW)
        assert reason and "has not checked in for 240 minute(s)" in reason

    def test_a_live_beacon_does_not_expire_a_fresh_handoff(self):
        assert ttl.expiry_reason(
            _record(), beacons=self._beacons(
                {"id": "b-1", "last_seen": NOW - 5}), now=NOW) is None

    def test_a_beacon_without_last_seen_counts_as_alive(self):
        assert ttl.expiry_reason(
            _record(), beacons=self._beacons({"id": "b-1"}), now=NOW) is None

    def test_without_a_beacon_list_only_the_age_applies(self):
        # the CLI may not have the C2 running: the liveness check simply
        # does not run, it does not fail the handoff
        assert ttl.expiry_reason(_record(), beacons=None, now=NOW) is None

    def test_liveness_is_reported_before_age(self):
        # the reason an operator reads first must be the one that survives a
        # re-run: a beacon that is gone, not a number of minutes
        reason = ttl.expiry_reason(
            _record(created_at=NOW - 5 * 3600),
            beacons=self._beacons({"id": "other"}), now=NOW)
        assert reason and "no longer known to the C2" in reason


class TestThePolicyInOneCall:
    def test_partition_keeps_the_reason_with_the_record(self):
        fresh = _record(beacon_id="b-new")
        old = _record(beacon_id="b-old", created_at=NOW - 5 * 3600)
        offerable, expired = ttl.partition([fresh, old], now=NOW)
        assert [r["beacon_id"] for r in offerable] == ["b-new"]
        assert [r["beacon_id"] for r, _ in expired] == ["b-old"]
        assert "minute(s) old" in expired[0][1]

    def test_an_empty_list_is_not_an_error(self):
        assert ttl.partition([], now=NOW) == ([], [])
        assert ttl.partition(None, now=NOW) == ([], [])

    def test_the_operator_line_says_what_to_do(self):
        line = ttl.describe("handoff is 120 minute(s) old (limit 60)")
        assert "launch" in line and "60" in line


class TestTheShellsOwnEventShape:
    """The events the AutoShell collects are what the policy has to read."""

    def _shell(self, events):
        shell = AutoShell()
        shell.events = {"10.0.0.9": events}
        return shell

    def _event(self, ago, bid=None):
        return {"kind": "handoff", "at": time.time() - ago,
                "beacon_id": bid or ("b-old" if ago > 3600 else "b-new")}

    def test_the_events_carry_what_the_policy_needs(self):
        shell = self._shell([self._event(30)])
        records = [ev for evs in shell.events.values() for ev in evs
                   if ev.get("kind") == "handoff"]
        assert ttl.expiry_reason(records[0]) is None

    def test_the_policy_expires_the_old_event(self):
        shell = self._shell([self._event(5 * 3600)])
        records = [ev for evs in shell.events.values() for ev in evs
                   if ev.get("kind") == "handoff"]
        assert ttl.is_expired(records[0])

    def test_the_cli_stops_offering_an_expired_handoff(self, monkeypatch):
        # a positive control in the same run: the FRESH handoff must still be
        # offered, or the test would pass on a shell that offers nothing
        shell = self._shell([self._event(5 * 3600), self._event(30,
                                                               bid="b-new")])
        captured = _Captured()
        monkeypatch.setattr(auto_shell, "console", captured)
        shell.do_handoff("list")
        listed = captured.text
        # "offered" is the offer ACTION (the `handoff take <id>` row): a
        # dropped handoff may still be NAMED in the "not offered" notice —
        # that is the point, the drop is not silent — but the offer must not
        # be there.
        assert "handoff take b-new" in listed, (
            f"the fresh handoff was not offered: {listed!r}")
        assert "handoff take b-old" not in listed, (
            f"the expired handoff is still offered: {listed!r}")
        assert "not offered" in listed, (
            f"the drop was silent: {listed!r}")


class TestTheDocumentedGaps:
    """The other two Section B defects, pinned as the intended end state."""

    def test_the_two_shells_means_different_things_by_run(self):
        # This is the divergence that makes the alias a trap, and it is the
        # part that is true today: MANUAL `run` executes one module, AUTO
        # `run` launches the whole chain.
        from phantom.core.shell import PhantomShell
        assert PhantomShell.do_run is not AutoShell.do_launch

    def test_run_is_not_an_alias_of_the_whole_chain(self):
        assert AutoShell.do_run is not AutoShell.do_launch

    def test_the_scope_changing_flags_are_reachable_from_the_repl(self):
        shell = AutoShell()
        # `force_network` widens a CIDR to a full engagement and `engine`
        # picks swarm vs agent: both change what the run IS.
        assert "force_network" in shell.flags
        assert "engine" in shell.flags
        kwargs = shell._run_kwargs()
        assert kwargs["force_network"] is False
        assert kwargs["engine"]

    def test_the_help_row_of_review_matches_what_review_does(self,
                                                             monkeypatch):
        shell = AutoShell()
        captured = _Captured()
        monkeypatch.setattr(auto_shell, "console", captured)
        shell.do_help("")
        # do_review prints the evolution / self-improvement status; the help
        # must describe THAT, not the launch approval gate it never was.
        assert "self-improvement" in AutoShell.do_review.__doc__
        rows = [ln for ln in captured.text.splitlines()
                if " review " in ln.lower()]
        assert rows, f"no help row for review: {captured.text!r}"
        assert "self-improvement" in rows[0].lower()
