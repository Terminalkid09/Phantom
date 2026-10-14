"""The C2 handoff must WAIT for the beacon, not race its registration.

The audit's requirement 6 (auto-mode establishes the beacon, brings the
listener up and hands the operator a shell already pointed at that beacon) is
satisfied — but only because the AGENT blocks on ``_await_beacon()`` before
the handoff is called. That leaves the other door unguarded: any caller (or a
future one) that hands off on ``beacon_established`` while the registration is
still landing lands in the ``Beacon <id> non trovato`` branch and silently
gets the GLOBAL C2 context instead of the beacon the run just established.

So ``run_c2`` now resolves the id through ``_await_beacon_id``: a bounded wait
(never blocks the operator past the timeout) and then the old fallback. These
pin the three behaviours that make it safe — instant when the beacon is there,
patient when it is late, bounded when it never shows up — plus the fact that
``run_c2`` actually goes through it.
"""

import phantom.core.c2_shell as c2_shell


# ── the wait itself ────────────────────────────────────────────────────────

def test_a_beacon_that_is_already_registered_is_returned_at_once(monkeypatch):
    monkeypatch.setattr(c2_shell, "_resolve_beacon_id", lambda bid: "beef1234")
    sleeps = []
    got = c2_shell._await_beacon_id("beef", sleep=sleeps.append,
                                    now=lambda: 0.0)
    assert got == "beef1234"
    assert sleeps == [], "no beacon to wait for: the wait must not sleep"


def test_a_late_registration_is_waited_for(monkeypatch):
    seen = {"n": 0}

    def resolver(bid):
        seen["n"] += 1
        return "beef1234" if seen["n"] >= 3 else None

    monkeypatch.setattr(c2_shell, "_resolve_beacon_id", resolver)
    clock = {"t": 0.0}
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        clock["t"] += seconds

    got = c2_shell._await_beacon_id("beef", sleep=sleep,
                                    now=lambda: clock["t"])
    assert got == "beef1234"
    assert seen["n"] >= 3, "it must re-resolve, not give up on the first miss"
    assert sleeps, "the wait actually waited"


def test_a_beacon_that_never_appears_gives_up_INSIDE_the_timeout(monkeypatch):
    monkeypatch.setattr(c2_shell, "_resolve_beacon_id", lambda bid: None)
    clock = {"t": 0.0}
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        clock["t"] += seconds

    got = c2_shell._await_beacon_id("beef", timeout=1.0, interval=0.25,
                                    sleep=sleep, now=lambda: clock["t"])
    assert got is None
    assert clock["t"] < 2.0, "bounded: the operator is never left waiting"
    # one resolve up front, then at most timeout/interval + 1 more
    assert len(sleeps) <= int(1.0 / 0.25) + 1


def test_an_ambiguous_prefix_is_not_a_resolution(monkeypatch):
    """Two beacons sharing the prefix must not be adopted by accident."""
    monkeypatch.setattr(c2_shell, "_resolve_beacon_id",
                        lambda bid: None if bid == "be" else "beef1234")
    clock = {"t": 0.0}
    got = c2_shell._await_beacon_id(
        "be", timeout=0.5, interval=0.25,
        sleep=lambda s: clock.__setitem__("t", clock["t"] + s),
        now=lambda: clock["t"])
    assert got is None


# ── run_c2 goes through it ────────────────────────────────────────────────

class _StubShell:
    """Enough C2Shell for the handoff: an id slot and the loop entry."""

    instances = []

    def __init__(self):
        self.active_beacon = None
        self.entered = False
        _StubShell.instances.append(self)

    def cmdloop(self):
        self.entered = True


def test_run_c2_hands_off_through_the_wait(monkeypatch):
    _StubShell.instances = []
    seen = []
    monkeypatch.setattr(c2_shell, "C2Shell", _StubShell)
    monkeypatch.setattr(c2_shell, "_await_beacon_id",
                        lambda bid, **kw: seen.append(bid) or "beef1234")

    c2_shell.run_c2(preferred_beacon="beef")

    assert seen == ["beef"], "the handoff must resolve through the wait"
    shell = _StubShell.instances[0]
    # the RESOLVED id is what the shell is pointed at, not the typed prefix
    assert shell.active_beacon == "beef1234"
    assert shell.entered, "the operator still lands in the C2 loop"


def test_run_c2_keeps_the_global_context_when_it_never_appears(monkeypatch):
    _StubShell.instances = []
    monkeypatch.setattr(c2_shell, "C2Shell", _StubShell)
    monkeypatch.setattr(c2_shell, "_await_beacon_id", lambda bid, **kw: None)

    c2_shell.run_c2(preferred_beacon="beef")

    shell = _StubShell.instances[0]
    assert shell.active_beacon is None, "no id, no active beacon"
    assert shell.entered


def test_run_c2_without_a_preferred_beacon_does_not_wait(monkeypatch):
    _StubShell.instances = []

    def _boom(*_a, **_kw):
        raise AssertionError("no handoff was requested: nothing to wait for")

    monkeypatch.setattr(c2_shell, "C2Shell", _StubShell)
    monkeypatch.setattr(c2_shell, "_await_beacon_id", _boom)

    c2_shell.run_c2()

    assert _StubShell.instances[0].active_beacon is None
