"""The OSINT transport must tell the truth about a 429.

Live defect this covers (2026-10-26): Instagram answers 429 to this egress,
`recon._fetch` threw the status away, and the short 429 shell entered marker
voting, which reported an EXISTING profile as `missing`. These tests pin the
three things that made the lie possible: no per-host pacing, no cooldown
after a rate-limit answer, and a fetch API that could not say "429".
"""

from __future__ import annotations

import inspect
import random
import time
from email.utils import formatdate

import pytest

from phantom.automation.social import ratelimit as rl
from phantom.automation.social import recon


class Clock:
    """Fake clock + sleep pair: the tests must never really wait."""

    def __init__(self) -> None:
        self.t = 1000.0
        self.sleeps = []

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def gov(clock, monkeypatch):
    g = rl.HostGovernor(min_spacing=1.2, clock=clock.now,
                        sleep=clock.sleep, rng=random.Random(7))
    monkeypatch.setattr(rl, "_GOVERNOR", g)
    return g


# ── pacing ──────────────────────────────────────────────────────────────────

def test_two_requests_to_one_host_are_spaced(gov, clock):
    assert gov.wait("instagram.com") == 0.0
    slept = gov.wait("instagram.com")
    assert slept > 0.0
    assert clock.sleeps == pytest.approx([slept])
    # ...and the NEXT one, after the gap elapsed, is free again.
    clock.t += 2.0
    assert gov.wait("instagram.com") == 0.0


def test_hosts_are_paced_independently(gov):
    gov.wait("instagram.com")
    assert gov.wait("github.com") == 0.0


# ── cooldown / breaker ─────────────────────────────────────────────────────

def test_429_starts_a_cooldown_that_doubles(gov):
    gov.note("instagram.com", 429)
    first = gov.cooling("instagram.com")
    assert first == pytest.approx(30.0, abs=0.001)
    gov.note("instagram.com", 429)
    assert gov.cooling("instagram.com") == pytest.approx(60.0, abs=0.001)
    assert gov.streak("instagram.com") == 2


def test_cooldown_is_capped(gov):
    for _ in range(12):
        gov.note("instagram.com", 429)
    assert gov.cooling("instagram.com") <= rl.COOLDOWN_MAX


def test_retry_after_wins_when_longer(gov):
    gov.note("instagram.com", 429, retry_after=600.0)
    assert gov.cooling("instagram.com") == pytest.approx(600.0, abs=0.001)
    # a SHORTER server value must not cut an earned backoff short
    gov2 = rl.HostGovernor(clock=lambda: 0.0, sleep=lambda _s: None)
    gov2.note("h", 429, retry_after=1.0)
    assert gov2.cooling("h") == pytest.approx(rl.COOLDOWN_BASE)


def test_retry_after_delta_and_http_date():
    assert rl.parse_retry_after("120") == pytest.approx(120.0)
    when = time.time() + 90
    assert rl.parse_retry_after(formatdate(when, usegmt=True),
                                now=time.time) == pytest.approx(90.0, abs=2.0)
    # garbage and a past date are 0.0, never an exception
    assert rl.parse_retry_after("soon") == 0.0
    assert rl.parse_retry_after("") == 0.0
    assert rl.parse_retry_after(formatdate(0, usegmt=True)) == 0.0


def test_success_clears_the_cooldown(gov):
    gov.note("instagram.com", 429)
    assert gov.cooling("instagram.com") > 0
    gov.note("instagram.com", 200)
    assert gov.cooling("instagram.com") == 0.0
    assert gov.streak("instagram.com") == 0


def test_a_404_does_not_park_the_host(gov):
    gov.note("instagram.com", 404)
    assert gov.cooling("instagram.com") == 0.0


def test_the_breaker_does_not_touch_the_network(gov, monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("the breaker must not reach the network")

    monkeypatch.setattr("phantom.core.executor.execute_quiet", boom)
    gov.note("instagram.com", 429)
    out = recon._fetch_ex("https://www.instagram.com/someone/")
    assert out.status == 0
    assert out.error == "cooling"
    assert out.body == ""
    assert out.retry_after > 0


# ── the fetch contract ────────────────────────────────────────────────────

def test_fetch_signature_is_unchanged():
    params = list(inspect.signature(recon._fetch).parameters)
    assert params == ["url", "timeout", "ua", "cookies"]


def test_fetch_returns_body_only(gov, monkeypatch):
    class Done:
        stdout = ("HTTP/1.1 200 OK\r\nRetry-After: 7\r\n\r\n"
                  "<html>profile</html>" + recon._STATUS_MARK + "200")

    monkeypatch.setattr("phantom.core.executor.execute_quiet",
                        lambda *a, **k: Done())
    assert recon._fetch("https://www.instagram.com/x/") == "<html>profile</html>"
    assert recon._fetch_ex("https://www.instagram.com/x/").status == 200


def test_429_body_is_never_returned_as_a_page(gov, monkeypatch):
    class Limited:
        stdout = ("HTTP/1.1 429 Too Many Requests\r\nRetry-After: 240\r\n\r\n"
                  "<html>slow down</html>" + recon._STATUS_MARK + "429")

    monkeypatch.setattr("phantom.core.executor.execute_quiet",
                        lambda *a, **k: Limited())
    out = recon._fetch_ex("https://www.instagram.com/x/")
    assert out.status == 429
    assert out.error == "rate_limited"
    assert out.body == ""                      # not evidence about the account
    assert recon._fetch("https://www.instagram.com/x/") == ""
    # the server's own Retry-After became the cooldown
    assert gov.cooling("instagram.com") == pytest.approx(240.0, abs=0.001)


def test_redirect_headers_are_not_page_content(gov, monkeypatch):
    class Redirected:
        stdout = ("HTTP/1.1 302 Found\r\nLocation: https://cdn.example/x\r\n\r\n"
                  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                  "<html>real page</html>" + recon._STATUS_MARK + "200")

    monkeypatch.setattr("phantom.core.executor.execute_quiet",
                        lambda *a, **k: Redirected())
    assert recon._fetch("https://instagram.com/x") == "<html>real page</html>"


# ── the verdict the operator sees ─────────────────────────────────────────

def test_state_vote_does_not_call_a_throttled_account_missing(monkeypatch):
    monkeypatch.setattr(recon.time, "sleep", lambda _s: None)
    monkeypatch.setattr(
        recon, "_fetch_ex",
        lambda *a, **k: rl.FetchResult("", 429, 60.0, "rate_limited"))
    state, conf, html = recon._state_vote("someone", "instagram")
    assert state == "unknown"
    assert conf == 0.0
    assert html == ""


def test_state_vote_drops_the_throttled_sample(monkeypatch):
    monkeypatch.setattr(recon.time, "sleep", lambda _s: None)
    calls = {"n": 0}

    def fake(*_a, **_k):
        calls["n"] += 1
        if calls["n"] == 1:
            return rl.FetchResult("", 429, 60.0, "rate_limited")
        return rl.FetchResult("<html>" + "x" * 5000 + "</html>", 200, 0.0, "")

    monkeypatch.setattr(recon, "_fetch_ex", fake)
    # `x` has no public markers, so its branch is the length heuristic: a
    # readable page there is the clean way to see ONE vote out of two samples.
    state, conf, _html = recon._state_vote("someone", "x")
    assert state == "public"
    # one readable page out of two attempts is not certainty
    assert conf <= 0.5
