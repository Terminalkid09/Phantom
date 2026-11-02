"""ratelimit.py — a per-host governor for the OSINT fetchers.

The defect this module exists for, seen live (2026-10-26): Instagram and
TikTok answer **429** to a datacenter egress, and the recon engine did not
know it. `recon._fetch` returned only the BODY, so a rate-limited shell went
through the same marker voting as a real page: a 429 answered in a few
hundred bytes and the engine reported an EXISTING account as `missing`. The
engine was not wrong about the bytes, it was blind to the transport — and
repeating the request is what deepens the limit.

So the transport state lives here, per host:

* SPACING   — two requests to the same host are at least ``MIN_SPACING``
              apart (jittered), so a pass over N platforms does not burst
              one of them;
* COOLDOWN  — a 429/503 puts the host on an exponential cooldown, or on the
              server's own ``Retry-After`` when that is longer (both the
              delta-seconds and the HTTP-date form are honoured);
* BREAKER   — while a host is cooling the caller is NOT allowed to hit the
              network at all and gets ``status=0, error="cooling"``, which
              is a different fact from "the page said not found";
* RESET     — any 2xx clears the host's cooldown and failure streak, so a
              recovered host is not punished for the rest of the process.

Pure state machine: the clock and the sleep are injectable, so the tests are
deterministic and never really wait. Thread-safe (a swarm can share it).
"""

from __future__ import annotations

import random
import threading
import time
from email.utils import parsedate_to_datetime
from typing import Callable, Dict, NamedTuple, Optional
from urllib.parse import urlsplit

#: Minimum gap between two requests to the same host, in seconds.
MIN_SPACING = 1.2
#: How much of ``MIN_SPACING`` is jittered (human pacing, not bot cadence).
_SPACING_JITTER = 0.3
#: First cooldown after a rate-limit answer; doubles per failure.
COOLDOWN_BASE = 30.0
#: A host is never parked longer than this, however many 429s it returns.
COOLDOWN_MAX = 900.0
#: Statuses that mean "you are going too fast", not "the page is gone".
RATE_STATUSES = frozenset((429, 503))


class FetchResult(NamedTuple):
    """What a governed fetch actually learned about the transport.

    ``status == 0`` means the request was NEVER MADE (breaker open, curl
    unavailable): the body is empty for lack of asking, not for lack of an
    answer, and no caller may read it as evidence about the target.
    """
    body: str
    status: int
    retry_after: float
    error: str


def host_of(url: str) -> str:
    """Lowercased host of a URL, "" when there is none.

    ``www.`` is stripped here and in every governor lookup: a rate limit hit
    through ``www.instagram.com`` (what ``_PROFILE_URLS`` builds) is the same
    limit as ``instagram.com``, and keying them separately is how one host
    quietly got two pacing tables and two breakers.
    """
    try:
        return _key(urlsplit(str(url or "")).hostname or "")
    except ValueError:
        return ""


def _key(host: str) -> str:
    """Canonical governor key for a host: lowercase, no leading ``www.``."""
    key = str(host or "").strip().lower()
    return key[4:] if key.startswith("www.") else key


def parse_retry_after(value: str, *, now: Optional[Callable[[], float]] = None) -> float:
    """Seconds to wait from a ``Retry-After`` header value.

    Both forms in RFC 9110 are accepted: delta-seconds (``"120"``) and an
    HTTP-date (``"Wed, 21 Oct 2015 07:28:00 GMT"``). Anything else — an empty
    header, a garbage value, a date in the past — is 0.0, never an exception:
    a bad header must not take the recon pass down with it.
    """
    text = str(value or "").strip()
    if not text:
        return 0.0
    try:
        return max(0.0, float(text))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return 0.0
    if when is None:
        return 0.0
    clock = now or time.time
    try:
        delta = when.timestamp() - clock()
    except (OverflowError, OSError, ValueError):
        return 0.0
    return max(0.0, float(delta))


class HostGovernor:
    """Spacing + cooldown + breaker state for a set of hosts."""

    def __init__(self, *, min_spacing: float = MIN_SPACING,
                 cooldown_base: float = COOLDOWN_BASE,
                 cooldown_max: float = COOLDOWN_MAX,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep,
                 rng: Optional[random.Random] = None) -> None:
        self.min_spacing = float(min_spacing)
        self.cooldown_base = float(cooldown_base)
        self.cooldown_max = float(cooldown_max)
        self._clock = clock
        self._sleep = sleep
        self._rng = rng or random.Random()
        self._lock = threading.Lock()
        self._last: Dict[str, float] = {}          # host -> last request time
        self._until: Dict[str, float] = {}         # host -> breaker deadline
        self._streak: Dict[str, int] = {}          # host -> consecutive 429s

    # ── state ────────────────────────────────────────────────────────────
    def cooling(self, host: str) -> float:
        """Seconds left on the breaker for ``host`` (0.0 = ready)."""
        key = _key(host)
        with self._lock:
            until = self._until.get(key, 0.0)
            left = until - self._clock()
        return max(0.0, left)

    def streak(self, host: str) -> int:
        """Consecutive rate-limit answers seen for ``host``."""
        with self._lock:
            return int(self._streak.get(_key(host), 0))

    def wait(self, host: str) -> float:
        """Sleep the pacing this host requires. Returns the seconds slept.

        The breaker is checked FIRST: a cooling host must not be touched, so
        the caller learns about it through ``cooling()``/``note()`` and not
        by paying a delay that ends in the same 429.
        """
        key = _key(host)
        if not key:
            return 0.0
        slept = 0.0
        with self._lock:
            last = self._last.get(key)
            now = self._clock()
            self._last[key] = now
            if last is not None:
                gap = self.min_spacing + self._rng.uniform(
                    -_SPACING_JITTER, _SPACING_JITTER)
                remaining = gap - (now - last)
                if remaining > 0:
                    slept = remaining
        if slept > 0:
            self._sleep(slept)
        return slept

    def note(self, host: str, status: int, retry_after: float = 0.0) -> None:
        """Record one response and update that host's breaker."""
        key = _key(host)
        if not key:
            return
        status = int(status or 0)
        with self._lock:
            if status in RATE_STATUSES:
                streak = self._streak.get(key, 0) + 1
                self._streak[key] = streak
                backoff = min(self.cooldown_base * (2 ** (streak - 1)),
                              self.cooldown_max)
                # The server's own answer wins when it is LONGER: ignoring a
                # `Retry-After: 600` is how a temporary limit becomes a ban.
                delay = min(max(backoff, float(retry_after or 0.0)),
                            self.cooldown_max)
                self._until[key] = self._clock() + delay
                return
            if 200 <= status < 300:
                self._streak[key] = 0
                self._until.pop(key, None)
                return
            # Any other status (403, 404, a timeout with status 0) is not a
            # rate limit: it must not park the host, and it must not erase a
            # cooldown that a previous 429 earned either.

    def reset(self, host: str = "") -> None:
        """Forget everything about ``host`` (all hosts when empty)."""
        key = _key(host)
        with self._lock:
            if not key:
                self._last.clear()
                self._until.clear()
                self._streak.clear()
                return
            self._last.pop(key, None)
            self._until.pop(key, None)
            self._streak.pop(key, None)


_GOVERNOR: Optional[HostGovernor] = None
_GOVERNOR_LOCK = threading.Lock()


def governor() -> HostGovernor:
    """The process-wide governor (one pacing table, shared by every caller)."""
    global _GOVERNOR
    with _GOVERNOR_LOCK:
        if _GOVERNOR is None:
            _GOVERNOR = HostGovernor()
        return _GOVERNOR


def set_governor(gov: Optional[HostGovernor]) -> None:
    """Swap the singleton (tests, and a caller that wants its own pacing)."""
    global _GOVERNOR
    with _GOVERNOR_LOCK:
        _GOVERNOR = gov
