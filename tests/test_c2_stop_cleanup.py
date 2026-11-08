"""C2Server.stop() must never create a coroutine nobody can await.

The leak measured on 2026-11-08 under tests/test_aitm.py:

    RuntimeWarning: coroutine 'C2Server.stop.<locals>.cleanup' was never
    awaited

``asyncio.run_coroutine_threadsafe(cleanup(), loop)`` creates the coroutine
BEFORE it discovers that the loop is closed, so the coroutine is orphaned and
collected later. The fix is structural: create it only for a loop that is
running, and close it if scheduling still fails (the loop can stop between the
check and the call).
"""

from __future__ import annotations

import asyncio
import inspect
import threading
import unittest
from unittest import mock

from phantom.core import c2_server
from phantom.core.c2_server import C2Server


class _Runner:
    def __init__(self) -> None:
        self.calls = 0

    async def cleanup(self) -> None:
        self.calls += 1


class _DeadLoop:
    """A loop object that exists but cannot accept work."""

    def __init__(self) -> None:
        self.stop_requests = 0

    def is_running(self) -> bool:
        return False

    def call_soon_threadsafe(self, callback) -> None:  # pragma: no cover
        raise AssertionError("must not schedule on a loop that is not running")

    def stop(self) -> None:
        self.stop_requests += 1


class _ClosedLoop:
    """Reports RUNNING (the race) but rejects the scheduling call."""

    def __init__(self) -> None:
        self.stop_requests = 0

    def is_running(self) -> bool:
        return True

    def call_soon_threadsafe(self, callback) -> None:
        raise RuntimeError("Event loop is closed")

    def stop(self) -> None:
        self.stop_requests += 1


class C2StopCleanupTests(unittest.TestCase):
    def test_a_loop_that_is_not_running_is_never_asked_to_clean_up(self):
        server = C2Server()
        server.loop = _DeadLoop()
        server.runner = _Runner()
        server.thread = None

        server.stop()                      # must not raise, must not leak

        self.assertIsNone(server.loop)
        self.assertIsNone(server.runner)

    def test_the_coroutine_is_closed_when_scheduling_fails(self):
        server = C2Server()
        server.loop = _ClosedLoop()
        server.runner = _Runner()
        server.thread = None
        seen = {}

        def _fail(coro, loop):
            seen["coro"] = coro
            raise RuntimeError("Event loop is closed")

        with mock.patch.object(c2_server.asyncio, "run_coroutine_threadsafe",
                               _fail):
            server.stop()

        self.assertIn("coro", seen)
        self.assertEqual(inspect.getcoroutinestate(seen["coro"]),
                         inspect.CORO_CLOSED)
        self.assertIsNone(server.loop)
        self.assertIsNone(server.runner)

    def test_a_live_loop_awaits_the_cleanup_before_stopping(self):
        loop = asyncio.new_event_loop()
        ready = threading.Event()

        def _run():
            asyncio.set_event_loop(loop)
            loop.call_soon(ready.set)
            loop.run_forever()

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        self.assertTrue(ready.wait(5), "event loop thread did not start")
        runner = _Runner()
        server = C2Server()
        server.loop = loop
        server.runner = runner
        server.thread = None

        try:
            server.stop()
        finally:
            thread.join(timeout=5)
            if loop.is_running():
                loop.call_soon_threadsafe(loop.stop)

        self.assertEqual(runner.calls, 1)
        self.assertFalse(loop.is_running())
        self.assertIsNone(server.loop)
        self.assertIsNone(server.runner)


if __name__ == "__main__":
    unittest.main()
