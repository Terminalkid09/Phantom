"""evolution/lab.py — on-demand local lab for the evolution loop.

Policy: NO user machine is ever a lab target. When the evolution loop
needs behavioural proof it starts the project's own two-host compose lab
(lab/docker-compose.yml, committed and shipped with phantom), waits for
the dmz web endpoint and tears it down after the gate. Ports are remapped
to a private range so it cannot collide with an operator-run lab.

Lifecycle:
    ensure()  -> up + wait  (called by the gate before stage 4)
    release() -> down -v    (called when the last consumer finishes)

Port remap (host-side): 8081->18081, 2222->12222, 2121->12121 so an
operator's own lab (or any local service) is never touched. The dry-run
targets the REMAPPED port; nothing else in phantom is affected.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[3]
COMPOSE = PROJECT_ROOT / "lab" / "docker-compose.yml"

# remapped host ports — private range, no collision with the operator's lab
WEB_PORT = 18081          # dmz web (compose default: 8081)
SSH_PORT = 12222          # dmz ssh (compose default: 2222)
FTP_PORT = 12121          # dmz ftp (compose default: 2121)
PROJECT_NAME = "phantom-evolution-lab"

START_TIMEOUT = 120       # seconds for compose up + endpoint wait
WAIT_SLEEP = 2.0

_lock = threading.Lock()
_refcount = 0
_started_here = False


class LabUnavailable(Exception):
    """Docker missing or the compose stack failed to come up."""


def _docker() -> Optional[str]:
    d = shutil.which("docker")
    return d


def _compose_cmd() -> Optional[Tuple[str, ...]]:
    d = _docker()
    if not d:
        return None
    return (d, "compose", "-f", str(COMPOSE), "-p", PROJECT_NAME)


def web_reachable(port: int = WEB_PORT, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def ensure() -> None:
    """Bring the evolution lab up (idempotent, refcounted)."""
    global _refcount, _started_here
    with _lock:
        _refcount += 1
        try:
            if web_reachable():
                return                      # already up (ours or remapped)
            cmd = _compose_cmd()
            if not cmd:
                raise LabUnavailable(
                    "docker not found — the evolution loop cannot obtain "
                    "behavioural proof on this machine (install Docker "
                    "Desktop or disable --evolution)")
            proc = subprocess.run(
                [*cmd, "up", "-d"], capture_output=True, text=True,
                timeout=START_TIMEOUT, cwd=str(PROJECT_ROOT))
            if proc.returncode != 0:
                raise LabUnavailable(
                    "lab compose failed: "
                    + (proc.stderr or proc.stdout or "").strip()[-300:])
            _started_here = True
            deadline = time.time() + START_TIMEOUT
            while time.time() < deadline:
                if web_reachable():
                    return
                time.sleep(WAIT_SLEEP)
            raise LabUnavailable(
                f"lab did not become reachable on 127.0.0.1:{WEB_PORT} "
                f"within {START_TIMEOUT}s")
        except Exception:
            _refcount -= 1
            raise


def release() -> None:
    """Tear the lab down when the last consumer is done (no-op if it was
    already running before us — we never kill someone else's stack)."""
    global _refcount, _started_here
    with _lock:
        _refcount = max(0, _refcount - 1)
        if _refcount > 0 or not _started_here:
            return
        _started_here = False
        cmd = _compose_cmd()
        if cmd:
            try:
                subprocess.run([*cmd, "down", "-v"], capture_output=True,
                               text=True, timeout=START_TIMEOUT,
                               cwd=str(PROJECT_ROOT))
            except (OSError, subprocess.TimeoutExpired):
                pass


class lab_session:
    """Context manager: ensure() on enter, release() on exit."""

    def __init__(self) -> None:
        self._entered = False

    def __enter__(self):
        ensure()
        self._entered = True
        return self

    def __exit__(self, *exc) -> None:
        if self._entered:
            release()
