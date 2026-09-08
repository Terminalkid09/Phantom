"""
toolrunner.py — silent background tool orchestration.

Spawns detached processes (netcat listeners, socat, msfconsole -r, shells)
with pipes: the agent can write to stdin, read stdout non-blocking, poll,
kill. No interactive prompts, no terminal capture.

The wrappers here are thin and OS-aware: tools like nc/socat exist on the
attacker box (Kali primary, Windows+Docker secondary); missing tools are
reported through AvailabilityError, never silently swallowed.
"""

from __future__ import annotations

import os
import shutil
import socket
import time
import threading
from typing import Optional, List

from phantom.core.executor import BackgroundProcess, execute_quiet_bg
from phantom.utils.notifier import notifier


class ToolMissingError(FileNotFoundError):
    """Raised when a required tool is not installed on the attacker host."""


class ToolRunner:
    """Registry + factory for silent background processes."""

    def __init__(self) -> None:
        self._jobs: List[BackgroundProcess] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ core

    def spawn(self, cmd: str, target_ip: str = "") -> BackgroundProcess:
        try:
            proc = execute_quiet_bg(cmd, target_ip)
        except FileNotFoundError as e:
            raise ToolMissingError(str(e))
        with self._lock:
            self._jobs.append(proc)
        return proc

    def close_all(self, grace: float = 1.0) -> None:
        with self._lock:
            jobs = list(self._jobs)
            self._jobs.clear()
        for j in jobs:
            if j.is_alive():
                j.terminate()
        time.sleep(grace)
        for j in jobs:
            if j.is_alive():
                j.kill()

    def close(self, proc: BackgroundProcess) -> None:
        if proc.is_alive():
            proc.terminate()
        with self._lock:
            if proc in self._jobs:
                self._jobs.remove(proc)

    def active(self) -> List[BackgroundProcess]:
        with self._lock:
            return [j for j in self._jobs if j.is_alive()]

    # ------------------------------------------------------------ listeners

    def netcat_listener(
        self, port: int, host: str = "0.0.0.0", verbose: bool = True
    ) -> BackgroundProcess:
        """Silent nc listener. Output drained into the process pipe."""
        exe = _require_tool(["nc", "ncat", "netcat"])
        if "ncat" in exe:
            cmd = f"{exe} -l -p {port} --send-only 2>/dev/null"
        elif "netcat" in exe:
            cmd = f"{exe} -l {port}"
        else:
            cmd = f"{exe} -l -p {port}"
        if verbose:
            cmd = cmd.replace(" 2>/dev/null", "") + ""
        return self.spawn(cmd)

    def socat_listener(
        self, port: int, host: str = "0.0.0.0", reexec: bool = True
    ) -> BackgroundProcess:
        _require_tool(["socat"])
        cmd = f"socat TCP-LISTEN:{port},bind={host},reuseaddr,fork STDOUT"
        return self.spawn(cmd)

    # ------------------------------------------------------------------ misc

    def reverse_shell_process(
        self, cmd: str, port: int, host: str = "0.0.0.0"
    ) -> BackgroundProcess:
        """Run a reverse-shell handler (nc/socat) for the given command."""
        exe = _require_tool(["nc", "ncat", "netcat"])
        if "ncat" in exe:
            return self.spawn(f"{exe} -l -p {port} --send-only")
        if "netcat" in exe:
            return self.spawn(f"{exe} -l {port}")
        return self.spawn(f"{exe} -l -p {port}")

    # -------------------------------------------------------------- waiting

    def wait_for_output(
        self, proc: BackgroundProcess, marker: str, timeout: float = 30.0
    ) -> bool:
        """Block until `marker` appears in the process output or timeout."""
        deadline = time.time() + timeout
        acc = ""
        while time.time() < deadline:
            chunk = proc.read(timeout=0.2)
            if chunk:
                acc += chunk
                if marker in acc:
                    return True
            elif not proc.is_alive():
                break
            time.sleep(0.1)
        return marker in acc


def _require_tool(names: List[str]) -> str:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    raise ToolMissingError(f"none of {names} installed on attacker host")


# ---------------------------------------------------------------------------
# Port helpers (used by listeners / egress)
# ---------------------------------------------------------------------------

def find_free_port(preferred: Optional[int] = None) -> int:
    """Return a free TCP port, preferring `preferred` if available."""
    if preferred is not None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("0.0.0.0", preferred))
            return preferred
        except OSError:
            pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


# Global runner instance
tool_runner = ToolRunner()
