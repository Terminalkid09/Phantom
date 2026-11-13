"""
reverse.py — reverse-shell / callback handling.

A CallbackListener is a pure-Python TCP acceptor (no netcat required),
which makes real callback verification possible even on minimal hosts.
It hands the attacker box a `handler`: wait for the connection, collect
output, decide whether the beacon really checked in.

Beacons that check in with Phantom's C2 protocol can be registered in
c2_state so the whole C2 stack (shell, tasks, results) keeps working.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import List, Optional, Tuple

from phantom.automation.runtime.toolrunner import tool_runner, find_free_port
from phantom.core.executor import BackgroundProcess


class CallbackListener:
    """Threaded TCP listener that accepts one connection and buffers data."""

    def __init__(self, host: str = "0.0.0.0", port: Optional[int] = None,
                 buffer_limit: int = 1_000_000) -> None:
        self.host = host
        self.port = port or find_free_port()
        self.buffer_limit = buffer_limit
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.data = b""
        self.connected = False
        self._lock = threading.Lock()

    def start(self) -> int:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(1)
        self._sock.settimeout(0.3)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self.port

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connected = True
            conn.settimeout(1.0)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    with self._lock:
                        self.data += chunk
                        if len(self.data) > self.buffer_limit:
                            self.data = self.data[-self.buffer_limit:]
            except (socket.timeout, OSError):
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
            break  # single connection per listener

    def wait_for_connection(self, timeout: float = 15.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.connected:
                return True
            time.sleep(0.05)
        return False

    def wait_for_data(self, marker: str, timeout: float = 15.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if marker.encode() in self.data:
                    return True
            time.sleep(0.05)
        return False

    def read(self) -> str:
        with self._lock:
            return self.data.decode(errors="replace")

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)


class ReverseHandler:
    """High-level reverse-shell session: listener + optional c2_state beacon."""

    def __init__(self, host: str = "0.0.0.0", port: Optional[int] = None,
                 register_in_c2: bool = True) -> None:
        self.listener = CallbackListener(host=host, port=port)
        self.register_in_c2 = register_in_c2
        self.beacon_id: Optional[str] = None

    def start(self) -> int:
        return self.listener.start()

    def wait_callback(self, timeout: float = 20.0) -> bool:
        return self.listener.wait_for_connection(timeout)

    def wait_marker(self, marker: str, timeout: float = 20.0) -> bool:
        return self.listener.wait_for_data(marker, timeout)

    def register_beacon(self, beacon_id: str, info: dict) -> None:
        if not self.register_in_c2:
            return
        try:
            from phantom.core.c2_server import c2_state
            c2_state.update_beacon(beacon_id, info)
            self.beacon_id = beacon_id
        except Exception:
            pass

    def task(self, command: str) -> Optional[str]:
        if not self.beacon_id:
            return None
        try:
            from phantom.core.c2_server import c2_state
            return c2_state.queue_task(self.beacon_id, command)
        except Exception:
            return None

    def results(self) -> List[dict]:
        if not self.beacon_id:
            return []
        try:
            from phantom.core.c2_server import c2_state
            return c2_state.get_results(self.beacon_id)
        except Exception:
            return []

    def wait_result(self, task_id: str, timeout: float = 30.0) -> Optional[str]:
        """Poll the C2 for the output of a specific task."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            for r in self.results():
                if r.get("task_id") == task_id:
                    return r.get("output", "")
            time.sleep(0.1)
        return None

    def stop(self) -> None:
        self.listener.stop()


def verify_reverse_callback(lhost: str, lport: int, marker: str = "PHANTOM",
                            timeout: float = 15.0) -> Tuple[bool, str]:
    """Spawn a local probe payload and confirm a real callback arrives."""
    from phantom.automation.runtime.payloads import python_callback_probe
    handler = ReverseHandler(host="127.0.0.1", port=lport)
    try:
        port = handler.start()
        probe = python_callback_probe("127.0.0.1", port, marker)
        proc = tool_runner.spawn(probe)
        ok = handler.wait_marker(marker, timeout)
        if proc.is_alive():
            proc.terminate()
        return ok, handler.listener.read()
    finally:
        handler.stop()
