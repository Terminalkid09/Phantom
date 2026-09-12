"""
msf_rpc.py — persistent Metasploit RPC client for the manual core.

Why this exists
---------------
The one-shot `msfconsole -q -x "...; run; sleep 30; exit"` integration
kills every Meterpreter session the moment msfconsole exits — a session
you fought to get is gone. The MSF RPC service keeps the framework
running as a daemon: Phantom connects, drives exploits, and sessions
PERSIST in the msfrpcd process. The operator can then:

    msf-status            list live sessions (shells + meterpreter)
    msf-interact <id>     drop into an interactive session loop
    fire / msf-fire       run exploits through RPC when available,
                          falling back to the one-shot console

Protocol: MessagePack-RPC (msgpack is a hard requirement of Phantom's
Python deps on Kali; it ships with metasploit itself). We speak the
protocol directly instead of pulling pymetasploit3 — one less dep.

Security model
--------------
* msfrpcd is started bound to 127.0.0.1, no TLS (traffic never leaves
  the box), with a random password generated once and stored in
  data/msf_rpc_password (gitignored, 0600).
* auth.login returns a token used for every subsequent call.
"""

from __future__ import annotations

import os
import secrets
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import msgpack
except ImportError:  # pragma: no cover - msgpack ships with kali/parrot metasploit
    msgpack = None

RPC_HOST = "127.0.0.1"
RPC_PORT = 55553
_PASSWORD_FILE = os.path.join("data", "msf_rpc_password")


class MsfRpcError(Exception):
    """Raised when the RPC call fails or the service is unavailable."""


# ── password management ─────────────────────────────────────────────────────

def rpc_password() -> str:
    """Load (or create once) the msfrpcd password."""
    os.makedirs("data", exist_ok=True)
    if os.path.exists(_PASSWORD_FILE):
        try:
            with open(_PASSWORD_FILE, "r", encoding="utf-8") as f:
                pw = f.read().strip()
                if pw:
                    return pw
        except OSError:
            pass
    pw = secrets.token_urlsafe(24)
    with open(_PASSWORD_FILE, "w", encoding="utf-8") as f:
        f.write(pw)
    try:
        os.chmod(_PASSWORD_FILE, 0o600)
    except OSError:
        pass
    return pw


# ── the client ──────────────────────────────────────────────────────────────

class MsfRpcClient:
    """Minimal MessagePack-RPC client for the Metasploit service."""

    def __init__(self, host: str = RPC_HOST, port: int = RPC_PORT,
                 timeout: float = 30.0):
        if msgpack is None:
            raise MsfRpcError("msgpack not installed (pip install msgpack)")
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._buf = b""
        self._msgid = 0
        self.token: str = ""

    # -- wire helpers ---------------------------------------------------------

    def _connect(self) -> None:
        self._sock = socket.create_connection((self.host, self.port),
                                              timeout=self.timeout)
        self._buf = b""
        self._msgid = 0

    def _close(self) -> None:
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass
        self._sock = None

    def _recv_until_response(self, msgid: int) -> Tuple[Any, Any]:
        """Read frames until the RESPONSE for msgid arrives."""
        unpacker = msgpack.Unpacker(raw=False)
        while True:
            unpacker.feed(self._buf)
            self._buf = b""
            for frame in unpacker:
                # RESPONSE = [1, msgid, error, result]
                if isinstance(frame, (list, tuple)) and len(frame) == 4 \
                        and frame[0] == 1 and frame[1] == msgid:
                    return frame[2], frame[3]
            # need more data
            chunk = self._sock.recv(65536)
            if not chunk:
                raise MsfRpcError("msfrpcd closed the connection")
            self._buf = chunk

    def call(self, method: str, *args: Any) -> Any:
        """One RPC round-trip: REQUEST = [0, msgid, method, params]."""
        if self._sock is None:
            self._connect()
        self._msgid += 1
        msgid = self._msgid
        req = msgpack.packb([0, msgid, method,
                             list(args) if not isinstance(args, dict) else args],
                            use_bin_type=True)
        try:
            self._sock.sendall(req)
            error, result = self._recv_until_response(msgid)
        except (socket.timeout, OSError) as e:
            self._close()
            raise MsfRpcError(f"msfrpcd unreachable: {e}") from e
        if error:
            raise MsfRpcError(f"{method}: {error}")
        if isinstance(result, dict) and result.get("error"):
            raise MsfRpcError(f"{method}: {result.get('error_message') or result}")
        return result

    # -- session lifecycle ------------------------------------------------------

    def login(self) -> None:
        result = self.call("auth.login", "msf", rpc_password())
        token = result.get("token") if isinstance(result, dict) else None
        if not token:
            raise MsfRpcError(f"auth.login failed: {result}")
        self.token = token

    def _authed(self, method: str, *args: Any) -> Any:
        """Call with the auth token prefixed (MSF convention)."""
        if not self.token:
            self.login()
        try:
            return self.call(method, self.token, *args)
        except MsfRpcError as e:
            # token may have expired — re-login once
            if "invalid token" in str(e).lower() or "auth" in str(e).lower():
                self.login()
                return self.call(method, self.token, *args)
            raise


# ── service management ──────────────────────────────────────────────────────

def is_service_up(host: str = RPC_HOST, port: int = RPC_PORT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def ensure_service(start: bool = True) -> bool:
    """Return True when msfrpcd is reachable, optionally starting it."""
    if is_service_up():
        return True
    if not start:
        return False
    import shutil
    msfrpcd = shutil.which("msfrpcd") or "msfrpcd"
    try:
        subprocess.Popen(
            [msfrpcd, "-P", rpc_password(), "-u", "msf",
             "-a", RPC_HOST, "-p", str(RPC_PORT), "-S", "-f"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return False
    # wait up to ~40s for the daemon to open the port
    for _ in range(40):
        if is_service_up():
            return True
        time.sleep(1)
    return False


def connect() -> MsfRpcClient:
    """Connect + authenticate. Raises MsfRpcError when unavailable."""
    if not ensure_service():
        raise MsfRpcError("msfrpcd not running and could not be started")
    client = MsfRpcClient()
    client.login()
    return client


# ── high-level operations (what the exploit module actually uses) ───────────

def run_exploit(module_path: str, rhost: str, rport: str,
                payload: Optional[str] = None,
                lhost: Optional[str] = None,
                extra_opts: Optional[Dict[str, Any]] = None,
                timeout: float = 90.0) -> Dict[str, Any]:
    """Select an exploit module, run it against rhost:rport, and report
    whether a NEW session opened. For reverse payloads LHOST must be set
    or msfrpcd rejects the run — pass lhost (the operator's callback IP).
    Returns a summary dict."""
    client = connect()
    before = set(client._authed("session.list").keys())

    client._authed("module.use", "exploit", module_path)
    opts: Dict[str, Any] = {"RHOSTS": rhost, "RPORT": str(rport), "RunAsJob": True}
    if payload:
        opts["PAYLOAD"] = payload
        if lhost and "reverse" in payload.lower():
            opts["LHOST"] = lhost
    if extra_opts:
        opts.update({k: str(v) for k, v in extra_opts.items()})
    result = client._authed("module.execute", "exploit", module_path, opts)
    if isinstance(result, dict) and result.get("error"):
        return {"ok": False, "error": result.get("error_message") or str(result)}

    # wait for a session to spawn (job runs async)
    deadline = time.time() + timeout
    new_id = None
    while time.time() < deadline:
        sessions = client._authed("session.list")
        for sid, info in sessions.items():
            if sid not in before:
                new_id = sid
                break
        if new_id is not None:
            break
        time.sleep(2)

    info = client._authed("session.list").get(new_id, {}) if new_id else {}
    return {
        "ok": new_id is not None,
        "session_id": new_id,
        "session_type": info.get("type", ""),
        "session_via": info.get("via_exploit", ""),
        "tunnel": info.get("tunnel_peer", ""),
    }


def list_sessions() -> Dict[int, Dict[str, Any]]:
    """Live sessions: {id: {type, tunnel_peer, via_exploit, ...}}."""
    client = connect()
    return {int(k): v for k, v in client._authed("session.list").items()}


def session_read_write(session_id: int, command: str,
                       wait: float = 3.0) -> str:
    """Run one command inside a live shell/meterpreter session and
    return its output."""
    client = connect()
    sessions = client._authed("session.list")
    info = sessions.get(session_id) or sessions.get(str(session_id))
    if info is None:
        raise MsfRpcError(f"no such session: {session_id}")
    stype = str(info.get("type", "shell"))
    if "meterpreter" in stype:
        client._authed("session.meterpreter_write", session_id, command)
    else:
        client._authed("session.shell_write", session_id, command)
    time.sleep(wait)
    if "meterpreter" in stype:
        out = client._authed("session.meterpreter_read", session_id)
    else:
        out = client._authed("session.shell_read", session_id)
    return out or ""


def interact(session_id: int) -> None:
    """Interactive REPL against a live session (the operator's terminal)."""
    print(f"[*] Interactive session {session_id} — type 'exit' to detach "
          f"(the session stays alive in msfrpcd).")
    while True:
        try:
            cmd = input("msf-session> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if cmd in ("exit", "detach", "back"):
            break
        if not cmd:
            continue
        try:
            out = session_read_write(session_id, cmd, wait=2.5)
        except MsfRpcError as e:
            print(f"[!] {e}")
            break
        if out:
            print(out)


def stop_service() -> None:
    """Best-effort: shut msfrpcd down (used on phantom exit if we started it)."""
    try:
        subprocess.run(["pkill", "-f", "msfrpcd"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
