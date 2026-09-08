"""Execution backends used by the local Electron bridge.

The dispatcher never changes Phantom's module command generation. It only
routes an already-reviewed command to the selected operator environment:
native host, Kali WSL2, or an SSH-accessible Kali machine.
"""

from __future__ import annotations

import os
import platform
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Optional

from phantom.core.executor import QuietResult, _is_safe_target, execute_quiet
from phantom.core.scope import is_in_scope
from phantom.core.session import session


@dataclass
class BackendConfig:
    kind: str = "auto"
    distro: str = "kali-linux"
    host: str = ""
    port: int = 22
    user: str = ""


class BackendDispatcher:
    """Detect and execute commands in the configured operator backend."""

    def __init__(self) -> None:
        self.config = BackendConfig(
            kind=os.getenv("PHANTOM_BACKEND", "auto"),
            distro=os.getenv("PHANTOM_WSL_DISTRO", "kali-linux"),
            host=os.getenv("PHANTOM_SSH_HOST", ""),
            port=int(os.getenv("PHANTOM_SSH_PORT", "22")),
            user=os.getenv("PHANTOM_SSH_USER", ""),
        )

    def update(self, values: dict[str, Any]) -> BackendConfig:
        if values.get("kind") is not None:
            self.config.kind = str(values["kind"])
        if values.get("distro") is not None:
            self.config.distro = str(values["distro"])
        if values.get("host") is not None:
            self.config.host = str(values["host"])
        if values.get("port") is not None:
            self.config.port = max(1, min(int(values["port"]), 65535))
        if values.get("user") is not None:
            self.config.user = str(values["user"])
        return self.config

    def detect(self) -> dict[str, Any]:
        """Return the best available backend without starting tools."""
        if self.config.kind in {"native", "wsl2", "ssh"}:
            return self._describe(self.config.kind, forced=True)

        if platform.system() == "Windows":
            wsl = self._describe("wsl2")
            if wsl["available"]:
                return wsl
        native = self._describe("native")
        if native["available"]:
            return native
        if self.config.host:
            return self._describe("ssh")
        return {
            "kind": "none",
            "available": False,
            "details": "No native, WSL2, or configured SSH backend detected.",
            "tools": [],
        }

    def run(self, command: str, target: str = "", timeout: float = 120.0) -> QuietResult:
        """Execute one command after scope and target validation."""
        if target and session.scope and not is_in_scope(target, session.scope):
            return QuietResult(command, error=f"out of scope: {target}", returncode=-1)
        if target and not _is_safe_target(target):
            return QuietResult(command, error=f"unsafe target: {target}", returncode=-1)
        if not command.strip():
            return QuietResult(command, error="empty command", returncode=-1)

        backend = self.detect()
        if not backend["available"]:
            return QuietResult(command, error=backend["details"], returncode=-1)
        kind = backend["kind"]
        if kind == "native":
            return execute_quiet(command, target, timeout=timeout)

        if kind == "wsl2":
            # Run as ROOT inside the distro: `sudo nmap ...` (and every other
            # sudo-prefixed module command) hangs forever waiting for a
            # password prompt when the WSL default user is not root and the
            # subprocess stdin is DEVNULL — producing a 2-minute "scan with
            # no output" for the operator. The default Kali WSL user is
            # `kali`, not root. `-u root` keeps `sudo` a no-op while still
            # honouring the operator's requested command verbatim.
            return self._run_argv(
                ["wsl.exe", "-d", self.config.distro, "-u", "root", "--",
                 "bash", "-lc", command],
                command, timeout,
            )

        if kind == "ssh":
            destination = f"{self.config.user}@{self.config.host}" if self.config.user else self.config.host
            return self._run_argv(
                ["ssh", "-p", str(self.config.port), "-o", "BatchMode=yes", destination, command],
                command, timeout,
            )

        return QuietResult(command, error=f"unsupported backend: {kind}", returncode=-1)

    @staticmethod
    def _run_argv(argv: list[str], original: str, timeout: float) -> QuietResult:
        import time
        started = time.time()
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
            )
        except OSError as exc:
            return QuietResult(original, error=f"spawn failed: {exc}", returncode=-1)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # SALVAGE: drain the pipe buffers after the kill — a long scan
            # killed at 90% still knows most of what it found. Returning an
            # EMPTY timed_out result made every module run look like it
            # produced nothing ("comando sì, output no").
            try:
                proc.kill()
            except OSError:
                pass
            try:
                stdout, stderr = proc.communicate(timeout=8)
            except Exception:
                stdout, stderr = "", ""
            return QuietResult(original, timed_out=True, returncode=None,
                               stdout=stdout or "", stderr=stderr or "",
                               duration=time.time() - started)
        return QuietResult(
            original,
            stdout=stdout or "",
            stderr=stderr or "",
            returncode=proc.returncode,
            duration=time.time() - started,
        )

    def _describe(self, kind: str, forced: bool = False) -> dict[str, Any]:
        if kind == "native":
            tools = [tool for tool in ("nmap", "sqlmap", "msfconsole", "hydra") if shutil.which(tool)]
            available = bool(tools) or platform.system() != "Windows"
            return {
                "kind": kind,
                "available": available,
                "details": f"Native backend ({len(tools)} common tools detected).",
                "tools": tools,
                "forced": forced,
            }
        if kind == "wsl2":
            wsl = shutil.which("wsl.exe") or shutil.which("wsl")
            if not wsl:
                return {"kind": kind, "available": False, "details": "WSL2 executable not found.", "tools": []}
            try:
                proc = subprocess.run(
                    [wsl, "-l", "-q"], capture_output=True, text=True, timeout=5,
                )
                distros = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
                available = proc.returncode == 0 and bool(distros)
                return {
                    "kind": kind,
                    "available": available,
                    "details": f"WSL2 distributions: {', '.join(distros) or 'none'}",
                    "tools": [],
                    "distros": distros,
                    "forced": forced,
                }
            except (OSError, subprocess.TimeoutExpired) as exc:
                return {"kind": kind, "available": False, "details": f"WSL2 probe failed: {exc}", "tools": []}
        if kind == "ssh":
            available = bool(self.config.host and shutil.which("ssh"))
            return {
                "kind": kind,
                "available": available,
                "details": "SSH backend configured." if available else "Configure an SSH host and ensure ssh is installed.",
                "tools": [],
                "host": self.config.host,
                "forced": forced,
            }
        return {"kind": kind, "available": False, "details": "Unknown backend.", "tools": []}


backend_dispatcher = BackendDispatcher()
