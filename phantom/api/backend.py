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

from phantom.core.executor import QuietResult, _is_safe_target
from phantom.core.scope import is_in_scope, scope_status
from phantom.core.session import session


def _is_identity_target(target: str) -> bool:
    """Identity targets (email/username/phone) are the engagement SUBJECT,
    not machines to authorize — the scope list gates hosts, never people."""
    try:
        from phantom.automation.guidance.targets import (
            classify_target, is_identity_target)
        return is_identity_target(classify_target(target))
    except Exception:
        return False


def _unscoped_allowed() -> bool:
    """Explicit opt-out for running targeted commands without an engagement
    scope. Default OFF: the API gate refuses; the documented escape hatch
    for lab/CTF work is ``phantom setup`` → engagement.allow_unscoped or
    PHANTOM_ALLOW_UNSCOPED=1. Never set by default: an authorization gate
    must fail closed."""
    from phantom.utils import config as cfg
    v = str(cfg.get("engagement.allow_unscoped", "",
                    env="PHANTOM_ALLOW_UNSCOPED"))
    return v.strip().lower() in ("1", "true", "yes", "on")


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

    def _gate_target(self, command: str, target: str) -> Optional[QuietResult]:
        """Scope + target validation, FAIL CLOSED for targeted commands:
          * scope declared + target out of scope -> refused
          * NO scope declared + remote target      -> refused unless the
            operator explicitly opted out (PHANTOM_ALLOW_UNSCOPED=1)
        An empty scope list must never mean \"everything is allowed\"."""
        if target and not _is_identity_target(target):
            status = scope_status(target, session.scope)
            if status == "out_of_scope":
                return QuietResult(command, error=f"out of scope: {target}",
                                   returncode=-1)
            if status == "unscoped" and not _unscoped_allowed():
                return QuietResult(
                    command,
                    error=("no engagement scope defined — set the session "
                           "scope (e.g. 10.0.0.0/8,172.16.0.0/12) or set "
                           "PHANTOM_ALLOW_UNSCOPED=1 to run without a scope"),
                    returncode=-1)
        if target and not _is_safe_target(target):
            return QuietResult(command, error=f"unsafe target: {target}", returncode=-1)
        if not command.strip():
            return QuietResult(command, error="empty command", returncode=-1)
        return None

    def run_pipeline(self, command: str, target: str = "",
                     timeout: float = 120.0) -> QuietResult:
        """Execute a command WITHOUT ever handing the raw string to a shell.

        The command is parsed into argv segments (quote-aware) and executed
        with `shell=False`; pipes/`;`/`&&`/`||` are wired natively for the
        native backend, and re-serialised with per-token quoting for the
        WSL2/ssh backends. A command the parser cannot represent as plain
        argv is refused — filtering shell strings was never a boundary.
        """
        gated = self._gate_target(command, target)
        if gated is not None:
            return gated
        from phantom.core.safe_exec import UnsafeCommand, parse, run_local
        try:
            parsed = parse(command)
        except UnsafeCommand as exc:
            return QuietResult(command, error=f"refused: {exc}", returncode=-1)

        backend = self.detect()
        if not backend["available"]:
            return QuietResult(command, error=backend["details"], returncode=-1)
        kind = backend["kind"]
        if kind == "native":
            return run_local(parsed, timeout=timeout)
        if kind == "wsl2":
            from phantom.core.safe_exec import to_shell_string
            return self._run_argv(
                ["wsl.exe", "-d", self.config.distro, "-u", "root", "--",
                 "bash", "-lc", to_shell_string(parsed)],
                command, timeout,
            )
        if kind == "ssh":
            from phantom.core.safe_exec import to_shell_string
            destination = (f"{self.config.user}@{self.config.host}"
                           if self.config.user else self.config.host)
            return self._run_argv(
                ["ssh", "-p", str(self.config.port), "-o", "BatchMode=yes",
                 destination, to_shell_string(parsed)],
                command, timeout,
            )
        return QuietResult(command, error=f"unsupported backend: {kind}",
                           returncode=-1)

    def run(self, command: str, target: str = "", timeout: float = 120.0) -> QuietResult:
        """Backward-compatible entry point. Delegates to `run_pipeline` so
        every caller inherits the argv-only execution path."""
        return self.run_pipeline(command, target, timeout)

    # NOTE (A-1): there is deliberately NO shell-string execution path left on
    # this dispatcher. `run()` and `run_pipeline()` are the only entry points
    # and both go through `safe_exec` / per-token re-serialisation. The CLI
    # shell keeps its own shell semantics (it is the operator's own command
    # line) — that is a different, documented boundary.

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
