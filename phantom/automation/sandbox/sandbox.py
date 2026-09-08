"""
sandbox.py — pre-flight validation engine.

Before any payload/dropper is deployed to a real target, it must pass
the sandbox gate. Layers (all free):

  * DockerBackend  — run the sample in a disposable, networkless container
                     and require a clean (non-crashing) execution.
  * DefenderBackend — Windows Defender scan of the sample (gold standard
                     for AV evasion validation; runs on a Windows eval VM
                     or any Windows box).
  * VmBackend      — full Windows eval VM detonation (optional; used when
                     a VM is configured, e.g. Hyper-V / VirtualBox).

An approved verdict requires every AVAILABLE backend to pass. If no
backend is available the sample is marked `skipped` (operator-aware:
the planner may still proceed at its own risk).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

from phantom.core.executor import execute_quiet


@dataclass
class SandboxResult:
    backend: str
    ok: bool
    detected: bool = False
    output: str = ""
    error: str = ""


@dataclass
class SandboxVerdict:
    approved: bool
    results: List[SandboxResult] = field(default_factory=list)
    reason: str = ""

    @property
    def skipped(self) -> bool:
        return not self.results

    def summary(self) -> str:
        if self.skipped:
            return "no sandbox backend available — sample not pre-flighted"
        if self.approved:
            return "approved by all available sandbox backends"
        return "denied: " + self.reason


class SandboxBackend(ABC):
    name: str = "sandbox"

    @abstractmethod
    def available(self) -> bool:
        ...

    @abstractmethod
    def run_sample(self, sample_path: str) -> SandboxResult:
        ...


class DockerBackend(SandboxBackend):
    """Runs the sample inside a disposable, networkless container."""

    name = "docker"

    def __init__(self, image: str = "debian:bookworm-slim",
                 memory: str = "256m", timeout: float = 20.0) -> None:
        self.image = image
        self.memory = memory
        self.timeout = timeout

    def available(self) -> bool:
        if not shutil.which("docker"):
            return False
        try:
            r = subprocess.run(["docker", "info"], capture_output=True,
                               text=True, timeout=10)
            return r.returncode == 0
        except Exception:
            return False

    def run_sample(self, sample_path: str) -> SandboxResult:
        if not os.path.exists(sample_path):
            return SandboxResult(backend=self.name, ok=False, error="sample missing")
        mount = os.path.dirname(os.path.abspath(sample_path))
        fname = os.path.basename(sample_path)
        # Copy the sample INSIDE the container instead of chmod-ing the
        # read-only mount: `-v ...:ro` makes chmod fail ("Read-only file
        # system"), which aborted every detonation with EXIT:1.
        #
        # The sample runs under `timeout <bound>` because a real implant is
        # PERSISTENT: it keeps running (waiting for its C2) until killed. A
        # clean detonation is therefore either an early exit 0 OR still
        # being alive when the bound expires (rc 124 from `timeout`) — both
        # mean "executed without crashing / without being blocked". Only a
        # nonzero exit BEFORE the bound (loader error, missing interpreter,
        # segfault, AV kill) is a deny. The bound stays comfortably under
        # the outer execute_quiet timeout so the container always exits.
        bound = max(3, min(int(self.timeout) - 5, 12))
        cmd = (
            f"docker run --rm --network=none -m {self.memory} "
            f"-v {mount}:/sample:ro {self.image} "
            f"sh -c \"cp /sample/{fname} /tmp/.smp && chmod +x /tmp/.smp && "
            f"timeout {bound} /tmp/.smp; rc=$?; "
            f"[ $rc -eq 124 ] && rc=0; echo EXIT:$rc\""
        )
        res = execute_quiet(cmd, timeout=int(self.timeout))
        if res.timed_out:
            return SandboxResult(backend=self.name, ok=False,
                                 error="container did not exit (docker unavailable?)")
        if res.returncode != 0:
            return SandboxResult(backend=self.name, ok=False,
                                 error=res.stderr.strip()[:300] or "nonzero exit")
        if "EXIT:0" not in res.stdout:
            return SandboxResult(backend=self.name, ok=False,
                                 error=f"sample exited nonzero: {res.stdout.strip()[:200]}")
        return SandboxResult(backend=self.name, ok=True, output=res.stdout.strip()[:500])


class DefenderBackend(SandboxBackend):
    """Windows Defender scan of the sample (MpCmdRun / Start-MpScan)."""

    name = "defender"

    def __init__(self, timeout: float = 120.0) -> None:
        self.timeout = timeout

    def available(self) -> bool:
        if os.name != "nt":
            return False
        # MpCmdRun.exe lives in the Defender platform dir; PowerShell always present
        return True

    @staticmethod
    def _scan_powershell(sample_path: str) -> str:
        script = (
            f"$p='{sample_path}';"
            "Add-MpPreference -ExclusionProcess 'powershell.exe' 2>$null;"
            "$threats=Get-MpThreat | Select-Object -ExpandProperty ThreatName;"
            "$sig=Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureVersion;"
            "if($threats){$threats|Out-String}else{'NO_THREAT'};"
            "Write-Output ('SIG:'+$sig)"
        )
        return f"powershell -NoProfile -Command \"{script}\""

    def run_sample(self, sample_path: str) -> SandboxResult:
        if not os.path.exists(sample_path):
            return SandboxResult(backend=self.name, ok=False, error="sample missing")
        # Prefer MpCmdRun (the supported CLI scanner): Start-MpScan fails on
        # machines where the Defender PowerShell module is half-registered
        # ("errori durante il tentativo di analizzare il dispositivo"), while
        # MpCmdRun -Scan works everywhere a Defender platform exists.
        mpcmd = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                             "Windows Defender", "MpCmdRun.exe")
        if not os.path.exists(mpcmd):
            plat = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                                "Microsoft", "Windows Defender", "Platform")
            try:
                versions = sorted(os.listdir(plat))
                if versions:
                    mpcmd = os.path.join(plat, versions[-1], "MpCmdRun.exe")
            except OSError:
                pass
        if os.path.exists(mpcmd):
            res = execute_quiet(
                f'"{mpcmd}" -Scan -ScanType 3 -File "{sample_path}"',
                timeout=int(self.timeout))
            # 0=clean, 2=threat found; anything else = scan failure
            if res.returncode == 2:
                return SandboxResult(backend=self.name, ok=False, detected=True,
                                     error="Defender: threat detected")
            if res.returncode not in (0, None) and "error" in (res.stderr or "").lower():
                return SandboxResult(backend=self.name, ok=False,
                                     error=res.stderr.strip()[:300] or "scan failed")
            return SandboxResult(backend=self.name, ok=True, detected=False,
                                 output=(res.stdout or "").strip()[:200])
        # fallback: PowerShell provider
        res = execute_quiet(
            f"powershell -NoProfile -Command \"Start-MpScan -ScanPath '{os.path.dirname(sample_path)}' -ScanType Custom\"",
            timeout=int(self.timeout))
        if res.returncode != 0 and res.returncode is not None:
            return SandboxResult(backend=self.name, ok=False,
                                 error=res.stderr.strip()[:300] or "scan failed")
        # check whether a threat was recorded for this sample
        check = execute_quiet(
            "powershell -NoProfile -Command \"$t=Get-MpThreat; if($t){$t.ThreatName}else{'NO_THREAT'}\"",
            timeout=30)
        detected = check.ok and "NO_THREAT" not in check.stdout
        return SandboxResult(backend=self.name, ok=not detected, detected=detected,
                             output=check.stdout.strip()[:300])


class VmBackend(SandboxBackend):
    """Full detonation inside a Windows eval VM (Hyper-V/VirtualBox).

    This is the gold standard: run the sample where Defender+EDR are
    fully live. Requires the operator to have provisioned the VM;
    `vm_exec` is a small wrapper (e.g. ssh into the VM) that runs the
    sample remotely.
    """

    name = "vm_windows"

    def __init__(self, vm_exec: Optional[str] = None,
                 copy_cmd: Optional[str] = None) -> None:
        # e.g. vm_exec="ssh -i key phantom@10.0.0.99", copy_cmd="scp ..."
        self.vm_exec = vm_exec
        self.copy_cmd = copy_cmd

    def available(self) -> bool:
        return bool(self.vm_exec and shutil.which(self.vm_exec.split()[0]))

    def run_sample(self, sample_path: str) -> SandboxResult:
        if not self.vm_exec:
            return SandboxResult(backend=self.name, ok=False, error="no VM configured")
        try:
            remote = f"C:\\phantom_sample_{int(time.time())}.exe"
            if self.copy_cmd:
                subprocess.run(f"{self.copy_cmd.format(local=sample_path, remote=remote)}",
                               shell=True, capture_output=True, timeout=60)
            r = subprocess.run(f"{self.vm_exec} {remote}", shell=True,
                               capture_output=True, text=True, timeout=int(self.timeout or 60))
            return SandboxResult(backend=self.name, ok=r.returncode == 0,
                                 output=r.stdout.strip()[:300],
                                 error=r.stderr.strip()[:200])
        except subprocess.TimeoutExpired:
            return SandboxResult(backend=self.name, ok=False, error="VM timeout")
        except Exception as e:
            return SandboxResult(backend=self.name, ok=False, error=str(e))

    def __getattr__(self, item):
        if item == "timeout":
            return 60.0
        raise AttributeError(item)


class SandboxEngine:
    """Runs all available backends; verdict = approved iff every one passes."""

    def __init__(self, backends: Optional[List[SandboxBackend]] = None) -> None:
        self.backends = backends if backends is not None else [
            DockerBackend(),
            DefenderBackend(),
            VmBackend(),
        ]

    def preflight(self, sample_path: str) -> SandboxVerdict:
        results: List[SandboxResult] = []
        for backend in self.backends:
            try:
                if not backend.available():
                    continue
                results.append(backend.run_sample(sample_path))
            except Exception as e:
                results.append(SandboxResult(backend=backend.name, ok=False, error=str(e)))
        if not results:
            return SandboxVerdict(approved=True, results=[],
                                  reason="no sandbox backend available — sample not pre-flighted")
        ok = all(r.ok for r in results)
        reason = ""
        if not ok:
            bad = [r for r in results if not r.ok][0]
            reason = f"{bad.backend}: {bad.error or 'detected by antivirus'}"
        return SandboxVerdict(approved=ok, results=results, reason=reason)
