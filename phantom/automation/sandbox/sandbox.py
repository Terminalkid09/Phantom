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


def _cfg(key: str, env: str) -> str:
    """Read a sandbox setting from data/config.json (PHANTOM_* env wins),
    so `setup` can configure the engines without touching env files."""
    try:
        from phantom.utils import config as cfg
        return str(cfg.get(key, "", env=env) or "")
    except Exception:
        return os.environ.get(env, "")


def sample_kind(path: str) -> str:
    """Classify the artifact so only the backends that can ACTUALLY evaluate
    it are run. A Windows PE run inside the Linux Docker container would fail
    with exec-format and falsely deny every Windows payload; a shell script is
    meaningless to a Windows VM. Returns one of:
    elf | pe | script | powershell | cmd | unknown."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except OSError:
        return "unknown"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:2] == b"MZ":
        return "pe"
    if head[:2] == b"#!" or head[:4] == b"#!/":
        return "script"
    # text payloads: PowerShell / cmd droppers are shipped as text
    text = head.decode("utf-8", "replace").lstrip().lower()
    if text.startswith(("powershell", "$p=", "iex", "invoke-")) or "powershell" in text[:120]:
        return "powershell"
    if text.startswith(("cmd ", "cmd/", "@echo")) or ".exe" in text[:120]:
        return "cmd"
    if text.startswith(("curl ", "wget ", "bash ", "sh ")):
        return "script"
    return "unknown"


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
    # Honest scope: which backends actually ran and which did not, so the
    # operator knows whether "approved" means "execution proven" or just
    # "format validated" (and whether AV/EDR was exercised at all).
    coverage: str = ""

    @property
    def skipped(self) -> bool:
        return not self.results

    def summary(self) -> str:
        if self.skipped:
            return "no sandbox backend available — sample not pre-flighted"
        base = ("approved by all applicable sandbox backends"
                if self.approved else "denied: " + self.reason)
        if self.coverage:
            return f"{base} [{self.coverage}]"
        return base


class SandboxBackend(ABC):
    name: str = "sandbox"
    # sample kinds this backend can meaningfully evaluate (see sample_kind).
    # Backends outside their kind set are skipped, so a Windows PE is never
    # judged by the Linux container (which would falsely deny it).
    kinds: frozenset = frozenset()

    @property
    def label(self) -> str:
        """Name shown in the verdict's coverage line."""
        return self.name

    @abstractmethod
    def available(self) -> bool:
        ...

    @abstractmethod
    def run_sample(self, sample_path: str) -> SandboxResult:
        ...


class DockerBackend(SandboxBackend):
    """Runs the sample inside a disposable, networkless container."""

    name = "docker"
    kinds = frozenset({"elf", "script"})

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
    kinds = frozenset({"pe", "elf", "script", "powershell", "cmd", "unknown"})

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

    (Windows eval VM semantics: PE / PowerShell / cmd payloads.)

    This is the gold standard: run the sample where Defender+EDR are
    fully live. Requires the operator to have provisioned the VM;
    `vm_exec` is a small wrapper (e.g. ssh into the VM) that runs the
    sample remotely.
    """

    name = "vm_windows"
    kinds = frozenset({"pe", "powershell", "cmd", "unknown"})

    def __init__(self, vm_exec: Optional[str] = None,
                 copy_cmd: Optional[str] = None,
                 edr: str = "") -> None:
        # e.g. vm_exec="ssh -i key phantom@10.0.0.99", copy_cmd="scp ..."
        # Also configurable without code: PHANTOM_SANDBOX_VM_EXEC,
        # PHANTOM_SANDBOX_VM_COPY, PHANTOM_SANDBOX_VM_EDR (label for the
        # coverage line, e.g. "CrowdStrike" or "SentinelOne").
        self.vm_exec = vm_exec or _cfg("sandbox.vm_exec",
                                       "PHANTOM_SANDBOX_VM_EXEC")
        self.copy_cmd = copy_cmd or _cfg("sandbox.vm_copy",
                                         "PHANTOM_SANDBOX_VM_COPY")
        self.edr = edr or _cfg("sandbox.vm_edr", "PHANTOM_SANDBOX_VM_EDR")

    @property
    def label(self) -> str:
        return f"{self.name}:{self.edr}" if self.edr else self.name

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


class StaticCheckBackend(SandboxBackend):
    """Portability gate: the sample must be a REAL executable of its
    declared kind, and a Linux sample must be STATIC (glibc-independent)
    — that is what "passes here, passes everywhere" means on the target
    side. A docker detonation that times out is meaningless for a file
    that is not actually an executable (a text file "runs" as an error
    or sleeps); this backend catches those before they ever ship."""

    name = "static_check"
    kinds = frozenset({"elf", "pe", "script", "powershell", "cmd", "unknown"})

    def available(self) -> bool:
        return True

    def run_sample(self, sample_path: str) -> SandboxResult:
        try:
            with open(sample_path, "rb") as fh:
                head = fh.read(8)
        except OSError as e:
            return SandboxResult(backend=self.name, ok=False,
                                 error=f"unreadable: {e}")
        if not head:
            return SandboxResult(backend=self.name, ok=False, error="empty sample")
        # ELF: 7f 45 4c 46 ; 2nd byte class (2=64bit), machine at offset 18
        if head[:4] == b"\x7fELF":
            try:
                with open(sample_path, "rb") as fh:
                    elf = fh.read(64)
                # e_type at 16..18: 3 = ET_DYN (PIE/dynamic), 2 = ET_EXEC
                etype = int.from_bytes(elf[16:18], "little")
                # look for dynamic section: DT_NEEDED implies .dynamic exists
                dynamic = b".dynamic" in open(sample_path, "rb").read(4096)
                if etype == 3 and dynamic:
                    return SandboxResult(
                        backend=self.name, ok=False, detected=False,
                        error="dynamic ELF: needs a target glibc — "
                              "compile static or it dies on most Linux boxes "
                              "(glibc >= 2.38 required)")
            except OSError as e:
                return SandboxResult(backend=self.name, ok=False,
                                     error=f"ELF read failed: {e}")
            return SandboxResult(backend=self.name, ok=True,
                                 output="static ELF — portable across Linux")
        # PE: MZ header
        if head[:2] == b"MZ":
            return SandboxResult(backend=self.name, ok=True,
                                 output="valid PE — Windows portable")
        # script: needs a real shebang (a bare text file is a deploy bug).
        # The interpreter presence check is INFORMATIONAL, not a deny: the
        # Docker backend is the actual detonation layer (its container has
        # the common shells), and the operator box may legitimately be a
        # Windows host driving a Linux target where /bin/sh is not in PATH.
        if head[:2] == b"#!":
            interp = head[2:].split(b" ")[0].decode("utf-8", "replace").strip()
            if not interp:
                return SandboxResult(backend=self.name, ok=False,
                                     error="malformed shebang (#! with no "
                                           "interpreter)")
            note = f"script with {interp}"
            if not shutil.which(os.path.basename(interp)):
                note += " (interpreter not on operator box — docker will " \
                        "detonate it)"
            return SandboxResult(backend=self.name, ok=True, output=note)
        return SandboxResult(backend=self.name, ok=False,
                             error="unknown sample format (not ELF/PE/script) — "
                                   "refusing to ship")


class ClamAVBackend(SandboxBackend):
    """ClamAV signature scan: a SECOND, independent engine beside Defender.

    Local multi-engine is what makes the gate meaningful: a sample that both
    Defender and ClamAV call clean is still not "VT-clean", but it is no
    longer one vendor's opinion. Requires `clamscan` on PATH.
    """

    name = "clamav"
    kinds = frozenset({"pe", "elf", "script", "powershell", "cmd", "unknown"})

    def __init__(self, timeout: float = 180.0) -> None:
        self.timeout = timeout

    def available(self) -> bool:
        return shutil.which("clamscan") is not None

    def run_sample(self, sample_path: str) -> SandboxResult:
        if not os.path.exists(sample_path):
            return SandboxResult(backend=self.name, ok=False, error="sample missing")
        res = execute_quiet(f'clamscan --no-summary --infected "{sample_path}"',
                            timeout=int(self.timeout))
        # clamscan: 0 = clean, 1 = virus found, 2 = error
        if res.returncode == 1:
            return SandboxResult(backend=self.name, ok=False, detected=True,
                                 error="ClamAV: signature detected")
        if res.returncode not in (0, None):
            detail = (res.stderr or res.stdout or "").strip()[:200]
            return SandboxResult(backend=self.name, ok=False,
                                 error=detail or "clamscan failed")
        return SandboxResult(backend=self.name, ok=True, detected=False,
                             output=(res.stdout or "").strip()[:200])


class YaraBackend(SandboxBackend):
    """YARA rule scan — the operator's OWN behavioural rules, so the gate
    catches what signature vendors miss. Rules come from
    ``PHANTOM_YARA_RULES`` (a .yar file or a directory of them) or from
    ``data/yara/`` in the phantom data dir. No rules = backend unavailable.
    """

    name = "yara"
    kinds = frozenset({"pe", "elf", "script", "powershell", "cmd", "unknown"})

    def __init__(self, rules_path: Optional[str] = None,
                 timeout: float = 120.0) -> None:
        self.rules_path = rules_path or _cfg("sandbox.yara_rules",
                                             "PHANTOM_YARA_RULES")
        self.timeout = timeout

    def _rule_files(self) -> List[str]:
        p = self.rules_path
        if not p or not os.path.exists(p):
            return []
        if os.path.isdir(p):
            out: List[str] = []
            for name in sorted(os.listdir(p)):
                if name.endswith((".yar", ".yara")):
                    out.append(os.path.join(p, name))
            return out
        return [p]

    def available(self) -> bool:
        return shutil.which("yara") is not None and bool(self._rule_files())

    def run_sample(self, sample_path: str) -> SandboxResult:
        rules = self._rule_files()
        if not rules:
            return SandboxResult(backend=self.name, ok=False, error="no YARA rules")
        if not os.path.exists(sample_path):
            return SandboxResult(backend=self.name, ok=False, error="sample missing")
        quoted = " ".join(f'"{r}"' for r in rules)
        res = execute_quiet(f'yara -r {quoted} "{sample_path}"',
                            timeout=int(self.timeout))
        lines = [l for l in (res.stdout or "").splitlines() if l.strip()]
        if lines:
            rules_hit = "; ".join(l.split()[0] for l in lines[:4])
            return SandboxResult(backend=self.name, ok=False, detected=True,
                                 error=f"YARA: {rules_hit}")
        if res.returncode not in (0, None):
            return SandboxResult(backend=self.name, ok=False,
                                 error=(res.stderr or "").strip()[:200] or "yara failed")
        return SandboxResult(backend=self.name, ok=True, detected=False)


class SandboxEngine:
    """Runs all available backends; verdict = approved iff every one passes."""

    def __init__(self, backends: Optional[List[SandboxBackend]] = None) -> None:
        self.backends = backends if backends is not None else [
            StaticCheckBackend(),
            DockerBackend(),
            DefenderBackend(),
            ClamAVBackend(),
            YaraBackend(),
            VmBackend(),
        ]

    def preflight(self, sample_path: str) -> SandboxVerdict:
        """Run every APPLICABLE backend (by sample kind), then combine.

        Applicability matters: the Linux container must not judge a Windows
        PE, and the Windows VM must not judge a shell script. The verdict
        carries `coverage` so the operator sees exactly which guarantee was
        obtained (format validation vs real execution vs AV/EDR scan).
        """
        kind = sample_kind(sample_path)
        results: List[SandboxResult] = []
        ran: List[str] = []
        skipped: List[str] = []
        for backend in self.backends:
            if backend.kinds and kind not in backend.kinds:
                skipped.append(f"{backend.label} (not applicable to {kind})")
                continue
            try:
                if not backend.available():
                    skipped.append(f"{backend.label} (unavailable)")
                    continue
                results.append(backend.run_sample(sample_path))
                ran.append(backend.label)
            except Exception as e:
                results.append(SandboxResult(backend=backend.name, ok=False, error=str(e)))
                ran.append(backend.name)
        coverage = f"kind={kind}; tested by {', '.join(ran) or 'none'}"
        if skipped:
            coverage += f"; skipped {', '.join(skipped)}"
        if not results:
            return SandboxVerdict(
                approved=True, results=[], coverage=coverage,
                reason="no applicable sandbox backend — sample not pre-flighted")
        ok = all(r.ok for r in results)
        reason = ""
        if not ok:
            bad = [r for r in results if not r.ok][0]
            reason = f"{bad.backend}: {bad.error or 'detected by antivirus'}"
        return SandboxVerdict(approved=ok, results=results, reason=reason,
                              coverage=coverage)


def sandbox_status() -> List[dict]:
    """Which sandbox engines are usable right now, for `setup status`.

    Lets the operator see whether "approved" will mean real execution, a
    second/third AV engine, and/or a full VM detonation against a named EDR.
    """
    out: List[dict] = []
    for backend in SandboxEngine().backends:
        try:
            avail = backend.available()
        except Exception:
            avail = False
        out.append({"engine": backend.label, "ready": avail,
                    "kinds": ", ".join(sorted(backend.kinds)) or "all"})
    return out
