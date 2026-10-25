"""recon_ladder.py — bounded, observable escalation for network recon.

The old escalation was a single inline step: when the top-100 scan found no
remote-access service, the agent fired one `-p 1-65535` scan. On a host that
DROPs probes that step is unbounded in practice (measured on this LAN:
13 552 s, ~3h46m, all 65 535 ports filtered) and a killed sweep leaves no
partial evidence at all.

This module replaces it with a LADDER whose every rung is bounded, whose
results survive a kill, and whose end state is a typed verdict rather than
"still scanning":

    preflight   ARP/ICMP/TCP reachability. A host that answers nothing is
                `unreachable` — scanning 65k ports at a sleeping laptop is
                not persistence, it is waste.
    rung TCP    the port space in CHUNKS (default 8192). Each chunk is its
                own nmap run, so open ports found early are real evidence
                even if the next chunk never returns. Two consecutive
                all-filtered chunks stop the rung (the host is dropping,
                not hiding).
    rung UDP    top UDP ports (161/500/1900/5353/67): on appliances the only
                surface is often UDP.
    verdict     open | filtered | partial | unreachable, with the counts as
                evidence, plus the PIVOT this implies: a filtered endpoint
                is not a network problem, it is an identity problem.

Design: every I/O touch is injectable (`runner`, `ping`, `tcp_probe`) so the
whole ladder is verifiable offline, and no function here executes anything
when merely building a plan.
"""

from __future__ import annotations

import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# ── policy defaults ─────────────────────────────────────────────────────────

CHUNK_SIZE = 8192
# Two consecutive fully-filtered chunks are enough to call the host a
# dropper: a firewall that hides one 8k slice hides the next one too.
FILTERED_CHUNKS_TO_STOP = 2
# Per-chunk wall clock. `--host-timeout` makes nmap return partial results,
# this is the outer belt for a hung WSL wrapper.
CHUNK_TIMEOUT = 150
UDP_PORTS = (161, 500, 1900, 5353, 67, 123, 69, 137, 138, 5353)
# Enough surfaces that a live endpoint is not declared dead: a host can
# block ICMP and 22/80/443 and still expose 445/3389/8080. An endpoint with
# none of these is a phone/asleep box — the identity pivot is the honest
# answer, and scanning 65k ports would not change it.
PREFLIGHT_PORTS = (22, 80, 443, 445, 3389, 8080, 8443, 8000, 53, 21, 25)
DEFAULT_BUDGET = 600.0

# nmap text lines: "22/tcp   open  ssh", "Not shown: 8191 filtered tcp ports"
_SERVICE_LINE = re.compile(
    r"^(\d{1,5})/(tcp|udp)\s+(open|filtered|closed|open\|filtered)"
    r"(?:\s+(\S+))?", re.MULTILINE)
_NOT_SHOWN = re.compile(r"Not shown:\s+(\d+)\s+(\w+)\s+(tcp|udp)\s+ports",
                        re.IGNORECASE)


# ── data model ──────────────────────────────────────────────────────────────

@dataclass
class Preflight:
    """What the target answered before any scan packet was sent."""

    reachable: bool = False
    icmp: bool = False
    tcp_open: List[int] = field(default_factory=list)
    error: str = ""

    def marker(self) -> str:
        return (f"RECON_PREFLIGHT: reachable={int(self.reachable)} "
                f"icmp={int(self.icmp)} tcp_open="
                f"{','.join(str(p) for p in self.tcp_open) or '-'}")


@dataclass
class ChunkResult:
    """One bounded slice of the port space."""

    spec: str
    proto: str = "tcp"
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    filtered: int = 0
    expected: int = 0
    ok: bool = True
    error: str = ""
    elapsed: float = 0.0

    @property
    def fully_filtered(self) -> bool:
        return (self.ok and not self.open_ports and self.expected > 0
                and self.filtered >= self.expected)

    def marker(self) -> str:
        return (f"RECON_CHUNK: spec={self.spec} proto={self.proto} "
                f"open={len(self.open_ports)} filtered={self.filtered} "
                f"expected={self.expected} ok={int(self.ok)}")


@dataclass
class LadderResult:
    """The ladder's end state: a verdict, not a process still running."""

    target: str
    verdict: str = "unreachable"      # open|filtered|partial|unreachable
    pivot: str = "identity"           # network|identity
    reason: str = ""
    preflight: Optional[Preflight] = None
    chunks: List[ChunkResult] = field(default_factory=list)
    udp: List[ChunkResult] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    elapsed: float = 0.0

    @property
    def surface(self) -> str:
        return self.verdict

    def marker(self) -> str:
        return (f"RECON_VERDICT: surface={self.verdict} pivot={self.pivot} "
                f"open={','.join(str(p) for p in self.open_ports) or '-'} "
                f"reason={_oneline(self.reason)}")

    def markers(self) -> List[str]:
        out: List[str] = []
        if self.preflight is not None:
            out.append(self.preflight.marker())
        out.extend(c.marker() for c in self.chunks)
        out.extend(c.marker() for c in self.udp)
        for port in self.open_ports:
            service = self.services.get(port, "")
            out.append(f"SERVICE: port={port} proto=tcp state=open "
                       f"service={service or 'unknown'}")
        out.append(self.marker())
        return out

    def to_dict(self) -> Dict[str, object]:
        return {"target": self.target, "verdict": self.verdict,
                "pivot": self.pivot, "reason": self.reason,
                "open_ports": list(self.open_ports),
                "services": dict(self.services),
                "elapsed": round(self.elapsed, 1),
                "chunks": [c.marker() for c in self.chunks],
                "udp": [c.marker() for c in self.udp]}


# ── planning (pure) ─────────────────────────────────────────────────────────

def port_chunks(size: int = CHUNK_SIZE, high: int = 65535) -> List[str]:
    """`["1-8192", "8193-16384", ...]` — bounded slices, never one 65k run."""
    if size <= 0:
        raise ValueError("chunk size must be positive")
    out: List[str] = []
    start = 1
    while start <= high:
        end = min(start + size - 1, high)
        out.append(f"{start}-{end}")
        start = end + 1
    return out


def chunk_command(target: str, spec: str, *, proto: str = "tcp",
                  style: str = "balanced") -> str:
    """The exact bounded command for one chunk (no side effects)."""
    rate = "500" if style == "full_stealth" else "1200"
    if proto == "udp":
        return (f"nmap -Pn -sU -p {spec} -T4 --max-retries 1 "
                f"--host-timeout 90s {target}")
    return (f"nmap -Pn -sT -p {spec} -T4 --min-rate {rate} "
            f"--max-retries 1 --host-timeout {CHUNK_TIMEOUT}s {target}")


# ── parsing ─────────────────────────────────────────────────────────────────

def parse_scan(output: str, *, proto: str = "tcp") -> Tuple[List[int], Dict[int, str], int]:
    """(open ports, {port: service}, filtered count) from nmap text output."""
    open_ports: List[int] = []
    services: Dict[int, str] = {}
    for m in _SERVICE_LINE.finditer(output or ""):
        port, line_proto, state, service = (
            int(m.group(1)), m.group(2), m.group(3), m.group(4) or "")
        if line_proto != proto or "open" not in state:
            continue
        if port not in open_ports:
            open_ports.append(port)
            services[port] = service
    filtered = 0
    for m in _NOT_SHOWN.finditer(output or ""):
        if m.group(3).lower() == proto:
            try:
                filtered += int(m.group(1))
            except ValueError:
                pass
    return sorted(open_ports), services, filtered


# ── I/O (injectable) ────────────────────────────────────────────────────────

def tcp_probe(host: str, port: int, timeout: float = 0.6) -> bool:
    """One connect() — true when the port answered anything."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def icmp_probe(host: str, timeout: float = 1.5) -> bool:
    """One ICMP echo. Uses the OS ping; absence/failure means 'no answer'."""
    import os
    if os.name == "nt":
        argv = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        argv = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout + 1.5)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def preflight(host: str, *, ping: Optional[Callable[[str], bool]] = None,
              probe: Optional[Callable[[str, int], bool]] = None,
              ports: Sequence[int] = PREFLIGHT_PORTS) -> Preflight:
    """Decide whether the host answers AT ALL before spending a scan on it."""
    out = Preflight()
    check = probe or tcp_probe
    try:
        out.tcp_open = [int(p) for p in ports if check(host, int(p))]
    except Exception as exc:                     # a broken probe is "no"
        out.error = str(exc)[:200]
    try:
        out.icmp = bool((ping or icmp_probe)(host))
    except Exception:
        out.icmp = False
    out.reachable = out.icmp or bool(out.tcp_open)
    return out


def _default_runner(cmd: str, timeout: float) -> Tuple[bool, str]:
    """Run nmap locally, or through the WSL wrapper when only WSL has it."""
    import shlex
    import shutil
    argv: List[str]
    if shutil.which("nmap"):
        argv = shlex.split(cmd)
    else:
        from phantom.automation.runtime.toolchain import _wsl_which
        wrapper = _wsl_which("nmap")
        if not wrapper:
            return False, "nmap: not installed on the host or in WSL"
        argv = shlex.split(wrapper) + shlex.split(cmd)[1:]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout)
        text = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode in (0, 1), text      # nmap: 1 = no match
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


# ── the ladder ──────────────────────────────────────────────────────────────

def run_ladder(
    target: str,
    *,
    runner: Optional[Callable[[str, float], Tuple[bool, str]]] = None,
    ping: Optional[Callable[[str], bool]] = None,
    probe: Optional[Callable[[str, int], bool]] = None,
    budget_s: float = DEFAULT_BUDGET,
    chunk_size: int = CHUNK_SIZE,
    filtered_chunks_to_stop: int = FILTERED_CHUNKS_TO_STOP,
    style: str = "balanced",
    udp: bool = True,
    emit: Optional[Callable[[str, Dict[str, object]], None]] = None,
) -> LadderResult:
    """Run the bounded ladder and return its typed verdict.

    ``runner(cmd, timeout) -> (ok, output)`` is injectable; the default runs
    nmap (via WSL when the host lacks it). Nothing here retries a filtered
    chunk: a dropper stays a dropper.
    """
    run = runner or _default_runner
    started = time.monotonic()
    result = LadderResult(target=target)

    def _emit(kind: str, **payload) -> None:
        if emit is not None:
            try:
                emit(kind, payload)
            except Exception:
                pass

    pre = preflight(target, ping=ping, probe=probe)
    result.preflight = pre
    _emit("recon_preflight", reachable=pre.reachable,
          icmp=pre.icmp, tcp_open=list(pre.tcp_open))
    if not pre.reachable:
        result.verdict = "unreachable"
        result.pivot = "identity"
        result.reason = ("no ICMP and no TCP answer on "
                         f"{','.join(str(p) for p in PREFLIGHT_PORTS)} — "
                         "host off, asleep or dropping everything")
        result.elapsed = time.monotonic() - started
        _emit("recon_verdict", verdict=result.verdict, pivot=result.pivot,
              reason=result.reason)
        return result

    consecutive_filtered = 0
    for spec in port_chunks(chunk_size):
        remaining = budget_s - (time.monotonic() - started)
        if remaining <= 5:
            result.reason = "time budget exhausted before the port space ended"
            break
        cmd = chunk_command(target, spec, style=style)
        expected = _spec_size(spec)
        t0 = time.monotonic()
        try:
            ok, output = run(cmd, max(5.0, min(CHUNK_TIMEOUT + 20, remaining)))
        except Exception as exc:
            ok, output = False, str(exc)[:300]
        chunk = ChunkResult(spec=spec, expected=expected, ok=bool(ok),
                            elapsed=time.monotonic() - t0,
                            error="" if ok else (output or "")[:200])
        if ok:
            ports, services, filtered = parse_scan(output, proto="tcp")
            chunk.open_ports = ports
            chunk.services = services
            chunk.filtered = filtered
            for port in ports:
                if port not in result.open_ports:
                    result.open_ports.append(port)
                result.services.setdefault(port, services.get(port, ""))
        result.chunks.append(chunk)
        _emit("recon_chunk", spec=spec, open=len(chunk.open_ports),
              filtered=chunk.filtered, ok=chunk.ok)
        if chunk.open_ports:
            consecutive_filtered = 0
            continue
        if chunk.fully_filtered:
            consecutive_filtered += 1
        else:
            consecutive_filtered = 0
        if consecutive_filtered >= max(1, filtered_chunks_to_stop):
            result.reason = (
                f"{consecutive_filtered} consecutive chunks "
                f"({consecutive_filtered * chunk_size} ports) fully filtered "
                "— the host drops probes, deeper TCP chunks will not help")
            _emit("recon_stop", reason=result.reason)
            break

    if udp and not result.open_ports:
        spec = ",".join(str(p) for p in sorted(set(UDP_PORTS)))
        remaining = budget_s - (time.monotonic() - started)
        if remaining > 5:
            cmd = chunk_command(target, spec, proto="udp")
            t0 = time.monotonic()
            try:
                ok, output = run(cmd, max(5.0, min(120, remaining)))
            except Exception as exc:
                ok, output = False, str(exc)[:300]
            u = ChunkResult(spec=spec, proto="udp", expected=len(set(UDP_PORTS)),
                            ok=bool(ok), elapsed=time.monotonic() - t0)
            if ok:
                ports, services, filtered = parse_scan(output, proto="udp")
                u.open_ports = ports
                u.services = services
                u.filtered = filtered
                for port in ports:
                    if port not in result.open_ports:
                        result.open_ports.append(port)
                    result.services.setdefault(port, services.get(port, ""))
            result.udp.append(u)
            _emit("recon_udp", open=len(u.open_ports), ok=u.ok)

    if result.open_ports:
        result.verdict = "open"
        result.pivot = "network"
        result.reason = (f"{len(result.open_ports)} open port(s): "
                         + ",".join(str(p) for p in result.open_ports))
    elif any(c.ok for c in result.chunks) and len(result.chunks) < len(
            port_chunks(chunk_size)):
        result.verdict = "filtered" if result.reason else "partial"
        result.pivot = "identity"
        if not result.reason:
            result.reason = "no open port found in the chunks that ran"
    elif result.chunks and all(c.ok for c in result.chunks):
        result.verdict = "filtered"
        result.pivot = "identity"
        result.reason = ("every TCP chunk returned no open port — the "
                         "surface is filtered, not hidden")
    else:
        result.verdict = "partial"
        result.pivot = "identity"
        result.reason = result.reason or "the scan could not be completed"

    if result.verdict in ("filtered", "partial") and result.pivot == "identity":
        result.reason += ("; network escalation is exhausted — pivot to the "
                          "identity path instead of re-arming the scan")
    result.elapsed = time.monotonic() - started
    _emit("recon_verdict", verdict=result.verdict, pivot=result.pivot,
          reason=result.reason)
    return result


def _spec_size(spec: str) -> int:
    """Number of ports a chunk spec covers (`1-8192` -> 8192)."""
    try:
        if "-" in spec:
            start, end = spec.split("-", 1)
            return max(0, int(end) - int(start) + 1)
        return len([p for p in spec.split(",") if p.strip()])
    except (TypeError, ValueError):
        return 0


def _oneline(text: str) -> str:
    return " ".join(str(text or "").split())[:240]


def pivot_for(result: LadderResult) -> str:
    """The goal a caller should switch to after this verdict."""
    return "identity" if result.pivot == "identity" else "deliver"
