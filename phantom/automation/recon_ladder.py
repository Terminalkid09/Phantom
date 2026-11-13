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

Scan profiles (one agent, never sub-agents — target contact stays serial):

    balanced    exactly the historical behaviour: -sT, -T4, min-rate 1200,
                chunks in ascending order, no delay. Default.
    quiet       -T2, min-rate 300, bounded inter-chunk jitter.
    blend       shuffled chunk order, per-chunk rate/timing/source-port
                rotation, bounded jitter, optional SYN only with an explicit
                `allow_syn=True`.

Honest limits: source-port selection and timing changes are WEAK camouflage,
not spoofing. A TCP handshake must return, so the source IP cannot be faked;
the only real way to change the origin is a different egress (proxy/VPN),
which this module does not pretend to provide. No decoys, no MAC spoofing.

Design: every I/O touch is injectable (`runner`, `ping`, `tcp_probe`,
`sleep`, `clock`) so the whole ladder is verifiable offline, and no function
here executes anything when merely building a plan.
"""

from __future__ import annotations

import random
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

SCAN_PROFILES = ("quiet", "balanced", "blend")
# A small set of ports that are almost always permitted through a firewall.
# One per BLEND chunk; documented as camouflage, never as spoofing.
SOURCE_PORTS = (53, 80, 443, 853)
_BLEND_RATES = (600, 900, 1200, 1800)
_BLEND_TIMINGS = ("-T3", "-T4")

# The profile the currently-running agent asked for. The in-process engine
# runs on a worker thread, so a thread-local would not survive; one module
# value is correct because every acting cell in a run shares the same
# operator policy, and calls are serialised by the egress permit.
_DEFAULT_PROFILE = "balanced"

# nmap text lines: "22/tcp   open  ssh", "Not shown: 8191 filtered tcp ports"
_SERVICE_LINE = re.compile(
    r"^(\d{1,5})/(tcp|udp)\s+(open|filtered|closed|open\|filtered)"
    r"(?:\s+(\S+))?", re.MULTILINE)
_NOT_SHOWN = re.compile(r"Not shown:\s+(\d+)\s+(\w+)\s+(tcp|udp)\s+ports",
                        re.IGNORECASE)


# ── scan profiles ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ScanProfile:
    """How one ladder run paces and varies its chunks."""

    name: str
    rate: int
    timing: str
    jitter: Tuple[float, float]      # (min, max) seconds between chunks
    shuffle: bool = False
    rotate_rate: bool = False
    rotate_timing: bool = False
    rotate_source_port: bool = False
    rotate_technique: bool = False


PROFILES: Dict[str, ScanProfile] = {
    "balanced": ScanProfile("balanced", 1200, "-T4", (0.0, 0.0)),
    "quiet": ScanProfile("quiet", 300, "-T2", (2.0, 5.0),
                         rotate_technique=True),
    "blend": ScanProfile("blend", 1200, "-T4", (0.5, 2.5), shuffle=True,
                         rotate_rate=True, rotate_timing=True,
                         rotate_source_port=True, rotate_technique=True),
}


def _profile(name: str) -> ScanProfile:
    try:
        return PROFILES[str(name or "balanced").lower()]
    except KeyError:
        raise ValueError(f"unknown scan profile {name!r} "
                         f"(want one of {', '.join(SCAN_PROFILES)})")


def set_default_profile(name: Optional[str]) -> None:
    """Set the profile used when ``run_ladder`` is called without one."""
    global _DEFAULT_PROFILE
    _DEFAULT_PROFILE = "balanced" if not name else _profile(name).name


def default_profile() -> str:
    return _DEFAULT_PROFILE


def profile_for_agent(agent) -> str:
    """Map the agent's own stealth/speed posture to a scan profile.

    `full_stealth`/`--stealth` buys quiet; `--aggressive`/`--speed` accepts
    the blend; everything else stays exactly as before.
    """
    style = str(getattr(getattr(agent, "wm", None), "scan_style",
                        "balanced") or "balanced")
    if getattr(agent, "stealth", False) or style == "full_stealth":
        return "quiet"
    if (getattr(agent, "aggressive", False) or getattr(agent, "speed", False)
            or style in ("top_loud", "top_fast")):
        return "blend"
    return "balanced"


def _chunk_params(profile: ScanProfile, rng: random.Random, index: int,
                  *, style: str, allow_syn: bool) -> Dict[str, object]:
    """Rate/timing/technique/source-port/jitter for ONE chunk.

    Balanced is byte-for-byte the historical command: it ignores ``rng``.
    """
    if profile.name == "balanced":
        rate = 500 if style == "full_stealth" else 1200
        return {"rate": rate, "timing": "-T4", "technique": "-sT",
                "source_port": None, "jitter": 0.0}
    rate = rng.choice(_BLEND_RATES) if profile.rotate_rate else profile.rate
    timing = rng.choice(_BLEND_TIMINGS) if profile.rotate_timing \
        else profile.timing
    sport = rng.choice(SOURCE_PORTS) if profile.rotate_source_port else None
    # SYN needs privileges; it is chosen ONLY when the caller said so. Every
    # third chunk rotates so a test (and an operator) can see it happen.
    technique = "-sS" if (allow_syn and profile.rotate_technique
                          and index % 3 == 2) else "-sT"
    jitter = round(rng.uniform(*profile.jitter), 2) if profile.jitter[1] > 0 \
        else 0.0
    return {"rate": rate, "timing": timing, "technique": technique,
            "source_port": sport, "jitter": jitter}


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
    profile: str = "balanced"
    rate: int = 0
    timing: str = ""
    technique: str = ""
    source_port: Optional[int] = None
    jitter_s: float = 0.0

    @property
    def fully_filtered(self) -> bool:
        return (self.ok and not self.open_ports and self.expected > 0
                and self.filtered >= self.expected)

    def marker(self) -> str:
        extra = ""
        if self.profile != "balanced":
            extra = (f" profile={self.profile} rate={self.rate} "
                     f"timing={self.timing or '?'} "
                     f"tech={self.technique or '?'} "
                     f"sport={self.source_port or '-'}")
        return (f"RECON_CHUNK: spec={self.spec} proto={self.proto} "
                f"open={len(self.open_ports)} filtered={self.filtered} "
                f"expected={self.expected} ok={int(self.ok)} "
                f"jitter={self.jitter_s:.2f}s{extra}")


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
    profile: str = "balanced"
    jitter_total_s: float = 0.0

    @property
    def surface(self) -> str:
        return self.verdict

    def marker(self) -> str:
        return (f"RECON_VERDICT: surface={self.verdict} pivot={self.pivot} "
                f"open={','.join(str(p) for p in self.open_ports) or '-'} "
                f"profile={self.profile} "
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
                "profile": self.profile,
                "jitter_total_s": round(self.jitter_total_s, 2),
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
                  style: str = "balanced", profile: str = "balanced",
                  rate: Optional[int] = None, timing: Optional[str] = None,
                  technique: Optional[str] = None,
                  source_port: Optional[int] = None) -> str:
    """The exact bounded command for one chunk (no side effects)."""
    if proto == "udp":
        return (f"nmap -Pn -sU -p {spec} -T4 --max-retries 1 "
                f"--host-timeout 90s {target}")
    chosen_rate = rate if rate is not None else (
        500 if style == "full_stealth" else 1200)
    chosen_timing = timing or "-T4"
    chosen_tech = technique or "-sT"
    sport = f" -g {source_port}" if source_port else ""
    return (f"nmap -Pn {chosen_tech} -p {spec} {chosen_timing} "
            f"--min-rate {chosen_rate} --max-retries 1 "
            f"--host-timeout {CHUNK_TIMEOUT}s{sport} {target}")


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
            from phantom.automation.perception import normalize_service
            services[port] = normalize_service(port, service)
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
    profile: Optional[str] = None,
    seed: Optional[int] = None,
    allow_syn: bool = False,
    sleep: Optional[Callable[[float], None]] = None,
    clock: Optional[Callable[[], float]] = None,
    udp: bool = True,
    emit: Optional[Callable[[str, Dict[str, object]], None]] = None,
) -> LadderResult:
    """Run the bounded ladder and return its typed verdict.

    ``runner(cmd, timeout) -> (ok, output)`` is injectable; the default runs
    nmap (via WSL when the host lacks it). ``profile`` selects pacing;
    ``None`` uses the agent's requested default (balanced). ``seed`` makes a
    blend run deterministic (tests, reproducible engagements). ``sleep`` and
    ``clock`` are injected by tests; production uses the real ones.

    Nothing here retries a filtered chunk: a dropper stays a dropper.
    """
    run = runner or _default_runner
    spec = _profile(profile or _DEFAULT_PROFILE)
    rng = random.Random(seed) if seed is not None else random.Random()
    now = clock or time.monotonic
    do_sleep = sleep or time.sleep
    started = now()
    result = LadderResult(target=target, profile=spec.name)

    def _emit(kind: str, **payload) -> None:
        if emit is not None:
            try:
                emit(kind, payload)
            except Exception:
                pass

    pre = preflight(target, ping=ping, probe=probe)
    result.preflight = pre
    _emit("recon_preflight", reachable=pre.reachable,
          icmp=pre.icmp, tcp_open=list(pre.tcp_open), profile=spec.name)
    if not pre.reachable:
        result.verdict = "unreachable"
        result.pivot = "identity"
        result.reason = ("no ICMP and no TCP answer on "
                         f"{','.join(str(p) for p in PREFLIGHT_PORTS)} — "
                         "host off, asleep or dropping everything")
        result.elapsed = now() - started
        _emit("recon_verdict", verdict=result.verdict, pivot=result.pivot,
              reason=result.reason, profile=spec.name)
        return result

    specs = port_chunks(chunk_size)
    if spec.shuffle:
        rng.shuffle(specs)

    consecutive_filtered = 0
    for index, range_spec in enumerate(specs):
        remaining = budget_s - (now() - started)
        if remaining <= 5:
            result.reason = "time budget exhausted before the port space ended"
            break
        params = _chunk_params(spec, rng, index, style=style,
                               allow_syn=allow_syn)
        jitter = 0.0
        if index and float(params["jitter"]):
            # Bounded by what is LEFT: camouflage must never eat the budget
            # that the remaining chunks need to produce a verdict.
            jitter = min(float(params["jitter"]), max(0.0, remaining - 5.0))
            if jitter > 0:
                do_sleep(jitter)
                result.jitter_total_s += jitter
                remaining = budget_s - (now() - started)
                if remaining <= 5:
                    result.reason = ("time budget exhausted during the "
                                     "inter-chunk delay")
                    break
        cmd_params = {k: v for k, v in params.items() if k != "jitter"}
        cmd = chunk_command(target, range_spec, style=style,
                            profile=spec.name, **cmd_params)
        expected = _spec_size(range_spec)
        t0 = now()
        try:
            ok, output = run(cmd, max(5.0, min(CHUNK_TIMEOUT + 20, remaining)))
        except Exception as exc:
            ok, output = False, str(exc)[:300]
        chunk = ChunkResult(
            spec=range_spec, expected=expected, ok=bool(ok),
            elapsed=now() - t0, error="" if ok else (output or "")[:200],
            profile=spec.name, rate=int(params["rate"]),
            timing=str(params["timing"]), technique=str(params["technique"]),
            source_port=params["source_port"], jitter_s=round(jitter, 2))
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
        _emit("recon_chunk", spec=range_spec, open=len(chunk.open_ports),
              filtered=chunk.filtered, ok=chunk.ok, profile=spec.name,
              jitter=chunk.jitter_s)
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
        udp_spec = ",".join(str(p) for p in sorted(set(UDP_PORTS)))
        remaining = budget_s - (now() - started)
        if remaining > 5:
            cmd = chunk_command(target, udp_spec, proto="udp")
            t0 = now()
            try:
                ok, output = run(cmd, max(5.0, min(120, remaining)))
            except Exception as exc:
                ok, output = False, str(exc)[:300]
            u = ChunkResult(spec=udp_spec, proto="udp",
                            expected=len(set(UDP_PORTS)), ok=bool(ok),
                            elapsed=now() - t0, profile=spec.name)
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
    elif any(c.ok for c in result.chunks) and len(result.chunks) < len(specs):
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
    result.elapsed = now() - started
    _emit("recon_verdict", verdict=result.verdict, pivot=result.pivot,
          reason=result.reason, profile=spec.name)
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
