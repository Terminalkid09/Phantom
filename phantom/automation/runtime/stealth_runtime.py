"""
stealth_runtime.py — operational stealth: human-like cadence, split scans.

A StealthRuntime sits between the orchestrator and the tool runner:
  * TimingGovernor  — machine-paced actions are fingerprints. Every action
                      waits a human-looking delay; the cadence is jittered
                      so no periodic pattern emerges.
  * ScanSplitter    — a big scan is a fingerprint too. Split into chunks
                      with random inter-chunk delays and shuffled order.
  * StealthRuntime  — wraps both + the egress lease: run(action, command)
                      acquires egress, sleeps human delay, executes via
                      execute_quiet, records opsec spend.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from phantom.automation.runtime.egress import Egress, EgressManager
from phantom.automation.guidance.stealth import StealthEngine


class TimingGovernor:
    """Human-ish pacing with anti-periodicity jitter."""

    def __init__(self, base_delay: float = 1.5, jitter: float = 0.6,
                 rng: Optional[random.Random] = None) -> None:
        self.base_delay = base_delay
        self.jitter = jitter
        self._rng = rng or random.Random()
        self._last: List[float] = []  # recent delays, for periodicity check

    def next_delay(self) -> float:
        d = max(0.1, self.base_delay + self._rng.uniform(-self.jitter, self.jitter))
        self._last.append(d)
        self._last = self._last[-8:]
        return d

    def wait(self) -> float:
        d = self.next_delay()
        time.sleep(d)
        return d

    def is_periodic(self) -> bool:
        """True if the last delays form a machine-like fixed cadence."""
        if len(self._last) < 4:
            return False
        spread = max(self._last) - min(self._last)
        return spread < 0.01  # identical delays = scripted


class ScanSplitter:
    """Splits one big scan command into chunks with human gaps."""

    def __init__(self, chunk_size: int = 20, gap_range: Tuple[float, float] = (2.0, 6.0),
                 rng: Optional[random.Random] = None) -> None:
        self.chunk_size = chunk_size
        self.gap_range = gap_range
        self._rng = rng or random.Random()

    def split_ports(self, ports: List[str], base: str = "nmap -Pn -sT") -> List[str]:
        """Split a port list into chunked commands with shuffled order."""
        if len(ports) <= self.chunk_size:
            return [f"{base} -p {','.join(ports)}"]
        chunks = [ports[i:i + self.chunk_size] for i in range(0, len(ports), self.chunk_size)]
        chunks = list(chunks)
        self._rng.shuffle(chunks)
        return [f"{base} -p {','.join(c)}" for c in chunks]

    def gap_between_chunks(self) -> float:
        return self._rng.uniform(*self.gap_range)


@dataclass
class StealthRun:
    command: str
    ok: bool
    output: str = ""
    delay: float = 0.0
    egress: Optional[str] = None
    timed_out: bool = False   # runner hit its timeout (output may be partial)
    elapsed: float = 0.0


class StealthRuntime:
    """The single point through which the agent executes commands."""

    def __init__(self, stealth: StealthEngine, runner: Callable = None,
                 governor: Optional[TimingGovernor] = None,
                 splitter: Optional[ScanSplitter] = None,
                 egress: Optional[EgressManager] = None,
                 cost_per_action: float = 0.5) -> None:
        from phantom.core.executor import execute_quiet
        self.stealth = stealth
        self.runner = runner or (lambda cmd, timeout: execute_quiet(cmd, timeout=timeout))
        self.governor = governor or TimingGovernor()
        self.splitter = splitter or ScanSplitter()
        self.egress = egress or EgressManager()
        self.cost_per_action = cost_per_action

    def run(self, command: str, category: str = "recon",
            stealth_level: str = "passive", agent: str = "agent-1",
            timeout: int = 60) -> StealthRun:
        # egress discipline: one box at a time
        lease = self.egress.acquire(agent)
        if lease is None:
            return StealthRun(command=command, ok=False,
                              output="egress busy (single-egress discipline)")
        try:
            delay = self.governor.wait()
            self.stealth.consume(self.cost_per_action)
            t0 = time.time()
            result = self.runner(command, timeout=timeout)
            return StealthRun(command=command, ok=result.ok,
                              output=(result.stdout or "")[:200_000],
                              delay=delay, egress=lease.name,
                              timed_out=bool(getattr(result, "timed_out", False)),
                              elapsed=time.time() - t0)
        finally:
            self.egress.release(lease)

    def run_split_scan(self, ports: List[str], base: str, category: str = "scan",
                       stealth_level: str = "active", agent: str = "agent-1",
                       timeout: int = 60) -> List[StealthRun]:
        """Run a big port list in human-gapped chunks."""
        runs = []
        for cmd in self.splitter.split_ports(ports, base=base):
            runs.append(self.run(cmd, category, stealth_level, agent, timeout))
            if not runs[-1].ok:
                break
            gap = self.splitter.gap_between_chunks()
            time.sleep(gap)
        return runs
