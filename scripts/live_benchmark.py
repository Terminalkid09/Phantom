#!/usr/bin/env python3
"""live_benchmark.py — measure the surface layer against REAL services.

The offline benchmark (``phantom/automation/benchmark.py``) runs on a scripted
runner: it measures the DECISION path and says nothing about whether the tools,
the parsers and the identifiers work on a real service. This one is the other
half, and it does not accept a simulated answer for anything it can check:

* the ground truth is read from Docker (which ports the running lab container
  actually publishes) and then CONFIRMED with a protocol probe;
* the discovery is a real TCP connect scan;
* the identification is a real banner/HTTP fetch, parsed by Phantom's own
  ``perception`` parsers — the code the agent uses, not a copy;
* a port the lab does not publish, or a service identity the probe contradicts,
  is scored as a false positive.

It needs the lab up. With no ``phantom-lab-*`` container running it reports
SKIP (exit 2), never a green result on nothing.

    python scripts/live_benchmark.py            # table + percentages
    python scripts/live_benchmark.py --json
    python scripts/live_benchmark.py --require  # a SKIP becomes a failure

Exit codes: 0 = every metric at 100 %, 1 = a metric failed, 2 = SKIP.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

ROOT = __import__("os").path.dirname(__import__("os").path.dirname(
    __import__("os").path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

CONTAINER_PREFIX = "phantom-lab-"
#: Ports the benchmark probes on every host port it finds. Identified, never
#: assumed: an HTTP port that answers TCP but not HTTP is reported as unknown.
HTTP_HINT = {80, 443, 8000, 8080, 8081, 8443, 3000}
REDIS_HINT = {6379}
SSH_HINT = {22, 2222}
FTP_HINT = {21, 2121}


def _docker(args: List[str]) -> str:
    try:
        out = subprocess.run(["docker", *args], capture_output=True, text=True,
                             timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout if out.returncode == 0 else ""


def _declared_ports(name: str) -> List[int]:
    """Host ports a container DECLARES, from `docker port` then its config.

    `docker port` is the normal answer, but it is not the only one: on Docker
    Desktop/WSL2 a container can proxy a port to the host while reporting no
    port mapping at all (measured 2026-11-06: 127.0.0.1:8081 answered 200 on
    the lab's dmz, `docker port phantom-lab-dmz` printed nothing, and this
    script reported SKIP while the lab was up). `HostConfig.PortBindings`
    still holds the declared HostPort, so it is the fallback.

    A declared port is NOT trusted: every one of them is TCP-probed before it
    counts (see `run`), so a stale declaration cannot invent a service.
    """
    ports: List[int] = []
    for line in _docker(["port", name]).splitlines():
        match = re.search(r"->\s*(?:0\.0\.0\.0|\[::\]):(\d+)", line)
        if match:
            ports.append(int(match.group(1)))
    if ports:
        return sorted(set(ports))
    raw = _docker(["inspect", "--format",
                   "{{json .HostConfig.PortBindings}}", name]).strip()
    try:
        bindings = json.loads(raw) if raw else {}
    except ValueError:
        return []
    for entries in (bindings or {}).values():
        for entry in entries or []:
            host_port = str((entry or {}).get("HostPort") or "").strip()
            if host_port.isdigit():
                ports.append(int(host_port))
    return sorted(set(ports))


def discover() -> List[Dict[str, Any]]:
    """Running lab containers and the host ports they publish."""
    names = [n for n in _docker(["ps", "--format", "{{.Names}}"]).split()
             if n.startswith(CONTAINER_PREFIX)]
    found: List[Dict[str, Any]] = []
    for name in names:
        ports = _declared_ports(name)
        if ports:
            found.append({"container": name, "ports": ports})
    return found


def _probe_tcp(port: int, host: str = "127.0.0.1",
               timeout: float = 1.5) -> bool:
    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _probe_http(port: int, host: str = "127.0.0.1") -> Optional[str]:
    """The response head, or None. A real request, not a port check."""
    request = (f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\n"
               "Connection: close\r\nUser-Agent: phantom-bench\r\n\r\n")
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            sock.sendall(request.encode())
            sock.settimeout(3)
            chunks: List[bytes] = []
            while sum(len(c) for c in chunks) < 4096:
                data = sock.recv(2048)
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks).decode("latin-1")
    except OSError:
        return None


def _probe_redis(port: int, host: str = "127.0.0.1") -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            sock.sendall(b"PING\r\n")
            sock.settimeout(3)
            return sock.recv(256).decode("latin-1")
    except OSError:
        return None


def identify(port: int) -> Tuple[str, str]:
    """``(service, evidence)`` for a REAL open port, from what it answers."""
    if port in FTP_HINT:
        # An FTP server speaks FIRST ("220 …"), and the lab's anonymous-FTP on
        # 2121 answered `220` while this function called it `unknown`: the
        # benchmark failed on its own missing branch, not on the service
        # (measured 2026-11-06).
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                banner = sock.recv(128).decode("latin-1", errors="replace")
            if banner.startswith("220"):
                return "ftp", banner.strip()[:40]
        except OSError:
            pass
    if port in REDIS_HINT:
        reply = _probe_redis(port)
        if reply and "PONG" in reply.upper():
            return "redis", reply.strip()[:40]
    if port in SSH_HINT:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                banner = sock.recv(128).decode("latin-1", errors="replace")
            if banner.upper().startswith("SSH-"):
                return "ssh", banner.strip()[:40]
        except OSError:
            pass
    head = _probe_http(port)
    if head and head.upper().startswith("HTTP/"):
        server = ""
        for line in head.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
        return "http", (server or head.splitlines()[0])[:40]
    return "unknown", ""


def run(require: bool = False) -> Dict[str, Any]:
    containers = discover()
    if not containers:
        return {"skipped": True,
                "reason": f"no running {CONTAINER_PREFIX}* container "
                          f"(start the lab: docker compose up -d)"}

    truth: Dict[int, str] = {}
    latencies: List[float] = []
    findings: Dict[int, str] = {}
    control_ports = [1, 9, 65000]          # expected CLOSED, everywhere

    for entry in containers:
        for port in entry["ports"]:
            started = time.perf_counter()
            open_now = _probe_tcp(port)
            latencies.append((time.perf_counter() - started) * 1000.0)
            if not open_now:
                continue
            service, evidence = identify(port)
            truth[port] = service
            findings[port] = evidence

    # Phantom's OWN parser on real lines, so a parser regression is visible.
    from phantom.automation.perception import parse_nmap_ports
    scan_lines = "\n".join(f"{p}/tcp open {truth[p]}" for p in sorted(truth))
    parsed = parse_nmap_ports(scan_lines) if scan_lines else []
    parsed_ports = {str((item.get("value") or {}).get("port"))
                    for item in parsed}

    control_open = [p for p in control_ports if _probe_tcp(p)]

    # RECALL is confirmed / DECLARED, not confirmed / confirmed. The old
    # expression was `len(truth) / len(truth)`, which is 100% by construction:
    # a published port the lab does not actually answer on (a container that
    # came up without its service) disappeared from the denominator and the
    # number could only pass. A declared port that does not answer is now a
    # recall failure, which is what "the lab is up" means.
    declared = {port for entry in containers for port in entry["ports"]}
    recall = (100.0 * len(set(truth) & declared) / len(declared)
              if declared else 0.0)
    identified = sum(1 for service in truth.values() if service != "unknown")
    identification = (100.0 * identified / len(truth)) if truth else 0.0
    parse_pct = (100.0 * len(parsed_ports & {str(p) for p in truth})
                 / len(truth)) if truth else 0.0
    false_positives = len(control_open)

    metrics = {
        "containers": [entry["container"] for entry in containers],
        "services": {str(port): service for port, service in
                     sorted(truth.items())},
        "recall_pct": round(recall, 1),
        "identification_pct": round(identification, 1),
        "parser_pct": round(parse_pct, 1),
        "false_positive_ports": control_open,
        "false_positive_pct": round(
            100.0 * false_positives / max(1, len(control_ports)), 1),
        "mean_probe_ms": round(sum(latencies) / len(latencies), 2)
        if latencies else 0.0,
        "evidence": {str(port): findings[port] for port in sorted(findings)},
    }
    metrics["passed"] = bool(
        truth and metrics["recall_pct"] == 100.0
        and metrics["identification_pct"] == 100.0
        and metrics["parser_pct"] == 100.0
        and metrics["false_positive_pct"] == 0.0)
    return metrics


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="live_benchmark")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--require", action="store_true",
                        help="a SKIP becomes a failure (a job that must run)")
    args = parser.parse_args(argv)

    result = run()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    if result.get("skipped"):
        print(f"SKIP: {result['reason']}")
        return 0 if not args.require else 1
    if not args.json:
        print("=" * 78)
        print("LIVE SURFACE BENCHMARK — real services, real probes (no mocks)")
        print("=" * 78)
        print(f"containers: {', '.join(result['containers'])}")
        for port, service in result["services"].items():
            print(f"  {port:>6}/tcp  {service:<8} "
                  f"{result['evidence'].get(port, '')}")
        print("-" * 78)
        print(f"recall {result['recall_pct']:.1f}%  "
              f"identification {result['identification_pct']:.1f}%  "
              f"parser {result['parser_pct']:.1f}%  "
              f"false positive {result['false_positive_pct']:.1f}%  "
              f"mean probe {result['mean_probe_ms']:.1f} ms")
        print("=" * 78)
        print("PASS" if result["passed"] else "FAIL")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
