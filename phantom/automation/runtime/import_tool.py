"""import_tool.py — level-3 capability discovery (assisted, offline).

AutoModeBrief §4.3: Phantom may PROPOSE a driver for a tool it has never seen,
but the flow must be

    verify hash -> run ONLY --help/-h/--version -> propose a CANDIDATE
    manifest -> leave it DISABLED

and never

    file found -> execute.

This module performs exactly that. :func:`probe` runs the binary with only
``--version`` and ``--help`` (never a target), through an injected runner so
tests are offline. :func:`propose` builds a candidate skeleton from the probe
evidence, hashes the binary for provenance, and — given a registry — records
it in the ``candidate`` state. It NEVER enables anything and never writes a
runnable command template: the operator reviews and approves.

:func:`render_manifest` writes the candidate JSON into a driver directory so
it can be inspected, but the manifest carries no ``command``/``argv`` yet, so
the driver loader ignores it until a human fills it in.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional

from phantom.automation.runtime import approval as _approval
from phantom.automation.runtime.capability_registry import (
    CapabilityRecord,
    sha256_file,
)

# only these flags are ever passed to a freshly discovered binary
PROBE_FLAGS = ("--version", "--help")
_PROBE_TIMEOUT = 8


def _default_runner(argv: List[str], timeout: int):
    """Run one probe command; returns (returncode, output). Never raises."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except Exception as exc:  # noqa: BLE001 — a failed probe is data, not fatal
        return -1, f"<probe failed: {exc}>"


@dataclass
class ProbeResult:
    binary: str
    path: str = ""
    sha256: str = ""
    version: str = ""
    help_text: str = ""
    findings: List[str] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return bool(self.path)


@dataclass
class Proposal:
    """A candidate manifest plus the evidence that produced it."""

    cap_id: str
    manifest: Dict[str, Any]
    probe: ProbeResult
    source: str = "unknown"          # a discovered tool starts untrusted
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.cap_id, "manifest": self.manifest,
                "probe": asdict(self.probe), "source": self.source,
                "note": self.note}


def resolve_binary(binary: str) -> str:
    """Absolute path of a binary on PATH, or '' when missing."""
    if not binary:
        return ""
    if os.path.isabs(binary) and os.path.isfile(binary):
        return binary
    return shutil.which(binary) or ""


def probe(binary: str,
          runner: Optional[Callable[[List[str], int], Any]] = None,
          timeout: int = _PROBE_TIMEOUT) -> ProbeResult:
    """Hash the binary and capture its ``--version`` / ``--help`` text only."""
    runner = runner or _default_runner
    path = resolve_binary(binary)
    result = ProbeResult(binary=binary, path=path)
    if not path:
        result.findings.append("binary not found on PATH")
        return result
    try:
        result.sha256 = sha256_file(path)
    except Exception:
        result.sha256 = ""
    for flag in PROBE_FLAGS:
        code, output = runner([path, flag], timeout)
        text = (output or "").strip()
        if flag == "--version":
            result.version = text[:200]
        else:
            result.help_text = text[:4000]
        (result.findings.append(f"{flag}: rc={code} ({len(text)} chars)"))
    return result


def propose(binary: str, *, cap_id: str = "", category: str = "recon",
            description: str = "",
            runner: Optional[Callable[[List[str], int], Any]] = None,
            registry: Any = None,
            name: str = "") -> Proposal:
    """Probe a binary and build a DISABLED candidate manifest + provenance."""
    probe_result = probe(binary, runner=runner)
    tool = os.path.basename(probe_result.path or binary) or binary
    stable_id = cap_id or _slug(name or tool)
    # a candidate skeleton: NO command/argv yet, so the loader ignores it
    # until a human supplies the invocation and approves.
    manifest: Dict[str, Any] = {
        "id": stable_id,
        "tool": tool,
        "category": category,
        "description": description or f"candidate driver for {tool}",
        "effects": [],
        "inputs": [{"name": "target", "type": "str", "required": True}],
        "requires": ["target"],
        "stealth_level": "active",
        "detection_risk": 0.5,
        "timeout": 60,
        "_candidate": True,
        "_version": probe_result.version,
    }
    proposal = Proposal(cap_id=stable_id, manifest=manifest,
                        probe=probe_result, source="unknown",
                        note="candidate: reviewed and enabled by an operator")
    if registry is not None:
        try:
            record = CapabilityRecord(
                capability=stable_id, tool=tool, state="discovered",
                version=probe_result.version, path=probe_result.path,
                sha256=probe_result.sha256, source="unknown",
                status_history=[], note=proposal.note)
            registry.discover(record)
            registry.transition(stable_id, "candidate", actor="import",
                                reason="proposed by import")
        except Exception:
            pass
    return proposal


def expected_action(manifest: Dict[str, Any]) -> _approval.ApprovalDecision:
    """The approval policy's verdict for a candidate manifest (for the CLI)."""
    from phantom.automation.runtime.drivers import parse_driver
    driver = parse_driver(manifest) if manifest.get("command") \
        or manifest.get("argv") else None
    if driver is None:
        return _approval.ApprovalDecision(
            _approval.ACTION_DENY, "incomplete manifest (no command yet)",
            ["fill in command/argv", "review", "approve"])
    return _approval.decide(driver, source="unknown", lab=False)


def render_manifest(proposal: Proposal, directory: str) -> str:
    """Write the candidate JSON into ``directory`` (disabled by construction).

    Returns the path written, or '' on failure. The file is not runnable
    until a human adds ``command``/``argv`` and approves the id.
    """
    try:
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f"{proposal.cap_id}.candidate.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(proposal.manifest, fh, indent=2, sort_keys=True)
        return path
    except OSError:
        return ""


def _slug(text: str) -> str:
    out = []
    for ch in str(text).strip().lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in "-_. ":
            out.append("_")
    slug = "".join(out).strip("_")
    return slug or "candidate"
