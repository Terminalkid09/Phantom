"""driver_contract.py — the manifest is a CLAIM; this checks it.

A driver manifest says "run ``nmap`` and read its output". The registry already
refuses a manifest whose command invokes something other than the declared
tool (``drivers._binary_matches``), which stops the trivial lie: a manifest
that names ``nmap`` cannot run ``curl``.

What that check cannot see is SUBSTITUTION. The command says ``nmap``, the
name resolves, and the binary that answers is a different program — replaced
on disk after the manifest was reviewed, or a shim planted earlier in PATH.
The declared tool and the executed tool are then the same WORD and a
different PROCESS.

A manifest may therefore PIN the binary's hash::

    {"id": "dnscan_subdomains", "tool": "dnscan",
     "binary_sha256": "9f2c…", "command": "dnscan -d {target} -o -"}

``verify_binary`` resolves the declared tool on PATH, hashes it and compares.
The result is deliberately three-valued, because "no pin" is neither a pass
nor a failure:

    ok=True,  pinned=False   no pin declared — NOT verified, only unchecked
    ok=True,  pinned=True    the binary matches the declared hash
    ok=False, pinned=True    not found, unreadable, or a DIFFERENT binary

The refusal is reported as ``driver_contract_violation`` so it can never be
confused with a scope refusal or a missing-tool skip.
"""
from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from typing import Any, Optional

#: The audit OUTCOME token for "the driver did not honour its contract".
CONTRACT_VIOLATION = "driver_contract_violation"

_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class ContractCheck:
    """The verdict for one driver's binary contract."""

    ok: bool
    pinned: bool
    reason: str = ""
    path: str = ""
    actual: str = ""

    @property
    def verified(self) -> bool:
        """True only when a pin was actually checked and matched. Unpinned is
        NOT verified — the word is reserved for what was really proven."""
        return bool(self.ok and self.pinned)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "pinned": self.pinned, "verified": self.verified,
                "reason": self.reason, "path": self.path,
                "sha256": self.actual}


def sha256_file(path: str) -> str:
    """Hex digest of a file, streamed (a binary can be large)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def binary_path(tool: str) -> str:
    """Where the declared tool resolves, or \"\"."""
    name = str(tool or "").strip()
    if not name:
        return ""
    # normalise a Windows `.exe` spelling so which() finds it either way
    candidates = [name]
    if os.name == "nt" and not name.lower().endswith(".exe"):
        candidates.append(name + ".exe")
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return ""


def verify_binary(driver: Any) -> ContractCheck:
    """Check a driver's declared binary against its optional pin.

    Never raises: a verifier that explodes must not brick every driver, and
    an UNPINNED manifest needs no check at all. A PINNED manifest whose
    binary cannot be resolved or read is a failure — that is the whole point
    of the pin.
    """
    want = str(getattr(driver, "binary_sha256", "") or "").strip().lower()
    tool = str(getattr(driver, "tool", "") or "").strip()
    if not want:
        return ContractCheck(ok=True, pinned=False, reason="unpinned")
    try:
        path = binary_path(tool)
    except Exception as exc:                              # pragma: no cover
        return ContractCheck(False, True,
                             f"cannot resolve {tool!r}: {exc}")
    if not path:
        return ContractCheck(False, True,
                             f"pinned tool {tool!r} not found on PATH")
    try:
        actual = sha256_file(path)
    except OSError as exc:
        return ContractCheck(False, True,
                             f"cannot read {path}: {exc}", path=path)
    if actual != want:
        return ContractCheck(
            False, True,
            f"sha256 mismatch for {tool}: manifest {want[:12]}…, "
            f"on disk {actual[:12]}… ({path})",
            path=path, actual=actual)
    return ContractCheck(True, True, "binary verified", path=path,
                         actual=actual)


def record_violation(driver: Any, check: Optional[ContractCheck] = None,
                     where: str = "broker.preflight",
                     reason: str = "") -> str:
    """Record a violation as a NAMED event and a typed failure.

    Two sinks on purpose: the decision audit keeps the engagement record
    (what was refused, and why), and the failure taxonomy keeps the category
    so the incident is countable next to the other failures. ``reason``
    overrides the check's own text, so the same event can carry a
    POST-RUN violation (declared effects never observed) as well as a
    pre-run one.
    """
    capability = getattr(driver, "id", "")
    detail = str(reason or (check.reason if check is not None else ""))
    try:
        from phantom.automation import decision_audit
        decision_audit.record(CONTRACT_VIOLATION, capability=capability,
                              tool=getattr(driver, "tool", ""),
                              detail=detail,
                              path=(check.path if check is not None else ""),
                              site=where,
                              expected_sha256=str(
                                  getattr(driver, "binary_sha256", ""))[:64],
                              actual_sha256=(check.actual
                                             if check is not None else ""))
    except Exception:                                     # pragma: no cover
        pass
    try:
        from phantom.utils.failure_taxonomy import record
        record(where, category="contract_violation",
               detail=f"{capability}: {detail}",
               extra={"contract": CONTRACT_VIOLATION,
                      "capability": capability})
    except Exception:                                     # pragma: no cover
        pass
    return CONTRACT_VIOLATION


def record_effects_violation(driver: Any, missing: Any,
                             where: str = "agent.postcondition") -> str:
    """The manifest declared effects, the run produced NONE of them.

    This is the second half of "the manifest is a claim": the binary check
    says the right program ran, this says the program did what it promised.
    It is reported on the same named outcome, because a driver whose declared
    effect never appears is exactly the driver that is about to be trusted
    for something it cannot do.
    """
    names = ", ".join(str(m) for m in (missing or [])) or "declared effect"
    return record_violation(driver, None, where=where,
                            reason=f"declared effect(s) not observed: {names}")


def verify_drivers() -> list:
    """Plain-data contract status for EVERY loaded driver (offline, read-only).

    For `config drivers` / `doctor`: the operator must be able to see which
    capabilities are actually pinned, which are merely unchecked, and which
    one has a pin that no longer matches the binary on disk.
    """
    out: list = []
    try:
        from phantom.automation.runtime.drivers import load_drivers
        drivers = load_drivers()
    except Exception as exc:                              # pragma: no cover
        return out
    for drv in drivers:
        row = {"id": getattr(drv, "id", ""),
               "tool": getattr(drv, "tool", "")}
        row.update(summary_for(drv))
        out.append(row)
    return out


def summary_for(driver: Any) -> dict:
    """Plain-data view for `tool list` / `doctor` (executes nothing)."""
    try:
        check = verify_binary(driver)
    except Exception as exc:                              # pragma: no cover
        return {"pinned": False, "verified": False,
                "reason": f"check failed: {exc}"}
    return {"pinned": check.pinned, "verified": check.verified,
            "reason": check.reason, "path": check.path}
