#!/usr/bin/env python3
"""Python <-> Go <-> beacon key-derivation parity, checked in one place.

`c2d` is a second implementation of the wire protocol. HKDF-SHA256 is where a
drift is SILENT: nothing errors, the beacon just never decrypts. So the three
implementations pin the SAME vectors, and this script fails the build if any
side stops producing them:

  * Python  — recomputed here from phantom.utils.c2_crypto
  * Go      — the vectors pinned in c2d/c2d_test.go (and `go test` asserts
              the Go code still produces them)
  * beacon  — the vectors pinned in tests/test_c2_crypto_keys.py, which the
              pytest suite runs; the C++ side is compiled by the beacon jobs

Exit code 1 on any mismatch, with the offending side named.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from phantom.utils.c2_crypto import (  # noqa: E402
    beacon_download_token,
    beacon_envelope_key,
)

SECRET = bytes(range(32))
CASES = {
    "B-TEST": "275c2265389eb7081752b239a2ab65fab82938b05e579d7937ded40bc33b5afc",
    "": "88170beeb2e2a92e1c5875050d69741b6d7384ed20e930ceaa366d2fa50ba182",
    "B-\u00e8-t\u00e9st": "7c6eb272b1b1478f38248badb802e48e71c5af45b8a74b6c68aa67aeff7b337e",
}
DOWNLOAD = "f8a955bf74dc5a93aa0407d58429898600aade9123bb3b23f5bb38dadcb608d6"


def check_python() -> bool:
    ok = True
    for beacon_id, expected in CASES.items():
        got = beacon_envelope_key(SECRET, beacon_id).hex()
        if got != expected:
            print(f"FAIL python envelope key for {beacon_id!r}: {got} != {expected}")
            ok = False
    got = beacon_download_token(SECRET, "B-TEST")
    if got != DOWNLOAD:
        print(f"FAIL python download token: {got} != {DOWNLOAD}")
        ok = False
    if ok:
        print("OK   python (phantom.utils.c2_crypto)")
    return ok


def _pinned(source: str, label: str) -> bool:
    text = open(os.path.join(ROOT, source), "r", encoding="utf-8").read()
    ok = True
    for beacon_id, expected in CASES.items():
        if expected not in text:
            print(f"FAIL {label}: vector for {beacon_id!r} ({expected}) is not "
                  f"pinned in {source}")
            ok = False
    if DOWNLOAD not in text:
        print(f"FAIL {label}: download-token vector is not pinned in {source}")
        ok = False
    if ok:
        print(f"OK   {label}")
    return ok


def check_beacon_source() -> bool:
    """The C++ side derives the key at runtime; assert the code that does it is
    still there in BOTH copies (the beacon and the remote module)."""
    ok = True
    for tree in ("beacon", "remote"):
        path = os.path.join(ROOT, "phantom", "payloads", tree, "src", "crypto.h")
        text = open(path, "r", encoding="utf-8").read()
        missing = [token for token in
                   ("hkdf_sha256", "envelope_key()", "payload_token()",
                    "phantom-envelope:", "phantom-download:")
                   if token not in text]
        if missing:
            print(f"FAIL beacon {tree}/crypto.h is missing: {', '.join(missing)}")
            ok = False
        if re.search(r"EVP_(En|De)cryptInit_ex\(ctx, NULL, NULL, AES_KEY, nonce\)", text):
            print(f"FAIL beacon {tree}/crypto.h still uses the static AES_KEY "
                  f"directly instead of the derived key")
            ok = False
    if ok:
        print("OK   beacon + remote crypto.h")
    return ok


def check_task_policy() -> bool:
    """The Go data plane must enforce the SAME task policy as Python.

    `c2d/policy_vectors.json` holds cases with the expectations the Python
    policy produced; both sides assert them (Python here, Go in
    c2d/task_policy_test.go). This is the check that keeps
    POST /api/v1/queue from being a task-injection primitive on one backend.
    """
    import json
    from phantom.core.task_policy import TaskPolicy, TypedTask

    path = os.path.join(ROOT, "c2d", "policy_vectors.json")
    try:
        doc = json.load(open(path, "r", encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"FAIL task policy: cannot read c2d/policy_vectors.json ({exc})")
        return False
    ok = True
    for case in doc.get("cases", []):
        policy = TaskPolicy()
        if case.get("grants") is not None:
            policy.set_grants(case["beacon"], case["grants"])
        typed = case.get("typed")
        if typed:
            decision = policy.check_typed(case["beacon"], TypedTask(
                capability_id=typed.get("capability_id", ""),
                args=typed.get("args", []),
                expires_at=typed.get("expires_at", 0.0)))
        else:
            decision = policy.check_legacy(case["beacon"],
                                           case.get("command") or "")
        if (decision.allowed, decision.mode, decision.reason) != (
                case["allowed"], case["mode"], case["reason"]):
            print(f"FAIL task policy case {case['name']!r}: python says "
                  f"{decision.allowed}/{decision.mode} but the shared "
                  f"vector says {case['allowed']}/{case['mode']}")
            ok = False
    go = open(os.path.join(ROOT, "c2d", "task_policy.go"), "r",
              encoding="utf-8").read()
    if "CheckLegacy" not in go or "CheckTyped" not in go:
        print("FAIL task policy: c2d/task_policy.go no longer implements the "
              "typed AND legacy checks")
        ok = False
    if ok:
        n = len(doc.get("cases", []))
        print(f"OK   task policy ({n} shared cases, python == go)")
    return ok


def check_audit_chain() -> bool:
    """Both audit trails must hash the same canonical record."""
    import hashlib
    import json
    from phantom.utils.audit_log import _canonical

    path = os.path.join(ROOT, "c2d", "audit_vectors.json")
    try:
        doc = json.load(open(path, "r", encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"FAIL audit chain: cannot read c2d/audit_vectors.json ({exc})")
        return False
    canonical = _canonical(doc["record"])
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if canonical != doc["canonical"] or digest != doc["sha256"]:
        print(f"FAIL audit chain: python canonical/hash drifted from the "
              f"shared vector ({digest} != {doc['sha256']})")
        return False
    go = open(os.path.join(ROOT, "c2d", "audit.go"), "r",
              encoding="utf-8").read()
    for token in ("prev", "recordHash", "Verify"):
        if token not in go:
            print(f"FAIL audit chain: c2d/audit.go lost {token!r} (the chain "
                  f"is no longer tamper-evident)")
            return False
    print("OK   audit chain (python == go, canonical record + digest pinned)")
    return True


def check_behaviour_constants() -> bool:
    """Lease and retention must not differ between the two backends."""
    from phantom.core.c2_server import (MAX_RESULTS_PER_BEACON,
                                        TASK_LEASE_SECONDS)

    text = open(os.path.join(ROOT, "c2d", "store.go"), "r",
                encoding="utf-8").read()
    ok = True
    for name, python_value in (("TaskLeaseSeconds", TASK_LEASE_SECONDS),
                               ("MaxResultsPerBeacon",
                                MAX_RESULTS_PER_BEACON)):
        match = re.search(rf"{name}\s*=\s*(\d+)", text)
        if not match:
            print(f"FAIL constants: c2d/store.go has no {name}")
            ok = False
        elif int(match.group(1)) != python_value:
            print(f"FAIL constants: {name} is {match.group(1)} in Go and "
                  f"{python_value} in Python")
            ok = False
    if ok:
        print("OK   constants (lease + result retention agree)")
    return ok


def main() -> int:
    results = [
        check_python(),
        _pinned("c2d/c2d_test.go", "go (c2d/c2d_test.go)"),
        _pinned("tests/test_c2_crypto_keys.py", "beacon tests"),
        check_beacon_source(),
        check_task_policy(),
        check_audit_chain(),
        check_behaviour_constants(),
    ]
    if all(results):
        print("PARITY OK: python == go == beacon, one set of vectors.")
        return 0
    print("PARITY BROKEN — a beacon built against one side will not be "
          "readable by the other.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
