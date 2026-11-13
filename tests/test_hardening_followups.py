"""Static contract checks for the residual audit follow-ups.

These tests do NOT run Electron, Vite or a C++ compiler: they pin invariants
in the source so a later refactor cannot silently reintroduce an audited
weakness (remote font fetch, missing CSP, dead IPC surface, unpinned remote
transport, mislabelled allowlist group).
"""
from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), "r", encoding="utf-8") as handle:
        return handle.read()


# ── Electron: self-hosted fonts + packaged CSP ──────────────────────────────

def test_fonts_are_self_hosted():
    index = _read("electron", "index.html")
    css = _read("electron", "src", "styles", "global.css")
    assert "fonts.googleapis.com" not in index, "remote Google Fonts <link> must be gone"
    assert "fonts.gstatic.com" not in index
    assert "fonts.googleapis.com" not in css, "remote @import must be gone"
    main = _read("electron", "src", "main.tsx")
    assert "@fontsource/inter" in main
    assert "@fontsource/jetbrains-mono" in main


def test_csp_is_defined_for_both_dev_and_packaged():
    main = _read("electron", "electron", "main.ts")
    vite = _read("electron", "vite.config.ts")
    assert "onHeadersReceived" in main, "dev http responses need the CSP header"
    assert "Content-Security-Policy" in main
    assert "Content-Security-Policy" in vite, (
        "packaged file:// loads bypass onHeadersReceived — the policy must be "
        "baked into the built index.html")
    assert "default-src 'self'" in vite
    assert "object-src 'none'" in vite


# ── Electron: the preload bridge must match what the backend offers ──────────

def test_preload_does_not_expose_put_or_delete():
    preload = _read("electron", "electron", "preload.ts")
    types = _read("electron", "vite-env.d.ts")
    assert "invoke('api-request', 'PUT'" not in preload
    assert "invoke('api-request', 'DELETE'" not in preload
    assert "put(endpoint" not in types
    assert "delete(endpoint" not in types


# ── allowlist: /api/osint/preview is a write-side action ────────────────────

def test_osint_preview_is_mutating():
    allowlist = _read("electron", "electron", "endpoint_allowlist.ts")
    rule = [ln for ln in allowlist.splitlines() if "/api/osint/preview" in ln]
    assert rule, "the osint preview rule disappeared"
    assert all("mutating" in ln for ln in rule), (
        "osint preview runs the real engine — it must not be `readonly`")


# ── remote transport: certificate pin parity with the beacon ────────────────

def test_remote_transport_pins_the_peer_certificate():
    net = _read("phantom", "payloads", "remote", "src", "remote_net.h")
    assert "BEACON_SERVER_FINGERPRINT" in net, "the remote pin must be derived from the build config"
    assert "WINHTTP_OPTION_SERVER_CERT_CONTEXT" in net, "WinHTTP peer cert must be queried"
    assert "X509_digest" in net, "OpenSSL peer cert must be hashed"
    assert "REMOTE_PIN_ENFORCED" in net


def test_remote_builder_forwards_the_pin():
    builder = _read("phantom", "utils", "builder.py")
    start = builder.index("def compile_remote")
    end = builder.index("def _compile_remote_ios", start)
    segment = builder[start:end]
    assert "pin=_cert_pin" in segment, (
        "compile_remote must pass the certificate pin to write_beacon_c2_config")


# ── duplicated crypto: catch silent drift between beacon and remote ─────────

def _code_only(path: str) -> list:
    """Executable lines of a C++ source, comments and blanks stripped, so only
    a CHANGE IN CODE counts as drift (the two copies differ in comments)."""
    src = _read(*path.split("/"))
    src = re.sub(r"//[^\n]*", "", src)
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return [ln.strip() for ln in src.splitlines() if ln.strip()]


def test_beacon_and_remote_crypto_stay_in_sync():
    """The remote module carries its OWN copy of crypto.h (AEAD + HKDF + HMAC).
    The copies are intentional (different include surface), but a silent drift
    would make one side unable to decrypt the other — exactly the class of bug
    a shared header would prevent. This pins them together."""
    beacon = _code_only("phantom/payloads/beacon/src/crypto.h")
    remote = _code_only("phantom/payloads/remote/src/crypto.h")
    assert beacon, "crypto.h not found or empty"
    assert beacon == remote, (
        "crypto.h drifted between beacon and remote — update BOTH copies")


# ── cross-layer limits: one rule, two spellings, no shared symbol ──────────
#
# The recurring damage in this repo is the SAME limit implemented twice in
# different layers and kept equal by hand. These pin the pairs that would
# break a run SILENTLY if they drifted apart.

def test_beacon_task_output_cap_fits_the_server_result_cap():
    """The beacon truncates a task's output at ``kMaxTaskOutput`` (C++); the
    listener rejects a result larger than ``MAX_RESULT_OUTPUT_BYTES`` (Python)
    with 413. Two ends of ONE limit with no shared symbol: if the beacon ever
    emitted more than the server accepts, the result is dropped and the
    operator sees a task that produced nothing."""
    from phantom.core.c2_server import MAX_RESULT_OUTPUT_BYTES
    main = _read("phantom", "payloads", "beacon", "src", "main.cpp")
    m = re.search(r"kMaxTaskOutput\s*=\s*([0-9][0-9\s\*]*);", main)
    assert m, "kMaxTaskOutput not found in the beacon"
    beacon_cap = eval(m.group(1))          # digits, spaces and '*' only
    assert beacon_cap <= MAX_RESULT_OUTPUT_BYTES, (
        f"beacon kMaxTaskOutput={beacon_cap} exceeds the server "
        f"MAX_RESULT_OUTPUT_BYTES={MAX_RESULT_OUTPUT_BYTES}; those results "
        f"would be rejected 413 and lost")


def test_beacon_response_cap_is_one_number_on_every_platform():
    """``network.h`` caps the C2 response twice: a named constant in the
    Windows read loop and a bare literal in the POSIX one. Two spellings of one
    limit — change one and the wire limit silently differs per platform."""
    network = _read("phantom", "payloads", "beacon", "src", "network.h")
    code = re.sub(r"//[^\n]*", "", network)
    caps = sorted(set(re.findall(r"(\d+)\s*\*\s*1024\s*\*\s*1024", code)))
    assert caps == ["10"], (
        f"response caps disagree across platforms: found {caps} (MiB) — the "
        f"Windows and POSIX read paths must bound the same size")


# ── silent result pruning ──────────────────────────────────────────────────
#
# ``C2State.add_result`` drops the OLDEST results once a beacon has more than
# ``MAX_RESULTS_PER_BEACON``. Dropping them is fine (memory must be bounded);
# doing it SILENTLY is not — on a long engagement the operator's first
# proof-of-access can disappear and nothing in the audit trail says so.

def test_pruning_results_is_reported_not_silent(monkeypatch):
    from phantom.core import c2_server as S
    from phantom.utils.audit_log import audit_log
    import phantom.api.server as api

    monkeypatch.setattr(S, "MAX_RESULTS_PER_BEACON", 3)

    logged = []
    monkeypatch.setattr(audit_log, "append",
                        lambda event, **fields: logged.append(
                            {"event": event, **fields}) or {"event": event})

    pushed = []
    monkeypatch.setattr(api, "_push_timeline",
                        lambda source, event_type, detail: pushed.append(
                            (source, event_type, detail)) or None)

    st = S.C2State()
    for i in range(6):
        st.add_result("B1", f"t{i}", f"out{i}")

    # bounded, newest kept, oldest dropped (the cap still works)
    assert [r["task_id"] for r in st.results["B1"]] == ["t3", "t4", "t5"]

    prune_events = [e for e in logged if e["event"] == "results_pruned"]
    assert prune_events, "pruning was silent: no audit event was emitted"
    assert all(e["beacon_id"] == "B1" for e in prune_events)
    assert sum(e["pruned"] for e in prune_events) == 3, (
        "the audit trail must count exactly the results that were dropped")
    assert all(e["kept"] == 3 for e in prune_events)

    assert any(kind == "results_pruned" for _, kind, _ in pushed), (
        "the UI timeline was never told about the pruning")
    assert any("B1" in detail for _, _, detail in pushed)
