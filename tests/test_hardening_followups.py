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
