"""Backend-level tests for the auto-mode event -> UI log translation.

This is the layer that used to drop half the engine's signal: it knew 17 of
the ~40 event kinds, so the stall diagnosis and every error/gate/shared/llm
event never reached the UI. The translation is now a pure function
(`phantom.api.server._automode_log_entries`) driven by the shared contract,
which makes it testable without an HTTP round trip.

The redaction cases are security invariants: this stream feeds the Electron
panel, so a raw password here is a leak, not a cosmetic bug.
"""
import pytest

from phantom.api.server import _automode_log_entries


class _FakeJob:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.current_step = -1
        self.done = False
        self.extra_steps = {}


def _entries(*events, verbose=False):
    return _automode_log_entries(_FakeJob(verbose=verbose), list(events))


def _texts(logs):
    return " | ".join(entry["text"] for entry in logs)


# ── every event reaches the UI ───────────────────────────────────────────

def test_stall_reaches_the_ui():
    """The diagnosis is the single most useful reasoning signal; it used to
    be emitted and dropped."""
    _, logs = _entries({"kind": "stall", "data": {
        "stall": "no_visibility", "reason": "nothing observed on the wire",
        "strategies": ["surface_map", "full_scan"], "policy": "breadth"}})
    assert len(logs) == 1
    assert logs[0]["level"] == "warn"
    assert "no_visibility" in logs[0]["text"]
    assert "surface_map" in logs[0]["text"]


def test_errors_and_gates_are_visible():
    _, logs = _entries(
        {"kind": "error", "data": {"capability": "cells",
                                   "detail": "roster unavailable"}},
        {"kind": "gate", "data": {"fact": "service", "waited": 12.0}},
        {"kind": "success", "data": {"detail": "goal beacon satisfied"}},
    )
    assert len(logs) == 3
    assert logs[0]["level"] == "error"
    assert "roster unavailable" in logs[0]["text"]
    assert any("Gate" in entry["text"] for entry in logs)


def test_peer_findings_are_verbose_only():
    """`shared` is reasoning chatter: padded out unless the operator asked
    for the trace."""
    event = {"kind": "shared", "data": {"kind": "creds",
                                        "from_target": "10.0.0.9"}}
    _, quiet = _entries(event, verbose=False)
    _, loud = _entries(event, verbose=True)
    assert quiet == []
    assert len(loud) == 1


def test_unknown_kind_is_never_silent():
    _, logs = _entries({"kind": "brand_new_kind", "data": {"detail": "hi"}})
    assert len(logs) == 1
    assert "hi" in logs[0]["text"]


def test_verbose_gating_matches_the_contract():
    reason = {"kind": "reason", "data": {
        "hypotheses": [{"capability": "ssh_login", "reason": "reuse creds"}]}}
    _, quiet = _entries(reason, verbose=False)
    _, loud = _entries(reason, verbose=True)
    assert quiet == []
    assert len(loud) == 1
    assert "ssh_login" in loud[0]["text"]


# ── structured extras the Electron panel reads ───────────────────────────

def test_run_carries_command_reason_and_stealth():
    updates, logs = _entries({"kind": "run", "data": {
        "capability": "ssh_login", "banner": "ssh login",
        "stealth_level": "paranoid", "cost": 1.2,
        "command": "sshpass -p x ssh a@10.0.0.5",
        "reason": "creds available: test reuse over SSH"}})
    assert len(logs) == 1
    entry = logs[0]
    assert entry["reason"] == "creds available: test reuse over SSH"
    assert entry["stealth"] == "paranoid"
    assert entry["level"] == "info"
    # the checklist still advances (ssh_login is the creds step)
    assert updates == [{"step": 5, "status": "running",
                        "detail": "ssh_login"}]


def test_found_advances_the_step_and_keeps_values():
    updates, logs = _entries({"kind": "found", "data": {
        "capability": "scan", "findings": ["service:tcp/22"],
        "values": {"service:tcp/22": "ssh"}}})
    assert updates and updates[0]["step"] == 0
    assert updates[0]["status"] == "done"
    assert "ssh" in logs[0]["text"]


def test_a_capability_outside_the_checklist_still_logs():
    """No step to advance is not a reason to drop the event."""
    updates, logs = _entries({"kind": "run", "data": {
        "capability": "ssh_banner", "banner": "ssh banner",
        "stealth_level": "passive", "command": "nc -w 5 10.0.0.5 22",
        "reason": "service ssh open"}})
    assert updates == []
    assert len(logs) == 1
    assert "ssh banner" in logs[0]["text"]


def test_beacon_up_sets_the_final_step():
    updates, logs = _entries({"kind": "beacon_up",
                              "data": {"beacon_id": "b-7"}})
    assert updates == [{"step": 6, "status": "done", "detail": "b-7"}]
    assert logs[0]["level"] == "success"


def test_failed_does_not_advance_the_checklist():
    updates, _ = _entries({"kind": "failed", "data": {
        "capability": "scan", "reason": "tool missing"}})
    assert updates[0]["status"] == "failed"


# ── redaction (security invariants) ──────────────────────────────────────

def test_credential_values_never_reach_the_ui_stream():
    _, logs = _entries({"kind": "found", "data": {
        "capability": "ssh_login", "findings": ["creds:ssh"],
        "values": {"creds:ssh": "admin:hunter2"}}})
    text = _texts(logs)
    assert "hunter2" not in text
    assert "[REDACTED]" in text


def test_secret_keys_are_masked_before_rendering():
    secret = "S3cr3t-Pa55w0rd!"
    _, logs = _entries({"kind": "note", "data": {
        "capability": "brute", "detail": "done",
        "password": secret}})
    assert secret not in _texts(logs)


def test_command_free_text_is_redacted():
    """A planner reason can quote the command, and the command can carry a
    password flag: `sshpass -p …` must not survive into the stream."""
    _, logs = _entries({"kind": "run", "data": {
        "capability": "ssh_login", "stealth_level": "active",
        "command": "sshpass -p hunter2 ssh operator@10.0.0.5 'id'",
        "reason": "reattempt ssh_login"}})
    text = _texts(logs) + str(logs[0].get("command", ""))
    assert "hunter2" not in text


def test_port_like_password_flag_is_not_mangled():
    """`ssh -p 22` is a port, not a secret: redaction must not destroy the
    command it is only supposed to protect."""
    _, logs = _entries({"kind": "run", "data": {
        "capability": "ssh_banner", "stealth_level": "passive",
        "command": "ssh -p 22 operator@10.0.0.5", "reason": "banner"}})
    assert "22" in logs[0]["command"]


def test_no_events_is_empty():
    updates, logs = _entries()
    assert updates == []
    assert logs == []
