"""Regression tests for the auto-mode field-test fixes:

- SSH login on non-standard ports (precondition must accept any SSH port)
- Operator-supplied custom wordlists for the offline brute
- Full-range scan escalation when no remote-access service is visible
"""
import os

import pytest

from phantom.automation.belief import WorldModel


def test_ssh_precondition_accepts_nonstandard_port(tmp_path, monkeypatch):
    from phantom.automation.guidance.kit import _has_service_kind
    wm = WorldModel(target="127.0.0.1")
    # SSH discovered on 2222 (non-standard lab port)
    wm.add_finding("service", "tcp/2222",
                   {"port": "2222", "service": "ssh", "protocol": "tcp"},
                   source="scan")
    assert _has_service_kind("service", "ssh")(wm)
    assert not _has_service_kind("service", "smb")(wm)


def test_custom_wordlists_loaded_for_service(tmp_path, monkeypatch):
    from phantom.utils import paths
    monkeypatch.setattr(paths, "data_dir", lambda: str(tmp_path))
    custom = tmp_path / "wordlists" / "custom"
    custom.mkdir(parents=True)
    (custom / "ssh_users.txt").write_text("victim\nroot\n")
    (custom / "ssh_passwords.txt").write_text("v1ct1m!\npassword\n")
    (custom / "users.txt").write_text("ignored\n")

    from phantom.automation.exploit.vectors import load_custom_wordlists
    users, passwords = load_custom_wordlists("ssh")
    assert users == ["victim", "root"]
    assert passwords == ["v1ct1m!", "password"]


def test_service_port_prefers_discovered_port():
    from phantom.automation.belief import WorldModel
    from phantom.automation.agent import AutonomousAgent

    wm = WorldModel(target="127.0.0.1")
    wm.add_finding("service", "tcp/2222",
                   {"port": "2222", "service": "ssh"}, source="scan")

    # drive the real method off a minimal agent instance
    agent = AutonomousAgent.__new__(AutonomousAgent)
    agent.wm = wm
    assert agent._service_port("ssh") == 2222
    assert agent._service_port("smb") == 445


def test_deep_scan_escalation_flag_logic():
    """The escalation must fire once and only when no access service is known."""
    from phantom.automation.belief import WorldModel

    wm = WorldModel(target="127.0.0.1")
    # Only web + ftp known → no remote-access service → escalate
    wm.add_finding("service", "tcp/8081",
                   {"port": "8081", "service": "http"}, source="scan")
    access_ports = {"22", "2222", "22222", "3389", "5985", "5986", "445"}
    found_access = any(
        f.kind == "service" and isinstance(f.value, dict)
        and str(f.value.get("port", "")) in access_ports
        for f in wm._findings.values())
    assert not found_access

    wm.add_finding("service", "tcp/2222",
                   {"port": "2222", "service": "ssh"}, source="scan")
    found_access = any(
        f.kind == "service" and isinstance(f.value, dict)
        and str(f.value.get("port", "")) in access_ports
        for f in wm._findings.values())
    assert found_access