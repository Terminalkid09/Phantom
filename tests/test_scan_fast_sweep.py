"""The scan module must answer `-p-` without waiting four hours for nmap.

Live defect (2026-10-30): on 192.168.1.18 `nmap -sV -sC -p-` took 3h46m for
65 535 filtered ports, so a scripted scan either waited an afternoon or was
killed with an EMPTY XML and reported "no services" — while the same question
asked over plain TCP connects found 5040 and 5357 in under two minutes.

These tests pin the wiring, not the network: the sweep itself is tested in
`tests/test_fast_port_sweep.py`.
"""
from __future__ import annotations

import pytest

from phantom.modules import scan as scan_mod


@pytest.fixture()
def target(monkeypatch):
    from phantom.core.session import session

    monkeypatch.setattr(session, "target", "192.168.1.18", raising=False)
    return session


@pytest.fixture()
def calls(monkeypatch):
    seen = {"sweep": [], "services": []}

    def fake_sweep(ip, **_kwargs):
        seen["sweep"].append(ip)
        return [5040, 5357], {"host": ip, "scanned": 65535, "open": 2,
                              "refused": 0, "filtered": 65533,
                              "elapsed": 118.1, "complete": True}

    def fake_add_service(port, service, **_kwargs):
        seen["services"].append((str(port), service))

    import phantom.core.knowledge as knowledge
    from phantom.core import netmap

    monkeypatch.setattr(netmap, "sweep_all_ports", fake_sweep)
    monkeypatch.setattr(knowledge, "add_service", fake_add_service)
    return seen


def test_a_full_range_request_runs_the_fast_sweep(target, calls):
    scan_mod.ScanModule()._fast_full_sweep([f"sudo nmap -Pn -sS -p- {target.target}"])
    assert calls["sweep"] == ["192.168.1.18"]
    # 5040 has no label on purpose (it answers a connect and then says
    # nothing), so it reaches the WorldModel as plain `tcp`.
    assert calls["services"] == [("5040", "tcp"), ("5357", "wsdapi")]


def test_a_quick_scan_stays_quick(target, calls):
    """Top-1000 rows must not pay for a 65 535-port sweep."""
    scan_mod.ScanModule()._fast_full_sweep(
        [f"sudo nmap -Pn -sV --top-ports 1000 {target.target}"])
    assert calls["sweep"] == []


def test_a_hostname_target_is_not_swept(target, calls, monkeypatch):
    monkeypatch.setattr(target, "target", "cristian.homenet.telecomitalia.it",
                        raising=False)
    scan_mod.ScanModule()._fast_full_sweep(["-p- whatever"])
    assert calls["sweep"] == []


def test_a_failed_sweep_never_breaks_the_scan(target, monkeypatch, capsys):
    from phantom.core import netmap
    from phantom.modules import scan as module

    def boom(*_a, **_k):
        raise OSError("network is down")

    monkeypatch.setattr(netmap, "sweep_all_ports", boom)
    # must not raise: the nmap rows are still there to do their job
    module.ScanModule()._fast_full_sweep(["-p- x"])
