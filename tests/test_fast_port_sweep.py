"""The fast full-range connect sweep: the scan that actually finishes.

Live defect this covers (2026-10-30): `nmap -sV -sC -p- 192.168.1.18` took
3h46m for 65 535 filtered ports and a quick `-sV` (top 1000) missed two open
ones, so the tool reported "no surface" on a Windows host with ports open.
The sweep asks the same question over plain TCP connects: no nmap, no root,
and a wall-clock budget.

The tests run against REAL sockets on 127.0.0.1 — a listener that is open, a
port that is closed (RST = refused), and a budget that is too small to finish.
"""
from __future__ import annotations

import socket

from phantom.core import netmap


def _listener() -> tuple[socket.socket, int]:
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(4)
    return sock, sock.getsockname()[1]


def _closed_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_an_open_port_is_found_and_a_closed_one_is_not():
    server, open_port = _listener()
    try:
        closed = _closed_port()
        first, last = min(open_port, closed), max(open_port, closed)
        ports, stats = netmap.sweep_all_ports(
            "127.0.0.1", first=first, last=last, workers=8, per_port=1.0,
            budget=20.0)
        assert open_port in ports
        assert closed not in ports
        assert stats["complete"] is True
        assert stats["scanned"] == last - first + 1
        assert stats["open"] == len(ports)
    finally:
        server.close()


def test_a_closed_port_is_never_reported_open():
    """A closed port is refused OR filtered, never "open", and both are counted.

    Which of the two depends on the platform: a RST arrives immediately on
    Linux while this Windows box answers nothing at all for a just-released
    port (measured while writing this test), so the assertion is on the two
    facts that hold everywhere — it is not open, and it is accounted for.
    """
    server, _open_port = _listener()
    try:
        closed = _closed_port()
        _ports, stats = netmap.sweep_all_ports(
            "127.0.0.1", first=closed, last=closed, workers=2, per_port=1.0,
            budget=20.0)
        assert stats["open"] == 0
        assert stats["refused"] + stats["filtered"] == 1
        assert stats["scanned"] == 1
    finally:
        server.close()


def test_a_sweep_that_runs_out_of_budget_says_it_is_partial():
    """A stopped scan must never read as \"nothing else is open\"."""
    server, open_port = _listener()
    try:
        ports, stats = netmap.sweep_all_ports(
            "127.0.0.1", first=1, last=65535, workers=4, per_port=0.05,
            budget=0.2)
        assert stats["complete"] is False
        assert stats["scanned"] < 65535
        assert isinstance(ports, list)
    finally:
        server.close()


def test_an_empty_host_is_reported_not_raised():
    ports, stats = netmap.sweep_all_ports("", first=1, last=10)
    assert ports == []
    assert stats["complete"] is False
