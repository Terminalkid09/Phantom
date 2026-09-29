"""Tests: auto-mode C2 listener bootstrap.

The contract:
  * ``c2.listener_auto_start = False`` -> never auto-start, warn instead;
  * otherwise bind ``c2.bind`` (0.0.0.0 by default: every interface, so a
    multi-homed box or a changed VPN/LAN address cannot make the C2
    unreachable). The address beacons are TOLD to dial stays
    get_c2_endpoint()[0], and is deliberately NOT the bind address;
  * when the configured bind is not bindable here (a public IP that is not
    local), fall back to the loopback for local-lab runs and say so;
  * when nothing is bindable, skip the listener and let the run continue.
"""
import socket
from unittest.mock import Mock, patch

import phantom.core.automode as am


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _FakeServer:
    def __init__(self, alive=False):
        self.calls = []
        if alive:
            t = Mock()
            t.is_alive.return_value = True
            self.thread = t
        else:
            self.thread = None

    def start(self, host=None, port=None, use_ssl=None):
        self.calls.append((host, port, use_ssl))


def _patch_cfg(auto_start, bind="0.0.0.0"):
    def _get(k, d=None, env=None):
        if k == "c2.listener_auto_start":
            return auto_start
        if k == "c2.bind":
            return bind
        return d
    return patch("phantom.utils.config.get", side_effect=_get)


def test_opt_out_never_starts_listener():
    fake = _FakeServer()
    with _patch_cfg(False), \
            patch.object(am, "notifier"), \
            patch("phantom.utils.network.get_c2_endpoint") as ep:
        assert am._ensure_c2_listener(server=fake) is False
    assert fake.calls == []
    ep.assert_not_called()


def test_already_running_listener_is_left_alone():
    fake = _FakeServer(alive=True)
    with _patch_cfg(False), \
            patch.object(am, "notifier"), \
            patch("phantom.utils.network.get_c2_endpoint") as ep:
        assert am._ensure_c2_listener(server=fake) is True
    assert fake.calls == []
    ep.assert_not_called()


def test_binds_configured_bind_not_the_dial_host():
    """The listener binds c2.bind (0.0.0.0 by default, every interface)
    while beacons are told to dial the derived address — the two roles are
    now separate keys."""
    port = _free_port()
    fake = _FakeServer()
    with _patch_cfg(True), \
            patch.object(am, "notifier"), \
            patch("phantom.utils.network.get_c2_endpoint",
                  return_value=("127.0.0.1", port)):
        assert am._ensure_c2_listener(server=fake) is True
    assert fake.calls == [("0.0.0.0", port, True)]


def test_unbindable_bind_falls_back_to_loopback():
    port = _free_port()
    fake = _FakeServer()
    with _patch_cfg(True, bind="203.0.113.9"), \
            patch.object(am, "notifier"), \
            patch("phantom.utils.network.get_c2_endpoint",
                  return_value=("203.0.113.9", port)):  # TEST-NET-3, non-local
        assert am._ensure_c2_listener(server=fake) is True
    assert fake.calls == [("127.0.0.1", port, True)]


def test_nothing_bindable_skips_listener_but_returns_false():
    fake = _FakeServer()
    # the configured bind is non-local AND the loopback fallback port is
    # held, so the only honest answer is "no listener"
    held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    held.bind(("127.0.0.1", 0))
    held.listen(1)
    port = held.getsockname()[1]
    try:
        with _patch_cfg(True, bind="203.0.113.9"), \
                patch.object(am, "notifier"), \
                patch("phantom.utils.network.get_c2_endpoint",
                      return_value=("203.0.113.9", port)):  # non-local + taken
            assert am._ensure_c2_listener(server=fake) is False
    finally:
        held.close()
    assert fake.calls == []
