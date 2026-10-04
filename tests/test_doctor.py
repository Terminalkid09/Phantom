"""tests/test_doctor.py — `phantom doctor` checks.

The doctor must diagnose the ENVIRONMENT without ever raising, flag real
breakage (bad config, unwritable data dir, missing model file) with a fix
hint, and keep every check offline unless --net is given.
"""
import os

from phantom.core import doctor
from phantom.core.doctor import Check, DoctorReport, run_doctor


# ── shape / never-raises ────────────────────────────────────────────────

def test_offline_report_has_base_checks(tmp_path, monkeypatch):
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    report = run_doctor(net=False)
    names = {c.name for c in report.checks}
    assert {"python", "core-deps", "beacon-toolchain", "data-dir",
            "config", "experience"} <= names
    # net probes are NOT in an offline run
    assert "c2-listener" not in names and "dead-drop" not in names


def test_report_accounting():
    r = DoctorReport(checks=[
        Check("a", "pass"), Check("b", "warn"), Check("c", "fail"),
    ])
    assert not r.ok()
    assert [c.name for c in r.fails] == ["c"]
    assert [c.name for c in r.warns] == ["b"]
    assert r.checks[2].mark == "✘" and r.checks[0].mark == "✔"


def test_failing_check_never_raises(monkeypatch):
    def boom():
        raise RuntimeError("boom")
    monkeypatch.setattr(doctor, "_python_check", boom)
    report = run_doctor(net=False)
    entry = next(c for c in report.checks if "boom" in c.detail)
    assert entry.status == "warn"
    # the rest of the report is still produced
    assert len(report.checks) >= 8


# ── individual checks ───────────────────────────────────────────────────

def test_python_check_passes_on_supported_version():
    assert doctor._python_check().status in ("pass", "fail")  # shape only
    # the suite itself runs on a supported interpreter, so: pass
    import sys
    if sys.version_info >= (3, 10):
        assert doctor._python_check().status == "pass"


def test_core_deps_pass_in_test_env():
    assert doctor._core_deps_check().status == "pass"


def test_data_dir_fail_when_path_is_a_file(tmp_path, monkeypatch):
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x")
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(blocker))
    c = doctor._data_dir_check()
    assert c.status == "fail" and c.hint


def test_data_dir_pass_on_fresh_dir(tmp_path, monkeypatch):
    d = tmp_path / "data"
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(d))
    c = doctor._data_dir_check()
    assert c.status == "pass" and os.path.isdir(d)


def test_config_check_flags_bad_port(monkeypatch):
    from phantom.utils import config as cfg
    monkeypatch.setattr(cfg, "_loaded",
                        {"c2": {"port": 99999, "host": "127.0.0.1"}})
    c = doctor._config_check()
    assert c.status == "fail" and "c2.port" in c.detail


def test_config_check_passes_on_sane_defaults(monkeypatch):
    from phantom.utils import config as cfg
    monkeypatch.setattr(cfg, "_loaded", {})
    assert doctor._config_check().status == "pass"


def test_experience_check_on_fresh_store(tmp_path, monkeypatch):
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    c = doctor._experience_check()
    assert c.status == "pass" and "0 episode" in c.detail
    assert not os.path.exists(os.path.join(str(tmp_path),
                                           "experience_cases.json.doctor_probe"))


def test_llm_check_flags_missing_model(monkeypatch):
    from phantom.utils import config as cfg
    monkeypatch.setattr(cfg, "_loaded",
                        {"llm": {"enabled": True,
                                 "model_path": "/no/such/model.gguf"}})
    c = doctor._llm_check()
    assert c.status == "fail" and "model" in c.detail


def test_llm_check_off_is_a_pass(monkeypatch):
    from phantom.utils import config as cfg
    monkeypatch.setattr(cfg, "_loaded", {"llm": {"enabled": False}})
    assert doctor._llm_check().status == "pass"


def test_external_services_check_lists_wired_apis(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    monkeypatch.delenv("PHANTOM_SHODAN_KEY", raising=False)
    # deterministic: no credentials configured, whatever the local config file
    from phantom.utils import api_keys
    monkeypatch.setattr(api_keys, "status", lambda: {
        name: {"label": name, "hint": "", "env": "",
               "configured": False, "source": "none", "masked": ""}
        for name in api_keys.names()})
    c = doctor._external_services_check()
    assert c.status == "pass"
    assert "shodan" in c.detail and "crt.sh" in c.detail
    assert c.hint  # keyless -> the key-registration hint


def test_external_services_check_notes_key(monkeypatch):
    # legacy SHODAN_API_KEY is still honoured, and the check now reports the
    # key plane by name instead of a single "authenticated" flag
    monkeypatch.setenv("SHODAN_API_KEY", "k")
    c = doctor._external_services_check()
    assert c.status == "pass" and "credentials set" in c.detail
    assert "shodan" in c.detail


def test_toolbelt_check_flags_unrouted_capability():
    from phantom.automation.brain.toolbelt import Toolbelt
    from phantom.automation.runtime.toolchain import ToolRegistry
    # nothing offensive installed: every shell capability is unrouted, but
    # the in-process ssh-banner engine still counts as available
    c = doctor._toolbelt_check(Toolbelt(ToolRegistry(installed=set())))
    assert c.status == "warn"
    assert "no installed tool" in c.detail and c.hint


def test_toolbelt_check_passes_when_tools_present():
    from phantom.automation.brain.toolbelt import Toolbelt
    from phantom.automation.runtime.toolchain import ToolRegistry
    belt = Toolbelt(ToolRegistry(installed={
        "masscan", "nmap", "nc", "smbmap", "hydra", "curl", "redis-cli"}))
    c = doctor._toolbelt_check(belt)
    assert c.status == "pass"


# ── net probes ──────────────────────────────────────────────────────────

def test_net_adds_probes_but_never_fails_closed(monkeypatch):
    from phantom.utils import config as cfg
    monkeypatch.setattr(cfg, "_loaded", {})   # dead drop unconfigured
    report = run_doctor(net=True)
    names = {c.name for c in report.checks}
    assert {"c2-listener", "msf-rpc", "dead-drop"} <= names
    dd = next(c for c in report.checks if c.name == "dead-drop")
    assert dd.status == "pass" and "not configured" in dd.detail
    # a closed port is a WARN, not a FAIL: no listener yet is normal
    c2 = next(c for c in report.checks if c.name == "c2-listener")
    assert c2.status in ("pass", "warn")


def test_dead_drop_net_check_reports_live_record(tmp_path, monkeypatch):
    import threading
    import http.server
    import socketserver
    from phantom.utils import config as cfg
    from phantom.utils import dead_drop as dd

    class H(http.server.BaseHTTPRequestHandler):
        body = dd.encode_record("10.0.0.9", 4444, True).encode()
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(self.body)))
            self.end_headers()
            self.wfile.write(self.body)
        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setattr(cfg, "_loaded",
                            {"c2": {"dead_drop":
                                    f"http://127.0.0.1:{srv.server_address[1]}/x"}})
        c = doctor._dead_drop_net_check()
        assert c.status == "pass" and "10.0.0.9:4444" in c.detail
    finally:
        srv.shutdown()


# ── CLI wiring ──────────────────────────────────────────────────────────

def test_doctor_command_registered_and_renders(tmp_path, monkeypatch):
    from phantom.core.shell.commands import system
    import phantom.utils.notifier as notifier_mod
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    printed = []

    class _C:
        def print(self, *a, **k):
            printed.append(a)
    monkeypatch.setattr(notifier_mod, "console", _C())

    assert "doctor" in system.COMMANDS
    system.cmd_doctor(None, "")
    assert printed                      # the report table was rendered


def test_doctor_net_flag_parses(tmp_path, monkeypatch):
    from phantom.core.shell.commands import system
    import phantom.utils.notifier as notifier_mod
    from phantom.utils import config as cfg

    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(cfg, "_loaded", {})
    printed = []

    class _C:
        def print(self, *a, **k):
            printed.append(a)
    monkeypatch.setattr(notifier_mod, "console", _C())

    system.cmd_doctor(None, "--net")
    assert printed
