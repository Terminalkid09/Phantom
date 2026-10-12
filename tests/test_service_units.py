"""Tests for the OS service definition that starts a supervised run at boot.

`--supervise` survives a crash inside one process. These tests pin the thing
that survives a REBOOT: the unit Phantom renders for systemd, launchd and the
Windows Task Scheduler.

What is worth pinning here is not the file syntax but three properties:

* **the argument list survives** — every renderer is parsed back (with the
  platform's own parsing rules, reimplemented in this file on purpose) and the
  rebuilt list must equal the command, so a target with a space, a quote or a
  shell metacharacter cannot become a flag or a second command in the
  operator's boot configuration;
* **nothing is written by accident** — rendering is pure, `--print-service`
  leaves the filesystem alone, and only `install_service` writes;
* **nothing secret is written** — a unit file is world-readable and lives in a
  well-known path, so a command line carrying a credential is refused.

The restart rules are pinned too, because they are the difference between
"comes back after a crash" and "starts again after the engagement finished".
"""
import os
import sys
import xml.etree.ElementTree as ET

import pytest

from phantom.utils import service_units as SU

#: a working directory that exists on both platforms without being created
WORK = os.path.abspath(os.sep + "phantom")

#: a target with a space, a quote and a shell metacharacter in it
TARGETS = ["10.0.0.5", "host with space", 'quo"te', "10.0.0.9; rm -rf /"]

COMMAND = [sys.executable or "python", "-m", "phantom.main", "--auto",
           *TARGETS, "--supervise", "--resume-latest", "--aggressive"]

_TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


# ── parsers: an INDEPENDENT reimplementation, so the test cannot agree with
#    the renderer by sharing its bug ────────────────────────────────────────

def _unquote_systemd(text: str) -> list:
    """systemd ExecStart, read back the way systemd reads it."""
    out, cur, in_quote, escape = [], [], False, False
    for ch in text:
        if escape:
            cur.append(ch)
            escape = False
            continue
        if in_quote and ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_quote = not in_quote
            continue
        if ch == " " and not in_quote:
            if cur:
                out.append(_inert("".join(cur)))
                cur = []
            continue
        cur.append(ch)
    if cur:
        out.append(_inert("".join(cur)))
    return out


def _inert(token: str) -> str:
    """Undo the two literal escapes systemd's parser layers on top."""
    return token.replace("$$", "$").replace("%%", "%")


def _systemd_argv(unit: str) -> list:
    line = next(line for line in unit.splitlines()
                if line.startswith("ExecStart="))
    return _unquote_systemd(line[len("ExecStart="):])


def _windows_argv(text: str) -> list:
    """CommandLineToArgvW, reimplemented for the test."""
    out, cur, in_quote, pending = [], [], False, 0
    for ch in text:
        if ch == "\\":
            pending += 1
            continue
        if ch == '"':
            cur.append("\\" * (pending // 2))
            if pending % 2:
                cur.append('"')
            else:
                in_quote = not in_quote
            pending = 0
            continue
        if pending:
            cur.append("\\" * pending)
            pending = 0
        if ch == " " and not in_quote:
            if cur:
                out.append("".join(cur))
                cur = []
            continue
        cur.append(ch)
    if pending:
        cur.append("\\" * pending)
    if cur:
        out.append("".join(cur))
    return out


def _plist_obj(node):
    """A plist element as a Python value."""
    if node.tag == "dict":
        out, kids, index = {}, list(node), 0
        while index < len(kids):
            if kids[index].tag != "key":
                index += 1
                continue
            out[kids[index].text] = _plist_obj(kids[index + 1])
            index += 2
        return out
    if node.tag == "array":
        return [_plist_obj(child) for child in node]
    if node.tag == "integer":
        return int(node.text)
    if node.tag == "true":
        return True
    if node.tag == "false":
        return False
    return node.text


def _plist(content: str) -> dict:
    return _plist_obj(ET.fromstring(content).find("dict"))


def _task(content: str):
    """The Task Scheduler document, parsed from the bytes it is written as."""
    return ET.fromstring(content.encode("utf-16"))


def _task_find(task, path: str):
    return task.find("/".join(f"{{{_TASK_NS}}}{part}"
                              for part in path.split("/")))


def _task_argv(content: str) -> list:
    task = _task(content)
    command = _task_find(task, "Actions/Exec/Command").text or ""
    arguments = _task_find(task, "Actions/Exec/Arguments").text or ""
    return [command] + _windows_argv(arguments)


# ── (a) the argument list survives the round trip ──────────────────────────

def test_the_systemd_exec_start_rebuilds_the_exact_argument_list():
    unit = SU.render_systemd_unit(COMMAND, working_dir=WORK)
    assert _systemd_argv(unit) == COMMAND


def test_the_plist_argument_array_rebuilds_the_exact_argument_list():
    plist = SU.render_launchd_plist(COMMAND, working_dir=WORK)
    assert _plist(plist)["ProgramArguments"] == COMMAND


def test_the_windows_actions_rebuild_the_exact_argument_list():
    xml = SU.render_windows_task_xml(COMMAND, working_dir=WORK)
    assert _task_argv(xml) == COMMAND


def test_every_argument_appears_exactly_once_in_each_renderer():
    rebuilt = {
        "systemd": _systemd_argv(
            SU.render_systemd_unit(COMMAND, working_dir=WORK)),
        "launchd": _plist(
            SU.render_launchd_plist(COMMAND,
                                    working_dir=WORK))["ProgramArguments"],
        "schtasks": _task_argv(
            SU.render_windows_task_xml(COMMAND, working_dir=WORK)),
    }
    for kind, argv in rebuilt.items():
        assert argv == COMMAND, kind
        for arg in COMMAND:
            assert argv.count(arg) == COMMAND.count(arg), kind


def test_a_shell_metacharacter_stays_inside_its_own_argument():
    """`10.0.0.9; rm -rf /` is a TARGET, not a second command.

    This is the whole point of the quoting layer: the operator's own boot
    configuration is the last place an argument may re-split into a command.
    """
    hostile = ["phantom", "--auto", "10.0.0.9; rm -rf /", "a & b"]
    unit = SU.render_systemd_unit(hostile, working_dir=WORK)
    argv = _systemd_argv(unit)
    assert argv == hostile
    line = next(x for x in unit.splitlines() if x.startswith("ExecStart="))
    assert line.count(";") == 1 and line.count("&") == 1
    # each hostile argument sits INSIDE one pair of quotes, whole: the quoting
    # is what keeps the metacharacter data instead of syntax
    assert '"10.0.0.9; rm -rf /"' in line, line
    assert '"a & b"' in line, line

    plist = SU.render_launchd_plist(hostile, working_dir=WORK)
    assert _plist(plist)["ProgramArguments"] == hostile

    xml = SU.render_windows_task_xml(hostile, working_dir=WORK)
    assert _task_argv(xml) == hostile


def test_systemd_specifiers_and_variables_are_escaped(monkeypatch):
    """`$HOME` and `%i` must reach Phantom, not systemd's expander."""
    args = ["phantom", "--auto", "host$HOME", "50%off", "%i"]
    unit = SU.render_systemd_unit(args, working_dir=WORK)
    assert _systemd_argv(unit) == args
    line = next(x for x in unit.splitlines() if x.startswith("ExecStart="))
    assert "$$HOME" in line and "50%%off" in line


# ── (b) restart rules: a crash comes back, a finished run does not ─────────

def test_systemd_restarts_on_failure_only(monkeypatch):
    unit = SU.render_systemd_unit(COMMAND, working_dir=WORK)
    assert "Restart=on-failure" in unit
    assert "RestartSec=30" in unit
    assert "Restart=always" not in unit
    # systemd's own loop guard, in addition to Phantom's persisted counter
    assert "StartLimitBurst=5" in unit
    assert "StartLimitIntervalSec=300" in unit


def test_the_user_unit_does_not_reference_a_system_only_target():
    """A user instance has no `network-online.target`: it would refuse it."""
    user_unit = SU.render_systemd_unit(COMMAND, working_dir=WORK, user=True)
    assert "network-online.target" not in user_unit
    assert "WantedBy=default.target" in user_unit
    system_unit = SU.render_systemd_unit(COMMAND, working_dir=WORK, user=False)
    assert "Wants=network-online.target" in system_unit
    assert "WantedBy=multi-user.target" in system_unit


def test_launchd_keeps_alive_on_failure_only():
    plist = _plist(SU.render_launchd_plist(COMMAND, working_dir=WORK))
    assert plist["KeepAlive"] == {"SuccessfulExit": False}
    assert plist["ThrottleInterval"] == 30
    assert plist["RunAtLoad"] is True
    assert plist["Label"] == "com.phantom.auto"


def test_the_windows_task_restarts_on_failure_and_hides_itself():
    task = _task(SU.render_windows_task_xml(COMMAND, working_dir=WORK))
    assert _task_find(task, "Settings/RestartOnFailure/Interval").text == "PT30S"
    assert _task_find(task, "Settings/RestartOnFailure/Count").text == "3"
    assert _task_find(task, "Settings/Hidden").text == "true"
    # PT0S = no time limit: a default limit would kill a multi-day run
    assert _task_find(task, "Settings/ExecutionTimeLimit").text == "PT0S"
    assert _task_find(task, "Triggers/BootTrigger/Delay").text == "PT1M"


# ── (c) the XML formats are really XML ─────────────────────────────────────

def test_both_xml_formats_parse_and_carry_the_working_directory():
    plist = SU.render_launchd_plist(COMMAND, working_dir=WORK)
    assert _plist(plist)["WorkingDirectory"] == WORK

    xml = SU.render_windows_task_xml(COMMAND, working_dir=WORK)
    assert _task_find(_task(xml), "Actions/Exec/WorkingDirectory").text == WORK


# ── (d) `--print-service`: stdout only, filesystem untouched ───────────────

def _run_cli(monkeypatch, argv, tmp_path):
    from phantom import main as cli
    monkeypatch.setattr(
        SU, "service_path",
        lambda kind, name, **kw: str(tmp_path / f"{name}.unit"))
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def test_print_service_writes_the_unit_to_stdout_and_nothing_to_disk(
        tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(SU, "HOST_OS", "linux")
    code = _run_cli(monkeypatch,
                    ["phantom", "--auto", "10.0.0.5", "--aggressive",
                     "--print-service", "systemd"], tmp_path)
    assert code == 0
    out = capsys.readouterr().out
    assert "[Unit]" in out and "ExecStart=" in out
    # the unit is the invocation's, so the run it starts is the one asked for
    assert "--supervise" in out and "--resume-latest" in out
    assert "--aggressive" in out and "10.0.0.5" in out
    assert list(tmp_path.iterdir()) == []


def test_print_service_without_a_kind_uses_the_host_format(
        tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(SU, "HOST_OS", "linux")
    code = _run_cli(monkeypatch,
                    ["phantom", "--auto", "10.0.0.5", "--print-service"],
                    tmp_path)
    assert code == 0
    assert "[Unit]" in capsys.readouterr().out


def test_print_service_refuses_without_a_target(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(SU, "HOST_OS", "linux")
    code = _run_cli(monkeypatch,
                    ["phantom", "--auto", "--print-service", "systemd"],
                    tmp_path)
    assert code == 2
    # no unit on stdout (the refusal went to the operator, not into the file
    # they were about to redirect)
    assert "[Unit]" not in capsys.readouterr().out
    assert list(tmp_path.iterdir()) == []


def test_print_service_refuses_in_plan_mode(tmp_path, capsys, monkeypatch):
    """A service that only previews a run is a service that does nothing."""
    monkeypatch.setattr(SU, "HOST_OS", "linux")
    code = _run_cli(monkeypatch,
                    ["phantom", "--auto", "10.0.0.5", "--plan",
                     "--install-service", "systemd"], tmp_path)
    assert code == 2
    assert list(tmp_path.iterdir()) == []


# ── (e) install / uninstall ────────────────────────────────────────────────

def test_install_writes_the_file_and_uninstall_removes_it(tmp_path):
    path = tmp_path / "nested" / "phantom-auto.service"
    plan = {"kind": "systemd", "name": "phantom-auto", "path": str(path),
            "content": "[Unit]\nDescription=x\n", "encoding": "utf-8"}
    written = SU.install_service(plan)
    assert written == str(path)
    assert path.read_text(encoding="utf-8") == plan["content"]
    if os.name == "posix":
        assert (path.stat().st_mode & 0o777) == 0o644
    assert SU.uninstall_service(str(path)) is True
    assert not path.exists()
    assert SU.uninstall_service(str(path)) is False     # gone is not an error


def test_install_refuses_an_empty_plan():
    with pytest.raises(ValueError):
        SU.install_service({})
    with pytest.raises(ValueError):
        SU.install_service({"path": "x.service", "content": ""})
    with pytest.raises(ValueError):
        SU.uninstall_service("")


def test_the_windows_definition_is_written_as_utf16(tmp_path, monkeypatch):
    """Task Scheduler reads its XML as Unicode; the declaration must match."""
    monkeypatch.setattr(SU, "HOST_OS", "windows")
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    plan = SU.plan_service("schtasks", COMMAND, working_dir=WORK)
    assert plan["encoding"] == "utf-16"
    path = SU.install_service(plan)
    with open(path, encoding="utf-16") as handle:
        assert "<Task" in handle.read()


# ── (f) a hostile NAME cannot escape either ────────────────────────────────

@pytest.mark.parametrize("name", ["../../etc/cron.d/x", "a/b", "..",
                                  "x service", "a;b", "a$(b)"])
def test_a_service_name_cannot_escape_the_unit_directory(name):
    with pytest.raises(ValueError):
        SU.service_path("systemd", name)
    with pytest.raises(ValueError):
        SU.render_unit("systemd", COMMAND, working_dir=WORK, name=name)


def test_an_empty_name_is_the_default_one_not_a_path():
    """`--service-name` absent means "pick one"; it never means "" as a file."""
    with pytest.raises(ValueError):
        SU.service_path("systemd", "")
    unit = SU.render_unit("systemd", COMMAND, working_dir=WORK, name="")
    assert "phantom-auto" in unit


# ── (g) no secret ever reaches a unit file ─────────────────────────────────

@pytest.mark.parametrize("bad", [
    ["phantom", "--auto", "10.0.0.5", "--api-token", "0f1e2d3c4b5a"],
    ["phantom", "--auto", "10.0.0.5", "--password=hunter2"],
    ["python", "-m", "phantom.main", "C2_TOKEN=abcdef"],
    ["python", "-m", "phantom.main", "PHANTOM_API_KEY=abcdef"],
])
def test_a_command_carrying_a_secret_is_refused(bad):
    for render in (SU.render_systemd_unit, SU.render_launchd_plist,
                   SU.render_windows_task_xml):
        with pytest.raises(ValueError):
            render(bad, working_dir=WORK)


def test_a_normal_unit_contains_no_secret_looking_word():
    """The property is "no credential in the file", not "this word is absent".

    A bare word search cannot state that: every Windows task declares
    `<LogonType>InteractiveToken</LogonType>`, which is the platform's own
    vocabulary, and the plist path contains `<StandardErrorPath>` — neither is
    a value Phantom wrote. What a credential actually looks like is a
    `key=value` pair or an opaque literal, so that is what is checked.
    """
    shapes = ("token=", "token:", "secret=", "password=", "passwd=",
              "api_key=", "apikey=", "credential=", "psk=", "hmac_secret",
              "bearer ")
    for unit in (SU.render_systemd_unit(COMMAND, working_dir=WORK),
                 SU.render_launchd_plist(COMMAND, working_dir=WORK),
                 SU.render_windows_task_xml(COMMAND, working_dir=WORK)):
        lowered = unit.lower()
        for shape in shapes:
            assert shape not in lowered, (shape, unit[:120])


# ── (h) a command that CARRIES a credential is refused, not rendered

def test_a_command_carrying_a_credential_is_refused():
    for render in (SU.render_systemd_unit, SU.render_launchd_plist,
                   SU.render_windows_task_xml):
        for command in (["phantom", "--auto", "10.0.0.9",
                         "--token", "abc123"],
                        ["phantom", "--auto", "10.0.0.9",
                         "TOKEN=abc123"],
                        ["phantom", "--auto", "10.0.0.9",
                         "PASSWORD=hunter2"]):
            with pytest.raises(ValueError):
                render(command, working_dir=WORK)


# ── (h) a format that does not belong to this OS refuses, and writes nothing

def test_an_unsupported_kind_is_refused_with_a_reason():
    ok, reason = SU.supported("nonsense", host_os="linux")
    assert not ok and "unknown service format" in reason

    ok, reason = SU.supported("systemd", host_os="windows")
    assert not ok and "linux" in reason and "schtasks" in reason
    with pytest.raises(ValueError):
        SU.plan_service("systemd", COMMAND, working_dir=WORK,
                        host_os="windows")


def test_the_cli_refuses_a_foreign_format_without_writing(
        tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(SU, "HOST_OS", "windows")
    code = _run_cli(monkeypatch,
                    ["phantom", "--auto", "10.0.0.5",
                     "--install-service", "systemd"], tmp_path)
    assert code == 2
    assert list(tmp_path.iterdir()) == []


def test_install_service_is_the_only_thing_that_writes(tmp_path, monkeypatch):
    """Rendering every format leaves the filesystem exactly as it was."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(SU, "HOST_OS", "linux")
    before = sorted(os.listdir(tmp_path))
    SU.render_systemd_unit(COMMAND, working_dir=str(tmp_path))
    SU.render_launchd_plist(COMMAND, working_dir=str(tmp_path))
    SU.render_windows_task_xml(COMMAND, working_dir=str(tmp_path))
    SU.plan_service("systemd", COMMAND, working_dir=str(tmp_path),
                    host_os="linux")
    assert sorted(os.listdir(tmp_path)) == before
