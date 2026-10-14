"""A boot-level service definition must be auditable, verifiable and non-clobbering.

The audit's P2 ("rete di sicurezza dell'operatore") asked for four things around
`--install-service`:

1. an AUDIT entry for the installation — a unit can start code at boot, which
   outlives the process, so it belongs in the hash-chained trail;
2. a HASH OF THE INVOCATION — so the file, the install message and the audit
   entry can be compared later instead of trusted;
3. a VERIFIABLE uninstall — "removed" must be checked, not assumed;
4. DETECTION of a pre-existing unit — never overwrite a different boot file in
   silence (it may be another engagement's, or the operator's own copy).

`--print-service` stays pure stdout, so none of this leaks into the file an
operator redirects into the unit directory.
"""
import io
import os
import sys

import pytest

from phantom.main import KIND_INSTALLED, KIND_REMOVED
from phantom.utils import service_units as SU

COMMAND = ["/usr/bin/python3", "-m", "phantom.main", "--auto", "10.0.0.5",
           "--supervise", "--resume-latest"]
WORK = "/tmp"


@pytest.fixture(autouse=True)
def _linux(monkeypatch):
    """Render the systemd format regardless of the machine running the tests."""
    monkeypatch.setattr(SU, "HOST_OS", "linux")
    return SU


def _capture(fn):
    """(stdout, stderr) with whitespace flattened — Rich wraps long lines."""
    out, err = io.StringIO(), io.StringIO()
    original = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        result = fn()
    finally:
        sys.stdout, sys.stderr = original
    flat = lambda s: " ".join(s.getvalue().split())  # noqa: E731
    return result, flat(out), flat(err)


# ── 2. the invocation hash ─────────────────────────────────────────────────

def test_the_invocation_digest_identifies_the_exact_argv():
    same = SU.invocation_digest(COMMAND)
    assert same == SU.invocation_digest(list(COMMAND))
    assert same != SU.invocation_digest(COMMAND[:-1])          # shorter
    assert same != SU.invocation_digest(COMMAND + ["--llm"])   # different run
    # order is part of the identity
    assert SU.invocation_digest(["a", "b"]) != SU.invocation_digest(["b", "a"])
    # and arguments cannot be shuffled across the join
    assert SU.invocation_digest(["a b", "c"]) != SU.invocation_digest(["a",
                                                                      "b c"])


def test_the_plan_carries_both_digests():
    plan = SU.plan_service("systemd", COMMAND, working_dir=WORK)
    assert plan["digest"] == SU.invocation_digest(COMMAND)
    assert plan["content_digest"] == SU.content_digest(plan["content"],
                                                       plan["encoding"])


def test_the_content_digest_follows_the_encoding():
    """UTF-16 (Task Scheduler) hashes differently from the same UTF-8 text."""
    text = "<Task>x</Task>"
    assert SU.content_digest(text, "utf-8") != SU.content_digest(text, "utf-16")


def test_file_digest_of_a_missing_file_is_empty(tmp_path):
    assert SU.file_digest(str(tmp_path / "nope.service")) == ""


# ── 4. a pre-existing unit is detected, not clobbered ──────────────────────

def test_a_different_existing_unit_is_refused_with_the_remedy(tmp_path):
    path = tmp_path / "phantom-auto.service"
    path.write_text("[Unit]\nDescription=someone else\n", encoding="utf-8")
    plan = SU.plan_service("systemd", COMMAND, working_dir=WORK)
    plan["path"] = str(path)
    with pytest.raises(ValueError) as excinfo:
        SU.install_service(plan)
    message = str(excinfo.value)
    assert "DIFFERENT service definition already exists" in message
    assert "uninstall-service" in message
    # and the other file is untouched
    assert "someone else" in path.read_text(encoding="utf-8")


def test_reinstalling_the_same_definition_is_idempotent(tmp_path):
    plan = SU.plan_service("systemd", COMMAND, working_dir=WORK)
    plan["path"] = str(tmp_path / "phantom-auto.service")
    first = SU.install_service(plan)
    second = SU.install_service(dict(plan))          # same bytes, no refusal
    assert first == second
    assert SU.file_digest(first) == plan["content_digest"]


def test_overwriting_is_possible_only_when_asked_explicitly(tmp_path):
    path = tmp_path / "phantom-auto.service"
    path.write_text("old\n", encoding="utf-8")
    plan = SU.plan_service("systemd", COMMAND, working_dir=WORK)
    plan["path"] = str(path)
    SU.install_service(plan, overwrite=True)
    assert SU.file_digest(str(path)) == plan["content_digest"]


def test_existing_service_reports_what_is_there(tmp_path):
    plan = SU.plan_service("systemd", COMMAND, working_dir=WORK)
    path = str(tmp_path / "phantom-auto.service")
    plan["path"] = path
    assert SU.existing_service(path, plan["content"], plan["encoding"]) \
        == ("", False)
    SU.install_service(plan)
    digest, same = SU.existing_service(path, plan["content"],
                                       plan["encoding"])
    assert same is True and digest == plan["content_digest"]
    _, same_other = SU.existing_service(path, "different", "utf-8")
    assert same_other is False


def test_the_write_is_verified_against_what_was_rendered(tmp_path, monkeypatch):
    """A write that does not land as rendered must raise, not pass silently."""
    plan = SU.plan_service("systemd", COMMAND, working_dir=WORK)
    plan["path"] = str(tmp_path / "phantom-auto.service")
    original = SU.file_digest
    calls = []

    def truncated(path):
        calls.append(path)
        return "0" * 64 if len(calls) > 1 else original(path)

    monkeypatch.setattr(SU, "file_digest", truncated)
    with pytest.raises(ValueError) as excinfo:
        SU.install_service(plan)
    assert "is not what was rendered" in str(excinfo.value)


# ── 3. the uninstall is verified ───────────────────────────────────────────

def test_remove_twice_reports_false_then_stays_honest(tmp_path):
    plan = SU.plan_service("systemd", COMMAND, working_dir=WORK)
    plan["path"] = str(tmp_path / "phantom-auto.service")
    SU.install_service(plan)
    assert SU.uninstall_service(plan["path"]) is True
    assert SU.uninstall_service(plan["path"]) is False
    assert not os.path.exists(plan["path"])


def test_a_file_that_survives_removal_is_an_error(tmp_path, monkeypatch):
    target = tmp_path / "phantom-auto.service"
    target.write_text("x\n", encoding="utf-8")

    def fake_remove(path):                       # pretend the FS lied
        pass

    monkeypatch.setattr(SU.os, "remove", fake_remove)
    with pytest.raises(ValueError) as excinfo:
        SU.uninstall_service(str(target))
    assert "still exists after removal" in str(excinfo.value)


# ── 1. the audit trail ─────────────────────────────────────────────────────

def test_the_cli_audit_kinds_match_the_decision_audit_vocabulary():
    """One vocabulary: the CLI constants ARE the audit module's constants."""
    from phantom.automation import decision_audit as da

    assert KIND_INSTALLED == da.KIND_SERVICE_INSTALLED
    assert KIND_REMOVED == da.KIND_SERVICE_REMOVED


class _FakeAudit:
    def __init__(self):
        self.events = []

    def record(self, kind, **fields):
        self.events.append((kind, fields))
        return {"event": kind, **fields}


@pytest.fixture
def audit(monkeypatch):
    sink = _FakeAudit()
    monkeypatch.setattr("phantom.automation.decision_audit.record",
                        sink.record)
    return sink


def _service_args(target="10.0.0.5", **overrides):
    from phantom.main import build_parser

    argv = ["--auto", target, "--install-service", "systemd"]
    for key, value in overrides.items():
        argv += [f"--{key.replace('_', '-')}", value]
    args = build_parser().parse_args(argv)
    return args, [target]


def test_install_records_an_audit_entry_with_both_digests(tmp_path, monkeypatch,
                                                          audit):
    from phantom import main as cli

    monkeypatch.setattr(SU, "service_path",
                        lambda kind, name, **kw: str(tmp_path / "u.service"))
    args, targets = _service_args()
    code = cli.run_service_command(args, targets)
    assert code == 0
    assert [kind for kind, _ in audit.events] == [KIND_INSTALLED]
    fields = audit.events[0][1]
    assert fields["path"].endswith("u.service")
    assert len(fields["digest"]) == 64
    assert len(fields["content_digest"]) == 64
    assert fields["format"] == "systemd"


def test_install_tells_the_operator_the_invocation_digest(tmp_path,
                                                          monkeypatch, audit):
    from phantom import main as cli

    monkeypatch.setattr(SU, "service_path",
                        lambda kind, name, **kw: str(tmp_path / "u.service"))
    args, targets = _service_args()

    def run():
        try:
            return cli.run_service_command(args, targets)
        except SystemExit:                    # not expected, but keep output
            return -1

    code, out, _err = _capture(run)
    assert code == 0
    digest = SU.invocation_digest(cli.build_service_command(args, targets))
    assert digest[:16] in out
    assert "audit" in out.lower()


def test_uninstall_records_the_digest_of_what_it_removed(tmp_path, monkeypatch,
                                                         audit):
    from phantom import main as cli

    unit = tmp_path / "u.service"
    monkeypatch.setattr(SU, "service_path",
                        lambda kind, name, **kw: str(unit))
    plan = SU.plan_service("systemd", COMMAND, working_dir=WORK)
    plan["path"] = str(unit)
    SU.install_service(plan)
    expected = plan["content_digest"]

    args, targets = _service_args()
    args.install_service = ""
    args.uninstall_service = "systemd"
    code, out, _err = _capture(lambda: cli.run_service_command(args, targets))
    assert code == 0
    assert not unit.exists()
    assert [kind for kind, _ in audit.events] == [KIND_REMOVED]
    assert audit.events[0][1]["digest"] == expected
    assert expected[:16] in out


def test_print_service_stays_pure_and_writes_no_audit_entry(tmp_path,
                                                            monkeypatch,
                                                            audit, capsys):
    """`--print-service > unit.service` must produce the unit, nothing else."""
    from phantom import main as cli

    args, targets = _service_args()
    args.install_service = ""
    args.print_service = "systemd"
    code, out, err = _capture(lambda: cli.run_service_command(args, targets))
    assert code == 0
    assert audit.events == [], "printing must not touch the audit trail"
    assert out.startswith("[Unit]"), out[:40]
    assert "sha256" not in out
    assert not os.path.exists(os.path.join(tmp_path, "u.service"))


def test_a_refused_install_records_nothing(tmp_path, monkeypatch, audit):
    from phantom import main as cli

    unit = tmp_path / "u.service"
    unit.write_text("someone else's unit\n", encoding="utf-8")
    monkeypatch.setattr(SU, "service_path",
                        lambda kind, name, **kw: str(unit))
    args, targets = _service_args()
    code, _out, _err = _capture(lambda: cli.run_service_command(args, targets))
    assert code == 2
    assert audit.events == [], "a refusal is not an audit entry"
    assert "someone else's unit" in unit.read_text(encoding="utf-8")
