"""The passive side effects must be ASSERTED, not implied by a default.

`c2.auto_persist` is ON by default (owner decision Q-1, kept): the first
check-in of a new beacon queues a `persist` task on the target with no operator
action. The audit's P2 accepted keeping the default but asked for the consent
to be EXPLICIT for "a side effect triggered by a passive check-in".

That means the operator can see the grant before it fires (doctor), and the
engagement's own trail states it the moment the listener opens — including the
exact way to revoke it — so nobody discovers it from the target's traffic.
"""
import pytest

from phantom.core import c2_server


class _Audit:
    def __init__(self):
        self.events = []

    def append(self, event, **fields):
        self.events.append((event, fields))
        return {"event": event, **fields}


@pytest.fixture
def audit(monkeypatch):
    sink = _Audit()
    monkeypatch.setattr("phantom.utils.audit_log.audit_log", sink,
                        raising=False)
    import phantom.utils.audit_log as audit_log_module
    monkeypatch.setattr(audit_log_module, "audit_log", sink, raising=False)
    return sink


def test_the_grant_is_recorded_once_when_the_listener_opens(audit, monkeypatch):
    server = c2_server.C2Server(host="127.0.0.1", port=0)
    monkeypatch.setattr(server, "use_ssl", True)
    server._record_engagement_grants()
    assert [event for event, _ in audit.events] == ["engagement_grants"]
    fields = audit.events[0][1]
    assert fields["auto_persist"] is True          # default ON, stated
    assert fields["auto_shell"] is False           # default OFF, stated
    assert "listener" in fields and "revoke" in fields
    assert "PHANTOM_AUTO_PERSIST" in fields["revoke"]


def test_a_revoked_grant_is_recorded_as_revoked(audit, monkeypatch):
    monkeypatch.setenv("PHANTOM_AUTO_PERSIST", "0")
    server = c2_server.C2Server(host="127.0.0.1", port=0)
    server._record_engagement_grants()
    assert audit.events[0][1]["auto_persist"] is False


def test_recording_the_grant_can_never_break_the_listener(monkeypatch):
    """Telemetry must not decide whether a C2 listener runs."""
    import phantom.utils.audit_log as audit_log_module

    class Broken:
        def append(self, *a, **kw):
            raise RuntimeError("audit sink down")

    monkeypatch.setattr(audit_log_module, "audit_log", Broken(),
                        raising=False)
    c2_server.C2Server(host="127.0.0.1", port=0)._record_engagement_grants()


class TestDoctorShowsTheGrant:
    def _check(self):
        from phantom.core import doctor

        return doctor._auto_persist_grant_check()

    def test_the_grant_is_reported_as_a_warning_with_the_kill_switch(
            self, monkeypatch):
        monkeypatch.delenv("PHANTOM_AUTO_PERSIST", raising=False)
        check = self._check()
        assert check.name == "auto-persist"
        assert check.status == "warn", "a passive side effect is not a pass"
        assert "persistence" in check.detail.lower()
        assert "PHANTOM_AUTO_PERSIST" in check.hint

    def test_a_revoked_grant_passes(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_AUTO_PERSIST", "0")
        check = self._check()
        assert check.status == "pass"
        assert "register-only" in check.detail

    def test_the_check_is_part_of_the_default_doctor_run(self):
        from phantom.core import doctor

        report = doctor.run_doctor(net=False)
        names = [c.name for c in report.checks]
        assert "auto-persist" in names
