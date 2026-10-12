"""The auto-mode job lifecycle, driven through the REAL objects.

F-27/F-25: the renderer used to hold a single boolean (`running`) plus its own
optimistic label, so a run that died on the backend kept showing "active", a
requested stop was never confirmed, and a `cancelled` run was indistinguishable
from a `completed` one. The backend now owns the lifecycle
(`AutoJob.state` / `state_history`), the status route serves it, and the
renderer narrows it into a union.

Nothing here is a mock or a double:

* the state machine is exercised on the very `AutoJob` the run thread writes,
  through the same `callback` the engines feed;
* the HTTP assertions go through the real aiohttp application on a real
  localhost socket, with the real bearer token;
* the last two tests read the RENDERER's TypeScript and check it agrees with
  the payload the backend actually produces — the drift no amount of
  Python-only testing catches.
"""
import asyncio
import os
import re

import pytest

from phantom.api.server import (
    AUTOMODE_IDLE,
    AUTOMODE_STATES,
    _IDLE_STATUS,
    auto_jobs,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_TS = os.path.join(REPO_ROOT, "electron", "src", "lib", "api.ts")


@pytest.fixture
def job():
    """A real job in the manager, removed afterwards.

    The manager keeps finished jobs for an hour, so a test that forgot to
    remove its job would make the NEXT test's `active()` answer about somebody
    else's run — the order-dependent flake this fixture exists to prevent.
    """
    created = auto_jobs.create(["10.0.0.5"], "default", "enterprise", "deliver")
    try:
        yield created
    finally:
        auto_jobs._jobs.pop(created.id, None)
        if auto_jobs._active_id == created.id:
            auto_jobs._active_id = None


@pytest.fixture
def no_active_job():
    """Guarantee the manager has no active run, then put back what was there.

    Without this the "nothing is running" answers would depend on whether some
    earlier test file happened to leave a job behind.
    """
    saved = auto_jobs._active_id
    auto_jobs._active_id = None
    try:
        yield None
    finally:
        auto_jobs._active_id = saved


# ── the state machine ──────────────────────────────────────────────────────

def test_a_new_job_is_planning_until_the_engine_reports_work(job):
    assert job.state == "planning"
    assert job.snapshot()["running"] is True

    # commentary about a run is NOT execution: a note cannot promote the job
    job.callback("note", {"detail": "thinking about it"})
    assert job.state == "planning"

    # ...an action going out is
    job.callback("run", {"capability": "scan_tcp"})
    assert job.state == "running"


def test_an_illegal_transition_is_refused_and_leaves_the_history_true(job):
    job.callback("run", {})
    assert job.state == "running"

    # backwards, and to a state the run never reached: both refused
    assert job.set_state("planning") is False
    assert job.set_state("paused") is False          # not a backend state
    assert job.state == "running"
    assert [h["state"] for h in job.state_history] == ["planning", "running"]


def test_a_stop_is_stopping_until_the_engine_actually_halts(job):
    job.callback("run", {})
    assert job.request_stop() is True
    assert job.state == "stopping"
    assert job.snapshot()["running"] is True          # asked, not done
    assert job.request_stop() is False                # asking twice is not new

    job.finish("stopped by operator")
    snap = job.snapshot()
    assert snap["state"] == "cancelled"               # the CAUSE decides
    assert snap["running"] is False
    assert snap["end_reason"] == "stopped by operator"


def test_a_crash_is_a_failure_and_keeps_its_reason(job):
    job.callback("run", {})
    job.error = "UnicodeEncodeError: the console killed the renderer"
    job.finish("sequence complete")                   # even a normal exit...

    snap = job.snapshot()
    assert snap["state"] == "failed"                  # ...is a failure here
    assert "UnicodeEncodeError" in snap["error"]


def test_a_run_that_ends_on_its_own_is_completed(job):
    job.callback("run", {})
    job.finish("sequence complete")
    assert job.state == "completed"
    assert job.snapshot()["end_reason"] == "sequence complete"


def test_the_state_history_is_a_bounded_tail(job, monkeypatch):
    """A long run must not grow the job's memory without limit, and what
    survives must still be the true tail."""
    import phantom.api.server as server

    monkeypatch.setattr(server, "_STATE_HISTORY_LIMIT", 2)
    job.callback("run", {})
    job.request_stop()
    history = [h["state"] for h in job.snapshot()["state_history"]]
    assert len(history) <= 2
    assert history[-1] == "stopping"


# ── handoffs ───────────────────────────────────────────────────────────────

def test_a_handoff_is_ready_until_the_operator_decides(job):
    job.callback("handoff", {"beacon_id": "B-7F3A", "target": "web-01"})

    snap = job.snapshot()
    assert snap["handoff_state"] == "ready"
    assert [h["beacon_id"] for h in snap["handoffs"]] == ["B-7F3A"]
    assert snap["handoffs"][0]["status"] == "ready"
    assert snap["handoffs"][0]["target"] == "web-01"

    assert job.resolve_handoff("B-7F3A", "accept") is True
    assert job.snapshot()["handoff_state"] == "accepted"
    assert job.snapshot()["handoffs"][0]["status"] == "accepted"

    # a LATER beacon re-opens the card: it is new information, not the old one
    job.callback("handoff", {"beacon_id": "B-9999"})
    assert job.snapshot()["handoff_state"] == "ready"


def test_a_handoff_the_run_never_produced_is_refused(job):
    job.callback("handoff", {"beacon_id": "B-7F3A"})
    assert job.resolve_handoff("B-NOPE", "accept") is False
    assert job.snapshot()["handoff_state"] == "ready"
    # a decision that is neither accept nor dismiss cannot be recorded
    assert job.resolve_handoff("B-7F3A", "maybe") is False
    assert job.snapshot()["handoff_state"] == "ready"


def test_the_same_beacon_is_recorded_once(job):
    for _ in range(3):
        job.callback("handoff", {"beacon_id": "B-7F3A"})
    assert len(job.snapshot()["handoffs"]) == 1


# ── the wire (real aiohttp app, real socket) ───────────────────────────────

def _calls(*calls):
    """Send (method, path, body) tuples to a REAL app and return the answers."""
    return asyncio.run(_calls_async(calls))


async def _calls_async(calls):
    from aiohttp.test_utils import TestClient, TestServer

    from phantom.api.server import create_app
    from phantom.utils import c2_crypto

    client = TestClient(TestServer(create_app()))
    await client.start_server()
    try:
        headers = {"Authorization": f"Bearer {c2_crypto.get_api_token()}"}
        out = []
        for method, path, *rest in calls:
            if method == "GET":
                response = await client.get(path, headers=headers)
            else:
                response = await client.post(path, json=rest[0], headers=headers)
            out.append((response.status, await response.json()))
        return out
    finally:
        await client.close()


def test_the_idle_answer_and_a_job_snapshot_have_the_same_keys(job):
    """One shape: the renderer parses ONE payload, idle or not.

    If the two drifted, `deriveJobState` would read `undefined` for whatever
    the idle answer forgot — silently, because a TS parser falls back.
    """
    assert set(_IDLE_STATUS) == set(job.snapshot())
    assert _IDLE_STATUS["state"] == AUTOMODE_IDLE
    assert AUTOMODE_IDLE not in AUTOMODE_STATES


def test_the_status_route_answers_the_active_job(job):
    job.callback("run", {"capability": "scan_tcp"})
    status, payload = _calls(("GET", "/api/automode/status"))[0]
    assert status == 200
    assert payload["job_id"] == job.id
    assert payload["state"] == "running"
    assert payload["running"] is True
    assert isinstance(payload["elapsed"], float)


def test_the_status_route_answers_idle_when_nothing_is_registered(no_active_job):
    status, payload = _calls(("GET", "/api/automode/status"))[0]
    assert status == 200
    assert payload["state"] == AUTOMODE_IDLE
    assert payload["job_id"] is None
    assert payload["handoffs"] == []


def test_the_status_route_serves_a_finished_job_by_id(job):
    job.finish("sequence complete")
    status, payload = _calls(("GET", f"/api/automode/status?job_id={job.id}"))[0]
    assert status == 200
    assert payload["state"] == "completed"
    assert payload["running"] is False
    assert payload["job_id"] == job.id


def test_an_unknown_job_id_answers_idle_and_never_errors():
    """A polling UI must not have to handle a 404 for a job that was pruned:
    "nothing to show" is an answer, not an error."""
    status, payload = _calls(("GET", "/api/automode/status?job_id=job_deadbeef"))[0]
    assert status == 200
    assert payload["state"] == AUTOMODE_IDLE
    assert payload["job_id"] is None


def test_stop_over_http_reports_stopping_not_stopped(job):
    job.callback("run", {})
    status, payload = _calls(("POST", "/api/automode/stop", {}))[0]
    assert status == 200
    assert payload["status"] == "stopped"
    assert payload["state"] == "stopping"       # NOT "cancelled" yet
    assert payload["job"]["state"] == "stopping"
    assert payload["job"]["running"] is True


def test_stop_over_http_with_nothing_running_says_so(no_active_job):
    status, payload = _calls(("POST", "/api/automode/stop", {}))[0]
    assert status == 200
    assert payload["note"] == "no active run"
    assert payload["job"]["state"] == AUTOMODE_IDLE


def test_the_handoff_route_records_the_decision(job):
    job.callback("handoff", {"beacon_id": "B-7F3A", "target": "web-01"})
    status, payload = _calls(
        ("POST", "/api/automode/handoff",
         {"beacon_id": "B-7F3A", "decision": "accept"}))[0]
    assert status == 200
    assert payload["decision"] == "accept"
    assert payload["handoff_state"] == "accepted"
    # the answer carries the whole snapshot: the caller does not re-poll to
    # learn what its own click did
    assert payload["job"]["job_id"] == job.id
    assert payload["job"]["handoffs"][0]["status"] == "accepted"

    _status, payload = _calls(
        ("POST", "/api/automode/handoff",
         {"beacon_id": "B-7F3A", "decision": "dismiss"}))[0]
    assert payload["handoff_state"] == "dismissed"


def test_the_handoff_route_refuses_bad_input(job):
    job.callback("handoff", {"beacon_id": "B-7F3A"})
    cases = [
        ({"decision": "accept"}, 400),                       # no beacon
        ({"beacon_id": "B-7F3A", "decision": "yolo"}, 400),  # not a decision
        ({"beacon_id": "B-STRANGER", "decision": "accept"}, 404),  # not ours
    ]
    for body, expected in cases:
        status, payload = _calls(("POST", "/api/automode/handoff", body))[0]
        assert status == expected, (body, status, payload)
    # ...and none of them changed the recorded state
    assert job.snapshot()["handoff_state"] == "ready"


# ── the renderer must agree with what the backend sends ───────────────────

def _ts_text() -> str:
    with open(API_TS, encoding="utf-8") as handle:
        return handle.read()


def _ts_interface(name: str) -> str:
    match = re.search(rf"export interface {name} \{{(.*?)\n\}}",
                      _ts_text(), re.DOTALL)
    assert match, f"interface {name} not found in {API_TS}"
    return match.group(1)


def test_the_renderer_interface_declares_every_field_the_backend_sends(job):
    fields = set(re.findall(r"^\s{2}([a-z_]+)\??:", _ts_interface("AutomodeStatus"),
                            re.MULTILINE))
    assert fields, "no fields parsed from AutomodeStatus"
    assert fields == set(job.snapshot()), (
        "the renderer's AutomodeStatus and the backend snapshot disagree: "
        f"only in TS: {sorted(fields - set(job.snapshot()))}, "
        f"only in the backend: {sorted(set(job.snapshot()) - fields)}")


def test_the_renderer_state_union_covers_every_backend_state():
    union = re.search(r"export type JobState =(.*?)\nconst ", _ts_text(), re.DOTALL)
    assert union, "JobState union not found"
    members = set(re.findall(r"'([a-z_]+)'", union.group(1)))
    assert set(AUTOMODE_STATES) | {AUTOMODE_IDLE} <= members, (
        "backend states the renderer cannot render: "
        f"{sorted((set(AUTOMODE_STATES) | {AUTOMODE_IDLE}) - members)}")
    # and the two operator-facing states the docs ask for
    assert {"handoff_ready", "awaiting_approval"} <= members
