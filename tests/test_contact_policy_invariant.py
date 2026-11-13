"""The contact rule is an INVARIANT, not a default.

Sub-agents parallelise only where they touch nothing: OSINT, payload
authoring, email-candidate reasoning. A scan or an exploit is target
contact and runs as ONE lead; a second worker may only be an advisory
(no execution), which the cell roster already models.

These tests pin the invariant even when a caller raises max_agents: the
scheduler must key the slot count on the CONTACT class, never on the
number alone.
"""
from __future__ import annotations

from phantom.automation.brain.cells import (
    ACTING_CAP,
    CONTACT_EXPLOIT,
    CONTACT_NONE,
    CONTACT_RECON,
)


def test_only_offline_contact_may_act_in_parallel():
    assert ACTING_CAP[CONTACT_NONE] > 1
    assert ACTING_CAP[CONTACT_RECON] == 1
    assert ACTING_CAP[CONTACT_EXPLOIT] == 1


class _Action:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class _Board:
    def ensure(self, _origin):
        return None


class _Orch:
    def __init__(self):
        self.submitted = []

    def submit(self, **kwargs):
        self.submitted.append(kwargs)
        return _Action(**kwargs)


def _task(contact: str, max_agents: int):
    from phantom.automation.swarm.tasks import SwarmTask
    return SwarmTask(id="t-0", goal="footprint", targets=["10.0.0.5"],
                     contact=contact, max_agents=max_agents)


def _slots(contact: str, max_agents: int) -> int:
    from phantom.automation.swarm.scheduler import _submit_origin_slots
    orch = _Orch()
    task = _task(contact, max_agents)
    _submit_origin_slots({"10.0.0.5": orch}, None, _Board(), task, 0,
                         "10.0.0.5")
    return len(orch.submitted)


def test_raising_the_number_never_parallelises_a_scan():
    assert _slots(CONTACT_RECON, 5) == 1


def test_raising_the_number_never_parallelises_an_exploit():
    assert _slots(CONTACT_EXPLOIT, 5) == 1


def test_offline_work_still_fans_out_up_to_the_cap():
    assert _slots(CONTACT_NONE, 4) == 4
    assert _slots(CONTACT_NONE, 99) == ACTING_CAP[CONTACT_NONE]
