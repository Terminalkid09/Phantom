"""The DM sequence: no link on the opener, suspicion stops, requests hand off."""
from __future__ import annotations

from phantom.automation.social import dm_flow as dm


def test_a_cold_thread_opens_without_a_link():
    flow = dm.Flow(target="@mario", platform="telegram")
    decision = dm.opening_decision(flow)
    assert decision.action == "send" and decision.stage == "opener"
    assert decision.link_allowed is False
    assert decision.delay_s > 0


def test_the_link_never_comes_before_the_minimum_exchanges():
    flow = dm.Flow(target="@mario", platform="telegram")
    dm.opening_decision(flow)
    first = dm.advance(flow, "thanks, who are you?")
    # a direct "who are you" is a handoff, not an escalation
    assert first.action == "handoff"
    assert first.link_allowed is False


def test_two_engaged_replies_unlock_the_pretext_then_the_link():
    flow = dm.Flow(target="@mario", platform="telegram")
    dm.opening_decision(flow)
    a = dm.advance(flow, "ok thanks")
    assert a.stage == "rapport" and not a.link_allowed
    b = dm.advance(flow, "sure, tell me")
    assert b.stage == "pretext" and not b.link_allowed
    c = dm.advance(flow, "va bene grazie")
    assert c.stage == "link" and c.link_allowed is True
    assert flow.link_sent is True


def test_suspicion_accumulates_and_then_stops_the_thread():
    flow = dm.Flow(target="@mario", platform="instagram")
    dm.opening_decision(flow)
    dm.advance(flow, "ok")
    first = dm.advance(flow, "how did you get my number?")
    assert first.action == "wait"
    second = dm.advance(flow, "this is strange")
    assert second.action == "stop"
    assert flow.state == dm.CLOSED


def test_hostility_closes_immediately():
    flow = dm.Flow(target="@mario")
    dm.opening_decision(flow)
    d = dm.advance(flow, "fuck off, scam")
    assert d.action == "stop" and flow.state == dm.CLOSED
    assert dm.advance(flow, "hello?").action == "stop"


def test_a_request_for_proof_goes_to_the_operator():
    flow = dm.Flow(target="@mario")
    d = dm.advance(flow, "prove it, who are you")
    assert d.action == "handoff"
    assert flow.state == dm.HANDOFF


def test_neutral_replies_never_escalate():
    flow = dm.Flow(target="@mario")
    dm.opening_decision(flow)
    d = dm.advance(flow, "hmm")
    assert d.action == "wait"
    assert d.stage == dm.OPENER


def test_classification_is_inspectable_and_ordered():
    assert dm.classify_reply("report you") == dm.HOSTILE
    assert dm.classify_reply("who are you?") == dm.REQUEST
    assert dm.classify_reply("how did you find me") == dm.SUSPICIOUS
    assert dm.classify_reply("sure, thanks") == dm.ENGAGED
    assert dm.classify_reply("") == dm.NEUTRAL
