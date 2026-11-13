"""Tests for the noise circuit breaker (detection-risk accounting)."""
import pytest

from phantom.automation.belief import WorldModel


def test_score_accumulates():
    wm = WorldModel(target="t", target_type="ip")
    assert wm.noise_score == 0.0
    wm.record_noise("exploit")
    assert wm.noise_score == pytest.approx(1.0)
    wm.record_noise("ad_attack")
    assert wm.noise_score == pytest.approx(3.5)


def test_breaker_trips_at_limit():
    wm = WorldModel(target="t", target_type="ip")
    for _ in range(5):
        wm.record_noise("brute_online")   # 2.0 each -> 10 < 12
    assert not wm.noise_breaker_tripped()
    wm.record_noise("brute_online")       # 12 -> trips
    assert wm.noise_breaker_tripped()


def test_score_persists_in_checkpoint():
    wm = WorldModel(target="t", target_type="ip")
    wm.record_noise("loud_scan")
    wm.record_noise("exploit")
    data = wm.to_dict()
    wm2 = WorldModel.from_dict(data)
    assert wm2.noise_score == pytest.approx(wm.noise_score)
    assert wm2.noise_breaker_tripped() == wm.noise_breaker_tripped()


def test_custom_weight():
    wm = WorldModel(target="t", target_type="ip")
    wm.record_noise("custom_event", weight=7.0)
    assert wm.noise_score == pytest.approx(7.0)


def test_unknown_event_default_weight():
    wm = WorldModel(target="t", target_type="ip")
    wm.record_noise("mystery")
    assert wm.noise_score == pytest.approx(0.5)


def test_events_bounded():
    wm = WorldModel(target="t", target_type="ip")
    for i in range(300):
        wm.record_noise("exploit")
    assert len(wm.noise_events) <= 200
    assert wm.noise_events[-1]["score"] == pytest.approx(300 * 1.0)
