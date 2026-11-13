"""Declared-effects postcondition (brief §7.1 / §10.1)."""
from phantom.automation.postconditions import declared_effects_met


class _F:
    def __init__(self, kind):
        self.kind = kind


def test_no_declared_effects_is_trivially_met():
    assert declared_effects_met([], [_F("anything")]) == (True, [])


def test_any_declared_effect_observed_is_met():
    met, missing = declared_effects_met(["service", "version"],
                                        [_F("service")])
    assert met is True
    assert missing == ["version"]


def test_only_undeclared_effects_is_drift():
    # produced a finding of an UNRELATED kind -> postcondition not met
    met, missing = declared_effects_met(["service"], [_F("hostname")])
    assert met is False
    assert missing == ["service"]


def test_nothing_produced_is_not_met():
    met, missing = declared_effects_met(["service"], [])
    assert met is False
    assert missing == ["service"]
