"""The operator can force the AI authority ladder from the CLI, loudly.

Measured 2026-11-02: `ai.authority` existed in the config schema and
`trust.apply_authority` already announced an override, but `phantom/main.py`
had no flag — the only way to use it was to edit a config file, which is the
kind of switch nobody can trace in a report. The flag closes the surface, and
the tests pin the two properties that make it safe: it validates its values,
and a forced level is recorded as an OVERRIDE rather than as evidence.
"""
from __future__ import annotations

import pytest

from phantom.automation.ai import config as ai_config
from phantom.automation.ai.trust import Trust, apply_authority
from phantom.main import build_parser


def test_the_parser_accepts_every_level_and_defaults_to_none():
    parser = build_parser()
    assert parser.parse_args([]).ai_authority is None
    for level in ("auto", "nudge", "decide", "full"):
        assert parser.parse_args(["--ai-authority", level]).ai_authority == level


def test_an_unknown_level_is_refused_by_argparse():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--ai-authority", "yolo"])


def test_the_flag_is_the_env_var_the_ladder_reads(monkeypatch):
    monkeypatch.delenv("PHANTOM_AI_AUTHORITY", raising=False)
    monkeypatch.setenv("PHANTOM_AI_AUTHORITY", "decide")
    assert ai_config.authority_override() == "decide"


def test_a_forced_level_is_announced_as_an_override(monkeypatch):
    monkeypatch.setenv("PHANTOM_AI_AUTHORITY", "decide")
    earned = Trust(phase="exploit", level="observe", bound=0.0, max_steps=0,
                   gap=0.0, source="manifest", reason="no promoted model")
    forced = apply_authority(earned)
    assert forced.level == "decide"
    assert forced.source == "operator-override"


def test_auto_leaves_the_earned_ladder_alone(monkeypatch):
    monkeypatch.setenv("PHANTOM_AI_AUTHORITY", "auto")
    earned = Trust(phase="exploit", level="observe", bound=0.0, max_steps=0,
                   gap=0.0, source="manifest", reason="no promoted model")
    assert apply_authority(earned) is earned
