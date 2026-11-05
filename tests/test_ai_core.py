"""AI runtime core: closed schema, off by default, no execution authority."""
from __future__ import annotations

import json
import os

import pytest

from phantom.automation.ai import config, router, schemas, telemetry
from phantom.automation.ai.client import MockClient
from phantom.automation.ai.registry import ModelRegistry

_PHASE_ENVS = (
    "PHANTOM_AI_EXPLOIT_MODE", "PHANTOM_AI_FINDING_MODE",
    "PHANTOM_AI_OSINT_MODE", "PHANTOM_AI_SOCIAL_MODE",
    "PHANTOM_AI_SCAN_PARSE_MODE", "PHANTOM_AI_EVOLUTION_MODE",
)


@pytest.fixture(autouse=True)
def clean_ai_env(monkeypatch, tmp_path):
    for name in ("PHANTOM_AI_MODE", *_PHASE_ENVS, "PHANTOM_AI_TELEMETRY",
                 "PHANTOM_AI_BUDGET_TOKENS", "PHANTOM_AI_CLOUD_KEY_ENV",
                 "TEST_AI_KEY"):
        monkeypatch.delenv(name, raising=False)
    log = tmp_path / "telemetry.jsonl"
    monkeypatch.setattr(telemetry, "telemetry_path",
                        lambda path=None: log)
    return log


def _mock(monkeypatch, scripted, mode="local"):
    client = MockClient(scripted)
    monkeypatch.setenv("PHANTOM_AI_MODE", mode)
    monkeypatch.setattr(router, "_client_for",
                        lambda phase, selected: client)
    return client


def test_ai_is_off_by_default_and_does_not_call_a_model(monkeypatch):
    called = []
    monkeypatch.setattr(router, "_client_for",
                        lambda *_: called.append(1))
    result = router.ask("exploit", {"candidates": []})
    assert result.ok is False
    assert result.error == "ai disabled"
    assert called == []
    assert router.ai_enabled("exploit") is False


def test_a_valid_exploit_rerank_passes_and_carries_no_command(monkeypatch):
    body = {"ranked": [{"id": "CVE-2099-1", "reason": "easiest",
                        "expected_success": 0.8}]}
    client = _mock(monkeypatch, {"exploit": json.dumps(body)})
    result = router.ask("exploit", {"candidates": [{"id": "CVE-2099-1"}]})
    assert result.ok is True, result.error
    assert result.data["ranked"][0]["id"] == "CVE-2099-1"
    assert result.model == "mock"
    assert client.calls and "UNTRUSTED_DATA" in client.calls[0][1]["content"]


def test_an_execution_shaped_key_is_rejected_wholesale(monkeypatch):
    body = {"ranked": [{"id": "CVE-2099-1", "command": "id"}]}
    _mock(monkeypatch, {"exploit": json.dumps(body)})
    result = router.ask("exploit", {"candidates": []})
    assert result.ok is False
    assert "execution-shaped key" in result.error


def test_social_schema_allows_text_only(monkeypatch):
    _mock(monkeypatch, {"social": json.dumps(
        {"text": "Ciao Mario, ti scrivo per il pacco.", "cmd": "id"})})
    result = router.ask("social", {"target": "Mario"})
    assert result.ok is False
    assert "execution-shaped key" in result.error


def test_an_unknown_finding_kind_is_rejected(monkeypatch):
    body = {"findings": [{"kind": "rootkit", "key": "x"}]}
    _mock(monkeypatch, {"finding": json.dumps(body)})
    result = router.ask("finding", {"findings": []})
    assert result.ok is False
    assert "kind not allowed" in result.error


def test_invalid_json_and_transport_errors_never_raise(monkeypatch):
    _mock(monkeypatch, "not json at all")
    assert router.ask("finding", {}).ok is False

    def boom(_messages, _schema):
        raise RuntimeError("endpoint down")

    _mock(monkeypatch, boom)
    result = router.ask("finding", {})
    assert result.ok is False
    assert "endpoint down" in result.error


def test_a_timeout_is_reported_as_such(monkeypatch):
    def slow(_messages, _schema):
        raise TimeoutError()

    _mock(monkeypatch, slow)
    result = router.ask("finding", {})
    assert result.ok is False
    assert "timeout" in result.error.lower()


def test_cloud_payload_is_redacted_before_it_leaves(monkeypatch):
    monkeypatch.setenv("PHANTOM_AI_CLOUD_KEY_ENV", "TEST_AI_KEY")
    monkeypatch.setenv("TEST_AI_KEY", "super-secret-value")
    client = _mock(monkeypatch, {"finding": json.dumps({"findings": []})},
                   mode="cloud")
    router.ask("finding", {"note": "password=hunter2",
                           "auth": "Bearer abc.def.ghi",
                           "host": "10.0.0.5"})
    sent = json.dumps(client.calls[0])
    assert "hunter2" not in sent
    assert "abc.def.ghi" not in sent
    assert "10.0.0.5" not in sent          # full target redaction on cloud


def test_a_missing_cloud_credential_names_the_variable_not_a_token(
        monkeypatch):
    monkeypatch.setenv("PHANTOM_AI_MODE", "cloud")
    monkeypatch.setenv("PHANTOM_AI_CLOUD_KEY_ENV", "TEST_AI_KEY")
    result = router.ask("finding", {})
    assert result.ok is False
    assert "TEST_AI_KEY" in result.error
    assert "super-secret" not in result.error


def test_the_budget_refuses_an_oversized_payload(monkeypatch):
    monkeypatch.setenv("PHANTOM_AI_BUDGET_TOKENS", "256")
    _mock(monkeypatch, {"finding": "{}"})
    result = router.ask("finding", {"blob": "x" * 4000})
    assert result.ok is False
    assert "budget" in result.error


def test_per_phase_override_wins_over_the_global_mode(monkeypatch):
    monkeypatch.setenv("PHANTOM_AI_MODE", "local")
    monkeypatch.setenv("PHANTOM_AI_OSINT_MODE", "off")
    assert router.ai_enabled("exploit") is True
    assert router.ai_enabled("osint") is False


def test_telemetry_stores_hashes_not_target_text(clean_ai_env, monkeypatch):
    _mock(monkeypatch, {"finding": json.dumps({"findings": []})})
    router.ask("finding", {"note": "password=hunter2"})
    text = clean_ai_env.read_text(encoding="utf-8")
    entry = json.loads(text.splitlines()[-1])
    assert entry["phase"] == "finding"
    assert entry["schema_ok"] is True
    assert "hunter2" not in text
    assert len(entry["prompt_sha"]) == 16
    assert entry["chars_in"] > 0


def _manifest(tmp_path, phase="exploit", version="v1", **overrides):
    manifest = {
        "phase": phase, "version": version,
        "base_model": "Qwen/Qwen3-1.7B", "adapter": "adapter/",
        "sha256": "abc123", "trained_at": "2026-10-25T10:00:00Z",
        "eval": {"ndcg": 0.71}, "baseline": {"ndcg": 0.63},
        "promoted": True,
    }
    manifest.update(overrides)
    folder = tmp_path / "models" / phase / version
    folder.mkdir(parents=True)
    # A promoted manifest that NAMES an adapter owes the directory: since
    # 2026-11-02 the registry refuses `promoted: true` over an artefact that
    # is not on disk (that is how a deleted ranker kept `trust` at `nudge`).
    # The fixture writes what a real promotion would have written.
    (folder / "adapter").mkdir(exist_ok=True)
    (folder / "manifest.json").write_text(json.dumps(manifest),
                                          encoding="utf-8")
    return manifest


def test_registry_promotes_only_a_measured_manifest(tmp_path):
    _manifest(tmp_path)
    registry = ModelRegistry(tmp_path)
    promoted = registry.promoted("exploit")
    assert promoted is not None
    assert promoted["version"] == "v1"


def test_registry_refuses_a_manifest_without_eval_scores(tmp_path):
    _manifest(tmp_path, eval={})
    assert ModelRegistry(tmp_path).promoted("exploit") is None


def test_registry_refuses_an_unpromoted_or_mismatched_manifest(tmp_path):
    _manifest(tmp_path, version="v2", promoted=False)
    _manifest(tmp_path, version="v3", phase="osint")
    assert ModelRegistry(tmp_path).promoted("exploit") is None


def test_registry_returns_the_newest_promoted_manifest(tmp_path):
    _manifest(tmp_path, version="v1", trained_at="2026-10-20T10:00:00Z")
    _manifest(tmp_path, version="v2", trained_at="2026-10-25T10:00:00Z")
    assert ModelRegistry(tmp_path).promoted("exploit")["version"] == "v2"


def test_schemas_reject_unknown_phases_instead_of_raising():
    assert schemas.validate("nope", {}) == ["no schema for phase: 'nope'"]
    assert schemas.SCHEMAS["social"]({"text": "ok"}) == []


def test_set_mode_applies_for_the_process(monkeypatch):
    try:
        assert config.set_mode("local") == "local"
        assert router.ai_enabled("exploit") is True
        assert config.set_mode("bogus") == "off"
    finally:
        # set_mode writes os.environ directly: do not leak it into a sibling
        os.environ.pop("PHANTOM_AI_MODE", None)
