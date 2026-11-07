"""Promoted means measured AND installed — in ONE place, the registry.

The defect this closes (measured 2026-11-02): ``models/exploit/
ranker-2026-10-30/manifest.json`` said ``promoted: true`` after its
``ranker.json`` was deleted. ``ModelRegistry.promoted('exploit')`` returned it
anyway, ``trust_for('exploit')`` reported ``nudge`` — so the advisor believed it
had a second opinion it could never load — and ``--ai integrated`` passed the
manifest's version string to a chat endpoint as a model id.

Three subsystems were told a model existed because one JSON file said so. The
rule pinned here is that the file and the model must agree: a promoted manifest
that NAMES an artifact owes that artifact, and the registry is the only place
that decides it.

A manifest that names no artifact (hand-written benchmark and test manifests) is
still validated by its measurement alone;
``test_a_manifest_that_names_no_artifact_keeps_the_measurement_rule`` pins
that, because tightening it would fail the fixtures rather than a real model.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from phantom.automation.ai import router
from phantom.automation.ai.registry import (
    PROJECT_ROOT,
    ModelRegistry,
    artifact_problem,
    manifest_errors,
)
from phantom.automation.ai.trust import trust_for

RANKER_WEIGHTS = {"weights": {"a": 1.0}, "context": {}, "bias": 0.0}


def _manifest_folder(tmp_path: Path, version: str = "v1") -> Path:
    folder = tmp_path / "models" / "exploit" / version
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _write(folder: Path, version: str = "v1", **overrides) -> dict:
    data = {
        "phase": "exploit",
        "version": version,
        "base_model": "linear-pairwise-ranker",
        "sha256": "0" * 64,
        "trained_at": "2026-10-30T00:00:00Z",
        "eval": {"ndcg": 0.9379},
        "baseline": {"ndcg": 0.9021},
        "promoted": True,
        "kind": "linear-ranker",
        "ranker": "ranker.json",
        "eval_gate": {"verdict": "promote", "n": 31, "min_rows": 20,
                      "delta": 0.0357, "ci_low": 0.0095,
                      "baseline": 0.9021},
    }
    data.update(overrides)
    (folder / "manifest.json").write_text(json.dumps(data), encoding="utf-8")
    return data


def _sync_digest(folder: Path) -> None:
    """Rewrite the manifest with the REAL digest of the artifact on disk.

    Since 2026-11-06 a promoted manifest's sha256 is ENFORCED, so a fixture
    that writes its artifact after the manifest has to update the claim —
    otherwise the registry refuses it for a digest mismatch and the test
    measures the fixture instead of the rule it is about.
    """
    manifest_path = folder / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = folder / "ranker.json"
    if artifact.is_file():
        data["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(data), encoding="utf-8")


def test_a_promoted_ranker_without_its_artifact_is_not_promoted(tmp_path):
    """The exact 2026-11-02 shape: manifest on disk, ranker.json gone."""
    folder = _manifest_folder(tmp_path)
    _write(folder)
    assert ModelRegistry(tmp_path).promoted("exploit") is None


def test_the_same_manifest_is_promoted_once_the_artifact_exists(tmp_path):
    """Not "never promoted": the rule is presence, not suspicion."""
    folder = _manifest_folder(tmp_path)
    _write(folder)
    (folder / "ranker.json").write_text(json.dumps(RANKER_WEIGHTS),
                                        encoding="utf-8")
    _sync_digest(folder)
    promoted = ModelRegistry(tmp_path).promoted("exploit")
    assert promoted is not None and promoted["version"] == "v1"


def test_a_promoted_adapter_manifest_needs_its_directory(tmp_path):
    folder = _manifest_folder(tmp_path)
    data = _write(folder, kind="", ranker="", adapter="adapter")
    assert "artifact" in " ".join(manifest_errors(data, "exploit", tmp_path))
    assert ModelRegistry(tmp_path).promoted("exploit") is None

    (folder / "adapter").mkdir()
    assert ModelRegistry(tmp_path).promoted("exploit") is not None


def test_a_manifest_that_names_no_artifact_keeps_the_measurement_rule(tmp_path):
    """Benchmark/test manifests name no file; their numbers are the only claim.

    Changing this would refuse the fixtures, not a model — and the fixtures are
    how the ladder is measured.
    """
    folder = _manifest_folder(tmp_path)
    _write(folder, kind="", ranker="")
    assert ModelRegistry(tmp_path).promoted("exploit") is not None


def test_the_error_says_which_file_is_missing(tmp_path):
    folder = _manifest_folder(tmp_path)
    data = _write(folder)
    errors = manifest_errors({**data, "_manifest_dir": str(folder)},
                             "exploit", tmp_path)
    assert any("ranker.json" in e for e in errors), errors


def test_a_non_promoted_manifest_is_refused_for_being_unpromoted(tmp_path):
    """The artifact rule must not hide the older, simpler reason."""
    folder = _manifest_folder(tmp_path)
    _write(folder, promoted=False)
    errors = manifest_errors({"promoted": False}, "exploit", tmp_path)
    assert errors and any("not promoted" in e for e in errors)


def test_integrated_refuses_a_linear_ranker(monkeypatch):
    """A ranker answers in process; a chat endpoint has no such model."""

    class _Registry:
        def promoted(self, phase):
            return {"kind": "linear-ranker", "version": "ranker-2026-10-30",
                    "ranker": "ranker.json"}

    monkeypatch.setattr(router, "ModelRegistry", _Registry)
    with pytest.raises(router.AIError) as caught:
        router._integrated_model("exploit")
    message = str(caught.value)
    assert "linear" in message and "ranker-2026-10-30" in message


def test_integrated_still_names_a_promoted_adapter(monkeypatch):
    """The ranker refusal must not close the adapter path it sits next to."""

    class _Registry:
        def promoted(self, phase):
            return {"kind": "lora", "version": "v9", "model_id": "phantom-x"}

    monkeypatch.setattr(router, "ModelRegistry", _Registry)
    assert router._integrated_model("exploit") == "phantom-x"


def test_trust_demotes_when_the_artifact_is_taken_away(tmp_path, monkeypatch):
    """The whole point: authority follows the model, not the JSON file."""
    monkeypatch.delenv("PHANTOM_AI_AUTHORITY", raising=False)
    monkeypatch.setenv("PHANTOM_AI_MODE", "off")
    folder = _manifest_folder(tmp_path)
    _write(folder)

    gone = trust_for("exploit", registry=ModelRegistry(tmp_path))
    assert gone.level == "observe"
    assert "no promoted model" in gone.reason

    (folder / "ranker.json").write_text(json.dumps(RANKER_WEIGHTS),
                                        encoding="utf-8")
    _sync_digest(folder)
    back = trust_for("exploit", registry=ModelRegistry(tmp_path))
    assert back.level == "nudge"
    assert back.source == "manifest"


def test_no_shipped_exploit_manifest_claims_an_absent_artifact():
    """Release guard: the tree may not ship the claim without the model."""
    for manifest_path in sorted((PROJECT_ROOT / "models" / "exploit")
                                .glob("*/manifest.json")):
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        if data.get("promoted") is not True:
            continue
        data["_manifest_dir"] = str(manifest_path.parent)
        assert artifact_problem(data) == "", manifest_path
