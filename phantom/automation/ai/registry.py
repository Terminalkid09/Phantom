"""registry.py — which trained adapter, if any, may serve a phase.

A manifest is the only way a model enters the runtime:

    models/<phase>/<version>/manifest.json
    {
      "phase": "exploit", "version": "2026-10-25-a",
      "base_model": "Qwen/Qwen3-1.7B", "adapter": "adapter/",
      "sha256": "<digest of the adapter or merged model>",
      "trained_at": "2026-10-25T12:00:00Z",
      "eval": {"ndcg": 0.71, "schema_ok": 0.99},
      "baseline": {"ndcg": 0.63, "schema_ok": 0.97},
      "promoted": true
    }

A manifest without non-empty numeric ``eval`` and ``baseline`` is REFUSED:
an unmeasured adapter is not a model, it is an experiment. That is the gate
between ``training/`` and the live decision path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[3]
REQUIRED = ("phase", "version", "base_model", "sha256", "trained_at",
            "eval", "baseline", "promoted")


def _numbers(mapping: Any) -> bool:
    return (isinstance(mapping, dict) and bool(mapping)
            and all(isinstance(v, (int, float)) and not isinstance(v, bool)
                    for v in mapping.values()))


def manifest_errors(manifest: Dict[str, Any], phase: str = "") -> List[str]:
    """Why this manifest may not serve ``phase`` (empty = acceptable)."""
    errors: List[str] = []
    if not isinstance(manifest, dict):
        return ["manifest is not an object"]
    missing = [key for key in REQUIRED if key not in manifest]
    if missing:
        errors.append("missing fields: " + ", ".join(missing))
    expected = str(phase or manifest.get("phase") or "")
    if expected and str(manifest.get("phase")) != expected:
        errors.append(f"phase mismatch: {manifest.get('phase')!r} != {expected}")
    for key in ("phase", "version", "base_model", "sha256", "trained_at"):
        value = manifest.get(key)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{key} must be a non-empty string")
    if not _numbers(manifest.get("eval")):
        errors.append("eval must be a non-empty map of metric -> number")
    if not _numbers(manifest.get("baseline")):
        errors.append("baseline must be a non-empty map of metric -> number")
    if manifest.get("promoted") is not True:
        errors.append("manifest is not promoted")
    return errors


class ModelRegistry:
    """Read-only view of ``models/``; never writes and never imports code."""

    def __init__(self, project_root: Optional[Path] = None) -> None:
        self.root = Path(project_root) if project_root is not None \
            else PROJECT_ROOT
        self.models_dir = self.root / "models"

    def candidates(self, phase: str) -> List[Dict[str, Any]]:
        """Every readable manifest for ``phase`` (invalid ones included)."""
        out: List[Dict[str, Any]] = []
        base = self.models_dir / phase
        if not base.is_dir():
            return out
        for manifest_path in sorted(base.glob("*/manifest.json")):
            try:
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                data = dict(data)
                data["_manifest_path"] = str(manifest_path)
                data["_manifest_dir"] = str(manifest_path.parent)
                out.append(data)
        return out

    def get(self, phase: str, version: str) -> Optional[Dict[str, Any]]:
        for manifest in self.candidates(phase):
            if str(manifest.get("version")) == str(version) \
                    and not manifest_errors(manifest, phase):
                return manifest
        return None

    def promoted(self, phase: str) -> Optional[Dict[str, Any]]:
        """The newest manifest that passed the eval gate, or ``None``.

        Sorting is by ``trained_at`` then ``version`` (both strings), so the
        registry is deterministic across filesystems.
        """
        valid = [m for m in self.candidates(phase)
                 if not manifest_errors(m, phase)]
        if not valid:
            return None
        valid.sort(key=lambda m: (str(m.get("trained_at", "")),
                                  str(m.get("version", ""))), reverse=True)
        return valid[0]
