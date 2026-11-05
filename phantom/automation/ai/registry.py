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

THE ARTIFACT MUST EXIST (measured 2026-11-02). A manifest is a claim about a
model, and the claim used to outlive the model: ``models/exploit/
ranker-2026-10-30/manifest.json`` still carried ``promoted: true`` after its
``ranker.json`` was deleted, so ``ModelRegistry.promoted('exploit')`` returned
it, ``trust_for('exploit')`` reported ``nudge`` (the runtime believed it had a
second opinion), and ``--ai integrated`` handed the manifest's version string
to a chat endpoint as a model id. Three subsystems were told a model existed
because one JSON file said so. ``manifest_errors`` now also refuses a promoted
manifest whose named artifact cannot be resolved on disk, which makes
"promoted" mean "measured AND installed" in ONE place — the registry — instead
of three.

A manifest that names no artifact at all (``ranker``/``adapter`` absent) is
still validated by its measurement alone: those are hand-written test and
benchmark manifests, and refusing them would test the rule rather than the
model. A manifest that NAMES an artifact owes that file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[3]
REQUIRED = ("phase", "version", "base_model", "sha256", "trained_at",
            "eval", "baseline", "promoted")


def _numbers(mapping: Any) -> bool:
    return (isinstance(mapping, dict) and bool(mapping)
            and all(isinstance(v, (int, float)) and not isinstance(v, bool)
                    for v in mapping.values()))


def _artifact_reference(manifest: Dict[str, Any]) -> Tuple[str, bool]:
    """``(reference, is_a_file)`` for the artifact this manifest names.

    A linear ranker is one JSON file; every other kind is a directory of
    adapter weights. The distinction lives here so the registry and
    ``linear.promoted`` cannot disagree about what "installed" means.
    """
    if str(manifest.get("kind") or "").strip().lower() == "linear-ranker":
        return str(manifest.get("ranker") or "").strip(), True
    return str(manifest.get("adapter") or "").strip(), False


def artifact_path(manifest: Dict[str, Any],
                  root: Optional[Path] = None) -> Optional[Path]:
    """Where the named artifact is, or would be (``None`` = names none).

    Resolution order matches ``linear.promoted``: next to the manifest first,
    then the registry root. Windows-authored manifests carry backslashes
    (``models\\exploit\\v1\\ranker.json``), so the reference is normalised
    before it becomes a path: on POSIX that string is one long filename, not a
    nested path.
    """
    reference, is_file = _artifact_reference(manifest)
    if not reference:
        return None
    candidate = Path(reference.replace("\\", "/"))
    if candidate.is_absolute():
        return candidate
    bases: List[Path] = []
    manifest_dir = str(manifest.get("_manifest_dir") or "").strip()
    if manifest_dir:
        bases.append(Path(manifest_dir))
    bases.append(Path(root) if root is not None else PROJECT_ROOT)
    for base in bases:
        resolved = base / candidate
        if (resolved.is_file() if is_file else resolved.is_dir()):
            return resolved
    return bases[0] / candidate


def artifact_problem(manifest: Dict[str, Any],
                     root: Optional[Path] = None) -> str:
    """Why the artifact this manifest names is not servable ("" = fine)."""
    kind = str(manifest.get("kind") or "").strip().lower()
    reference, is_file = _artifact_reference(manifest)
    if not reference:
        # A manifest that CLAIMS to be a ranker and names no file is broken,
        # not measurement-only; the same holds for an explicitly empty
        # ``adapter`` path. A manifest with neither key is a test/benchmark
        # fixture and keeps the old, measurement-only rule.
        if kind == "linear-ranker":
            return "a linear-ranker manifest must name its 'ranker' file"
        if "adapter" in manifest:
            return "the 'adapter' path is empty"
        return ""
    resolved = artifact_path(manifest, root)
    exists = bool(resolved is not None
                  and (resolved.is_file() if is_file else resolved.is_dir()))
    if exists:
        return ""
    what = "file" if is_file else "directory"
    return (f"artifact {what} missing: {reference!r} (a promoted manifest "
            f"owes the model it names)")


def manifest_errors(manifest: Dict[str, Any], phase: str = "",
                    root: Optional[Path] = None) -> List[str]:
    """Why this manifest may not serve ``phase`` (empty = acceptable).

    ``root`` is the registry's project root; it is only used to resolve a
    relative artifact reference, so a test registry stays self-contained
    instead of resolving against the real checkout.
    """
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
    else:
        problem = artifact_problem(manifest, root)
        if problem:
            errors.append(problem)
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
                    and not manifest_errors(manifest, phase, self.root):
                return manifest
        return None

    def promoted(self, phase: str) -> Optional[Dict[str, Any]]:
        """The newest manifest that passed the eval gate, or ``None``.

        Sorting is by ``trained_at`` then ``version`` (both strings), so the
        registry is deterministic across filesystems.
        """
        valid = [m for m in self.candidates(phase)
                 if not manifest_errors(m, phase, self.root)]
        if not valid:
            return None
        valid.sort(key=lambda m: (str(m.get("trained_at", "")),
                                  str(m.get("version", ""))), reverse=True)
        return valid[0]
