"""manifest.py — the contract a trained adapter must satisfy to be loaded.

The runtime (``phantom.automation.ai.registry``) refuses a model whose
manifest is missing, whose evaluation is empty, or whose score is below the
deterministic baseline. That refusal is the point: a fine-tuned model that
is only "probably better" is a regression with extra steps.

Contract (one JSON file per version):

    models/<phase>/<version>/manifest.json
    {
      "phase":      "exploit",
      "version":    "2026-10-25",
      "base_model": "Qwen/Qwen3-1.7B",
      "adapter":    "models/exploit/2026-10-25/adapter",
      "sha256":     "<hash of the adapter weights file>",
      "trained_at": "2026-10-25T12:00:00Z",
      "eval":       {"ndcg": 0.71},
      "baseline":   {"ndcg": 0.64},
      "promoted":   true
    }

No weights are committed to the repository; only this manifest and the
README are versioned, so a checkout never carries gigabytes of adapter.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from training.phases import PHASE_ORDER

REQUIRED_FIELDS = ("phase", "version", "base_model", "adapter", "sha256",
                   "trained_at", "eval", "baseline", "promoted")
MANIFEST_NAME = "manifest.json"


def sha256_file(path: str | Path) -> str:
    """SHA-256 of one file (empty string when unreadable, never a guess)."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def manifest_dir(root: str | Path, phase: str, version: str) -> Path:
    return Path(root) / "models" / phase / version


def build_manifest(phase: str, version: str, base_model: str, adapter: str,
                   *, sha256: str = "", trained_at: Optional[str] = None,
                   eval_metrics: Optional[Dict[str, float]] = None,
                   baseline: Optional[Dict[str, float]] = None,
                   promoted: Optional[bool] = None,
                   extra: Optional[Dict[str, object]] = None
                   ) -> Dict[str, object]:
    """Assemble a manifest; promotion is DERIVED unless forced false.

    ``promoted`` may only be set False by a caller who knows better (the
    trainer writes False until the eval has run). It can never be True for a
    manifest that would fail validation.
    """
    if phase not in PHASE_ORDER:
        raise ValueError(f"unknown phase {phase!r}")
    data: Dict[str, object] = {
        "phase": phase,
        "version": str(version),
        "base_model": str(base_model),
        "adapter": str(adapter),
        "sha256": str(sha256 or ""),
        "trained_at": trained_at or datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "eval": dict(eval_metrics or {}),
        "baseline": dict(baseline or {}),
        "promoted": False,
    }
    if extra:
        data.update(extra)
    errors = validate_manifest(data)
    data["promoted"] = bool(not errors) if promoted is None else bool(promoted)
    return data


def write_manifest(manifest: Dict[str, object], directory: str | Path) -> Path:
    path = Path(directory) / MANIFEST_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def load_manifest(directory: str | Path) -> Dict[str, object]:
    path = Path(directory) / MANIFEST_NAME
    return json.loads(path.read_text(encoding="utf-8"))


def validate_manifest(manifest: Dict[str, object],
                      required_metrics: Iterable[str] = ()
                      ) -> List[str]:
    """Every reason this manifest must NOT be loaded (empty = valid)."""
    errors: List[str] = []
    if not isinstance(manifest, dict):
        return ["manifest is not an object"]
    missing = [f for f in REQUIRED_FIELDS if f not in manifest]
    if missing:
        errors.append(f"missing fields: {', '.join(missing)}")
        # still inspect what is present, so one report lists every problem
    phase = str(manifest.get("phase") or "")
    if phase and phase not in PHASE_ORDER:
        errors.append(f"unknown phase: {phase!r}")
    for field in ("version", "base_model", "adapter"):
        if field in manifest and not str(manifest.get(field) or "").strip():
            errors.append(f"empty {field}")
    if "sha256" in manifest:
        value = str(manifest.get("sha256") or "")
        if value and (len(value) != 64
                      or any(c not in "0123456789abcdef" for c in value)):
            errors.append("sha256 is not a hex digest")
    evals = manifest.get("eval")
    baseline = manifest.get("baseline")
    if not isinstance(evals, dict) or not evals:
        errors.append("eval is missing or empty: an unmeasured model cannot "
                      "be promoted")
    if not isinstance(baseline, dict) or not baseline:
        errors.append("baseline is missing or empty: there is nothing to "
                      "compare against")
    if isinstance(evals, dict) and isinstance(baseline, dict):
        for metric, value in evals.items():
            if not _is_number(value):
                errors.append(f"eval.{metric} is not a number")
                continue
            if metric not in baseline:
                errors.append(f"baseline has no {metric!r} score")
                continue
            base = baseline.get(metric)
            if not _is_number(base):
                errors.append(f"baseline.{metric} is not a number")
                continue
            if float(value) < float(base):
                errors.append(
                    f"eval.{metric}={value} is BELOW the baseline {base}")
        for metric in required_metrics:
            if metric not in evals:
                errors.append(f"required metric {metric!r} is missing")
    promoted = manifest.get("promoted")
    if not isinstance(promoted, bool):
        errors.append("promoted must be a boolean")
    elif promoted and errors:
        errors.append("promoted=true on an invalid manifest")
    return errors


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_promotable(manifest: Dict[str, object],
                  required_metrics: Iterable[str] = ()) -> bool:
    return not validate_manifest(manifest, required_metrics)
