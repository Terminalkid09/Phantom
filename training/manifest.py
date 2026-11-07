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
      "promoted":   true,
      "promotion_basis":  "gate",
      "promotion_reason": "<one sentence naming the measurement>"
    }

No weights are committed to the repository; only this manifest and the
README are versioned, so a checkout never carries gigabytes of adapter.

The defect closed here (measured 2026-11-02): ``promoted`` used to be
``bool(not validate_manifest(manifest))``, and validation refused only a
score BELOW the baseline — so a TIE validated, and an eval measured on three
rows validated. The evidence is on disk:
``models/evolution/2026-10-26-cpu-v3/manifest.json`` carried
``"promoted": true`` over ``eval == baseline == {"exact_match": 1.0}`` with
``golden_rows: 3`` and no ``eval_gate``. The runtime did save us —
``trust_for("evolution")`` returns ``observe`` with "promoted manifest
carries no eval_gate" — but the FILE asserted a promotion this repository
cannot back, and the reader who trusts the file (a report, a dashboard, the
next reviewer) was told a model had been promoted on evidence that does not
exist.

Two rules follow from that measurement:

* a tie is not evidence: a manifest may not claim ``promoted`` on a metric
  that merely EQUALS its baseline (``<=``, never ``<``);
* a promotion records its BASIS in the file. ``promotion_basis`` is one of
  ``"gate"`` (a statistical eval gate promoted it), ``"strict-eval"`` (every
  metric strictly improved, and the reason says the runtime still caps such a
  manifest at ``observe`` because it carries no gate), ``"insufficient-rows"``
  (the eval was measured on fewer than ``training.gate.MIN_ROWS`` rows) or
  ``"none"``. ``promotion_reason`` states it in one sentence, where the claim
  is made, so no reader has to reconstruct it.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from training.gate import MIN_ROWS
from training.phases import PHASE_ORDER

REQUIRED_FIELDS = ("phase", "version", "base_model", "adapter", "sha256",
                   "trained_at", "eval", "baseline", "promoted")
MANIFEST_NAME = "manifest.json"

#: Every value ``promotion_basis`` may take. ``"gate"`` and ``"strict-eval"``
#: are the only two that can carry ``promoted: true``: a gate measured it, or
#: every metric strictly improved (a weaker claim, and the reason says so).
PROMOTION_BASES = ("gate", "strict-eval", "insufficient-rows", "none")
PROMOTING_BASES = ("gate", "strict-eval")


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


def sha256_tree(directory: str | Path) -> str:
    """Deterministic SHA-256 of a directory of adapter weights.

    A LoRA artifact is not one file: ``save_pretrained`` writes the weights
    plus the tokenizer and the adapter config, and any of them can change the
    model that is actually served. The MIRROR of this function lives in
    ``phantom.automation.ai.registry._tree_digest`` (the runtime cannot import
    ``training/``, which is not shipped); ``tests/test_model_integrity.py``
    compares the two on the same fixture, because a trainer that records one
    scheme and a registry that checks another would refuse every promoted
    adapter.

    Entries are sorted by relative POSIX path and each contributes its path,
    its size and its bytes (the size is what separates ``ab`` from ``a`` +
    ``b``; the path is what stops a rename from keeping the digest).
    """
    base = Path(directory)
    try:
        files = sorted((p for p in base.rglob("*") if p.is_file()),
                       key=lambda p: p.relative_to(base).as_posix())
    except OSError:
        return ""
    if not files:
        return ""
    digest = hashlib.sha256()
    for path in files:
        try:
            data = path.read_bytes()
        except OSError:
            return ""
        rel = path.relative_to(base).as_posix().encode("utf-8")
        digest.update(rel + b"\0" + str(len(data)).encode("ascii") + b"\0")
        digest.update(data)
    return digest.hexdigest()


def manifest_dir(root: str | Path, phase: str, version: str) -> Path:
    return Path(root) / "models" / phase / version


def build_manifest(phase: str, version: str, base_model: str, adapter: str,
                   *, sha256: str = "", trained_at: Optional[str] = None,
                   eval_metrics: Optional[Dict[str, float]] = None,
                   baseline: Optional[Dict[str, float]] = None,
                   promoted: Optional[bool] = None,
                   extra: Optional[Dict[str, object]] = None
                   ) -> Dict[str, object]:
    """Assemble a manifest; promotion is DERIVED from a recorded BASIS.

    ``promoted`` is never inferred from "validation found nothing", which is
    what let a three-row tie call itself promoted: :func:`promotion_evidence`
    reads the evidence (an ``eval_gate`` dict, the ``golden_rows`` the eval
    actually measured, then the metric-by-metric comparison) and returns the
    verdict WITH its basis and a one-sentence reason. Both are written into
    the manifest, so the file states what it rests on.

    ``promoted=False`` may still be forced by a caller who knows better (the
    trainer withholding a promotion), but ``promoted=True`` is honoured only
    when the evidence already supports it: a caller cannot write a claim the
    measurement does not carry — that is the whole defect being closed.
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
    derived, basis, reason = promotion_evidence(data.get("eval"),
                                                data.get("baseline"), data)
    if promoted is True and not derived:
        reason = _with_clause(reason, "a caller's promotion request is "
                                       "refused because the measurement "
                                       "does not carry it")
    elif promoted is False and derived:
        reason = _with_clause(reason, "the caller withheld promotion")
    if promoted is None:
        data["promoted"] = derived
    else:
        data["promoted"] = derived and bool(promoted)
    data["promotion_basis"] = basis
    data["promotion_reason"] = reason
    return data


def promotion_evidence(evals: object, baseline: object,
                       extra: Optional[Dict[str, object]] = None
                       ) -> Tuple[bool, str, str]:
    """(promoted, basis, reason) — what the evidence actually supports.

    Ordered by authority, because the strongest evidence decides:

    1. a measured ``eval_gate`` — the only basis that can raise a model above
       the ``observe`` level downstream;
    2. the row floor that gate itself requires — ``training.gate.MIN_ROWS``,
       imported rather than repeated, so the trainer, the gate and this file
       cannot drift apart;
    3. a strict improvement on every metric — real, but ungated, and the
       reason says the runtime will cap it at ``observe``;
    4. otherwise ``"none"``: a tie, a loss, an empty eval or a missing
       baseline is recorded as what it is.

    Never raises: a malformed metric or gate becomes a verdict with the
    problem named in the reason, not a crashed training run.
    """
    extras = extra if isinstance(extra, dict) else {}
    gate = extras.get("eval_gate")
    if isinstance(gate, dict):
        return _gate_verdict(gate)
    rows = extras.get("golden_rows")
    if isinstance(rows, int) and not isinstance(rows, bool) and rows < MIN_ROWS:
        return (False, "insufficient-rows",
                f"{rows} golden row(s) is below the {MIN_ROWS}-row floor that "
                f"training.gate.MIN_ROWS requires, so no score computed on "
                f"that sample can promote a model.")
    improved, detail = _strict_improvement(evals, baseline)
    if improved:
        return (True, "strict-eval",
                f"eval strictly beats the baseline on every metric "
                f"({detail}), but the improvement is not statistically "
                f"gated: phantom.automation.ai.trust refuses a manifest that "
                f"carries no eval_gate, so the runtime will cap this model at "
                f"'observe' until a gate measures it.")
    return (False, "none", detail)


def _gate_verdict(gate: Dict[str, object]) -> Tuple[bool, str, str]:
    """(promoted, "gate", reason) from the gate the eval harness wrote."""
    verdict = str(gate.get("verdict") or "").strip().lower()
    numbers = (f"n={_as_int(gate.get('n'))} row(s) over a "
               f"{_as_int(gate.get('min_rows'))}-row floor, delta "
               f"{_as_float(gate.get('delta')):+.3f}, 95% CI low "
               f"{_as_float(gate.get('ci_low')):+.3f}")
    if verdict == "promote":
        return (True, "gate",
                f"the eval gate returned 'promote' on {numbers}: the whole "
                f"interval sits above the baseline, so the advantage was "
                f"measured rather than assumed.")
    reasons = [str(reason).strip() for reason in (gate.get("reasons") or [])
               if str(reason).strip()]
    why = reasons[0] if reasons else "it measured no advantage above noise"
    return (False, "gate",
            f"the eval gate returned {verdict or 'no verdict'!r} on "
            f"{numbers}: {why.rstrip('.')}.")


def _strict_improvement(evals: object, baseline: object) -> Tuple[bool, str]:
    """(a strict win on EVERY metric, a sentence saying what happened)."""
    if not isinstance(evals, dict) or not evals:
        return (False, "eval is missing or empty: an unmeasured model cannot "
                       "be promoted.")
    if not isinstance(baseline, dict) or not baseline:
        return (False, "baseline is missing or empty: there is nothing to "
                       "compare the eval against.")
    wins: List[str] = []
    for metric, value in evals.items():
        if not _is_number(value):
            return (False, f"eval.{metric} is not a number.")
        if metric not in baseline:
            return (False, f"baseline has no {metric!r} score, so the claimed "
                           f"improvement on it is unmeasured.")
        base = baseline.get(metric)
        if not _is_number(base):
            return (False, f"baseline.{metric} is not a number.")
        if float(value) <= float(base):
            relation = "TIES" if float(value) == float(base) else "is BELOW"
            return (False, f"eval.{metric}={value} {relation} the baseline "
                           f"{base}, and only a strictly larger score is "
                           f"evidence for a promotion.")
        wins.append(f"{metric} {value} > {base}")
    return (True, ", ".join(wins))


def _with_clause(reason: str, clause: str) -> str:
    """One sentence plus one clause, so a reason stays readable."""
    return f"{str(reason).rstrip('.')}; {clause}."


def _as_int(value: object) -> int:
    """A gate number as an int, 0 when it is not one (never a crash)."""
    return int(value) if _is_number(value) else 0


def _as_float(value: object) -> float:
    """A gate number as a float, 0.0 when it is not one (never a crash)."""
    return float(value) if _is_number(value) else 0.0


def write_manifest(manifest: Dict[str, object], directory: str | Path) -> Path:
    """Write the manifest with LF on every host.

    The digest inside it is computed over the ARTIFACT, not this file, but a
    manifest that changes bytes with the operating system shows up as a diff
    on every Windows checkout for no reason — and `models/**` is now marked
    binary in `.gitattributes`, so the bytes here are the bytes everywhere.
    """
    path = Path(directory) / MANIFEST_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return path


def load_manifest(directory: str | Path) -> Dict[str, object]:
    path = Path(directory) / MANIFEST_NAME
    return json.loads(path.read_text(encoding="utf-8"))


def validate_manifest(manifest: Dict[str, object],
                      required_metrics: Iterable[str] = ()
                      ) -> List[str]:
    """Every reason this manifest must NOT be loaded (empty = valid).

    The defect this closes (measured 2026-11-02): the comparison used ``<``
    only, so a metric that merely TIED its baseline produced no error, and
    ``build_manifest`` read "no errors" as "promoted". A manifest that claims
    ``promoted`` is now held to ``<=`` — a tie is not evidence of anything.
    A NON-promoted manifest is still compared at ``<``: ``eval < baseline``
    is the honest record of a failed run, and it has to stay writable
    (``build_manifest`` writes ``promoted: false`` for it) instead of turning
    into an error file nobody can store.

    ``promotion_basis``/``promotion_reason`` are checked only when present,
    so manifests written before 2026-11-02 stay readable; a manifest that
    carries them must carry a basis that could support its own verdict.
    """
    errors: List[str] = []
    if not isinstance(manifest, dict):
        return ["manifest is not an object"]
    claims_promotion = manifest.get("promoted") is True
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
            elif claims_promotion and float(value) <= float(base):
                # A tie is not evidence: the model reproduced the baseline,
                # which says nothing about it being better.
                errors.append(
                    f"eval.{metric}={value} only TIES the baseline {base}: a "
                    f"tie is not evidence, so it cannot carry a promotion")
        for metric in required_metrics:
            if metric not in evals:
                errors.append(f"required metric {metric!r} is missing")
    promoted = manifest.get("promoted")
    if not isinstance(promoted, bool):
        errors.append("promoted must be a boolean")
    elif promoted and errors:
        errors.append("promoted=true on an invalid manifest")
    if "promotion_basis" in manifest:
        basis = manifest.get("promotion_basis")
        if basis not in PROMOTION_BASES:
            errors.append(
                f"promotion_basis {basis!r} is not one of "
                f"{', '.join(PROMOTION_BASES)}")
        elif claims_promotion and basis not in PROMOTING_BASES:
            errors.append(
                f"promoted=true on promotion_basis {basis!r}: that basis "
                f"does not support a promotion")
    if "promotion_reason" in manifest:
        reason = manifest.get("promotion_reason")
        if not isinstance(reason, str) or not reason.strip():
            errors.append("promotion_reason must be a non-empty string")
    return errors


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_promotable(manifest: Dict[str, object],
                  required_metrics: Iterable[str] = ()) -> bool:
    return not validate_manifest(manifest, required_metrics)
