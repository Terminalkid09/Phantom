"""linear.py — the CPU ranker at runtime, with no training dependency.

``training.ranker`` fits a pairwise logistic model over the exploit candidate
table and writes it as JSON. The runtime cannot import ``training/`` (that
package is not shipped), so this module is the tiny scorer that reads the
exported weights and reproduces the same score.

It is a SECOND OPINION, not a decision: it returns an order over the ids the
caller already supplied and nothing else. Eligibility, ``actionable``,
``auto_execute`` and the success estimate stay with the deterministic engine,
and the caller still applies its (trust-bounded) re-ranking cap.

Why this exists at all: it is the one ML component in this repository that can
be measured on a CPU in milliseconds, so the plane can show a real advantage
without a GPU, a base model or a serving stack. Measured 2026-10-31 by
``python -m training.ranker --cv``: ndcg 0.9420 against the 0.9021
deterministic baseline, bootstrap CI [+0.0150, +0.0662] on 31 held-out rows,
and a grouped 5-fold CV on the training rows of 0.9420 ± 0.0142 over 78 target
groups — i.e. the number is not an artifact of which rows landed in the
holdout.

``CONTEXT`` and the vector it indexes MUST match ``training.ranker._context``
field for field and in the same order: the weights are keyed by name, so a
feature that is computed differently here is not an error anyone sees — it is
a term multiplied by the wrong thing. ``tests/test_ranker.py`` compares the two
vectors on a table of payloads for exactly that reason.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODELS_DIR = PROJECT_ROOT / "models"

#: Mirror of ``training.ranker.CONTEXT`` — same names, same order, same
#: defaults. ``has_cves`` is table-level; ``priority`` is per candidate and is
#: 0.0 unless the caller's candidate objects carry one (``AccessCandidate``
#: does not today, which the training docstring also says out loud).
CONTEXT = ("tried", "is_cve", "web_surface", "goal_deliver",
           "profile_stealth", "has_cves", "priority",
           "success", "noise", "complexity")
#: Production's neutral for a candidate that carries no number — the SAME
#: default ``AccessCandidate`` uses (``success=0.5, complexity=0.5,
#: noise=0.5``), so a missing value is "unmeasured", not "hopeless".
NEUTRAL_STAT = 0.5
#: Ports that mean "there is an HTTP-ish surface to work with".
WEB_PORTS = {"80", "443", "8000", "8080", "8081", "8443", "8888"}


class LinearRanker:
    """The exported weights: per-id, plus context interactions."""

    def __init__(self, weights: Dict[str, float],
                 context: Optional[Dict[str, float]] = None,
                 interactions: Optional[Dict[str, Dict[str, float]]] = None,
                 bias: float = 0.0, version: str = "") -> None:
        self.weights = {str(k): float(v) for k, v in (weights or {}).items()}
        self.context = {str(k): float(v) for k, v in (context or {}).items()}
        self.interactions = {str(cid): {str(k): float(v) for k, v in row.items()}
                             for cid, row in (interactions or {}).items()}
        self.bias = float(bias)
        self.version = str(version or "")

    def score(self, cid: str, context: Dict[str, float]) -> float:
        cid = str(cid)
        total = self.weights.get(cid, 0.0) + self.bias
        for key in CONTEXT:
            value = float(context.get(key, 0.0))
            total += self.context.get(key, 0.0) * value
            total += (self.interactions.get(cid) or {}).get(key, 0.0) * value
        return total

    def rank(self, ids: List[str],
             context: Optional[Dict[str, float]] = None,
             contexts: Optional[Dict[str, Dict[str, float]]] = None
             ) -> List[str]:
        """Best-first order. ``contexts`` overrides the shared context PER ID.

        That override is not a convenience: ``is_cve`` is a property of the
        candidate, and the trainer fits ``interactions[cid]["is_cve"]`` for
        exactly that reason. The first runtime version passed ONE shared dict
        with ``is_cve`` fixed at 0.0, so every learned interaction with it was
        multiplied by zero — the exported model was measured with a term it
        could never apply. Callers pass ``contexts_for_candidates(...)``.
        """
        shared = dict(context or {})
        per_id = contexts or {}
        # `sorted` is stable, so an exact tie keeps the deterministic order.
        return sorted(
            [str(i) for i in ids],
            key=lambda cid: -self.score(
                cid, {**shared, **(per_id.get(str(cid)) or {})}))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LinearRanker":
        return cls(weights=data.get("weights") or {},
                   context=data.get("context") or {},
                   interactions=data.get("interactions") or {},
                   bias=float(data.get("bias") or 0.0),
                   version=str(data.get("version") or ""))


def context_from_candidates(candidates, *, mode: str = "", goal: str = "",
                            profile: str = "") -> Dict[str, float]:
    """The flags the model was TRAINED with, from what the caller has.

    ``tried`` defaults to 0 — the sweep filters already-tested paths out
    before it asks for a second opinion — and is filled when the caller has the
    list (the trained flag is per candidate, so it is applied in
    ``contexts_for_candidates``). The web flag is read from the candidate
    ports, so the advisor needs no access to the world model.

    ``profile_stealth`` is fitted against the payload's ``profile`` in
    ``training.ranker._context``, NOT against the mode; the two were being
    conflated here (a stealth-pass candidate was compared with steer-to-mode
    weights). ``profile`` is the trained meaning; ``mode`` is kept as the
    fallback for a caller that only has one, so the old behaviour is reachable
    but no longer the only path.
    """
    ports = {str(getattr(c, "port", "") or "").split("/")[0]
             for c in candidates}
    stealth = profile or mode
    return {
        "tried": 0.0,                       # per candidate: see below
        "is_cve": 0.0,                       # per candidate: see below
        "web_surface": 1.0 if ports & WEB_PORTS else 0.0,
        "goal_deliver": 1.0 if str(goal) == "deliver" else 0.0,
        "profile_stealth": 1.0 if str(stealth) in ("stealth", "paranoid")
                           else 0.0,
        "has_cves": 1.0 if any(str(getattr(c, "cve", "") or "").strip()
                               for c in candidates) else 0.0,
        "priority": 0.0,                     # per candidate: see below
        # per candidate as well: the shared dict carries the neutral value
        "success": NEUTRAL_STAT,
        "noise": NEUTRAL_STAT,
        "complexity": NEUTRAL_STAT,
    }


def contexts_for_candidates(candidates, *, mode: str = "", goal: str = "",
                            profile: str = "",
                            tried: Iterable[str] = ()
                            ) -> Dict[str, Dict[str, float]]:
    """One context dict per candidate id, with the PER-candidate flags filled.

    ``context_from_candidates`` answers "does this TABLE have a web surface"
    (shared by every row) and cannot answer "is THIS move a CVE". Returning
    one shared dict meant ``is_cve`` was 0.0 for every id, so the interaction
    the trainer fitted per candidate was dead at runtime — the exported model
    was not the model that had been measured.

    ``priority`` is filled the same way, from the candidate when it has one and
    0.0 when it does not: ``AccessCandidate`` carries no priority today, so a
    caller that wants the trained term to bite has to supply it.

    ``success``/``noise``/``complexity`` come straight off the candidate (they
    are planner output, not a guess) and fall back to ``NEUTRAL_STAT`` when a
    caller's candidate type has no such field.
    """
    base = context_from_candidates(candidates, mode=mode, goal=goal,
                                   profile=profile)
    seen = {str(x) for x in tried or ()}
    out: Dict[str, Dict[str, float]] = {}
    for cand in candidates:
        cid = str(getattr(cand, "id", ""))
        if not cid:
            continue
        ctx = dict(base)
        ctx["tried"] = 1.0 if cid in seen else 0.0
        cve = str(getattr(cand, "cve", "") or "").strip()
        ctx["is_cve"] = 1.0 if (cve or cid.upper().startswith("CVE-")) else 0.0
        try:
            priority = float(getattr(cand, "priority", 0.0) or 0.0)
        except (TypeError, ValueError):
            priority = 0.0
        ctx["priority"] = max(0.0, min(1.0, priority))
        # The three the PLANNER already computes. They are the reason a ranker
        # can learn the mode instead of just the usual id order, and they were
        # missing on both sides until now: the runtime had them on the
        # candidate and the trainer had no column for them.
        for key in ("success", "noise", "complexity"):
            try:
                value = float(getattr(cand, key, NEUTRAL_STAT))
            except (TypeError, ValueError):
                value = NEUTRAL_STAT
            ctx[key] = max(0.0, min(1.0, value))
        out[cid] = ctx
    return out


def load(path: str | Path) -> Optional[LinearRanker]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("weights"), dict):
        return None
    return LinearRanker.from_dict(data)


def promoted(phase: str = "exploit",
             models_dir: Optional[Path] = None) -> Optional[LinearRanker]:
    """The ranker of a promoted ``kind="linear-ranker"`` manifest, or None.

    It reuses ``ModelRegistry`` so there is ONE definition of "promoted": a
    manifest without ``eval``/``baseline`` numbers is refused here exactly as
    it is for an adapter, and a gate that has not passed cannot be smuggled in
    by dropping a JSON file in ``models/``.

    The DIGEST is checked again here, on the exact file that is about to be
    loaded. The registry already refuses a mismatch, so this is defence in
    depth rather than the only check: a caller that builds a manifest dict in
    memory (a benchmark, an API body) never passes through the registry's
    directory scan, and serving weights nobody hashed is the failure this
    layer exists to prevent.
    """
    from phantom.automation.ai.registry import ModelRegistry, artifact_digest

    registry = ModelRegistry(models_dir.parent) if models_dir else ModelRegistry()
    manifest = registry.promoted(phase)
    if not isinstance(manifest, dict):
        return None
    if str(manifest.get("kind") or "") != "linear-ranker":
        return None
    gate = manifest.get("eval_gate")
    if not isinstance(gate, dict) or str(gate.get("verdict")) != "promote":
        return None
    reference = str(manifest.get("ranker") or "")
    if not reference:
        return None
    path = Path(reference)
    if not path.is_absolute():
        # Relative to the manifest first (``ranker.json`` next to
        # ``manifest.json``), then to the project root.
        base = Path(str(manifest.get("_manifest_dir") or ""))
        candidates = [base / reference, PROJECT_ROOT / reference]
        path = next((p for p in candidates if p.is_file()), candidates[-1])
    declared = str(manifest.get("sha256") or "").strip().lower()
    if declared:
        actual = artifact_digest(manifest)
        if actual and actual != declared:
            return None
    return load(path)
