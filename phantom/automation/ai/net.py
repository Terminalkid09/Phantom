"""net.py — the nonlinear ranker at runtime, in plain Python.

``training.net`` fits the same pairwise objective as ``training.ranker`` but
with a hidden layer, which is what lets it express an interaction the linear
form cannot: "this move is good *because* the context has a web surface",
rather than one fixed weight per feature. It exports the fitted matrices as
JSON.

The runtime cannot import ``training/`` (that package is not shipped), so this
module reproduces the forward pass:

    score = tanh(W1 . [context | onehot(candidate_id)] + b1) . W2 + b2

No numpy here on purpose: scoring twenty candidates is a few hundred
multiply-adds, and the shipped tool should not gain a numerical stack to do
something a loop already does. ``tests/test_net_ranker.py`` fits a model with
numpy, saves it, loads it through this module and asserts the scores agree —
a drift between the two implementations would otherwise be a silent scoring
bug in the field only.

It is a SECOND OPINION like the linear ranker: it returns an order over the
ids the caller supplied, never a decision, and the caller still applies its
trust-bounded re-ranking cap.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional

from phantom.automation.ai.linear import CONTEXT

PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODELS_DIR = PROJECT_ROOT / "models"


class NetRanker:
    """Exported MLP weights: one hidden layer, one output."""

    def __init__(self, ids: List[str], W1: List[List[float]],
                 b1: List[float], W2: List[float], b2: float = 0.0,
                 version: str = "") -> None:
        self.ids = [str(i) for i in ids]
        self.W1 = [[float(v) for v in row] for row in W1]
        self.b1 = [float(v) for v in b1]
        self.W2 = [float(v) for v in W2]
        self.b2 = float(b2)
        self.version = str(version or "")
        self._index = {cid: i for i, cid in enumerate(self.ids)}

    def score(self, cid: str,
              context: Optional[Dict[str, float]] = None) -> float:
        cid = str(cid)
        x = [float((context or {}).get(key, 0.0)) for key in CONTEXT]
        onehot = [0.0] * len(self.ids)
        index = self._index.get(cid)
        if index is not None:
            onehot[index] = 1.0
        x += onehot
        hidden = [math.tanh(sum(w * v for w, v in zip(row, x)) + bias)
                  for row, bias in zip(self.W1, self.b1)]
        return sum(w * h for w, h in zip(self.W2, hidden)) + self.b2

    def rank(self, ids: List[str],
             context: Optional[Dict[str, float]] = None,
             contexts: Optional[Dict[str, Dict[str, float]]] = None
             ) -> List[str]:
        shared = dict(context or {})
        per_id = contexts or {}
        # stable sort: an exact tie keeps the deterministic order
        return sorted(
            [str(i) for i in ids],
            key=lambda cid: -self.score(
                cid, {**shared, **(per_id.get(str(cid)) or {})}))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetRanker":
        return cls(ids=data.get("ids") or [], W1=data.get("W1") or [],
                   b1=data.get("b1") or [], W2=data.get("W2") or [],
                   b2=float(data.get("b2") or 0.0),
                   version=str(data.get("version") or ""))


def load(path: str | Path) -> Optional[NetRanker]:
    """Read an exported net, or ``None`` if the file is missing/unusable."""
    try:
        return NetRanker.from_dict(json.loads(Path(path).read_text(
            encoding="utf-8")))
    except (OSError, ValueError, TypeError, KeyError):
        return None


def promoted(phase: str = "exploit") -> Optional[NetRanker]:
    """The net a statistical gate PROMOTED for ``phase``, else ``None``.

    Promotion is the manifest, exactly as for the linear ranker: a ``net.json``
    on disk with no manifest is a candidate somebody trained, not a model the
    system is allowed to score with.
    """
    root = MODELS_DIR / phase
    manifest_path = root / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(manifest, dict) or not manifest.get("promoted"):
        return None
    if str(manifest.get("kind") or "") != "mlp":
        return None
    return load(root / str(manifest.get("net") or "net.json"))
