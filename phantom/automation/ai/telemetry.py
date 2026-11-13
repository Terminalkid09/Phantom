"""telemetry.py — one JSONL line per AI call, without the target's text.

The point is to make the AI layer measurable (latency, schema success,
model, phase) and to build a training corpus LATER without turning the log
into a copy of every engagement. Prompts and responses are stored as
``sha256[:16]`` plus character counts; the raw text stays in memory only.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional


def _digest(text: str) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8", "replace")).hexdigest()[:16]


def telemetry_path(path: Optional[Path] = None) -> Path:
    if path is not None:
        return Path(path)
    from phantom.utils.paths import data_dir
    return Path(data_dir()) / "ai" / "telemetry.jsonl"


def enabled() -> bool:
    """On by default; ``PHANTOM_AI_TELEMETRY=0`` turns it off for a run."""
    return str(os.getenv("PHANTOM_AI_TELEMETRY", "1")).strip().lower() \
        not in ("0", "false", "no", "off", "")


def record(phase: str, *, model: str = "", latency_ms: int = 0,
           schema_ok: bool = False, error: str = "",
           prompt: str = "", response: str = "",
           tokens_in: int = 0, tokens_out: int = 0,
           path: Optional[Path] = None) -> None:
    """Append one line. Best effort: telemetry never breaks a run."""
    if not enabled():
        return
    entry = {
        "ts": round(time.time(), 3),
        "phase": str(phase or ""),
        "model": str(model or ""),
        "latency_ms": int(latency_ms),
        "schema_ok": bool(schema_ok),
        "error": str(error or "")[:300],
        "prompt_sha": _digest(prompt),
        "response_sha": _digest(response),
        "chars_in": len(str(prompt or "")),
        "chars_out": len(str(response or "")),
        "tokens_in": int(tokens_in),
        "tokens_out": int(tokens_out),
    }
    try:
        target = telemetry_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError:
        pass
