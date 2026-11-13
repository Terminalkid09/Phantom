"""engagement.py — the versioned serializable contract of engagement truth.

The live engagement (session target/scope/notes/history, knowledge base,
results) is mirrored across the CLI, the API and Electron with bidirectional
runtime merges. Consumers used to read that mirror with defensive
``getattr``/``default=str``, so a shape change broke data written by an older
build silently.

This module fixes the SHAPE: one declared field set, one ``SNAPSHOT_VERSION``
and ``snapshot()``/``restore()`` over it. ``restore`` is tolerant by design —
unknown keys are ignored and a snapshot without a version is treated as v1,
so a file written by a previous build still loads instead of vanishing.
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, Optional

# Bump when the on-disk shape changes in a way that needs a migration.
SNAPSHOT_VERSION = 2

# The stable, serializable engagement fields (the auto-session mirror).
# `results` and the knowledge base are intentionally NOT here: they are
# derived/merged by session_bridge, not part of the operator-editable mirror.
SNAPSHOT_FIELDS = ("target", "scope", "lhost", "lport", "active_wordlist",
                   "notes", "history")

# Values that mean "not set" and must never overwrite a restored field.
_UNSET = (None, "", [], 0)


def snapshot() -> Dict[str, Any]:
    """A versioned, serializable snapshot of the live session's mirror."""
    from phantom.core.session import session
    data: Dict[str, Any] = {k: getattr(session, k, None)
                            for k in SNAPSHOT_FIELDS}
    data["version"] = SNAPSHOT_VERSION
    data["saved_at"] = datetime.now().isoformat(timespec="seconds")
    return data


def migrate(data: Dict[str, Any]) -> Dict[str, Any]:
    """Upgrade an older snapshot to the current version.

    v1 wrote the fields with no ``version`` key and the same shape, so the
    migration is just stamping the current version. Future shape changes add
    their own branch here instead of breaking load.
    """
    if not isinstance(data, dict):
        return {}
    version = int(data.get("version") or 0)
    if version < SNAPSHOT_VERSION:
        data = dict(data)
        data["version"] = SNAPSHOT_VERSION
    return data


def restore(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Apply a snapshot to the live session, tolerant of version drift.

    Returns a small report: which fields were applied and the version the
    snapshot claimed (0 when it predates versioning).
    """
    from phantom.core.session import session
    report: Dict[str, Any] = {"applied": [], "version": 0}
    if not isinstance(data, dict):
        return report
    data = migrate(data)
    report["version"] = data.get("version", SNAPSHOT_VERSION)
    for key in SNAPSHOT_FIELDS:
        if key in data and data[key] not in _UNSET:
            setattr(session, key, data[key])
            report["applied"].append(key)
    return report


def save(path: str) -> bool:
    """Atomically write a snapshot to ``path`` (best effort)."""
    import json
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(snapshot(), fh, indent=2, default=str)
        os.replace(tmp, path)
        return True
    except Exception:
        return False


def load(path: str) -> Dict[str, Any]:
    """Read and apply a snapshot from ``path`` (best effort). Returns the
    restore report (empty when the file is missing/unreadable)."""
    import json
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return {}
    return restore(data)
