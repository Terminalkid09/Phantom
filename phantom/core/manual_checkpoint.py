"""manual_checkpoint.py — resumable progress for LONG manual runs (G15).

Only auto-mode wrote checkpoints (one per wave, into ``data/sessions/auto_*/``).
A manual brute force that ran for 40 minutes and then lost its terminal had to
start again from zero: the engagement's time is the operator's, and the tool
must not throw it away. This gives every manual command batch the same resume
guarantee, at command granularity.

The checkpoint lives at ``data/sessions/manual_<module>_<safe_target>.json``
(gitignored like every other session artifact). Writes are atomic (temp file +
``os.replace``) so an interrupted save can never leave an unparseable file.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime
from typing import Any, Dict

SCHEMA_VERSION = 1


def _safe(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", text or "unknown")[:80]


class ManualCheckpoint:
    """Command-level progress for one manual module against one target."""

    def __init__(self, module: str, target: str, path: str = "") -> None:
        self.module = module
        self.target = target or ""
        if not path:
            from phantom.utils.paths import sessions_dir
            path = os.path.join(
                sessions_dir(),
                f"manual_{_safe(module)}_{_safe(target)}.json")
        self.path = path
        self._data = self._load()

    # ── persistence ──────────────────────────────────────────────────────
    def _load(self) -> Dict[str, Any]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and \
                    data.get("schema_version") == SCHEMA_VERSION:
                return data
        except (OSError, ValueError):
            pass
        return {
            "schema_version": SCHEMA_VERSION,
            "module": self.module,
            "target": self.target,
            "created_at": datetime.now().isoformat(),
            "completed": {},
            "last_command": "",
            "finished": False,
        }

    def save(self) -> None:
        """Atomic write: an interrupted save never leaves a broken file."""
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        self._data["updated_at"] = datetime.now().isoformat()
        with tempfile.NamedTemporaryFile(
                mode="w", dir=directory, delete=False, suffix=".json",
                encoding="utf-8") as tmp:
            json.dump(self._data, tmp, indent=2, default=str)
            tmp_path = tmp.name
        os.replace(tmp_path, self.path)

    # ── progress ─────────────────────────────────────────────────────────
    def completed(self) -> Dict[str, str]:
        return dict(self._data.get("completed") or {})

    def mark(self, command: str, output: str = "") -> None:
        self._data.setdefault("completed", {})[command] = output
        self._data["last_command"] = command
        self.save()

    def finish(self) -> None:
        self._data["finished"] = True
        self.save()

    def clear(self) -> None:
        try:
            os.remove(self.path)
        except OSError:
            pass
        self._data["completed"] = {}
        self._data["finished"] = False

    def is_finished(self) -> bool:
        return bool(self._data.get("finished"))

    def progress(self) -> int:
        return len(self.completed())

    def summary(self) -> str:
        return (f"{self.progress()} command(s) already completed"
                f"{' (finished)' if self.is_finished() else ''}")
