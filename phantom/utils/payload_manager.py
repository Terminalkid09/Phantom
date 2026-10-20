import json
import os
import time
import shutil
import uuid
import hashlib
from typing import List, Dict, Any, Optional

VALID_PLATFORMS = ["windows", "linux", "macos", "android"]


def _payload_history_path() -> str:
    """Resolve payload history file relative to project root."""
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(project_root, "data", "payload_history.json")

def add_custom_beacon(
    platform: str,
    command: str,
    description: str,
    source: str = "c2_shell",
    *,
    connect: Optional[Dict[str, Any]] = None,
    bind: Optional[Dict[str, Any]] = None,
    listener_alive: Optional[bool] = None,
    artifact_path: Optional[str] = None,
    artifact_sha256: Optional[str] = None,
    artifact_size: Optional[int] = None,
    token_fingerprint: Optional[str] = None,
    profile: Optional[str] = None,
    target: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Registers a custom beacon in the shared registry with validation and deduplication.

    Besides the command itself, persist the endpoint the artefact was built
    against and a few immutable provenance fields.  The command is printed and
    then often lost in scrollback; months later ``payloads <id>`` must still
    answer "which IP:port does this beacon call, and what was listening?".
    Unknown platforms are allowed but normalized to lower-case.

    Returns the registry entry (new or the existing duplicate).
    """
    platform = (platform or "").lower()
    if platform not in VALID_PLATFORMS:
        # Normalize unknown platforms to 'unknown' for easier filtering later
        platform = "unknown"

    history = get_custom_beacons()

    # Compute a stable hash for deduplication
    key = f"{platform}|{command}"
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()

    provenance = {
        "connect": connect,
        "bind": bind,
        "listener_alive": listener_alive,
        "artifact_path": artifact_path,
        "artifact_sha256": artifact_sha256,
        "artifact_size": artifact_size,
        "token_fingerprint": token_fingerprint,
        "profile": profile,
        "target": target,
    }
    provenance = {k: v for k, v in provenance.items() if v is not None}

    for entry in history:
        if entry.get("_hash") == h:
            # Same artefact command: keep the stable id/created_at, but refresh
            # provenance so a rebuild/regeneration does not report stale data.
            if provenance:
                entry.update(provenance)
            entry["last_generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            _save_history(history)
            return entry

    new_entry = {
        "id": str(uuid.uuid4()),
        "platform": platform,
        "command": command,
        "description": description,
        "source": source,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "_hash": h,
    }
    new_entry.update(provenance)

    history.append(new_entry)
    _save_history(history)
    return new_entry

def get_custom_beacons() -> List[Dict[str, Any]]:
    """Reads custom beacons from the registry."""
    path = _payload_history_path()
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except (json.JSONDecodeError, IOError):
        pass
    return []

def clear_payload_history():
    """Wipes the payload history file."""
    path = _payload_history_path()
    if os.path.exists(path):
        os.remove(path)

def _save_history(history: List[Dict[str, Any]]):
    """Saves the history list to disk using an atomic-like write."""
    path = _payload_history_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp_file = path + ".tmp"
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=4, ensure_ascii=False)
        # Use shutil.move which is atomic on most OSes
        shutil.move(temp_file, path)
    except IOError:
        if os.path.exists(temp_file):
            os.remove(temp_file)
