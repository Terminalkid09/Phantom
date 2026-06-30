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

def add_custom_beacon(platform: str, command: str, description: str, source: str = "c2_shell"):
    """
    Registers a custom beacon in the shared registry with validation and deduplication.
    Produces a stable UUID id and stores a hash to prevent duplicates. Unknown
    platforms are allowed but normalized to lower-case.
    """
    platform = (platform or "").lower()
    if platform not in VALID_PLATFORMS:
        # Normalize unknown platforms to 'unknown' for easier filtering later
        platform = "unknown"

    history = get_custom_beacons()

    # Compute a stable hash for deduplication
    key = f"{platform}|{command}"
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()

    for entry in history:
        if entry.get("_hash") == h:
            # duplicate; update timestamp/source if desired and exit
            return

    new_entry = {
        "id": str(uuid.uuid4()),
        "platform": platform,
        "command": command,
        "description": description,
        "source": source,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "_hash": h
    }

    history.append(new_entry)
    _save_history(history)

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
