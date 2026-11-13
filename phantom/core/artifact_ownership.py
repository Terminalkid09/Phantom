"""artifact_ownership.py — who owns each binary artifact.

The remote viewer is authenticated PER BEACON, so it must only ever expose
frames that belong to ITS beacon. The stored filename is NOT a safe signal:
it is derived by truncating the beacon id to its first 16 alphanumerics, and
`generate_beacon_id()` builds ids as ``WIN-<hostname>-<hex>`` — two hosts
sharing a long name prefix (``WORKSTATION-1`` / ``WORKSTATION-2``) truncate to
the SAME prefix. Ownership is therefore recorded explicitly, at save time, in
an append-only sidecar index next to the artifacts, and read back by the
viewer.

Append-only (O_APPEND) keeps writes line-atomic across the C2 listener process
and the viewer process without a read-modify-write race; the last entry for a
name wins (a name reused by another beacon transfers ownership).
"""
from __future__ import annotations

import json
import os
import threading
from typing import Dict, Optional

_LOCK = threading.Lock()
_INDEX_NAME = ".owners.jsonl"


def _index_path(subdir: str) -> str:
    from phantom.utils.paths import data_dir
    return os.path.join(data_dir(), subdir, _INDEX_NAME)


def record_owner(subdir: str, name: str, beacon_id: str) -> None:
    """Record that ``name`` in ``data/<subdir>/`` belongs to ``beacon_id``."""
    if not subdir or not name or not beacon_id:
        return
    try:
        path = _index_path(subdir)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        line = json.dumps({"name": name, "beacon": beacon_id},
                          sort_keys=True) + "\n"
        with _LOCK:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
            finally:
                os.close(fd)
    except OSError:
        # ownership tracking must never break artifact saving
        pass


def _latest_owners(subdir: str) -> Dict[str, str]:
    """Map name -> LAST recorded beacon (empty when there is no index)."""
    owners: Dict[str, str] = {}
    try:
        with open(_index_path(subdir), "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                name = rec.get("name")
                beacon = rec.get("beacon")
                if isinstance(name, str) and isinstance(beacon, str):
                    owners[name] = beacon
    except OSError:
        return {}
    return owners


def owner_of(subdir: str, name: str) -> Optional[str]:
    """The beacon id that owns ``name``, or ``None`` when unrecorded."""
    return _latest_owners(subdir).get(name)


def owned_names(subdir: str, beacon_id: str) -> set:
    """Names in ``subdir`` whose LAST recorded owner is ``beacon_id``."""
    if not beacon_id:
        return set()
    return {name for name, owner in _latest_owners(subdir).items()
            if owner == beacon_id}
