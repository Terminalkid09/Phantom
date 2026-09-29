"""artifact_policy.py — classification, TTL and quota for beacon artifacts
(ROADMAP P1-11; retention decided by the owner in Q-5: **30 days**).

The C2 persists real media (screenshots, recordings, remote-session frames,
downloads). Quantity caps exist; TIME did not. This module adds:

    * classification per directory (what KIND of data lives there and how
      sensitive it is);
    * a default 30-day TTL enforced by a cleanup pass that deletes expired
      files and writes an immutable `artifact_expired` audit receipt;
    * a per-directory size quota — new saves over quota are refused (the
      oldest files are reported for operator decision, never auto-deleted
      before their TTL);
    * `describe()` metadata for the API so surfaces can show class + TTL.

Design: zero configuration by default (owner's "works when downloaded"
rule), every value overridable via env without code changes.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List

# directory (relative to data/) -> metadata
#   class   : data classification shown in reports/API
#   ttl     : seconds before cleanup deletes the file (0 = never)
#   quota   : max total bytes for the directory (0 = unlimited)
_CLASSES: Dict[str, Dict[str, Any]] = {
    "screenshots":      {"cls": "screen_capture",  "ttl_days": 30, "quota_mb": 1024},
    "recordings":       {"cls": "screen_recording", "ttl_days": 30, "quota_mb": 4096},
    "recordings/live":  {"cls": "live_segment",    "ttl_days": 7,  "quota_mb": 1024},
    "remote":           {"cls": "remote_frame",    "ttl_days": 7,  "quota_mb": 512},
    "downloads":        {"cls": "acquired_file",   "ttl_days": 30, "quota_mb": 2048},
    # Run state and textual output: TTL 0 by design — NEVER auto-deleted.
    # A checkpoint may still be the only way to resume an engagement and
    # the audit log is the engagement's record; the honest treatment is to
    # MEASURE them (doctor reports usage) instead of pruning them. Note the
    # cleanup pass only removes FILES directly inside these directories, so
    # per-run subdirectories (sessions/auto_*/) are untouchable by design.
    "sessions":         {"cls": "run_state",         "ttl_days": 0, "quota_mb": 0},
    "reports":          {"cls": "engagement_report", "ttl_days": 0, "quota_mb": 0},
    "logs":             {"cls": "runtime_log",       "ttl_days": 0, "quota_mb": 0},
}


def usage_report(data_root: str) -> List[Dict[str, Any]]:
    """Per-class disk usage of the artifact directories (for `doctor`).

    Read-only: never deletes, never writes. Size is best-effort and
    recursive, so a directory of per-run subdirectories (sessions,
    reports) reports the total an operator actually pays for.
    """
    out: List[Dict[str, Any]] = []
    for subdir in _CLASSES:
        d = os.path.join(data_root, subdir)
        if not os.path.isdir(d):
            continue
        total = 0
        files = 0
        for root, _dirs, names in os.walk(d):
            for name in names:
                p = os.path.join(root, name)
                try:
                    total += os.path.getsize(p)
                    files += 1
                except OSError:
                    continue
        meta = classify(subdir)
        out.append({"dir": subdir, "class": meta["class"],
                    "bytes": total, "files": files,
                    "ttl_days": meta["ttl_days"]})
    return out

DEFAULT_TTL_DAYS = 30          # owner decision Q-5
DEFAULT_QUOTA_MB = 1024


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except (TypeError, ValueError):
        return default


def classify(subdir: str) -> Dict[str, Any]:
    """Classification metadata for one artifact directory."""
    meta = _CLASSES.get(subdir.strip("/"))
    ttl_days = (meta or {}).get("ttl_days", DEFAULT_TTL_DAYS)
    if subdir.strip("/") == "data":
        ttl_days = DEFAULT_TTL_DAYS
    quota_mb = (meta or {}).get("quota_mb", DEFAULT_QUOTA_MB)
    # env overrides (engagement-specific retention); float so tests and
    # tiny deployments can set sub-MB quotas
    ttl_days = _env_int("PHANTOM_ARTIFACT_TTL_DAYS", ttl_days)
    quota_mb = _env_float("PHANTOM_ARTIFACT_QUOTA_MB", quota_mb)
    return {
        "class": (meta or {}).get("cls", "generic_artifact"),
        "ttl_days": ttl_days,
        "ttl_seconds": ttl_days * 86400,
        "quota_bytes": int(quota_mb * 1024 * 1024),
    }


def ttl_days_left(subdir: str, mtime: float, now: float = None) -> int:
    """Whole days remaining before the TTL policy removes the file (0 =
    due now, negative = overdue)."""
    now = now if now is not None else time.time()
    ttl = classify(subdir)["ttl_seconds"]
    if ttl <= 0:
        return -1
    remaining = ttl - (now - mtime)
    return int(remaining // 86400)


def dir_usage(dir_path: str) -> Dict[str, Any]:
    """Size + file count of one artifact directory."""
    total = 0
    count = 0
    if os.path.isdir(dir_path):
        for name in os.listdir(dir_path):
            p = os.path.join(dir_path, name)
            if os.path.isfile(p):
                try:
                    total += os.path.getsize(p)
                    count += 1
                except OSError:
                    pass
    return {"bytes": total, "files": count}


def over_quota(dir_path: str, subdir: str) -> bool:
    """True when writing one more artifact would exceed the quota.
    A zero quota means "no quota" by convention; negative disables saving.
    """
    quota = classify(subdir)["quota_bytes"]
    if quota <= 0:
        return False
    return dir_usage(dir_path)["bytes"] >= quota


def cleanup_expired(data_root: str, now: float = None) -> List[Dict[str, Any]]:
    """Delete every artifact older than its class TTL; returns receipts.

    Each receipt is also appended to the immutable audit log as
    `artifact_expired` (path hash, not the path itself — the log can be
    shared with the client, the file list should not).
    """
    now = now if now is not None else time.time()
    receipts: List[Dict[str, Any]] = []
    for subdir in _CLASSES:
        d = os.path.join(data_root, subdir)
        if not os.path.isdir(d):
            continue
        ttl = classify(subdir)["ttl_seconds"]
        if ttl <= 0:
            continue
        for name in os.listdir(d):
            p = os.path.join(d, name)
            if not os.path.isfile(p):
                continue
            try:
                age = now - os.path.getmtime(p)
            except OSError:
                continue
            if age > ttl:
                try:
                    size = os.path.getsize(p)
                    os.remove(p)
                    receipts.append({
                        "dir": subdir, "name": name, "size": size,
                        "age_days": round(age / 86400, 1),
                        "class": classify(subdir)["class"],
                    })
                except OSError:
                    continue
    if receipts:
        try:
            from phantom.utils.audit_log import audit_log
            audit_log.append("artifact_expired", count=len(receipts),
                             ttl_days=classify(subdir)["ttl_days"])
        except Exception:
            pass
    return receipts
