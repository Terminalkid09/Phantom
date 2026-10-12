"""
auto_session.py — automatic session persistence.

Every Phantom open/close cycle is an engagement. This module makes sure an
operator NEVER loses state:

  * on open     -> the session is registered in data/sessions/index.json and,
                   if a `latest.pm` exists, the operator is asked whether to
                   resume the last engagement (restores target/scope/WM/
                   checkpoint, so `suggest` and the planner work from the
                   accumulated findings — no restart from zero).
  * on close    -> the engagement is exported to a portable, ENCRYPTED .pm:
                   `latest.pm` is always overwritten (the "last session"
                   pointer); a dated copy `auto_<YYYY-MM-DD>.pm` is written
                   per engagement — overwritten when the file belongs to the
                   SAME engagement (same target + opening timestamp), a NEW
                   file when it is a different engagement.

Both hooks run from main.py AND from `auto_shell.run_auto_shell`, so the
double Ctrl+C exit is covered too (not just `exit`/`quit`) — including the
interactive AUTO-MODE shell, which is the surface that actually runs kill
chains and which used to write no `.pm` at all.

The write itself is atomic (`.pm.tmp` + `os.replace`, see
`session_bundle._atomic_gzip_write`): the close paths that export are exactly
the ones that can be killed, and a truncated `latest.pm` used to be reported
as a key mismatch and quietly replaced by a fresh session.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from phantom.utils.paths import sessions_dir
from phantom.utils.session_bundle import (
    _engagement_id,
    export_session,
    import_session,
    is_key_mismatch,
    read_bundle,
)

_LATEST = "latest.pm"


def _warn(message: str) -> None:
    """Tell the operator something went wrong on a close/open path.

    Best effort by construction: these hooks run while a shell is shutting
    down, so the warning must never be the thing that breaks the exit.
    """
    try:
        from phantom.utils.notifier import notifier
        notifier.warn(message)
    except Exception:
        try:
            print(f"[!] {message}")
        except Exception:
            pass


def _root() -> str:
    root = sessions_dir()
    os.makedirs(root, exist_ok=True)
    return root


def _index_path() -> str:
    return os.path.join(_root(), "index.json")


# ── open ───────────────────────────────────────────────────────────────────

def register_open() -> None:
    """Record this shell session in the sessions index (idempotent per pid+start)."""
    entry = {
        "opened_at": datetime.now().isoformat(timespec="seconds"),
        "pid": os.getpid(),
        "engagement_id": _engagement_id(),
    }
    try:
        idx = []
        if os.path.isfile(_index_path()):
            with open(_index_path(), "r", encoding="utf-8") as f:
                idx = json.load(f)
        if not isinstance(idx, list):
            idx = []
        idx.append(entry)
        with open(_index_path(), "w", encoding="utf-8") as f:
            json.dump(idx[-200:], f, indent=2)
    except (OSError, ValueError):
        pass


def offer_resume(quiet: bool = False) -> bool:
    """If a latest.pm exists, ask whether to resume the last engagement.

    Returns True when the operator accepted (session + WM restored).
    Skipped entirely when not an interactive TTY or `quiet=True`.
    """
    latest = os.path.join(_root(), _LATEST)
    if not os.path.isfile(latest):
        return False
    if quiet or not sys.stdin.isatty():
        return False
    try:
        data = read_bundle(latest)
    except ValueError as exc:
        # "a bundle from another machine" and "my last session is damaged"
        # are different problems and used to print the same way. Both mean a
        # fresh start, but the operator has to know WHICH ONE happened.
        if is_key_mismatch(exc):
            _warn(f"cannot read {latest}: wrong PHANTOM_PM_KEY on this "
                  f"machine — starting fresh")
        else:
            _warn(f"{latest} is unreadable ({exc}) — the last engagement "
                  f"could NOT be restored; starting fresh. The file is "
                  f"still on disk.")
        return False
    sess = data.get("session") or {}
    target = sess.get("target") or "-"
    n_findings = len((data.get("checkpoint") or {}).get("wm", {}).get("findings", []) or []) \
        or len((sess.get("_wm") or {}).get("findings", []) or [])
    n_notes = len(sess.get("notes") or [])
    print(f"\n[?] Last engagement found: target={target} · "
          f"findings={n_findings} · notes={n_notes} · {os.path.basename(latest)}")
    answer = input("    Resume it? [Y/n]: ").strip().lower()
    if answer == "n":
        return False
    try:
        result = import_session(latest)
        print(f"[+] Session restored: target={result.get('target') or '-'} · "
              f"findings={result.get('findings', 0)} · "
              f"checkpoint={'yes' if result.get('resume_path') else 'no'}")
        print("    `suggest` and the planner now work from the restored "
              "knowledge. Use `auto --resume` to continue the kill chain.")
        return True
    except (ValueError, OSError) as e:
        print(f"[!] Could not restore session: {e}")
        return False


# ── close ──────────────────────────────────────────────────────────────────

def _dated_copy_path() -> str:
    date = datetime.now().strftime("%Y-%m-%d")
    base = os.path.join(_root(), f"auto_{date}.pm")
    if not os.path.isfile(base):
        return base
    # same engagement -> overwrite the dated copy
    try:
        existing = read_bundle(base)
        if existing.get("engagement_id") == _engagement_id():
            return base
    except ValueError:
        pass
    # different engagement today -> keep history, add a suffix
    n = 2
    while os.path.isfile(os.path.join(_root(), f"auto_{date}_{n}.pm")):
        n += 1
    return os.path.join(_root(), f"auto_{date}_{n}.pm")


def auto_export() -> Optional[str]:
    """Export the current engagement to latest.pm + a dated copy.

    Returns the latest.pm path written, or None when there is nothing
    worth persisting (no target AND no notes AND no findings).
    """
    from phantom.core.knowledge import session_wm
    from phantom.core.session import session
    wm = session_wm()
    has_content = bool(session.target or session.notes or wm.all_findings())
    if not has_content:
        return None
    latest_path = os.path.join(_root(), _LATEST)
    try:
        latest = export_session(out_path=latest_path)
        export_session(out_path=_dated_copy_path())
        return latest
    except Exception as exc:
        # A failed auto-save IS data loss, and it used to be a silent `None`:
        # the operator closed the shell believing the engagement was on disk.
        # The write itself is atomic now (`_atomic_gzip_write`), so what lands
        # here is a real failure worth saying out loud.
        _warn(f"session auto-save FAILED ({exc.__class__.__name__}: {exc}) — "
              f"{latest_path} is stale; run `export <file>.pm` before closing")
        return None


# ── listing ────────────────────────────────────────────────────────────────

def list_auto() -> List[Dict[str, Any]]:
    """Metadata for latest.pm + dated auto_*.pm copies (for `sessions`)."""
    out: List[Dict[str, Any]] = []
    for name in sorted(os.listdir(_root())):
        if not name.endswith(".pm"):
            continue
        full = os.path.join(_root(), name)
        entry: Dict[str, Any] = {
            "name": name,
            "size": os.path.getsize(full),
            "mtime": datetime.fromtimestamp(os.path.getmtime(full)).strftime("%Y-%m-%d %H:%M"),
            "target": "-",
            "findings": 0,
        }
        try:
            data = read_bundle(full)
            sess = data.get("session") or {}
            entry["target"] = sess.get("target") or "-"
            entry["findings"] = len((data.get("checkpoint") or {}).get("wm", {}).get("findings", []) or []) \
                or len((sess.get("_wm") or {}).get("findings", []) or [])
        except ValueError as exc:
            entry["target"] = ("(wrong key on this machine)"
                               if is_key_mismatch(exc)
                               else "(unreadable: corrupt .pm)")
        out.append(entry)
    return out
