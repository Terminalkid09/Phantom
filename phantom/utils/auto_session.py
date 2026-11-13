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
#: Dated auto copies kept on disk. `latest.pm` is always kept on top of these;
#: every engagement used to add one file and nothing ever pruned them, so
#: `data/sessions/` grew without bound (and `sessions` listed all of it).
AUTO_KEEP = 20


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


def _quarantine_index(path: str) -> str:
    """Move an unreadable index aside instead of overwriting it.

    It used to be read with `json.load`, and an invalid result was silently
    replaced by `[]` on the next write: one corrupted file (two shells writing
    at once) erased the whole open/close history with no trace. The bad file
    is PRESERVED next to the fresh one; it costs a few KB and it is the only
    evidence of what happened.
    """
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    aside = f"{path}.corrupt-{stamp}"
    try:
        os.replace(path, aside)
        return aside
    except OSError:
        return ""


def _read_index() -> List[Dict[str, Any]]:
    """The sessions index, tolerating a missing/foreign/corrupt file."""
    path = _index_path()
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            idx = json.load(f)
    except (OSError, ValueError):
        _quarantine_index(path)
        return []
    if not isinstance(idx, list):
        _quarantine_index(path)
        return []
    return [row for row in idx if isinstance(row, dict)]


def _write_index(rows: List[Dict[str, Any]]) -> None:
    """Write the index atomically (temp in the same dir + `os.replace`).

    The Electron app and a terminal can open an engagement at the same time,
    and the close hook runs while the process can still be killed: written in
    place, `index.json` was truncatable, and a reader could see half a JSON
    array.
    """
    path = _index_path()
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rows[-200:], f, indent=2)
        os.replace(tmp, path)
    except OSError:
        try:
            if os.path.isfile(tmp):
                os.remove(tmp)
        except OSError:
            pass


def _entry_key(row: Dict[str, Any]) -> tuple:
    """Identity of ONE open: pid + opening second + engagement."""
    return (row.get("pid"), row.get("opened_at"), row.get("engagement_id"))


# ── open ───────────────────────────────────────────────────────────────────

def register_open() -> None:
    """Record this shell session in the sessions index (idempotent per pid+start).

    Idempotent for real: the same pid opening twice within the same second for
    the same engagement is ONE row. A double registration used to look like
    two engagements, which is exactly what `sessions` shows the operator.
    """
    entry = {
        "opened_at": datetime.now().isoformat(timespec="seconds"),
        "pid": os.getpid(),
        "engagement_id": _engagement_id(),
    }
    try:
        idx = _read_index()
        if any(_entry_key(row) == _entry_key(entry) for row in idx):
            return
        idx.append(entry)
        _write_index(idx)
    except (OSError, ValueError):
        pass


def close_registration() -> None:
    """Stamp `closed_at` on the newest open that belongs to this engagement.

    Without it an engagement that crashed and one the operator closed
    cleanly looked identically "open" in the index. Best effort: it runs on
    the close path, so it must never be the thing that breaks the exit.
    """
    try:
        idx = _read_index()
        wanted = _engagement_id()
        for row in reversed(idx):
            if row.get("engagement_id") == wanted:
                if not row.get("closed_at"):
                    row["closed_at"] = datetime.now().isoformat(
                        timespec="seconds")
                    _write_index(idx)
                return
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
    worth persisting — no target, no notes, no findings, no result from any
    module, and an empty knowledge base.

    `session.results` (what each module actually produced) and the knowledge
    base count as content: an engagement whose ONLY durable output was, say, a
    scan result was not persisted at all (audit §6.5.4 holds that a bundle
    WITH data must exist). `export_session` records the results either way, so
    the gate only has to stop refusing them.
    """
    from phantom.core.knowledge import session_wm
    from phantom.core.session import session
    wm = session_wm()
    # `session.results` is what the MODULES produced: an engagement whose only
    # durable output was a scan (no note, no finding in the world model) used
    # to be dropped on the floor. History is deliberately NOT part of this:
    # every typed command lands there, so it would make the gate always true
    # and write a bundle for an empty shell.
    has_content = bool(session.target or session.notes or wm.all_findings()
                       or session.results)
    if not has_content:
        return None
    latest_path = os.path.join(_root(), _LATEST)
    try:
        latest = export_session(out_path=latest_path)
        export_session(out_path=_dated_copy_path())
        # Only AFTER both writes landed: the index says "this engagement was
        # closed", and a stamp written before the bundle would be a lie.
        close_registration()
        try:
            _prune_dated()
        except OSError:
            # Retention is housekeeping. A full/read-only sessions dir must
            # not turn a bundle that WAS written into "auto-save FAILED".
            pass
        return latest
    except Exception as exc:
        # A failed auto-save IS data loss, and it used to be a silent `None`:
        # the operator closed the shell believing the engagement was on disk.
        # The write itself is atomic now (`_atomic_gzip_write`), so what lands
        # here is a real failure worth saying out loud.
        _warn(f"session auto-save FAILED ({exc.__class__.__name__}: {exc}) — "
              f"{latest_path} is stale; run `export <file>.pm` before closing")
        return None


# ── retention ──────────────────────────────────────────────────────────────

def _prune_dated(keep: int = AUTO_KEEP) -> List[str]:
    """Keep the newest `keep` dated copies; return the names removed.

    Only a bundle that `read_bundle` READS is deleted. A corrupt file, a
    bundle from another machine (wrong `PHANTOM_PM_KEY`) or one written by a
    newer build is the operator's only copy of that engagement — retention
    must never be the reason an engagement disappears. `latest.pm` is not
    dated and is never a candidate.
    """
    removed: List[str] = []
    root = _root()
    rows: List[tuple] = []
    for name in os.listdir(root):
        if not (name.startswith("auto_") and name.endswith(".pm")):
            continue
        full = os.path.join(root, name)
        try:
            rows.append((os.path.getmtime(full), name, full))
        except OSError:
            continue
    rows.sort(key=lambda row: (row[0], row[1]), reverse=True)
    for _mtime, name, full in rows[max(0, int(keep)):]:
        try:
            read_bundle(full)
        except (ValueError, OSError):
            continue
        try:
            os.remove(full)
            removed.append(name)
        except OSError:
            continue
    return removed


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
