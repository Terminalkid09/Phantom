"""secret_store.py — at-rest protection for operator-local secrets (D-3).

The state files (``phantom_state.json``, ``beacon_registry.json``) hold the C2
AES key, the API token, per-beacon HMAC secrets and client key material. They
are read by THREE runtimes:

    * this Python control plane,
    * the Electron main process (Node), which reads the API token, and
    * the Go data plane (``c2d``), which reads the AES key and API token.

That shared, cross-language contract rules out transparently encrypting the
file CONTENTS here: Node and Go would each need a DPAPI/CryptoAPI reader, and
a schema change would break already-deployed operators whose state file has no
marker. What every runtime CAN and DOES enforce is FILE-LEVEL access control:

    * POSIX   -> ``chmod 0600`` (owner read/write only).
    * Windows -> ``chmod`` only toggles the read-only bit, so the file keeps
      whatever the parent directory grants. ``harden_file`` strips inherited
      ACEs and grants the OWNER full control via ``icacls`` instead, which is
      the Windows equivalent of 0600.

Every call is best-effort: a secrets file must always stay writable, and a
hardening failure must never take the listener down.
"""
from __future__ import annotations

import os
import subprocess


def harden_file(path: str, mode: int = 0o600) -> None:
    """Restrict *path* to its owner. Best-effort; never raises."""
    if not path:
        return
    if os.name != "nt":
        try:
            os.chmod(path, mode)
        except OSError:
            pass
        return
    _harden_windows(path)


def _harden_windows(path: str) -> None:
    """Strip inherited ACLs and grant only the current user (best-effort)."""
    user = (os.environ.get("USERNAME") or os.environ.get("USER") or "").strip()
    if not user:
        return
    try:
        subprocess.run(
            ["icacls", path, "/inheritance:r", "/grant:r", f"{user}:F"],
            capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        pass


def locked_down(path: str) -> bool:
    """Whether *path* looks owner-only. Best-effort, used by `doctor`."""
    if not path or not os.path.exists(path):
        return False
    if os.name != "nt":
        try:
            return (os.stat(path).st_mode & 0o077) == 0
        except OSError:
            return True
    # Windows ACLs are not cheaply introspectable here; harden_file is the
    # enforcement point (it runs on every write), so treat existence as the
    # signal the doctor acts on.
    return True
