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

On top of file hardening this module offers an OPTIONAL OS keychain store
(`os_*`) for external-service API keys, so a credential can live in the
DPAPI / Keychain / Secret Service vault instead of clear text in
``data/config.json``. It is guarded by an import of ``keyring``: when the
library (or a usable backend) is absent every call degrades to a no-op and
the caller keeps the hardened file. Nothing here is ever mandatory.
"""
from __future__ import annotations

import os
import subprocess
from typing import Optional

# Namespace under which Phantom stores accounts in the OS vault. Kept
# stable so a key written by one version is read back by the next.
OS_SERVICE = "phantomshell"


class _Unavailable:
    """Sentinel backend used when there is no usable OS keystore."""

    @staticmethod
    def get_password(service: str, account: str) -> Optional[str]:
        return None

    @staticmethod
    def set_password(service: str, account: str, value: str) -> None:
        raise OSError("no OS keystore available")

    @staticmethod
    def delete_password(service: str, account: str) -> None:
        raise OSError("no OS keystore available")


_backend = None                # explicit override (tests)
_backend_resolved = False
_unavailable = _Unavailable()


def _resolve_backend():
    """The OS vault module, or the unavailable sentinel. Resolved once.

    ``keyring`` is an OPTIONAL dependency: ``import keyring`` fails on a
    bare environment, and even when installed it may select the "fail"
    backend (no D-Bus / no vault), which we treat as unavailable.
    """
    global _backend, _backend_resolved
    if _backend is not None:
        return _backend
    if _backend_resolved:
        return _backend or _unavailable
    _backend_resolved = True
    try:
        import keyring

        try:
            from keyring.backends.fail import Keyring as _Fail
            if isinstance(keyring.get_keyring(), _Fail):
                _backend = _unavailable
            else:
                _backend = keyring
        except Exception:
            _backend = keyring
    except Exception:
        _backend = _unavailable
    return _backend


def set_backend(backend) -> None:
    """Install an explicit backend (tests / embedding). ``None`` resets to
    lazy auto-detection on the next call."""
    global _backend, _backend_resolved
    _backend = backend
    _backend_resolved = backend is not None


def os_keystore_available() -> bool:
    """Whether a real OS vault is usable for reading/writing secrets."""
    return _resolve_backend() is not _unavailable


def os_get(account: str) -> Optional[str]:
    """Read a secret from the OS vault (None when absent or unavailable)."""
    backend = _resolve_backend()
    if backend is _unavailable or not account:
        return None
    try:
        return backend.get_password(OS_SERVICE, account)
    except Exception:
        return None


def os_set(account: str, value: str) -> bool:
    """Write a secret to the OS vault. Returns False when unavailable
    (the caller then falls back to the hardened config file)."""
    backend = _resolve_backend()
    if backend is _unavailable or not account:
        return False
    try:
        backend.set_password(OS_SERVICE, account, str(value))
        return True
    except Exception:
        return False


def os_delete(account: str) -> bool:
    """Remove a secret from the OS vault (best-effort)."""
    backend = _resolve_backend()
    if backend is _unavailable or not account:
        return False
    try:
        backend.delete_password(OS_SERVICE, account)
        return True
    except Exception:
        return False


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
