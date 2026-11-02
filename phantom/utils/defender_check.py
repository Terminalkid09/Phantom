"""Utility to detect if Windows Defender (or its service) is present.

The beacon can be configured to disable aggressive injection paths when Defender
is active. The detection is deliberately lightweight – it only queries the
registry for the service name ``Windefend`` which is present on all Windows
systems with Defender built‑in. If the registry cannot be accessed (e.g. on non‑Windows
hosts or in CI) the function returns ``False`` so the beacon stays functional.
"""

from __future__ import annotations

def is_defender_present() -> bool:
    """Return ``True`` if the Windows Defender service is registered.

    The function tries to open ``HKLM\SYSTEM\CurrentControlSet\Services\Windefend``.
    If the key exists, Defender is present (even if disabled). Any exception –
    including ``ImportError`` on non‑Windows platforms – results in ``False``.
    """
    try:
        import winreg  # type: ignore
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\Windefend"):
            return True
    except Exception:
        return False
