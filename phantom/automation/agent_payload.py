"""agent_payload.py — the payload / sandbox boundary of the agent loop.

Extracted from ``agent.py`` (2026-11-05) as the third slice of the monolith
split. These three helpers answer one question: *what artifact do we hand to
the sandbox, and what did it say?* They were buried in a 5.2k-line module
next to the planner, the social engine and the checkpoint code.

Bodies are unchanged; the only structural difference is that the two helpers
that used ``self`` now take the agent as their first argument. ``AutoAgent``
keeps thin methods with the original names and signatures that delegate
here, so every call site is untouched.
"""
from __future__ import annotations

import os

from phantom.automation.sandbox.sandbox import SandboxVerdict


def materialize_payload(command: str) -> str:
    """Write the payload command to a temp file so sandbox backends can
    actually scan/detonate it (Defender, Docker, VM). The dropper is a
    shell script staged from our C2 listener."""
    import tempfile
    fd, path = tempfile.mkstemp(prefix="phantom_payload_", suffix=".sh",
                                dir=tempfile.gettempdir())
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(command)
    return path


def deploy_sample_path(agent) -> str:
    """The artifact the sandbox backends scan/detonate for beacon_deploy:
    the actual binary shipped to the target (the static Linux build when
    present — exactly what _wrap_remote_exec scp's over). Scanning the
    *deployment command* instead validated nothing: a scp/ssh or curl
    dropper cannot run inside the networkless docker container (no
    sshpass, no curl) so it always "crashed" with EXIT:127, and it is
    the binary — not the one-liner — that AV/EDR would ever see."""
    binary = getattr(agent, "_last_beacon_binary", "")
    if not binary or not os.path.exists(binary):
        return ""
    static = os.path.join(os.path.dirname(binary), "beacon_linux_static")
    if os.path.exists(static):
        return static
    return binary


def preflight(agent, capability_id: str,
              sample_path: str = "") -> SandboxVerdict:
    """Emit the sandbox event and return the verdict.

    A backend blowing up must not take the run down with it: an exception
    becomes a DENIED verdict with the reason attached, exactly as before.
    """
    agent._emit("sandbox", capability=capability_id,
                detail="pre-flight sample validation",
                sample=sample_path)
    try:
        return agent.sandbox.preflight(sample_path)
    except Exception as e:
        return SandboxVerdict(approved=False, results=[],
                              reason=f"sandbox error: {e}")
