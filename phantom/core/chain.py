"""
chain.py — manual-core exploit chaining with approval gates.

The auto-mode composes attack paths from typed operators (SSRF →
metadata → cloud keys; upload + traversal → webshell → RCE; SQLi →
file read → creds → SSH). The manual core never had access to that
reasoning — until now. `chain` in the exploit module:

    1. projects the session WorldModel into the operator fact space
    2. searches the CHEAPEST operator chain to each goal
    3. shows the chain with per-step cost/noise and the CONCRETE
       command each step would run (mapped onto real capabilities)
    4. executes only the steps the operator approves, feeding every
       finding back into the shared WorldModel so later steps see it

Steps whose operator has no manual-core capability mapping are shown
but marked engine-only (they run inside auto-mode, where adapters
exist for every operator).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

# operator id → (capability id, note) — capabilities whose adapters can
# actually execute the operator's primitive from the manual shell.
_OP_TO_CAP: Dict[str, Tuple[str, str]] = {
    "web.enum_params": ("hunt_web", "fuzzes mapped parameters"),
    "web.find_uploads": ("hunt_web", "fuzzes upload endpoints"),
    "web.find_admin": ("hunt_web", "fuzzes admin/auth surface"),
    "web.sqli_read": ("hunt_web", "sqli probe class"),
    "web.sqli_admin": ("hunt_web", "sqli auth-bypass probe"),
    "web.upload_shell": ("rce_foothold", "upload+traversal -> webshell"),
    "web.write_rce": ("rce_foothold", "webshell -> code execution"),
    "ssh.use_creds": ("ssh_login", "harvested creds -> SSH session"),
    "cloud.harvest_keys": ("cloud_creds_harvest", "metadata -> role keys"),
    # post-exploitation goals: the manual core plans and approves the SAME
    # moves the auto-mode runs — privesc, lateral movement, persistence —
    # executed through the mapped capabilities with the operator's approval.
    "priv.system": ("privesc_system", "escalate the beacon to SYSTEM/root"),
    "persist.installed": ("persistence_install", "install beacon persistence"),
    "pivot.smb": ("smb_pivot", "PsExec-style deploy to a peer (pass-the-hash ok)"),
    "pivot.winrm": ("winrm_pivot", "evil-winrm deploy to a peer"),
    # operator primitives -> the capability that executes them in the
    # manual core (chain preview/execute path)
    "post.escalate": ("privesc_system", "live beacon -> SYSTEM/root escalation"),
    "post.persist": ("persistence_install", "live beacon -> persistence install"),
    "post.escalate_persist": ("persistence_install", "SYSTEM session -> boot persistence"),
    "smb.pivot": ("smb_pivot", "SMB creds + beacon -> peer deploy"),
    "winrm.pivot": ("winrm_pivot", "creds + beacon -> evil-winrm deploy"),
    # internal expansion: map the network from the beacon, probe the peers
    "recon.internal": ("internal_recon", "beacon -> internal interfaces/routes/ARP"),
    "probe.internal": ("internal_probe", "in-scope peers -> pivot-service probe"),
}

# goals worth searching for, in operator-fact terms
GOALS: List[str] = [
    "rce.web",        # remote code execution on the web tier
    "creds.ssh",      # a usable SSH credential pair
    "creds.db",       # a usable database credential pair
    "creds.admin",    # application admin credential
    "cloud.keys",     # harvested cloud API keys
    "file.read",      # arbitrary file read primitive
    # post-exploitation: the kill chain does not end at the first shell
    "priv.system",    # SYSTEM/root on the foothold
    "persist.installed",  # beacon survives reboot
    "internal.host",  # map the internal network from the foothold
    "internal.service",  # pivot services on the internal peers
    "pivot.smb",      # lateral movement to an SMB peer
    "pivot.winrm",    # lateral movement to a WinRM peer
]


def plan(session_wm, max_chains: int = len(GOALS)) -> List[dict]:
    """Search operator chains from the manual session's WorldModel.
    Returns a list of {goal, chain, cost, noise, steps:[...]} dicts,
    cheapest first, skipping goals already satisfied."""
    from phantom.automation.brain.composition import CompositionEngine
    from phantom.automation.brain.operators import default_operators

    engine = CompositionEngine(default_operators())
    have = engine.facts_from_worldmodel(session_wm)

    out: List[dict] = []
    for goal in GOALS:
        if goal in have:
            continue  # already have this fact — nothing to compose
        comp = engine.search(set(have), goal)
        if comp is None or comp.empty:
            continue
        steps = []
        for s in comp.steps:
            op = default_operators().get(s.op_id)
            mapping = _OP_TO_CAP.get(s.op_id)
            steps.append({
                "op": s.op_id,
                "desc": op.desc if op else s.op_id,
                "cap": mapping[0] if mapping else None,
                "note": mapping[1] if mapping else "engine-only (auto-mode)",
                "cost": s.cost,
                "noise": s.noise,
                "facts": list(s.facts_produced),
            })
        out.append({
            "goal": goal,
            "steps": steps,
            "cost": round(comp.total_cost, 2),
            "noise": round(comp.total_noise, 2),
        })
        if len(out) >= max_chains:
            break
    out.sort(key=lambda c: c["cost"])
    return out


def preview_step(step: dict, target: str = "") -> Tuple[bool, str]:
    """Build the CONCRETE command a chain step would run, WITHOUT
    executing it — `chain preview <plan.step>` in the manual shell. Lets
    the operator audit exactly what an approved step ships before
    approving (the 'show me the command, not just the label' move)."""
    cap_id = step.get("cap")
    if not cap_id:
        return False, "engine-only step — no manual-core command exists"
    try:
        from phantom.automation.guidance.commands import make_registry
        from phantom.core.knowledge import session_wm
        cap = make_registry().get(cap_id)
    except Exception as e:
        return False, f"import failed: {e}"
    if cap is None:
        return False, f"unknown capability {cap_id}"
    wm = session_wm()
    try:
        cmd = cap.make_command(wm, {})
    except Exception as e:
        return False, f"cannot build command (missing data: {e})"
    # dynamic shaping is applied at execution time; preview shows the
    # exact command the executor will run after shaping too
    try:
        from phantom.automation.guidance.dynamics import DynCommandBuilder
        cmd = DynCommandBuilder(seed=hash(str(wm.target)) % 2**31).shape(cmd, wm)
    except Exception:
        pass
    return True, cmd


def execute_step(step: dict, target: str) -> Tuple[bool, str]:
    """Run ONE approved chain step through its mapped capability:
    build the concrete command, execute it, interpret findings back
    into the session WorldModel. Returns (ok, summary)."""
    cap_id = step.get("cap")
    if not cap_id:
        return False, "engine-only step — run it through auto-mode"
    try:
        from phantom.automation.guidance.commands import make_registry
        from phantom.core.knowledge import session_wm
        from phantom.core.executor import run_command
    except Exception as e:
        return False, f"import failed: {e}"

    cap = make_registry().get(cap_id)
    if cap is None:
        return False, f"unknown capability {cap_id}"
    wm = session_wm()
    try:
        cmd = cap.make_command(wm, {})
    except Exception as e:
        return False, f"cannot build command (missing data: {e})"
    output = run_command(cmd, target)
    try:
        findings = cap.interpret(output or "", wm, {})
        for f in findings:
            wm.add_finding(kind=f.kind, key=f.key, value=f.value,
                           confidence=getattr(f, "confidence", 0.6),
                           source=cap_id, evidence=(output or "")[:200])
    except Exception:
        pass
    return True, f"$ {cmd}\n{(output or '')[-800:]}"
