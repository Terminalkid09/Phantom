#!/usr/bin/env python3
"""hardened_target_sim.py — offline coverage simulation (auto-mode vs guided
manual core) against a deliberately HARDENED, NON-STANDARD target.

The scenario is a "Fortress" appliance that has removed every well-trodden
door and left a few obscure ones:

  * SSH only on a NON-standard port 2222 (no 22).
  * NO port 80/443 at all.
  * The only web surface is a custom appliance admin UI on 8443 (self-signed
    TLS) whose RCE/upload handler is hidden at a NON-standard path, not at
    `/upload`.
  * No default or discoverable credentials.

This script answers one question with code, not opinion: do the automated
kill-chain planner AND the guided manual core have a MOVE for every step of
this path, and does anything stall?

It is fully OFFLINE: every command is answered by a scripted runner; no
packet leaves the box. Run it with `python scripts/hardened_target_sim.py`.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import Mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TARGET = "10.13.37.9"
SSH_PORT = "2222"
WEB_PORT = "8443"
HIDDEN_PATH = "/internal/v2/_dash"

SSH_VERSION_BANNER = ("2222/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13\n"
                      "8443/tcp open  ssl/http FRTX-Admin 2.1")
PORT_ONLY_BANNER = ("2222/tcp open  ssh\n"
                    "8443/tcp open  ssl/https")
WEB_HEADERS = ("HTTP/1.1 200 OK\n"
               "Server: FRTX/2.1\n"
               "X-Powered-By: FRTX-Appliance\n"
               "Content-Type: text/html\n"
               "\n"
               "<html><head><title>Fortress Admin</title></head>"
               f"<body><script src=\"{HIDDEN_PATH}.js\"></script></body></html>")


def hardened_runner(log):
    """Scripted answers for the Fortress appliance (offline)."""
    def runner(cmd, timeout=None):
        log.append(cmd)
        res = Mock()
        res.ok = False
        res.stdout = ""
        res.stderr = ""
        c = str(cmd)
        versionish = ("-sV" in c or "--version-intensity" in c or "-O" in c)
        if ("nmap" in c or "masscan" in c or "nc -z" in c) and versionish:
            res.ok, res.stdout = True, SSH_VERSION_BANNER
        elif "nmap" in c or "masscan" in c or c.startswith("nc "):
            res.ok, res.stdout = True, PORT_ONLY_BANNER
        elif "curl" in c and WEB_PORT in c:
            res.ok, res.stdout = True, WEB_HEADERS
        elif "curl" in c and "/upload" in c:
            # the hardened app does NOT expose /upload
            res.ok, res.stdout = True, "404 Not Found"
        elif "curl" in c or "httpx" in c or "wget" in c:
            # no port 80/443 on this box: every default probe is refused
            res.ok, res.stdout = False, ""
        elif ("sshpass" in c or "ssh " in c or "hydra" in c
              or "medusa" in c or "msfconsole" in c):
            res.ok, res.stdout = False, ""
        return res
    return runner


def _engine(wm):
    from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
    return StealthEngine(wm, StealthConfig())


def _fresh_wm():
    from phantom.automation.belief import WorldModel
    return WorldModel(target=TARGET)


def run_shell_cap(registry, wm, cap_id, slots, runner, log):
    """Build -> run -> interpret one shell_command capability (offline)."""
    cap = registry.get(cap_id)
    if cap is None:
        return cap_id, None, 0
    cmd = cap.make_command(wm, dict(slots))
    run = runner(cmd)
    findings = cap.interpret(run.stdout, wm, slots) or []
    for f in findings:
        try:
            wm.add_finding(f.kind, f.key, f.value, confidence=f.confidence,
                           source=getattr(f, "source", cap_id))
        except Exception:
            pass
    return cap_id, cmd, len(findings)


def main() -> int:
    from phantom.automation.guidance.commands import make_registry
    from phantom.automation.planner import Planner

    registry = make_registry()
    log = []

    print("=" * 74)
    print(f"HARDENED TARGET SIMULATION — {TARGET} (offline, scripted runner)")
    print("=" * 74)

    # ── Step 1: footprint through the REAL scan capability ──────────────────
    wm = _fresh_wm()
    runner = hardened_runner(log)
    _, cmd, n = run_shell_cap(registry, wm, "scan_tcp", {}, runner, log)
    print("\n[scan_tcp] command:", cmd)
    print("[scan_tcp] service findings:", n)
    for f in wm.find("service"):
        print("           ", f.value)

    # ── Step 2: version detection ───────────────────────────────────────────
    _, cmd, n = run_shell_cap(registry, wm, "version_detect", {}, runner, log)
    print("\n[version_detect] command:", cmd)
    print("[version_detect] findings:", n)

    # ── Step 3: HTTP fingerprint — AUTO default vs MANUAL explicit URL ──────
    auto_wm = _fresh_wm()
    for f in list(wm.all_findings()):
        auto_wm.add_finding(f.kind, f.key, f.value, confidence=f.confidence,
                            source="seed")
    http_cap = registry.get("http_probe")
    auto_cmd = http_cap.make_command(auto_wm, {})
    print("\n[http_probe AUTO]  command:", auto_cmd)
    print("                   -> targets port 80 by default "
          f"({'CANNOT reach 8443' if WEB_PORT not in auto_cmd else 'reaches 8443'})")
    manual_cmd = http_cap.make_command(
        auto_wm, {"url": f"https://{TARGET}:{WEB_PORT}/"})
    print("[http_probe MANUAL] command:", manual_cmd)
    run = runner(manual_cmd)
    findings = http_cap.interpret(run.stdout, auto_wm, {"url": f"https://{TARGET}:{WEB_PORT}/"})
    for f in findings:
        auto_wm.add_finding(f.kind, f.key, f.value, confidence=f.confidence,
                            source="http_probe")
    print("[http_probe MANUAL] findings:", [(f.kind, f.key) for f in findings])

    # ── Step 4: the RCE probe — where does it aim? ──────────────────────────
    rce_cap = registry.get("web_rce")
    rce_cmd = rce_cap.make_command(auto_wm, {})
    print("\n[web_rce] command:", rce_cmd)
    print("          -> probes a FIXED path; hidden RCE path is",
          HIDDEN_PATH, "->",
          "MISSED" if HIDDEN_PATH not in rce_cmd else "covered")

    # ── Step 5: what does the AUTO planner chain to 'beacon'? ───────────────
    print("\n" + "-" * 74)
    print("AUTO-MODE PLAN (goal=complete_kill_chain)")
    print("-" * 74)
    planner = Planner(registry, _engine(auto_wm))
    plan = planner.plan(auto_wm, goal="complete_kill_chain")
    print("complete:", plan.complete)
    for i, s in enumerate(plan.steps, 1):
        print(f"  {i}. {s.capability.id:24} {s.reason}")
    if plan.blocked_reason:
        print("  blocked:", plan.blocked_reason)

    # ── Step 6: guided MANUAL core (follow the next suggestion) ─────────────
    print("\n" + "-" * 74)
    print("GUIDED MANUAL CORE (planner.suggest_next, one move at a time)")
    print("-" * 74)
    manual_wm = auto_wm
    for i in range(10):
        step = planner.suggest_next(manual_wm, goal="complete_kill_chain")
        if step is None:
            print(f"  {i + 1}. <no further suggestion>")
            break
        cap = step.capability
        if cap.exec_class == "shell_command":
            _, c, n = run_shell_cap(registry, manual_wm, cap.id, {},
                                    runner, log)
            print(f"  {i + 1}. {cap.id:24} ran -> {n} finding(s)")
        else:
            print(f"  {i + 1}. {cap.id:24} ({cap.exec_class}) "
                  "not executable by the guided shell loop")
        if manual_wm.find("beacon"):
            break

    # ── Step 7: the MANUAL MODULE SURFACE (the operator's own console) ──────
    print("\n" + "-" * 74)
    print("MANUAL MODULE SURFACE (what the operator can type by hand)")
    print("-" * 74)
    try:
        from phantom.core.session import session
        session.target = TARGET
        from phantom.modules.web import WebModule
        groups = WebModule().build_commands() or {}
        fuzz_cmds = []
        for g, cmds in groups.items():
            for c in cmds or []:
                if any(t in c for t in ("ffuf", "gobuster", "feroxbuster")):
                    fuzz_cmds.append(c)
        print("  fuzzing commands available:", len(fuzz_cmds))
        for c in fuzz_cmds[:3]:
            print("     ", c)
        print("  -> the operator can retarget the URL at :8443 and supply a")
        print("     custom wordlist/word, so the hidden path IS reachable by hand.")
    except Exception as exc:  # pragma: no cover - sim diagnostics only
        print("  (module surface unavailable:", exc, ")")

    # ── Verdict ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 74)
    print("COVERAGE VERDICT")
    print("=" * 74)
    reached = {
        "port scan on non-standard ports (2222/8443)": bool(log and any(
            "nmap" in c or "masscan" in c for c in log)),
        "version detection": bool(wm.find("service")),
        "AUTO web fingerprint reaching :8443": WEB_PORT in auto_cmd,
        "AUTO/guided hidden-path RCE discovery": HIDDEN_PATH in rce_cmd,
        "AUTO beacon established": bool(auto_wm.find("beacon")),
    }
    for k, v in reached.items():
        print(f"  [{'OK ' if v else 'GAP'}] {k}")
    print()
    print("  Manual core: the guided planner hint is EMPTY on this target")
    print("  (suggest_next only offers the GOAL fact -> beacon, whose sources")
    print("  need creds or a confirmed rce_foothold). The hand-driven module")
    print("  surface, however, exposes unrestricted fuzzing + free-form run,")
    print("  so a skilled operator CAN reach the hidden path the automaton")
    print("  has no move for.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
