#!/usr/bin/env python3
"""coverage_matrix_sim.py — offline coverage MATRIX across target types.

This generalises ``scripts/hardened_target_sim.py`` from ONE scenario (a
hardened web appliance) to a matrix that answers the same question for every
entity an operator may be handed:

    * a bare device IP (SMB / RDP / DB only, no web)
    * a normal server IP (ssh + web + db)
    * a full URL (https://host:port/path)
    * a domain
    * a social username
    * an email address
    * a phone number
    * an Active Directory host

For each target the simulator runs the REAL capabilities against a scripted,
offline runner and asks, in code:

  1. AUTO-MODE   : what does ``Planner.plan()`` chain toward the goal, and is
                   it actually executable (a planned step ready NOW) or just
                   optimistic (``complete=True`` with no live foothold)?
  2. GUIDED CORE : what does ``Planner.suggest_next()`` offer, one move at a
                   time (the in-run hint an operator would follow)?
  3. MANUAL CORE : what does the operator's own module surface put in their
                   hands (``phantom/modules/suggest.py`` groups, driven from
                   the SAME footprint the automaton found)?
  4. BEACON      : can the beacon EVER turn on, and through which gate —
                   valid credentials (``beacon_deploy``) or a confirmed RCE
                   foothold (``beacon_via_rce``)?

Nothing leaves the box: every shell answer is scripted; social capabilities
are fed the stable marker lines the SocialEngine emits.

Run: ``python scripts/coverage_matrix_sim.py``
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from unittest.mock import Mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from phantom.automation.belief import WorldModel          # noqa: E402
from phantom.automation.guidance.commands import make_registry, Registry  # noqa: E402
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine  # noqa: E402
from phantom.automation.planner import Planner            # noqa: E402

WIDTH = 78


# ─────────────────────────────────────────────────────────────────────────────
# scripted shell runner
# ─────────────────────────────────────────────────────────────────────────────

def make_runner(version_banner: str = "", port_banner: str = "",
                web_headers: str = "",
                extra: Optional[Dict[str, Tuple[bool, str]]] = None) -> Callable:
    """Scripted, offline answers for the shell tooling.

    ``extra`` is checked first: substring -> (ok, stdout). Everything else is
    routed by tool family so the SAME runner serves every scenario.
    """
    def runner(cmd: Any, timeout: Any = None) -> Mock:
        res = Mock()
        res.ok = False
        res.stdout = ""
        res.stderr = ""
        c = str(cmd)
        for needle, (ok, out) in (extra or {}).items():
            if needle in c:
                res.ok, res.stdout = ok, out
                return res
        versionish = any(t in c for t in ("-sV", "--version-intensity",
                                          "-sC", "-O", " --osscan"))
        if ("nmap" in c or "masscan" in c) and versionish:
            res.ok, res.stdout = True, version_banner
        elif "nmap" in c or "masscan" in c or c.startswith("nc "):
            res.ok, res.stdout = True, port_banner
        elif web_headers and any(t in c for t in ("curl", "httpx", "wget")):
            res.ok, res.stdout = True, web_headers
        return res
    return runner


def failing_runner(cmd: Any, timeout: Any = None) -> Mock:
    res = Mock()
    res.ok, res.stdout, res.stderr = False, "", ""
    return res


# ─────────────────────────────────────────────────────────────────────────────
# capability execution (offline)
# ─────────────────────────────────────────────────────────────────────────────

def run_cap(registry: Registry, wm: WorldModel, cap_id: str,
            slots: Optional[Dict[str, Any]] = None,
            runner: Optional[Callable] = None,
            output: Optional[str] = None,
            log: Optional[List[str]] = None) -> Tuple[str, Optional[str], List]:
    """Build -> (run | use scripted output) -> interpret one capability."""
    slots = dict(slots or {})
    cap = registry.get(cap_id)
    if cap is None:
        return cap_id, None, []
    cmd: Optional[str]
    if output is not None:
        cmd = "(scripted marker output)"
    else:
        try:
            cmd = cap.make_command(wm, slots)
        except Exception as exc:  # bad slots -> surface it, do not hide it
            return cap_id, f"<make_command failed: {exc}>", []
        if runner is None:
            return cap_id, cmd, []
        run = runner(cmd)
        if log is not None:
            log.append(str(cmd))
        output = run.stdout or ""
    findings = cap.interpret(output, wm, slots) or []
    for f in findings:
        try:
            wm.add_finding(f.kind, f.key, f.value,
                           confidence=getattr(f, "confidence", 0.6),
                           source=getattr(f, "source", cap_id))
        except Exception:
            pass
    return cap_id, cmd, findings


def clone_with(wm: WorldModel, extra_findings: List[Tuple]) -> WorldModel:
    """A copy of the world with simulated facts injected (for gate testing)."""
    clone = WorldModel.from_dict(wm.to_dict())
    for kind, key, value, conf in extra_findings:
        clone.add_finding(kind, key, value, confidence=conf, source="sim")
    return clone


# ─────────────────────────────────────────────────────────────────────────────
# scenarios
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Scenario:
    key: str
    title: str
    target: str
    target_type: str
    goal: str
    seeds: List[Dict[str, Any]] = field(default_factory=list)
    runner: Optional[Callable] = None
    manual_surface: bool = True
    notes: str = ""


WEB_HEADERS = ("HTTP/1.1 200 OK\n"
               "Server: nginx\n"
               "X-Powered-By: PHP/8.2\n"
               "Content-Type: text/html\n\n"
               "<html><head><title>App</title></head><body>ok</body></html>")

FRTX_HEADERS = ("HTTP/1.1 200 OK\n"
                "Server: FRTX/2.1\n"
                "X-Powered-By: FRTX-Appliance\n"
                "Content-Type: text/html\n\n"
                "<html><head><title>Fortress Admin</title></head>"
                "<body><script src=\"/internal/v2/_dash.js\"></script></body></html>")


def build_scenarios() -> List[Scenario]:
    S: List[Scenario] = []

    # 1 ── hardened web appliance: web only on a NON-standard port ----------- #
    S.append(Scenario(
        key="web_appliance",
        title="Web appliance, web on 8443 only (hidden RCE path)",
        target="10.13.37.9",
        target_type="ip",
        goal="complete_kill_chain",
        seeds=[
            {"cap": "scan_tcp"},
            {"cap": "version_detect"},
            {"cap": "http_probe", "slots": {"url": "https://10.13.37.9:8443/"},
             "output": FRTX_HEADERS},
        ],
        runner=make_runner(
            version_banner=("2222/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13\n"
                            "8443/tcp open  ssl/http FRTX-Admin 2.1"),
            port_banner=("2222/tcp open  ssh\n"
                         "8443/tcp open  ssl/https"),
            web_headers=FRTX_HEADERS,
            extra={"/upload": (True, "404 Not Found")},
        ),
        notes="Hidden RCE lives at /internal/v2/_dash, not /upload.",
    ))

    # 2 ── bare Windows device: SMB/RDP/DB only, NO web, NO ssh ------------- #
    S.append(Scenario(
        key="bare_windows_device",
        title="Bare Windows device (SMB/RDP/MySQL, no web, no ssh)",
        target="10.20.30.40",
        target_type="ip",
        goal="complete_kill_chain",
        seeds=[
            {"cap": "scan_tcp"},
            {"cap": "version_detect"},
        ],
        runner=make_runner(
            version_banner=("135/tcp  open  msrpc         Microsoft Windows RPC\n"
                            "445/tcp  open  microsoft-ds  Windows 10 Pro microsoft-ds\n"
                            "3306/tcp open  mysql         MySQL 8.0.36\n"
                            "3389/tcp open  ms-wbt-server Microsoft Terminal Services"),
            port_banner=("135/tcp  open  msrpc\n"
                         "445/tcp  open  microsoft-ds\n"
                         "3306/tcp open  mysql\n"
                         "3389/tcp open  ms-wbt-server"),
        ),
        notes="No ssh and no web: the classic 'nothing convenient open' box.",
    ))

    # 3 ── normal Linux server: ssh + web + db ------------------------------ #
    S.append(Scenario(
        key="linux_server",
        title="Normal Linux server (ssh + web + mysql + redis)",
        target="10.20.30.41",
        target_type="ip",
        goal="complete_kill_chain",
        seeds=[
            {"cap": "scan_tcp"},
            {"cap": "version_detect"},
            {"cap": "http_probe", "slots": {"url": "http://10.20.30.41/"},
             "output": WEB_HEADERS},
        ],
        runner=make_runner(
            version_banner=("22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6\n"
                            "80/tcp   open  http    nginx 1.24.0\n"
                            "3306/tcp open  mysql   MySQL 8.0.35\n"
                            "6379/tcp open  redis   Redis 7.2.4"),
            port_banner=("22/tcp   open  ssh\n"
                         "80/tcp   open  http\n"
                         "3306/tcp open  mysql\n"
                         "6379/tcp open  redis"),
            web_headers=WEB_HEADERS,
        ),
    ))

    # 4 ── domain, web-facing ----------------------------------------------- #
    S.append(Scenario(
        key="domain_web",
        title="Domain with a web front (corp.example.com)",
        target="corp.example.com",
        target_type="domain",
        goal="complete_kill_chain",
        seeds=[
            {"cap": "scan_tcp"},
            {"cap": "version_detect"},
            {"cap": "http_probe", "slots": {"url": "https://corp.example.com/"},
             "output": WEB_HEADERS},
        ],
        runner=make_runner(
            version_banner=("25/tcp  open  smtp      Postfix smtpd\n"
                            "443/tcp open  ssl/http  nginx 1.25.3"),
            port_banner=("25/tcp  open  smtp\n"
                         "443/tcp open  ssl/http"),
            web_headers=WEB_HEADERS,
        ),
    ))

    # 5 ── social username --------------------------------------------------- #
    S.append(Scenario(
        key="username_social",
        title="Social username (mario_rossi)",
        target="mario_rossi",
        target_type="username",
        goal="identity",
        seeds=[
            {"cap": "osint_identity",
             "output": ("IDENTITY: username=mario_rossi platform=instagram "
                        "url=https://instagram.com/mario_rossi")},
            {"cap": "profile_recon",
             "output": ("PROFILE: username=mario_rossi platform=instagram "
                        "private=0 bio=cyclist link=https://mario.example")},
        ],
        runner=failing_runner,
        notes="Identity chain: osint -> profile -> phish -> grabber -> victim_ip.",
    ))

    # 6 ── email identity ---------------------------------------------------- #
    S.append(Scenario(
        key="email_identity",
        title="Email identity (mario.rossi@example.com)",
        target="mario.rossi@example.com",
        target_type="email",
        goal="identity",
        seeds=[
            {"cap": "osint_identity",
             "output": ("IDENTITY: email=mario.rossi@example.com "
                        "platform=linkedin url=https://linkedin.com/in/mario-rossi")},
            {"cap": "breach_check",
             "output": ("BREACH: email=mario.rossi@example.com "
                        "password=hunter2 source=linkedin")},
        ],
        runner=failing_runner,
    ))

    # 7 ── phone identity ---------------------------------------------------- #
    S.append(Scenario(
        key="phone_identity",
        title="Phone number (+393331234567)",
        target="+393331234567",
        target_type="phone",
        goal="identity",
        seeds=[
            {"cap": "osint_identity",
             "output": ("IDENTITY: phone=+393331234567 carrier=Vodafone "
                        "region=IT")},
        ],
        runner=failing_runner,
    ))

    # 8 ── Active Directory host -------------------------------------------- #
    S.append(Scenario(
        key="ad_host",
        title="Active Directory host (LDAP/Kerberos/SMB)",
        target="10.20.30.50",
        target_type="ip",
        goal="complete_kill_chain",
        seeds=[
            {"cap": "scan_tcp"},
            {"cap": "version_detect"},
        ],
        runner=make_runner(
            version_banner=("88/tcp  open  kerberos-sec Microsoft Windows Kerberos\n"
                            "389/tcp open  ldap         Microsoft Windows AD LDAP\n"
                            "445/tcp open  microsoft-ds\n"
                            "636/tcp open  ssl/ldap     Microsoft Windows AD LDAP"),
            port_banner=("88/tcp  open  kerberos-sec\n"
                         "389/tcp open  ldap\n"
                         "445/tcp open  microsoft-ds\n"
                         "636/tcp open  ssl/ldap"),
        ),
    ))

    # 9 ── full URL target: the operator hands over a link, not a host ---- #
    # The scope gate authorizes a URL through its HOST, and every adapter
    # must normalize the URL back to a bare host before tooling. This
    # scenario pins that: a URL target gets the same footprint, the same
    # web gate and the same creds path as the bare-IP form of the same box.
    S.append(Scenario(
        key="url_target",
        title="URL target (https://10.13.37.9:8443/app)",
        target="https://10.13.37.9:8443/app",
        target_type="url",
        goal="complete_kill_chain",
        seeds=[
            {"cap": "scan_tcp"},
            {"cap": "version_detect"},
            {"cap": "http_probe",
             "slots": {"url": "https://10.13.37.9:8443/app"},
             "output": FRTX_HEADERS},
        ],
        runner=make_runner(
            version_banner=("8443/tcp open  ssl/http FRTX-Admin 2.1"),
            port_banner=("8443/tcp open  ssl/https"),
            web_headers=FRTX_HEADERS,
        ),
        notes="A URL target must normalize to its host and still fire the web gate.",
    ))
    return S


# ─────────────────────────────────────────────────────────────────────────────
# analysis
# ─────────────────────────────────────────────────────────────────────────────

def _ready_now(step, wm: WorldModel) -> bool:
    try:
        return all(p(wm) for p in step.capability.preconditions)
    except Exception:
        return False


def _web_triggers(wm: WorldModel) -> List[Tuple[str, str]]:
    """Services that actually make `_has_web_service()` fire, evaluated with
    the REAL gate so the reading can never drift from kit.py.

    Each finding is probed on its own: an `ssl/ldap` 636 is not web, an
    `ssl/http` on any port is, and `ssl` alone is web only on a web port."""
    from phantom.automation.guidance.kit import _has_web_service
    gate = _has_web_service()
    out = []
    for f in wm.find("service"):
        v = f.value if isinstance(f.value, dict) else {}
        probe = WorldModel(target=str(wm.target), target_type="ip")
        probe.add_finding("service", f.key, v, confidence=0.9, source="sim")
        try:
            is_web = gate(probe)
        except Exception:
            is_web = False
        if is_web:
            out.append((str(v.get("port", "?")),
                        str(v.get("service", "")).lower()))
    return out


def _creds_source_rows(registry: Registry, wm: WorldModel) -> Tuple[List[Tuple[str, str]], List[str]]:
    """Which `creds` producers the planner indexes, and their readiness.

    Returns (rows, unindexed): rows is (cap_id, READY|blocked) for every
    source in `_FACT_SOURCES["creds"]`; unindexed lists creds-producing
    capabilities the planner can NEVER reach (absent from the index).
    """
    from phantom.automation.planner import _FACT_SOURCES
    rows = []
    for cap_id in _FACT_SOURCES.get("creds", []):
        cap = registry.get(cap_id)
        if cap is None:
            rows.append((cap_id, "<missing>"))
            continue
        try:
            ready = all(p(wm) for p in cap.preconditions) if cap.preconditions else True
        except Exception:
            ready = False
        rows.append((cap_id, "READY" if ready else "blocked"))
    indexed = set(_FACT_SOURCES.get("creds", []))
    producers = [c.id for c in registry.all() if "creds" in c.effects]
    unindexed = [p for p in producers if p not in indexed]
    return rows, unindexed


def _beacon_gate_in_plan(plan) -> Tuple[bool, str]:
    ids = [s.capability.id for s in plan.steps]
    if "beacon_deploy" in ids:
        return True, "beacon_deploy (valid creds gate)"
    if "beacon_via_rce" in ids:
        return True, "beacon_via_rce (rce_foothold gate)"
    if any("beacon" in s.capability.effects for s in plan.steps):
        return True, "other beacon-effect source"
    return False, "no beacon step in plan"


def _seed_session_services(wm: WorldModel) -> None:
    """Mirror the WorldModel's services into the session so the MANUAL module
    suggestions react to the same footprint the automaton discovered."""
    from phantom.core.session import session
    services = []
    for f in wm.find("service"):
        v = f.value if isinstance(f.value, dict) else {}
        services.append({
            "port": str(v.get("port", "")),
            "proto": str(v.get("protocol", "tcp")),
            "service": str(v.get("service", "")).lower(),
            "product": str(v.get("product", "")),
            "version": str(v.get("version", "")),
        })
    if services:
        session.add_result("service_summary", services)


def _manual_module_groups() -> Dict[str, List[str]]:
    """The operator's own module surface, state-aware (suggest.py)."""
    groups: Dict[str, List[str]] = {}
    try:
        from phantom.modules import suggest as sug
        layers = [
            sug.first_steps_suggestion_group,
            sug.service_suggestion_group,
            sug.osint_suggestion_group,
            sug.web_suggestion_group,
            sug.brute_suggestion_group,
        ]
        for fn in layers:
            try:
                for k, cmds in (fn() or {}).items():
                    groups.setdefault(k, []).extend(cmds or [])
            except Exception:
                continue
    except Exception:
        pass
    return groups


def analyze(scn: Scenario, registry: Registry) -> Dict[str, Any]:
    from phantom.core.session import session
    from phantom.core import knowledge

    wm = WorldModel(target=scn.target, target_type=scn.target_type)
    log: List[str] = []

    print("=" * WIDTH)
    print(f"SCENARIO  {scn.key}  —  {scn.title}")
    print(f"target={scn.target}  type={scn.target_type}  goal={scn.goal}")
    print("=" * WIDTH)
    if scn.notes:
        print(f"  note: {scn.notes}")

    # ── seed the footprint through the REAL capabilities ───────────────────
    for seed in scn.seeds:
        cap_id, cmd, findings = run_cap(
            registry, wm, seed["cap"], seed.get("slots"),
            runner=scn.runner, output=seed.get("output"), log=log)
        kinds = ", ".join(sorted({f.kind for f in findings})) or "none"
        print(f"  [seed] {cap_id:16} -> {len(findings)} finding(s) [{kinds}]")
        if cmd and cmd != "(scripted marker output)":
            print(f"          cmd: {cmd}")

    svc = wm.find("service")
    print("  footprint:")
    for f in svc:
        v = f.value if isinstance(f.value, dict) else {}
        print(f"      {v.get('port', '?'):>6}/tcp  {v.get('service', ''):<14} "
              f"{str(v.get('version', ''))[:40]}")
    if not svc:
        print(f"      (no services — {len(wm.find('identity'))} identity finding(s), "
              f"{len(wm.find('profile'))} profile finding(s))")

    # ── planner ─────────────────────────────────────────────────────────────
    stealth = StealthEngine(wm, StealthConfig())
    planner = Planner(registry, stealth)

    result: Dict[str, Any] = {"key": scn.key, "title": scn.title}

    # AUTO plan toward the scenario goal
    print("\n  AUTO-MODE  plan(goal=%r):" % scn.goal)
    plan = planner.plan(wm, goal=scn.goal)
    print(f"      complete={plan.complete}  steps={len(plan.steps)}"
          + (f"  blocked={plan.blocked_reason!r}" if plan.blocked_reason else ""))
    for i, s in enumerate(plan.steps[:8], 1):
        ready = "READY" if _ready_now(s, wm) else "needs-facts"
        print(f"      {i}. {s.capability.id:20} [{s.capability.exec_class:17}] "
              f"{ready}  — {s.reason}")
    if len(plan.steps) > 8:
        print(f"      ... {len(plan.steps) - 8} more")
    auto_ready = any(_ready_now(s, wm) for s in plan.steps)
    result["auto_plan_steps"] = len(plan.steps)
    result["auto_has_ready_move"] = auto_ready
    result["auto_complete"] = plan.complete

    # AUTO full kill chain (always, for the beacon question)
    chain = planner.plan(wm, goal="complete_kill_chain")
    beacon_ok, beacon_how = _beacon_gate_in_plan(chain)
    result["auto_chain_complete"] = chain.complete
    result["auto_chain_has_beacon"] = beacon_ok

    # AUTO creds goal
    creds_plan = planner.plan(wm, goal="creds")
    result["auto_creds_steps"] = len(creds_plan.steps)

    # ── creds reachability: the honesty check behind every 'complete' plan ──
    rows, unindexed = _creds_source_rows(registry, wm)
    ready_creds = [c for c, st in rows if st == "READY"]
    print("\n  CREDS SOURCES  (the gate beacon_deploy needs):")
    for cap_id, status in rows:
        print(f"      {cap_id:18} {status}")
    if unindexed:
        print(f"      !! creds producers the planner CANNOT reach: {unindexed}")
    result["creds_sources_ready"] = bool(ready_creds)
    trig = _web_triggers(wm)
    if "web_creds" in [c for c, _ in rows]:
        print(f"      web-service triggers (what makes web_creds 'ready'): {trig}")
    result["web_triggers"] = trig

    # ── GUIDED core (one move at a time) ───────────────────────────────────
    print("\n  GUIDED CORE  suggest_next(goal=%r):" % scn.goal)
    guided = 0
    step = planner.suggest_next(wm, goal=scn.goal)
    if step is None:
        print("      <no suggestion — the goal fact has no ready source>")
    else:
        guided = 1
        print(f"      {step.capability.id} ({step.capability.exec_class})")
    result["guided_hint"] = guided

    # ── MANUAL module surface ──────────────────────────────────────────────
    print("\n  MANUAL CORE  module suggestions (suggest.py):")
    session.target = scn.target
    session.results = {}
    session.knowledge_base["target_type"] = scn.target_type
    knowledge.reset_wm(scn.target, scn.target_type)
    for f in wm.all_findings():
        knowledge.session_wm().add_finding(f.kind, f.key, f.value,
                                           confidence=f.confidence,
                                           source=f.source)
    _seed_session_services(wm)
    groups = _manual_module_groups()
    total = sum(len(v) for v in groups.values())
    result["manual_suggestion_count"] = total
    for g in list(groups)[:6]:
        print(f"      -- {g} ({len(groups[g])})")
        for c in groups[g][:2]:
            print(f"           {c}")

    # ── BEACON reachability ────────────────────────────────────────────────
    print("\n  BEACON reachability:")
    print(f"      natural chain: {'YES' if beacon_ok else 'NO'} "
          f"({beacon_how if beacon_ok else 'there is no source at all'})")

    creds_wm = clone_with(wm, [
        ("creds", "sim:valid", {"username": "admin", "password": "S3cret!",
                                "valid": True, "service": "ssh"}, 0.9)])
    p_creds = Planner(registry, StealthEngine(creds_wm, StealthConfig())).plan(
        creds_wm, goal="complete_kill_chain")
    ok_creds, how_creds = _beacon_gate_in_plan(p_creds)
    print(f"      +valid creds  -> beacon: {'YES' if ok_creds else 'NO'} "
          f"({how_creds})")

    rce_wm = clone_with(wm, [
        ("rce_foothold", "sim", {"vector": "web_upload", "uid": "0"}, 0.9)])
    p_rce = Planner(registry, StealthEngine(rce_wm, StealthConfig())).plan(
        rce_wm, goal="complete_kill_chain")
    ok_rce, how_rce = _beacon_gate_in_plan(p_rce)
    print(f"      +rce_foothold -> beacon: {'YES' if ok_rce else 'NO'} "
          f"({how_rce})")
    result["beacon_with_creds"] = ok_creds
    result["beacon_with_rce"] = ok_rce

    # ── identity convergence (identity scenarios only) ─────────────────────
    if scn.target_type in ("username", "email", "phone"):
        conv = clone_with(wm, [
            ("phish", "sim", {"to": scn.target, "channel": "email",
                              "link": "https://grab.test/x"}, 0.9),
            ("victim_ip", "203.0.113.7", {"ip": "203.0.113.7"}, 0.9)])
        usable = [c.id for c in registry.usable(conv)]
        network_move = [i for i in usable
                        if i in ("scan_tcp", "version_detect", "curl_probe")]
        p_conv = Planner(registry, StealthEngine(conv, StealthConfig())).plan(
            conv, goal="complete_kill_chain")
        ids = [s.capability.id for s in p_conv.steps]
        print("\n  IDENTITY CONVERGENCE  (after phish click -> victim_ip):")
        print(f"      network move AVAILABLE now: {network_move or 'none'}")
        print(f"      beacon plan steps: {ids[:8]}")
        result["identity_converges"] = bool(network_move)

        # realistic harvest: the grabber also returned an UNVALIDATED pair
        harvest = clone_with(wm, [
            ("phish", "sim", {"to": scn.target, "channel": "email",
                              "link": "https://grab.test/x"}, 0.9),
            ("victim_ip", "203.0.113.7", {"ip": "203.0.113.7"}, 0.9),
            ("creds", "phish:mario", {"username": "mario",
                                       "password": "hunter2", "valid": False,
                                       "service": "harvest"}, 0.8)])
        p_h = Planner(registry, StealthEngine(harvest, StealthConfig())).plan(
            harvest, goal="complete_kill_chain")
        h_ids = [s.capability.id for s in p_h.steps]
        print(f"      harvest(valid=False) plan steps: {h_ids[:8]}")
        result["identity_validated_creds"] = any(
            i in ("cred_spray", "ssh_login", "web_creds") for i in h_ids)

    print()
    return result


def main() -> int:
    print("#" * WIDTH)
    print("# PHANTOM COVERAGE MATRIX — offline (scripted runner, no packets)")
    print("# auto-mode  vs  guided core  vs  manual module surface  vs  beacon")
    print("#" * WIDTH + "\n")

    registry = make_registry()
    results = []
    for scn in build_scenarios():
        try:
            results.append(analyze(scn, registry))
        except Exception as exc:  # one bad scenario must not kill the matrix
            import traceback
            print(f"!! scenario {scn.key} crashed: {exc}")
            traceback.print_exc()
            results.append({"key": scn.key, "title": scn.title, "error": str(exc)})

    # ── matrix ─────────────────────────────────────────────────────────────
    print("#" * WIDTH)
    print("# COVERAGE MATRIX")
    print("#" * WIDTH)
    hdr = (f"{'scenario':22} {'plan':>4} {'ready':>5} {'creds':>5} "
           f"{'chain':>5} {'beacon':>6} {'+crds':>5} {'+rce':>5} "
           f"{'manual':>6} {'guided':>6}")
    print(hdr)
    print("-" * len(hdr))
    for r in results:
        if "error" in r:
            print(f"{r['key']:22} ERROR: {r['error'][:48]}")
            continue
        print(f"{r['key']:22} "
              f"{r.get('auto_plan_steps', 0):>4} "
              f"{('Y' if r.get('auto_has_ready_move') else 'n'):>5} "
              f"{('Y' if r.get('creds_sources_ready') else 'n'):>5} "
              f"{('Y' if r.get('auto_chain_complete') else 'n'):>5} "
              f"{('Y' if r.get('auto_chain_has_beacon') else 'n'):>6} "
              f"{('Y' if r.get('beacon_with_creds') else 'n'):>5} "
              f"{('Y' if r.get('beacon_with_rce') else 'n'):>5} "
              f"{r.get('manual_suggestion_count', 0):>6} "
              f"{r.get('guided_hint', 0):>6}")
    print("-" * len(hdr))
    print("legend: plan=steps toward goal  ready=a planned step runnable NOW")
    print("        creds=a creds source is usable from the live footprint")
    print("        chain=complete_kill_chain complete  beacon=beacon in plan")
    print("        +crds/+rce=beacon reachable with creds / rce_foothold")
    print("        manual=module suggestions  guided=suggest_next hint")
    print()
    print("READING: chain/beacon=Y with creds=n is the planner being OPTIMISTIC")
    print("(it lists a creds source whose precondition can never fire here).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
