"""netmap.py — pre-engagement network mapping.

`discover_network()` finds live hosts on the local network (or around a
target CIDR) using whatever is available (arp-scan → nmap -sn → ping
sweep). Every found host is written into the SHARED WorldModel as a
`host` finding, so the Electron network map (/api/network-map) and the
auto-mode planner both see the full network before a target is chosen.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional


def _run(cmd: List[str], timeout: float = 60.0) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        return (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception:
        return ""


def _local_cidrs() -> List[str]:
    """Best-effort list of local subnets (IPv4) to sweep."""
    cidrs: List[str] = []
    try:
        import socket
        host = socket.gethostbyname(socket.gethostname())
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            # assume a /24 around the interface IP
            cidrs.append(str(ipaddress.ip_network(f"{host}/24", strict=False)))
    except Exception:
        pass
    if not cidrs:
        cidrs.append("192.168.1.0/24")
    return cidrs


def _parse_arp_scan(text: str) -> List[Dict[str, str]]:
    hosts: List[Dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and _is_ip(parts[0]):
            hosts.append({
                "ip": parts[0],
                "mac": parts[1] if len(parts) > 1 and ":" in parts[1] else "",
                "vendor": " ".join(parts[2:]) if len(parts) > 2 else "",
            })
    return hosts


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _parse_nmap_sn(text: str) -> List[Dict[str, str]]:
    hosts: List[Dict[str, str]] = []
    cur: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Nmap scan report for"):
            if cur:
                hosts.append(cur)
            rest = line.split("for", 1)[1].strip()
            cur = {"ip": rest, "hostname": ""}
            if " (" in rest:
                cur["hostname"] = rest.split(" (")[0]
                cur["ip"] = rest.split("(")[1].rstrip(")")
        elif "MAC Address:" in line:
            mac = line.split("MAC Address:", 1)[1].strip()
            cur["mac"] = mac.split(" (")[0] if " (" in mac else mac
            if " (" in mac:
                cur["vendor"] = mac.split("(", 1)[1].rstrip(")")
    if cur:
        hosts.append(cur)
    return hosts


def _ping_sweep(cidr: str, timeout: float = 45.0) -> List[Dict[str, str]]:
    """Last-resort ICMP sweep (no nmap/arp-scan).

    Runs pings in parallel worker threads (bounded concurrency) with a short
    per-host timeout so a sweep of a /24 completes in a few seconds instead
    of minutes. Never blocks longer than `timeout` overall.
    """
    hosts: List[Dict[str, str]] = []
    try:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import platform

        net = ipaddress.ip_network(cidr, strict=False)
        addrs = list(net.hosts())[:254]
        ping = shutil.which("ping")
        if not ping or not addrs:
            return hosts
        is_win = "win" in platform.system().lower()

        def _one(ip_s) -> Optional[str]:
            try:
                cmd = [ping, "-n", "1", "-w", "800", str(ip_s)] if is_win \
                    else [ping, "-c", "1", "-W", "1", str(ip_s)]
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=2)
                return str(ip_s) if proc.returncode == 0 else None
            except Exception:
                return None

        deadline = time.time() + timeout
        with ThreadPoolExecutor(max_workers=24) as pool:
            futs = {pool.submit(_one, a): a for a in addrs}
            for fut in as_completed(futs, timeout=max(1.0, timeout)):
                if time.time() > deadline:
                    break
                ip_s = fut.result()
                if ip_s:
                    hosts.append({"ip": ip_s})
    except Exception:
        pass
    return hosts


_LAST_SCAN: Dict[str, Any] = {}

# ── Persistent device store ───────────────────────────────────────────────────
# Discovered devices must SURVIVE target changes and app restarts — they are
# network facts, not engagement facts. The WorldModel is per-engagement and
# reset on target change, so the map keeps a small JSON side-store that is
# re-seeded into the WM whenever needed.

import json as _json


def _hosts_store_path() -> str:
    try:
        from phantom.utils.paths import data_dir
        return os.path.join(data_dir(), "network_hosts.json")
    except Exception:
        return ""


def save_discovered_hosts(hosts: List[Dict[str, str]]) -> None:
    """Persist discovered devices to disk (merge by IP, newest wins)."""
    path = _hosts_store_path()
    if not path:
        return
    try:
        existing: Dict[str, Dict[str, str]] = {}
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for h in _json.load(f) or []:
                    if isinstance(h, dict) and h.get("ip"):
                        existing[h["ip"]] = h
        for h in hosts:
            if h.get("ip"):
                merged = dict(existing.get(h["ip"], {}))
                merged.update({k: v for k, v in h.items() if v})
                existing[h["ip"]] = merged
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            _json.dump(list(existing.values()), f, indent=2)
    except Exception:
        pass


def load_discovered_hosts() -> List[Dict[str, str]]:
    """Return previously discovered devices from disk (empty if none)."""
    path = _hosts_store_path()
    if not path:
        return []
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return [h for h in _json.load(f) or []
                        if isinstance(h, dict) and h.get("ip")]
    except Exception:
        pass
    return []


def reseed_known_hosts() -> int:
    """Re-seed persisted devices into the (possibly reset) WorldModel."""
    return seed_worldmodel(load_discovered_hosts(), source="netmap")



# ---------------------------------------------------------------------------
# Host enrichment — turn bare IPs into identified devices (no more "unknown")
# ---------------------------------------------------------------------------

def _arp_table() -> Dict[str, Dict[str, str]]:
    """Parse the system ARP cache: {ip: {mac, vendor}}."""
    out: Dict[str, Dict[str, str]] = {}
    text = _run(["arp", "-a"]) if shutil.which("arp") else ""
    if not text:
        text = _run(["ip", "neigh"])  # Linux fallback
    for line in text.splitlines():
        line = line.strip()
        if (not line or line.startswith("Interface")
                or line.lower().startswith("internet address")):
            continue
        parts = line.split()
        ip = mac = ""
        for p in parts:
            bare = p.strip("()").rstrip(":")
            if _is_ip(bare):
                ip = bare
            else:
                norm = p.lower().replace("-", ":")
                if ":" in norm and len(norm.split(":")) == 6 and all(
                        len(h) in (1, 2) for h in norm.split(":")):
                    mac = norm
        if ip and (mac or len(parts) >= 2):
            # skip multicast / broadcast / link-local noise (224.0.0.x,
            # 239.x, 255.255.255.255) — they are not real devices
            try:
                first = int(ip.split(".")[0])
                if first in (224, 239, 255) or ip == "255.255.255.255":
                    continue
            except Exception:
                pass
            out[ip] = {"mac": mac, "vendor": _mac_vendor(mac) if mac else ""}
    return out


_MAC_PREFIXES = {
    "00:1a:11": "Google", "00:50:56": "VMware", "00:0c:29": "VMware",
    "00:05:69": "VMware", "00:1c:14": "VMware", "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM", "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "00:1b:63": "Apple", "ac:de:48": "Apple",
    "f0:18:98": "Apple", "3c:22:fb": "Apple", "a4:83:e7": "Apple",
    "d0:03:4b": "Apple", "00:17:88": "Philips Hue", "00:17:e2": "Cisco",
    "00:1a:a1": "Cisco", "00:1b:0c": "Cisco", "00:21:1b": "Cisco",
    "00:23:04": "Cisco", "00:24:14": "Cisco", "00:26:0c": "Cisco",
    "00:00:0c": "Cisco", "00:1d:7e": "Cisco", "00:26:99": "Cisco",
    "58:97:1e": "Cisco", "64:d8:14": "TP-Link", "50:c7:bf": "TP-Link",
    "ac:84:c6": "TP-Link", "c0:25:e9": "TP-Link", "94:d9:b3": "Xiaomi",
    "f0:b4:29": "Xiaomi", "74:23:44": "Xiaomi", "78:11:dc": "Xiaomi",
    "64:09:80": "Xiaomi", "00:9e:c8": "Xiaomi", "f4:f5:d8": "Xiaomi",
    "00:1d:7f": "Huawei", "34:6b:d3": "Huawei", "78:1d:ba": "Huawei",
    "b4:15:00": "Huawei", "e8:cd:2d": "Huawei", "c8:d7:19": "Huawei",
    "40:9f:38": "AzureWave (WiFi module)", "00:e0:4c": "Realtek",
    "52:55:c0": "Generic (virtual)", "00:15:5d": "Microsoft (Hyper-V/WSL)",
}


def _mac_vendor(mac: str) -> str:
    m = (mac or "").lower().replace("-", ":")
    if not m or m.count(":") != 5:
        return ""
    first = int(m.split(":")[0], 16)
    if first & 0x02:
        # locally-administered bit set: randomized MAC (modern phones,
        # Windows, IoT privacy) — that fact itself is a device hint
        return "Randomized (privacy MAC)"
    for prefix, vendor in _MAC_PREFIXES.items():
        if m.startswith(prefix):
            return vendor
    return ""


def _reverse_dns(ip: str, timeout: float = 1.5) -> str:
    """Best-effort reverse DNS / NetBIOS name for a host."""
    import socket
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        # drop the trailing local suffix Windows adds ("pc.localdomain")
        return name.split(".")[0] if name and "." in name else (name or "")
    except Exception:
        pass
    if shutil.which("nbtstat"):
        out = _run(["nbtstat", "-A", ip], timeout=4)
        for line in out.splitlines():
            if "<00>" in line and "UNIQUE" in line.upper():
                name = line.split("<00>")[0].strip()
                if name and not name.startswith("MAC"):
                    return name
    return ""


def _enrich_hosts(hosts: List[Dict[str, str]], timeout: float = 12.0) -> None:
    """Fill in hostname / mac / vendor for discovered hosts (in place).

    Bounded by `timeout` overall so a dead network never stalls the scan.
    """
    if not hosts:
        return
    try:
        from concurrent.futures import ThreadPoolExecutor
        arp = _arp_table()
        deadline = time.time() + timeout

        def _one(h: Dict[str, str]) -> None:
            if time.time() > deadline:
                return
            ip = h.get("ip", "")
            if not ip:
                return
            info = arp.get(ip, {})
            if info.get("mac") and not h.get("mac"):
                h["mac"] = info["mac"]
            if info.get("vendor") and not h.get("vendor"):
                h["vendor"] = info["vendor"]
            elif h.get("mac") and not h.get("vendor"):
                h["vendor"] = _mac_vendor(h["mac"])
            if not h.get("hostname"):
                name = _reverse_dns(ip)
                if name:
                    h["hostname"] = name

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(_one, hosts))
    except Exception:
        pass


def discover_network(target: Optional[str] = None,
                     timeout: float = 90.0) -> Dict[str, Any]:
    """Discover live hosts. `target` may be a CIDR (sweep that) or None
    (sweep the local subnets). Returns {cidrs, hosts, method, elapsed}.

    Results are cached for 60s so repeated UI polls don't re-scan the
    network on every request.
    """
    cache_key = target or "<local>"
    if _LAST_SCAN.get("key") == cache_key and \
            time.time() - _LAST_SCAN.get("at", 0) < 60:
        return dict(_LAST_SCAN.get("data", {}))
    started = time.time()
    if target and "/" in target:
        try:
            cidrs = [str(ipaddress.ip_network(target, strict=False))]
        except ValueError:
            cidrs = _local_cidrs()
    else:
        cidrs = _local_cidrs()

    hosts: List[Dict[str, str]] = []
    method = ""
    arp_scan = shutil.which("arp-scan")
    nmap = shutil.which("nmap")

    for cidr in cidrs:
        if arp_scan and not hosts:
            out = _run([arp_scan, "--localnet"], timeout=timeout)
            hosts = _parse_arp_scan(out)
            method = "arp-scan" if hosts else ""
        if nmap and not hosts:
            out = _run([nmap, "-sn", "-PR", cidr], timeout=timeout)
            hosts = _parse_nmap_sn(out)
            method = "nmap -sn" if hosts else ""
        if not hosts:
            hosts = _ping_sweep(cidr, timeout=timeout)
            method = "ping sweep" if hosts else method

    # dedupe by IP
    seen: set = set()
    unique: List[Dict[str, str]] = []
    for h in hosts:
        ip = h.get("ip", "")
        if ip and ip not in seen:
            seen.add(ip)
            unique.append(h)

    # identify devices: ARP cache, MAC vendor lookup, reverse DNS / NetBIOS
    _enrich_hosts(unique, timeout=min(12.0, max(4.0, timeout / 4)))
    # fingerprint each device a little deeper: quick TCP probe of the top
    # service ports (so every card shows WHAT is listening) + an OS guess
    _quick_probe_hosts(unique, timeout=min(15.0, max(6.0, timeout / 5)))
    for h in unique:
        v = _mac_vendor(h.get("mac", ""))
        if v and not h.get("vendor"):
            h["vendor"] = v
        # a device without a hostname is what the UI renders as "unknown" —
        # fall back to vendor, then a readable label, never a bare "unknown"
        if not h.get("hostname"):
            if h.get("vendor"):
                h["hostname"] = h["vendor"]
            else:
                h["hostname"] = f"host-{h['ip'].rsplit('.', 1)[-1]}"

    result = {"cidrs": cidrs, "hosts": unique, "method": method or "none",
              "elapsed": round(time.time() - started, 1),
              "topology": detect_topology(unique)}
    _LAST_SCAN["key"] = cache_key
    _LAST_SCAN["at"] = time.time()
    _LAST_SCAN["data"] = result
    # persist so the map and planner see these devices even after a target
    # change (WM reset) or an app restart
    save_discovered_hosts(unique)
    return result


def _quick_probe_hosts(hosts: List[Dict[str, Any]], timeout: float = 15.0) -> None:
    """Give every discovered device a small fingerprint so the map shows
    WHAT a device is, not just that it exists: top service ports probed
    (TCP connect), a one-shot service banner from the highest-value port,
    and an OS guess from the port set + banner.

    Bounded overall by `timeout`; failures are silently tolerated — this is
    enrichment, not a gate.
    """
    if not hosts:
        return
    # a focused subset: the ports that identify a device type fastest
    probe = [53, 80, 443, 445, 139, 22, 23, 21, 3389, 5900, 8080, 8443,
             8009, 3306, 6379, 5555, 5353, 1900, 500, 4500, 161]
    try:
        from concurrent.futures import ThreadPoolExecutor
        deadline = time.time() + timeout

        def _one(h: Dict[str, Any]) -> None:
            if time.time() > deadline:
                return
            ip = h.get("ip", "")
            if not ip:
                return
            open_ports = _probe_ports(ip, probe, per_port=0.45, workers=16)
            if open_ports:
                h["ports"] = open_ports
                h["services"] = ", ".join(
                    _SERVICE_NAMES.get(p, f"tcp/{p}") for p in open_ports[:6])
                # one banner grab on the most identifying port
                banner = ""
                try:
                    best = max(open_ports,
                               key=lambda p: 1 + _RISK_WEIGHT.get(p, 0))
                    with socket.create_connection((ip, best), timeout=1.2) as s:
                        s.settimeout(1.2)
                        banner = (s.recv(120) or b"").decode(
                            "utf-8", errors="replace").strip()
                except Exception:
                    banner = ""
                if banner:
                    h["banner"] = banner[:80]
                h["os_guess"] = _guess_os(open_ports, banner)

        with ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(_one, hosts))
    except Exception:
        pass


def _guess_os(open_ports: List[int], banner: str = "") -> str:
    """Coarse OS guess from the open-port fingerprint + banner."""
    b = (banner or "").lower()
    if "windows" in b or "microsoft" in b or "iis" in b:
        return "Windows"
    if "linux" in b or "ubuntu" in b or "debian" in b or "openssh" in b:
        return "Linux"
    if "darwin" in b or "macos" in b:
        return "macOS"
    if "android" in b or "adb" in b:
        return "Android"
    if "ios" in b or "airplay" in b or "raop" in b:
        return "iOS"
    ports = set(open_ports or [])
    if ports & {3389, 135, 139, 445, 5985}:
        return "Windows (likely)"
    if ports & {22, 111, 2049} and not ports & {135, 139, 445}:
        return "Linux (likely)"
    if ports & {1900, 500, 4500, 53} and len(ports) <= 4:
        return "Router/IoT firmware"
    return ""


def detect_topology(hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Infer the LAN shape from the discovered device set.

    Heuristics (all cheap, no extra packets):
    * gateway present + many hosts with few inter-host ports  → STAR
    * many hosts exposing SMB/445 to each other               → FLAT/BROADCAST
    * a single uplink device with everything behind it and
      few directly open hosts                                 → TREE (routed)
    """
    if not hosts:
        return {"kind": "unknown", "gateway": "", "confidence": 0.0,
                "note": "no devices discovered yet"}
    ips = [h.get("ip", "") for h in hosts if h.get("ip")]
    # find the likely gateway: .1/.254 of the subnet, or anything whose
    # hostname/vendor says router/modem/gateway
    gw = ""
    for h in hosts:
        blob = f"{h.get('hostname', '')} {h.get('vendor', '')}".lower()
        if any(k in blob for k in ("modem", "router", "gateway", "fibra",
                                   "tim", "vodafone", "wind", "fastweb")):
            gw = h.get("ip", "")
            break
    if not gw:
        try:
            import ipaddress as _ip
            nets = {_ip.ip_network(f"{ip}/24", strict=False) for ip in ips}
            for net in nets:
                for cand in (str(net.network_address + 1),
                             str(net.broadcast_address - 1)):
                    if cand in ips:
                        gw = cand
                        break
                if gw:
                    break
        except Exception:
            pass
    # how many hosts expose SMB/RPC (a flat/broadcast LAN signature)?
    smb_hosts = 0
    for h in hosts:
        ports = h.get("ports") or []
        if isinstance(ports, list) and (445 in ports or 139 in ports):
            smb_hosts += 1
    n = len(ips)
    if gw and n >= 4 and smb_hosts <= 1:
        kind, conf = "star", 0.75
        note = (f"{n} devices behind a single gateway ({gw}) with no "
                f"inter-host SMB — switched star topology")
    elif smb_hosts >= 3 and smb_hosts >= n * 0.4:
        kind, conf = "broadcast", 0.7
        note = (f"{smb_hosts}/{n} devices expose SMB/NetBIOS — flat "
                f"broadcast segment (host-to-host reachable)")
    elif gw and n >= 6:
        kind, conf = "tree", 0.6
        note = (f"{n} devices behind {gw} — routed/tree segments likely "
                f"(multiple subnets or VLANs)")
    else:
        kind, conf = "star", 0.5
        note = f"small LAN ({n} devices) — default star assumption around {gw or 'the gateway'}"
    return {"kind": kind, "gateway": gw, "confidence": conf, "note": note}


def seed_worldmodel(hosts: List[Dict[str, str]], source: str = "netmap") -> int:
    """Write discovered hosts into the shared WorldModel as host findings so
    the Electron map and the planner see them. Returns count written."""
    if not hosts:
        return 0
    try:
        from phantom.core.knowledge import session_wm
        wm = session_wm()
    except Exception:
        return 0
    count = 0
    for h in hosts:
        ip = h.get("ip", "")
        if not ip:
            continue
        try:
            detail = ", ".join(p for p in (
                h.get("hostname"), h.get("vendor"), h.get("os_guess")) if p)
            wm.add_finding(kind="host", key=ip,
                           value={"ip": ip, "mac": h.get("mac", ""),
                                  "vendor": h.get("vendor", ""),
                                  "hostname": h.get("hostname", ""),
                                  "os": h.get("os_guess", ""),
                                  "ports": h.get("ports", []),
                                  "services": h.get("services", ""),
                                  "detail": detail},
                           confidence=0.8, source=source, target=ip)
            count += 1
        except Exception:
            pass
    return count


# ---------------------------------------------------------------------------
# Exposure ranking — "which device is the weakest / best place to start?"
# ---------------------------------------------------------------------------
# A quick parallel TCP-connect probe of common service ports on every
# discovered device. No banners, no version detection — just what is
# reachable and how dangerous the service class is. Weighted score:
#   base 1 per open port + extra weight for high-risk services (SMB, RDP,
#   Telnet, Redis, Mongo, Docker, ADB, WebLogic, ...).

_COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    512, 513, 514, 636, 873, 1080, 1098, 1099, 1433, 1521, 2049, 2222,
    2375, 2376, 3000, 3306, 3389, 4243, 4848, 5000, 5037, 5432, 5555,
    5900, 5985, 5986, 61616, 6379, 7000, 7001, 7070, 8000, 8009, 8080,
    8081, 8443, 8888, 9000, 9090, 9200, 9443, 10000, 11211, 27017, 49152,
]

# high-risk service classes → extra score weight
_RISK_WEIGHT = {
    23: 3, 445: 3, 3389: 3, 2375: 3, 2376: 3, 5555: 3, 7001: 3,
    1099: 3, 1098: 3, 61616: 3, 3306: 2, 5432: 2, 6379: 2, 27017: 2,
    9200: 2, 11211: 2, 5900: 2, 5985: 2, 5986: 2, 1433: 2, 1521: 2,
    389: 2, 636: 2, 5037: 2, 8009: 2, 873: 2, 22: 1, 21: 1, 161: 1,
}

_SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    512: "rexec", 513: "rlogin", 514: "rsh", 636: "ldaps", 873: "rsync",
    1080: "socks", 1098: "rmi-registry", 1099: "rmi", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2222: "ssh-alt", 2375: "docker",
    2376: "docker-tls", 3000: "http-alt", 3306: "mysql", 3389: "rdp",
    4243: "docker", 4848: "glassfish", 5000: "http-alt", 5037: "adb",
    5432: "postgres", 5555: "adb", 5900: "vnc", 5985: "winrm",
    5986: "winrm-tls", 61616: "activemq", 6379: "redis", 7000: "cassandra",
    7001: "weblogic", 7070: "http-alt", 8000: "http-alt", 8009: "ajp",
    8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9090: "http-alt", 9200: "elasticsearch",
    9443: "https-alt", 10000: "webmin", 11211: "memcached",
    27017: "mongodb", 49152: "ephemeral",
}


def _probe_ports(ip: str, ports: List[int], per_port: float = 0.6,
                 workers: int = 24) -> List[int]:
    """Parallel TCP-connect probe. Returns the list of open ports."""
    open_ports: List[int] = []
    try:
        import socket as _socket
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _one(port: int) -> Optional[int]:
            try:
                with _socket.create_connection((ip, port), timeout=per_port):
                    return port
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_one, p): p for p in ports}
            for fut in as_completed(futs, timeout=max(5.0, per_port * 4)):
                p = fut.result()
                if p:
                    open_ports.append(p)
    except Exception:
        pass
    return sorted(open_ports)


def rank_hosts_exposure(hosts: List[Dict[str, Any]],
                       ports: Optional[List[int]] = None,
                       timeout: float = 40.0) -> List[Dict[str, Any]]:
    """Score every discovered device by reachable attack surface.

    Returns devices sorted by exposure (most exposed first), each with
    `score`, `open_ports` (port + service) and a `risk` label. Safe: pure
    TCP connect, bounded per-port timeout, parallel across hosts, never
    blocks longer than `timeout` total.
    """
    if not hosts:
        return []
    port_list = ports or _COMMON_PORTS
    results: List[Dict[str, Any]] = []
    deadline = time.time() + timeout
    try:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        # skip the local machine itself (it will usually have the most
        # open ports and is not a real target)
        local_ips: set = {"127.0.0.1", "::1"}
        try:
            import socket as _socket
            local_ips.add(_socket.gethostbyname(_socket.gethostname()))
            local_ips.add(_socket.gethostbyname_ex(_socket.gethostname())[2][0])
        except Exception:
            pass

        def _assess(h: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            ip = h.get("ip", "")
            if not ip or ip in local_ips:
                return None
            open_ports = _probe_ports(ip, port_list)
            if not open_ports:
                return None
            # grab a short service banner from the highest-risk open port so
            # the ranking can consider WHAT is listening, not just how many
            # ports (a router with 5 trivial admin ports is not automatically
            # weaker than a PC with one stale SMB listening)
            banner_probe = ""
            try:
                best_p = max(open_ports,
                             key=lambda p: 1 + _RISK_WEIGHT.get(p, 0))
                with socket.create_connection((ip, best_p), timeout=1.5) as s:
                    s.settimeout(1.5)
                    banner_probe = (s.recv(120) or b"").decode(
                        "utf-8", errors="replace").strip()
            except Exception:
                banner_probe = ""
            score = 0
            details: List[Dict[str, Any]] = []
            for p in open_ports:
                w = 1 + _RISK_WEIGHT.get(p, 0)
                score += w
                details.append({"port": p,
                                "service": _SERVICE_NAMES.get(p, "tcp"),
                                "weight": w})
            # service-version surface: infer from the grabbed banner (e.g.
            # "SSH-2.0-OpenSSH_8.4" adds version exposure to the score)
            version_note = ""
            if banner_probe:
                score += 1  # ANY readable banner means an unauthenticated info leak
                version_note = banner_probe[:80]
                m = re.search(r"(\d+\.\d+(?:\.\d+)?)", banner_probe)
                if m:
                    score += 1  # version disclosure on top
            risk = ("CRITICAL" if score >= 10 else "HIGH" if score >= 6
                    else "MEDIUM" if score >= 3 else "LOW")
            return {"ip": ip, "hostname": h.get("hostname", ""),
                    "vendor": h.get("vendor", ""), "mac": h.get("mac", ""),
                    "score": score, "risk": risk,
                    "open_ports": details,
                    "port_count": len(open_ports),
                    "banner": version_note}

        with ThreadPoolExecutor(max_workers=12) as pool:
            futs = {pool.submit(_assess, h): h for h in hosts}
            for fut in as_completed(futs, timeout=timeout):
                if time.time() > deadline:
                    break
                r = fut.result()
                if r:
                    results.append(r)
    except Exception:
        pass
    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def recommend_starting_target(hosts: List[Dict[str, Any]],
                              timeout: float = 40.0) -> Dict[str, Any]:
    """Pick the best first target: the most exposed device with a human
    reason (open services), or a no-target verdict when nothing is exposed.
    """
    ranked = rank_hosts_exposure(hosts, timeout=timeout)
    if not ranked:
        return {"ranked": [], "recommended": None,
                "reason": "No reachable open service found on any device — "
                           "nothing to start from."}
    top = ranked[0]
    ports = ", ".join(f"{p['port']}/{p['service']}" for p in top["open_ports"][:8])
    ban = f" banner: {top['banner']}" if top.get("banner") else ""
    reason = (f"{top.get('hostname') or top['ip']} exposes {top['port_count']} "
              f"service(s) ({ports}){ban} — highest weighted surface: risky "
              f"services (SMB/RDP/DB/docker) count more than plain ports "
              f"(risk {top['risk']}).")
    return {"ranked": ranked, "recommended": top, "reason": reason}