"""
probes.py — protocol-specific service fingerprinting engine.

Deep-fingerprints 15+ protocols beyond what nmap -sV provides, extracting
structured information that feeds the planner, exploit module, and anomaly
engine.

Design:
- Pure socket-level probes (no external tools)
- Each probe: connect → send → receive → parse → return structured dict
- Connection timeout 5s, bounded reads, never raises
- Non-lethal: service is NOT disrupted by fingerprinting
"""

from __future__ import annotations

import re
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class FingerprintResult:
    """Structured result of a single service fingerprint."""
    host: str
    port: int
    protocol: str           # tcp | udp
    service: str            # smb | mysql | ssh | ...
    product: str = ""
    version: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    raw_banner: str = ""
    error: str = ""
    took_ms: float = 0.0

    @property
    def ok(self) -> bool:
        return bool(self.product or self.version or self.extra or self.raw_banner)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extra": self.extra,
            "error": self.error,
            "took_ms": self.took_ms,
        }


# ── helpers ───────────────────────────────────────────────────────────

def _connect(host: str, port: int, timeout: float = 5.0) -> Optional[socket.socket]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except Exception:
        return None


def _recv_all(sock: socket.socket, timeout: float = 3.0, max_size: int = 8192) -> bytes:
    """Read whatever the service sends back, bounded."""
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(c) for c in chunks) >= max_size:
                break
    except socket.timeout:
        pass
    except Exception:
        pass
    return b"".join(chunks)


def _send_recv(sock: socket.socket, payload: bytes, timeout: float = 3.0) -> bytes:
    """Send then receive."""
    try:
        sock.sendall(payload)
    except Exception:
        return b""
    return _recv_all(sock, timeout)


# ── individual probes ──────────────────────────────────────────────────

def _probe_ssh(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="tcp", service="ssh")
    t0 = time.time()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.error = "connection refused"
        result.took_ms = (time.time() - t0) * 1000
        return result
    try:
        data = _recv_all(sock, timeout=3.0)
        result.raw_banner = data.decode("utf-8", errors="replace").strip()
        # Format: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        match = re.match(r"SSH-([\d.]+)-(\S+)", result.raw_banner)
        if match:
            result.version = match.group(1)
            result.product = match.group(2)
            # Extract OS hint from banner
            if "ubuntu" in result.product.lower():
                result.extra["os_hint"] = "ubuntu"
            elif "debian" in result.product.lower():
                result.extra["os_hint"] = "debian"
            elif "rhel" in result.product.lower() or "el" in result.product.lower():
                result.extra["os_hint"] = "rhel"
    finally:
        sock.close()
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_smb(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="tcp", service="smb")
    t0 = time.time()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.error = "connection refused"
        result.took_ms = (time.time() - t0) * 1000
        return result
    try:
        # SMB Negotiate Protocol Request (SMBv1/2/3 dialect negotiation)
        # NetBIOS Session Request
        nbss = b"\x00\x00\x00\x54\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x01\xc0" + \
               b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
               b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
               b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
               b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
               b"\x00\x00\x00\x00"
        data = _send_recv(sock, nbss, timeout=3.0)
        if data:
            result.raw_banner = data.hex()
            # Check for SMBv1 dialect support
            if len(data) > 8:
                # Parse dialect from negotiate response
                if b"\xff\x53\x4d\x42" in data:
                    result.product = "Microsoft Windows SMB"
                    result.extra["smb_signing"] = bool(data[39] & 0x08) if len(data) > 39 else None
                    # SMBv1 check: look for "SMB" magic at offset 4
                    if data[4:8] == b"\xff\x53\x4d\x42":
                        # Check if it's a negotiate response with SMBv1 dialect
                        if len(data) > 40:
                            result.extra["smbv1_enabled"] = True
        # Fallback: try NetBIOS session service name query
        if not result.ok:
            try:
                # Send NetBIOS name service query
                nb_query = b"\x81" + b"\x00" * 11 + b"\x00\x00\x20\x43\x4b" + b"\x00" * 32
                sock2 = _connect(host, 137, timeout=2.0)
                if sock2:
                    sock2.close()
                    result.extra["netbios_ns_open"] = True
            except Exception:
                pass
    finally:
        sock.close()
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_mysql(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="tcp", service="mysql")
    t0 = time.time()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.error = "connection refused"
        result.took_ms = (time.time() - t0) * 1000
        return result
    try:
        data = _recv_all(sock, timeout=3.0)
        if len(data) >= 4:
            # MySQL handshake packet: 4-byte header + protocol_version + server_version
            pkt_len = data[0] | (data[1] << 8) | (data[2] << 16)
            seq = data[3]
            if len(data) > 4:
                proto_ver = data[4]
                # Server version is null-terminated starting at offset 5
                end = data.find(b"\x00", 5)
                if end > 5:
                    server_ver = data[5:end].decode("utf-8", errors="replace")
                    result.product = "MySQL"
                    result.version = server_ver
                    result.extra["protocol_version"] = proto_ver
                    result.extra["packet_length"] = pkt_len
                    # Extract auth plugin if available
                    if len(data) > end + 20:
                        result.extra["connection_id"] = struct.unpack_from("<I", data, end + 1)[0]
                    result.raw_banner = server_ver
        # Try MySQL query if handshake failed
        if not result.ok:
            # Send COM_QUERY
            query = b"\x17\x00\x00\x00\x03" + b"SELECT VERSION()"
            data2 = _send_recv(sock, query, timeout=2.0)
            if data2 and len(data2) > 4:
                result.raw_banner = data2[4:].decode("utf-8", errors="replace").strip()
                result.product = "MySQL/MariaDB"
    finally:
        sock.close()
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_mssql(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="tcp", service="mssql")
    t0 = time.time()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.error = "connection refused"
        result.took_ms = (time.time() - t0) * 1000
        return result
    try:
        # TDS 7.x Pre-Login packet
        # Minimal TDS pre-login with version option
        prelogin = (
            b"\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b"
            b"\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01"
            b"\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00"
            b"\x73\x08\x00\x00"
        )
        data = _send_recv(sock, prelogin, timeout=3.0)
        if data and len(data) >= 4:
            # TDS response: parse version from pre-login response
            result.product = "Microsoft SQL Server"
            result.extra["tds_raw"] = data.hex()[:80]
            # Look for version bytes in TDS pre-login response
            if len(data) > 20:
                # Version is typically at specific offsets in the pre-login response
                for off in range(8, min(len(data) - 4, 40)):
                    if data[off] > 0 and data[off] <= 20 and data[off + 1] == 0:
                        # Possible TDS version byte
                        pass
                result.extra["response_size"] = len(data)
            result.raw_banner = f"TDS response: {len(data)} bytes"
    finally:
        sock.close()
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_postgresql(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="tcp", service="postgresql")
    t0 = time.time()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.error = "connection refused"
        result.took_ms = (time.time() - t0) * 1000
        return result
    try:
        # PostgreSQL Startup Message (SSLRequest)
        length = struct.pack("!I", 8)
        ssl_code = struct.pack("!I", 80877103)  # SSLRequest magic number
        data = _send_recv(sock, length + ssl_code, timeout=3.0)
        if data:
            if data[0:1] == b"S":
                result.extra["ssl_supported"] = True
            elif data[0:1] == b"N":
                result.extra["ssl_supported"] = False
        # Standard startup message (version 3.0, user: "phantom")
        user = b"phantom\x00"
        startup_body = b"user\x00" + user + b"database\x00phantom\x00\x00"
        startup_len = struct.pack("!I", len(startup_body) + 8)
        startup_ver = struct.pack("!I", 196608)  # 3.0
        data2 = _send_recv(sock, startup_len + startup_ver + startup_body, timeout=3.0)
        if data2 and len(data2) > 4:
            msg_type = data2[0:1]
            if msg_type == b"R":
                result.product = "PostgreSQL"
                result.extra["auth_type"] = struct.unpack("!I", data2[5:9])[0] if len(data2) > 8 else None
                # MD5 auth = 5, plaintext = 3, trust = 0
                result.extra["auth_method"] = {0: "trust", 3: "password", 5: "md5", 10: "scram"}.get(
                    result.extra["auth_type"], f"type_{result.extra['auth_type']}")
            elif msg_type == b"E":
                result.product = "PostgreSQL"
                err_msg = data2[5:].decode("utf-8", errors="replace")
                result.raw_banner = err_msg
                # Parse server version from error
                ver_match = re.search(r"version\s+([\d.]+)", err_msg, re.I)
                if ver_match:
                    result.version = ver_match.group(1)
    finally:
        sock.close()
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_redis(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="tcp", service="redis")
    t0 = time.time()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.error = "connection refused"
        result.took_ms = (time.time() - t0) * 1000
        return result
    try:
        # Redis PING
        data = _send_recv(sock, b"PING\r\n", timeout=2.0)
        if b"PONG" in data:
            result.product = "Redis"
            result.extra["auth_required"] = False
            # Try INFO to get version
            info = _send_recv(sock, b"INFO\r\n", timeout=2.0)
            for line in info.decode("utf-8", errors="replace").split("\r\n"):
                if line.startswith("redis_version:"):
                    result.version = line.split(":", 1)[1].strip()
                elif line.startswith("redis_mode:"):
                    result.extra["mode"] = line.split(":", 1)[1].strip()
                elif line.startswith("os:"):
                    result.extra["os"] = line.split(":", 1)[1].strip()
                elif line.startswith("arch_bits:"):
                    result.extra["arch"] = line.split(":", 1)[1].strip()
            result.raw_banner = f"Redis {result.version}" if result.version else "Redis"
        elif b"NOAUTH" in data or b"ERR AUTH" in data:
            result.product = "Redis"
            result.extra["auth_required"] = True
            result.raw_banner = "Redis (auth required)"
        elif b"ERR" in data:
            result.product = "Redis"
            result.extra["auth_required"] = True
    finally:
        sock.close()
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_mongodb(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="tcp", service="mongodb")
    t0 = time.time()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.error = "connection refused"
        result.took_ms = (time.time() - t0) * 1000
        return result
    try:
        # MongoDB Wire Protocol: build isMaster command
        # BSON document: {"isMaster": 1}
        msg = b"\x31\x00\x00\x00"  # message length (49 bytes placeholder)
        msg += b"\x00\x00\x00\x00"  # requestID
        msg += b"\x00\x00\x00\x00"  # responseTo
        msg += b"\xd4\x07\x00\x00"  # OP_QUERY
        msg += b"\x00\x00\x00\x00"  # flags
        msg += b"admin.$cmd\x00"    # full collection name
        msg += b"\x00\x00\x00\x00"  # numberToSkip
        msg += b"\xff\xff\xff\xff"  # numberToReturn (-1 = all)
        # BSON: {"isMaster": 1}
        bson = b"\x10\x00\x00\x00"     # size
        bson += b"\x10" + b"isMaster\x00"  # int32 key
        bson += b"\x01\x00\x00\x00"         # value 1
        bson += b"\x00"                     # terminator
        msg = msg[:4] + struct.pack("<I", len(msg) + len(bson) - 4)[:4] + msg[4:] + bson
        data = _send_recv(sock, msg, timeout=3.0)
        if data and len(data) > 36:
            result.product = "MongoDB"
            # Parse isMaster response for version
            body = data.decode("utf-8", errors="replace")
            ver_match = re.search(r'"version"\s*:\s*"([^"]+)"', body)
            if ver_match:
                result.version = ver_match.group(1)
            build_match = re.search(r'"gitVersion"\s*:\s*"([^"]+)"', body)
            if build_match:
                result.extra["git_version"] = build_match.group(1)
            max_wire = re.search(r'"maxWireVersion"\s*:\s*(\d+)', body)
            if max_wire:
                result.extra["max_wire_version"] = int(max_wire.group(1))
            result.raw_banner = f"MongoDB {result.version}" if result.version else "MongoDB"
    finally:
        sock.close()
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_rdp(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="tcp", service="rdp")
    t0 = time.time()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.error = "connection refused"
        result.took_ms = (time.time() - t0) * 1000
        return result
    try:
        # RDP Connection Request (TPKT + X.224)
        tpkt = struct.pack("!BBH", 3, 0, 19)  # TPKT header
        x224_len = b"\x11"
        x224_type = b"\xe0"  # CR – Connection Request
        x224_dst = b"\x00\x00"
        x224_src = b"\x00\x00"
        x224_opts = b"\x00"    # no options
        rdp_nego = (b"\x01\x00\x08\x00\x03\x00\x00\x00")  # RDP Negotiation Request
        payload = tpkt + x224_len + x224_type + x224_dst + x224_src + x224_opts + rdp_nego
        data = _send_recv(sock, payload, timeout=3.0)
        if data and len(data) >= 8:
            result.product = "Microsoft RDP"
            result.extra["response_size"] = len(data)
            # Look for negotiation response in the data
            if b"\xd0" in data[5:10]:
                result.extra["tls_supported"] = True
            # Extract protocol version from negotiation flags
            if len(data) > 11:
                result.extra["nego_flags"] = data[11:12].hex()
            result.raw_banner = f"RDP (TPKT response: {len(data)} bytes)"
    finally:
        sock.close()
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_ftp(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="tcp", service="ftp")
    t0 = time.time()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.error = "connection refused"
        result.took_ms = (time.time() - t0) * 1000
        return result
    try:
        data = _recv_all(sock, timeout=3.0)
        banner = data.decode("utf-8", errors="replace").strip()
        result.raw_banner = banner
        # Parse FTP banner: "220 ProFTPD 1.3.5 Server ..."
        match = re.match(r"220[ -](.*)", banner)
        if match:
            server_info = match.group(1)
            result.product = server_info.split()[0] if server_info else ""
            ver_match = re.search(r"([\d.]+[a-z]?\d*)", server_info)
            if ver_match:
                result.version = ver_match.group(1)
        # Try anonymous login check
        try:
            _send_recv(sock, b"USER anonymous\r\n", timeout=1.0)
            anon_resp = _send_recv(sock, b"PASS phantom@test.com\r\n", timeout=1.0)
            if anon_resp.startswith(b"230"):
                result.extra["anonymous"] = True
            elif anon_resp.startswith(b"331") or anon_resp.startswith(b"530"):
                result.extra["anonymous"] = False
        except Exception:
            pass
    finally:
        sock.close()
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_smtp(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="tcp", service="smtp")
    t0 = time.time()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.error = "connection refused"
        result.took_ms = (time.time() - t0) * 1000
        return result
    try:
        data = _recv_all(sock, timeout=3.0)
        result.raw_banner = data.decode("utf-8", errors="replace").strip()
        # Send EHLO
        ehlo_resp = _send_recv(sock, b"EHLO phantom.local\r\n", timeout=2.0)
        ehlo_text = ehlo_resp.decode("utf-8", errors="replace")
        result.extra["capabilities"] = []
        for line in ehlo_text.split("\r\n"):
            if line.startswith("250-") or line.startswith("250 "):
                cap = line[4:].strip().upper()
                if cap:
                    result.extra["capabilities"].append(cap)
        result.extra["starttls"] = "STARTTLS" in result.extra["capabilities"]
        # Parse banner for product
        match = re.match(r"220[ -](.*)", result.raw_banner)
        if match:
            server_info = match.group(1)
            result.product = server_info.split()[0] if server_info else ""
            ver_match = re.search(r"([\d.]+[a-z]?\d*)", server_info)
            if ver_match:
                result.version = ver_match.group(1)
    finally:
        sock.close()
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_snmp(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="udp", service="snmp")
    t0 = time.time()
    try:
        # SNMPv2c GET request for sysDescr (1.3.6.1.2.1.1.1.0) with community "public"
        # ASN.1 BER-encoded SNMP GET
        snmp_get = bytes.fromhex(
            "302602010104067075626c6963a01902044eb2fca4020100020100"
            "300b300906052b06010201010100"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(snmp_get, (host, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        if data:
            result.product = "SNMP"
            # Extract string from ASN.1 response
            body = data.decode("utf-8", errors="replace")
            # Find the OID value in the response
            for part in re.findall(rb'[\x20-\x7e]{4,}', data):
                decoded = part.decode("utf-8", errors="replace")
                if any(k in decoded.lower() for k in ("ios", "linux", "windows", "ubuntu", "router", "switch")):
                    result.raw_banner = decoded
                    result.extra["sys_descr"] = decoded
                    # Extract product from sysDescr
                    lowered = decoded.lower()
                    if "cisco ios" in lowered:
                        result.product = "Cisco IOS"
                    elif "ubuntu" in lowered:
                        result.product = "Ubuntu"
                    elif "windows" in lowered:
                        result.product = "Microsoft Windows"
                    break
            if not result.raw_banner:
                result.raw_banner = f"SNMP response: {len(data)} bytes"
    except socket.timeout:
        result.error = "timeout"
    except Exception as e:
        result.error = str(e)
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_ldap(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="tcp", service="ldap")
    t0 = time.time()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.error = "connection refused"
        result.took_ms = (time.time() - t0) * 1000
        return result
    try:
        # LDAP search request for rootDSE (anonymous bind)
        # BER-encoded LDAP search
        ldap_search = bytes.fromhex(
            "300c020101600702010304008000"
        )
        data = _send_recv(sock, ldap_search, timeout=3.0)
        if data and len(data) > 2:
            result.product = "LDAP"
            result.extra["response_size"] = len(data)
            body = data.decode("utf-8", errors="replace")
            # Extract namingContexts from rootDSE
            nc_match = re.search(r"namingContexts[^A-Za-z]*([A-Za-z]+=[^,]+,DC=[a-zA-Z0-9._-]+)", body)
            if nc_match:
                result.extra["naming_context"] = nc_match.group(1)
            # Extract domain functional level
            dfl_match = re.search(r"domainFunctionality[:\s]*(\d+)", body)
            if dfl_match:
                result.extra["domain_functional_level"] = int(dfl_match.group(1))
                # Map to Windows Server version
                dfl = result.extra["domain_functional_level"]
                if dfl >= 7:
                    result.extra["os_hint"] = "Windows Server 2016+"
                elif dfl >= 6:
                    result.extra["os_hint"] = "Windows Server 2012 R2"
                elif dfl >= 5:
                    result.extra["os_hint"] = "Windows Server 2012"
                elif dfl >= 4:
                    result.extra["os_hint"] = "Windows Server 2008 R2"
            dc_match = re.search(r"(DC=[a-zA-Z0-9._-]+)", body)
            if dc_match:
                result.extra["domain"] = dc_match.group(1).lower()
            result.raw_banner = f"LDAP rootDSE: {result.extra.get('naming_context', '')}" if result.extra.get("naming_context") else f"LDAP: {len(data)} bytes response"
    finally:
        sock.close()
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_docker(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="tcp", service="docker")
    t0 = time.time()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.error = "connection refused"
        result.took_ms = (time.time() - t0) * 1000
        return result
    try:
        # Docker API GET /version
        http_req = b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n"
        data = _send_recv(sock, http_req, timeout=3.0)
        if data:
            result.raw_banner = data.decode("utf-8", errors="replace")[:500]
            if "ApiVersion" in result.raw_banner or "Version" in result.raw_banner:
                result.product = "Docker Engine"
                # Parse JSON-like response
                ver_match = re.search(r'"Version"\s*:\s*"([^"]+)"', result.raw_banner)
                if ver_match:
                    result.version = ver_match.group(1)
                api_match = re.search(r'"ApiVersion"\s*:\s*"([^"]+)"', result.raw_banner)
                if api_match:
                    result.extra["api_version"] = api_match.group(1)
                os_match = re.search(r'"Os"\s*:\s*"([^"]+)"', result.raw_banner)
                if os_match:
                    result.extra["host_os"] = os_match.group(1)
                arch_match = re.search(r'"Arch"\s*:\s*"([^"]+)"', result.raw_banner)
                if arch_match:
                    result.extra["host_arch"] = arch_match.group(1)
                result.extra["api_exposed"] = True
            elif "Docker" in result.raw_banner:
                result.product = "Docker"
                result.extra["api_exposed"] = True
    finally:
        sock.close()
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_kubernetes(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="tcp", service="kubernetes")
    t0 = time.time()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.error = "connection refused"
        result.took_ms = (time.time() - t0) * 1000
        return result
    try:
        # Kubernetes API: GET /api
        http_req = b"GET /api HTTP/1.0\r\nHost: localhost\r\n\r\n"
        data = _send_recv(sock, http_req, timeout=3.0)
        if data:
            body = data.decode("utf-8", errors="replace")
            result.raw_banner = body[:500]
            if "kubernetes" in body.lower() or '"kind"' in body:
                result.product = "Kubernetes API"
                ver_match = re.search(r'"major"\s*:\s*"([^"]+)",\s*"minor"\s*:\s*"([^"]+)"', body)
                if ver_match:
                    result.version = f"{ver_match.group(1)}.{ver_match.group(2)}"
                result.extra["api_exposed"] = True
    finally:
        sock.close()
    # Also try kubelet on 10250
    if port in (6443, 443) or not result.ok:
        try:
            sock2 = _connect(host, 10250, timeout=3.0)
            if sock2:
                http_req2 = b"GET /pods HTTP/1.0\r\nHost: localhost\r\n\r\n"
                data2 = _send_recv(sock2, http_req2, timeout=2.0)
                sock2.close()
                if data2 and (b"kind" in data2 or b"items" in data2 or b"kubernetes" in data2.lower()):
                    if not result.product:
                        result.product = "Kubernetes Kubelet"
                    result.extra["kubelet_readonly"] = True
                    result.extra["pod_enum_possible"] = True
        except Exception:
            pass
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_dns(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    result = FingerprintResult(host=host, port=port, protocol="udp", service="dns")
    t0 = time.time()
    try:
        # DNS query for version.bind (CHAOS class, TXT type)
        dns_query = bytes.fromhex(
            "000001000001000000000000"   # header
            "0776657273696f6e0462696e64"  # version.bind
            "0000100003"                  # TXT, CHAOS class
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(dns_query, (host, port))
        data, _ = sock.recvfrom(512)
        sock.close()
        if data and len(data) > 12:
            result.product = "DNS"
            # Extract TXT record value
            body = data.decode("utf-8", errors="replace")
            # Try to extract version string
            for match in re.finditer(r'[A-Za-z0-9._/-]{5,}', body[12:]):
                val = match.group(0)
                if any(k in val.lower() for k in ("bind", "dns", "powerdns", "unbound", "named", "dnsmasq")):
                    result.raw_banner = val
                    result.extra["version_bind"] = val
                    if "bind" in val.lower():
                        result.product = "ISC BIND"
                        ver_match = re.search(r"(\d+\.\d+\.\d+)", val)
                        if ver_match:
                            result.version = ver_match.group(1)
                    break
    except socket.timeout:
        result.error = "timeout"
    except Exception as e:
        result.error = str(e)
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_http(host: str, port: int, timeout: float = 5.0,
                tls: bool = False) -> FingerprintResult:
    """Pure-Python HTTP(S) probe: GET / and fingerprint Server header,
    title, redirect target and common CMS markers — no curl required."""
    service = "https" if tls else "http"
    result = FingerprintResult(host=host, port=port, protocol="tcp",
                               service=service)
    t0 = time.time()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        request = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\n"
            "User-Agent: Mozilla/5.0 (compatible; Phantom/1.0)\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        )
        sock.sendall(request.encode())
        data = _recv_all(sock, timeout=timeout, max_size=65536)
        if not data:
            result.error = "empty response"
            return result
        head, _, body = data.partition(b"\r\n\r\n")
        text = head.decode("utf-8", "replace")
        result.raw_banner = text[:200]
        status_match = re.search(r"HTTP/\S+\s+(\d{3})", text)
        if status_match:
            result.extra["status"] = status_match.group(1)
        server_match = re.search(r"(?im)^Server:\s*(.+)$", text)
        if server_match:
            result.product = server_match.group(1).strip()
        location_match = re.search(r"(?im)^Location:\s*(.+)$", text)
        if location_match:
            result.extra["redirect"] = location_match.group(1).strip()
        # CMS / framework markers in headers + body
        markers = {
            "wordpress": ("wp-content", "wordpress"),
            "drupal": ("drupal", "x-generator: drupal"),
            "joomla": ("joomla", "x-generator: joomla"),
            "nginx": ("nginx", ""),
            "apache": ("apache", ""),
            "tomcat": ("tomcat", "apache-coyote"),
            "iis": ("microsoft-iis", "asp.net"),
            "php": ("php", "x-powered-by: php"),
            "shibboleth": ("shibboleth", ""),
        }
        combined = (text + body.decode("utf-8", "replace")[:4096]).lower()
        for name, (needle, alt) in markers.items():
            if needle in combined or (alt and alt in combined):
                result.extra.setdefault("cms", name)
        title_match = re.search(r"<title[^>]*>\s*([^<]{1,120})\s*</title>",
                                body.decode("utf-8", "replace"), re.I)
        if title_match:
            result.extra["title"] = title_match.group(1).strip()
    except socket.timeout:
        result.error = "timeout"
    except Exception as e:
        result.error = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    result.took_ms = (time.time() - t0) * 1000
    return result


def _probe_https(host: str, port: int, timeout: float = 5.0) -> FingerprintResult:
    return _probe_http(host, port, timeout=timeout, tls=True)


# ── probe registry ────────────────────────────────────────────────────

PROBE_MAP: Dict[str, Tuple[Callable, int]] = {
    "ssh":       (_probe_ssh, 22),
    "smb":       (_probe_smb, 445),
    "mysql":     (_probe_mysql, 3306),
    "mssql":     (_probe_mssql, 1433),
    "postgresql": (_probe_postgresql, 5432),
    "redis":     (_probe_redis, 6379),
    "mongodb":   (_probe_mongodb, 27017),
    "rdp":       (_probe_rdp, 3389),
    "ftp":       (_probe_ftp, 21),
    "smtp":      (_probe_smtp, 25),
    "snmp":      (_probe_snmp, 161),
    "ldap":      (_probe_ldap, 389),
    "docker":    (_probe_docker, 2375),
    "kubernetes": (_probe_kubernetes, 6443),
    "dns":       (_probe_dns, 53),
    "http":      (_probe_http, 80),
    "https":     (_probe_https, 443),
}

# Port-to-service mapping (for nmap output parsing)
PORT_SERVICE_MAP: Dict[int, str] = {
    22: "ssh", 21: "ftp", 25: "smtp", 53: "dns", 80: "http",
    135: "rpc", 139: "netbios", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb",
    636: "ldaps", 1433: "mssql", 1521: "oracle",
    2375: "docker", 2376: "docker-tls", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5985: "winrm",
    6379: "redis", 6443: "kubernetes", 8443: "kubernetes",
    27017: "mongodb",
}


# ── engine ─────────────────────────────────────────────────────────────

class FingerprintEngine:
    """Deep fingerprint one or more services and plug findings into WorldModel."""

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout
        self.results: List[FingerprintResult] = []

    def probe(self, host: str, port: int, protocol: str = "tcp",
              service: Optional[str] = None) -> Optional[FingerprintResult]:
        """Deep fingerprint a single host:port.

        If `service` is given, probe only that protocol.
        Otherwise, auto-detect from port number.
        """
        candidates = []
        if service:
            if service.lower() in PROBE_MAP:
                candidates = [(service.lower(), port)]
        else:
            # Map all services that commonly use this port
            for svc, (_, default_port) in PROBE_MAP.items():
                if default_port == port:
                    candidates.append((svc, port))
            # Also check port map
            mapped = PORT_SERVICE_MAP.get(port, "")
            if mapped and mapped in PROBE_MAP:
                candidates.append((mapped, port))

        if not candidates:
            # Just try to connect and get raw banner
            return self._raw_probe(host, port)

        # Try all matching probes, take the first one that works
        best: Optional[FingerprintResult] = None
        for svc, p in candidates:
            probe_fn, _ = PROBE_MAP.get(svc, (None, 0))
            if probe_fn is None:
                continue
            try:
                r = probe_fn(host, p, self.timeout)
                if r.ok:
                    self.results.append(r)
                    return r
                if r.raw_banner and (best is None or len(r.raw_banner) > len(best.raw_banner or "")):
                    best = r
            except Exception:
                continue

        result = best or self._raw_probe(host, port)
        if result:
            self.results.append(result)
        return result

    def _raw_probe(self, host: str, port: int) -> FingerprintResult:
        """Connect and grab raw banner (any unknown protocol)."""
        result = FingerprintResult(host=host, port=port, protocol="tcp", service="unknown")
        t0 = time.time()
        sock = _connect(host, port, self.timeout)
        if sock is None:
            result.error = "connection refused"
            result.took_ms = (time.time() - t0) * 1000
            return result
        try:
            data = _recv_all(sock, timeout=3.0)
            if data:
                result.raw_banner = data.decode("utf-8", errors="replace")[:500]
                result.product = "unknown"
                result.extra["raw_hex"] = data[:64].hex()
        finally:
            sock.close()
        result.took_ms = (time.time() - t0) * 1000
        return result

    def probe_all(self, host: str, open_ports: List[int]) -> List[FingerprintResult]:
        """Deep fingerprint every open port on a host."""
        for port in open_ports:
            r = self.probe(host, port)
            if r:
                self.results.append(r)
        return self.results

    def to_worldmodel(self, wm, host: str) -> int:
        """Feed results into WorldModel. Returns count of services added."""
        from phantom.core.knowledge import add_service
        count = 0
        for r in self.results:
            if r.host == host and r.ok:
                add_service(
                    str(r.port), r.service,
                    product=r.product or "",
                    version=r.version or "",
                    confidence=0.9 if r.version else 0.7,
                    source="fingerprint",
                )
                # Store structured fingerprint result as a finding for the planner
                wm.add_finding(
                    kind="fingerprint",
                    key=f"{r.service}/{r.port}",
                    value=r.to_dict(),
                    confidence=0.9 if r.version else 0.7,
                    source="fingerprint_probe",
                    evidence=r.raw_banner[:200],
                    target=host,
                )
                count += 1
        return count


# ── standalone (not requiring WorldModel) ──────────────────────────────

def fingerprint_service(host: str, port: int, service: Optional[str] = None,
                        timeout: float = 5.0) -> Optional[dict]:
    """Quick single fingerprint, returns dict or None."""
    engine = FingerprintEngine(timeout=timeout)
    result = engine.probe(host, port, service=service)
    return result.to_dict() if (result and result.ok) else None


def fingerprint_all(host: str, open_ports: List[int],
                    timeout: float = 5.0) -> List[dict]:
    """Fingerprint all open ports on a host, returns list of dicts."""
    engine = FingerprintEngine(timeout=timeout)
    results = engine.probe_all(host, open_ports)
    return [r.to_dict() for r in results if r.ok]