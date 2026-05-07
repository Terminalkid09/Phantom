import os
import json
from datetime import datetime
from phantom.utils.parser import parse_nmap_xml

HISTORY_DIR = "data/scan_history"

def save_scan_history(target: str, xml_path: str):
    """Parse Nmap XML and save to history JSON."""
    os.makedirs(HISTORY_DIR, exist_ok=True)
    services = parse_nmap_xml(xml_path)
    # Filter only open ports with version info
    versioned = [s for s in services if s.state == "open" and (s.version or s.product)]
    data = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "services": [
            {
                "port": s.port,
                "protocol": s.protocol,
                "service": s.service,
                "version": s.version or s.product or ""
            }
            for s in versioned
        ]
    }
    filename = f"{HISTORY_DIR}/{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    return filename

def load_history(target: str, timestamp: str = None):
    """Load all history files for a target, optionally filter by timestamp."""
    files = [f for f in os.listdir(HISTORY_DIR) if f.startswith(target) and f.endswith(".json")]
    files.sort(reverse=True)  # newer first
    if timestamp:
        files = [f for f in files if timestamp in f]
    result = []
    for f in files:
        with open(os.path.join(HISTORY_DIR, f), "r") as fp:
            result.append(json.load(fp))
    return result

def diff_scans(old_services, new_services):
    """Compare two lists of services and return additions, removals, changes."""
    old_dict = {f"{s['port']}/{s['protocol']}": s for s in old_services}
    new_dict = {f"{s['port']}/{s['protocol']}": s for s in new_services}
    added = [s for k, s in new_dict.items() if k not in old_dict]
    removed = [s for k, s in old_dict.items() if k not in new_dict]
    changed = []
    for k, new_s in new_dict.items():
        if k in old_dict:
            old_s = old_dict[k]
            if old_s.get("version") != new_s.get("version") or old_s.get("service") != new_s.get("service"):
                changed.append((old_s, new_s))
    return added, removed, changed