# Phantom

```text
  ________  ___  ___  ________  ________   _________  ________  _____ ______          .**.  .**.
  |\   __  \|\  \|\  \|\   __  \|\   ___  \|\___   ___\\   __  \|\   _ \  _   \       .*******.
  \ \  \|\  \ \  \\\  \ \  \|\  \ \  \\ \  \|___ \  \_\ \  \|\  \ \  \\\__\ \  \     .*******.
   \ \   ____\ \   __  \ \   __  \ \  \\ \  \   \ \  \ \ \  \\\  \ \  \\|__| \  \     .*****.
    \ \  \___|\ \  \ \  \ \  \ \  \ \  \\ \  \   \ \  \ \ \  \\\  \ \  \    \ \  \      .***.
     \ \__\    \ \__\ \__\ \__\ \__\ \__\\ \__\   \ \__\ \ \_______\ \__\    \ \__\       .*.
      \|__|     \|__|\|__|\|__|\|__|\|__| \|__|    \|__|  \|_______|\|__|     \|__|        *
  ----------------------------------------------------------------------------------
  Offensive Security Framework  v1.1.0
  Python 3.10+   OS Linux/Windows   Time current
  ----------------------------------------------------------------------------------
  Use 'help' for commands. Use responsibly and legally.
```

Phantom is a Python-based offensive security CLI framework that orchestrates reconnaissance, OSINT, web testing, brute force, exploitation, and reporting into a single interactive session – with previewable, editable command workflows.

## Features

- Interactive CLI with persistent session (target, scope, notes, command history)
- Preview and edit commands before execution (remove, edit, add, run-group, run-single)
- Target and scope management – prevents accidental out-of-scope tests
- Mode-driven workflows – recon, osint, full, exploit modes with `run` to execute sequence automatically
- Profiles – save/load your preferred settings (`save-profile`, `load-profile`)
- Scan history diff – compare scan results over time (`scan-diff`)
- Plugin system – drop a Python module in `~/.phantom/plugins/` to add custom commands
- 10+ built-in modules: scan, osint, web, brute, exploit, payload, handler, pivot, analyzer, report
- Report export – JSON, HTML, PDF
- External APIs – NVD, crt.sh, ExploitDB, Shodan, GitHub (optional)

## Requirements

### Python packages (required)
- rich
- requests
- python-nmap
- scapy
- reportlab
- python-whois
- dnspython

### System tools (required – most are pre-installed on Kali)
```
nmap, gobuster, hydra, sqlmap, nikto, enum4linux, sslscan, traceroute,
arp-scan, netdiscover, amass, subfinder, whatweb, wafw00f, feroxbuster,
ffuf, wfuzz, john, hashcat, medusa, dirb, dnsenum, dnsrecon, fierce,
tshark, searchsploit, msfvenom, chisel
```

> Note: Some tools (like subfinder, assetfinder) are optional – Phantom will skip them if not found.

## Installation

### From source (recommended)
```bash
git clone https://github.com/Terminalkid09/phantom.git
cd phantom
pip install -e .
phantom
```

### Using pipx (isolated)
```bash
pipx install git+https://github.com/Terminalkid09/phantom.git
```

## Running Tests
```bash
pip install pytest pytest-mock
pytest tests/ -v
```

## Quick Start
```bash
phantom
set target scanme.nmap.org
set scope 45.33.32.156
set mode full
run                                  
use report
export json report.json
```

## Command Reference

### Global Shell Commands

| Command | Description |
|---------|-------------|
| `set target <ip/domain>` | Set the target |
| `set mode <recon/ osint/ full/ exploit>` | Select operation mode |
| `set scope <cidr,ip,...>` | Whitelist IP/CIDR (warnings) |
| `run` | Execute the mode-specific module sequence automatically |
| `show session/ scope/ mode` | Display current state |
| `note "text"` / `notes` | Add/show inline notes |
| `save-session <name>` / `load-session <name>` | Persist session to disk |
| `list-sessions` | Show saved sessions |
| `history` | View command history |
| `save-profile <name>` / `load-profile <name>` | Save/load settings profiles |
| `wordlists list/ use/ search/ info` | Wordlist manager |
| `scan-diff <target> [--since YYYY-MM-DD]` | Compare scan history |
| `export json/ pdf/ html <file>` | Generate report |
| `use <module>` | Enter a module (scan, osint, web, brute, exploit, payload, handler, pivot, analyzer, report) |
| `exit` / `quit` | Close Phantom (asks to save) |

### Built-in Modules

| Module | Command | Description | Key Sub-commands |
|--------|---------|-------------|-------------------|
| Scan | `use scan` | Network reconnaissance (Nmap, traceroute, service enum) | `preview`, `run-all`, `run-group`, `edit`, `remove`, `add` |
| OSINT | `use osint` | Passive domain/IP intelligence, APIs (crt.sh, Shodan, BGP) | `crtsh`, `shodan`, `bgp` |
| Web | `use web` | Web enumeration, fuzzing, SQLmap | `preview`, `run-all` |
| Brute | `use brute` | Controlled brute-force wizard (Hydra, Medusa, John, Hashcat) | `run`, `crack` |
| Exploit | `use exploit` | CVE correlation & exploitability scoring (NVD, searchsploit, GitHub) | `run` |
| Payload | `use payload` | msfvenom payload generator + listener helper | `generate` |
| Handler | `use handler` | Reverse-shell listener (Metasploit, netcat) | `listen`, `nc` |
| Pivot | `use pivot` | Port forwarding & tunneling (SSH, Chisel) | `setup` |
| Analyzer | `use analyzer` | PCAP analysis and anomaly detection (scapy) | `capture`, `load` |
| Report | `use report` | Export session results | `export` |

## Extending Phantom – Plugins

Phantom automatically loads any Python module placed in `~/.phantom/plugins/`.  
To add a new module:

1. Create a file `~/.phantom/plugins/my_module.py`
2. Inherit from `BaseModule` (from `phantom.modules.base_module`)
3. Implement `build_commands()`, `do_preview()`, and `do_run()`
4. Restart Phantom – the module will appear in the `use` list.

Example plugin:

```python
from phantom.modules.base_module import BaseModule

class MyModule(BaseModule):
    module_name = "mymod"
    def build_commands(self):
        return {"CUSTOM": ["echo 'Hello from plugin'"]}
    def do_preview(self, _):
        # ... implement preview logic
```

## Scan History & Diff

Each time you run the `scan` module, Phantom saves the detected services (from Nmap XML) into `data/scan_history/<target>/`.  
Use `scan-diff <target> --since 2025-03-01` to see what changed between scans – open ports, new services, version updates.

## Profiles

Save your current session settings (target, mode, scope, active wordlist, etc.) as a profile:

```bash
save-profile myprofile
```

Later, reload them:

```bash
load-profile myprofile
```

Profiles are stored in `~/.phantom/profiles/`.

## Legal Disclaimer

Phantom is designed for authorized penetration testing and security research only.  
Use this tool only on systems you own or have explicit written permission to test.  
Unauthorized use is illegal. The author assumes no liability for misuse or damage.

## Contributing

To add a built-in module:
1. Create `phantom/modules/newmodule.py`
2. Inherit from `BaseModule`
3. Add the module to the dictionary in `phantom/core/shell.py` under `do_use()`
4. Write tests in `tests/` with pytest

For plugins, just drop your file into `~/.phantom/plugins/` – no pull request required.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Author

**Terminalkid09** – [GitHub](https://github.com/Terminalkid09)
