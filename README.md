```text
  ██████╗ ██╗  ██╗ █████╗ ███╗  ██╗████████╗ ██████╗ ███╗  ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗ ██║╚══██╔══╝██╔═══██╗████╗████║
  ██████╔╝███████║███████║██╔██╗██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚████║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚███║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
  v1.0.0 — Offensive Security Framework
```

![CI](https://github.com/Terminalkid09/phantom/workflows/CI/badge.svg)

# Phantom

Phantom is a Python-based offensive security CLI framework that orchestrates reconnaissance, OSINT, web testing, brute force, exploitation, and reporting into a single interactive session. It exists to reduce manual tool chaining and keep the operator in control with previewable, editable command workflows.

## Features
- Interactive CLI shell with persistent session state
- Target and scope management for safe operations
- Preview-driven command generation and editing
- Network scanning and recon orchestration
- OSINT and subdomain discovery workflows
- Web enumeration and fuzzing command generation
- Brute force and payload generation support
- Exploitability scoring and vulnerability correlation
- Report export in JSON, HTML, and PDF formats
- API integrations: NVD, crt.sh, ExploitDB, Shodan, GitHub

## Requirements
- Python 3.10+
- `pip` dependencies:
  - rich
  - requests
  - python-nmap
  - scapy
  - reportlab
  - python-whois
  - dnspython
- System tools required:
  - nmap
  - gobuster
  - hydra
  - sqlmap
  - metasploit-framework
  - nikto
  - enum4linux
  - sslscan
  - traceroute
  - arp-scan
  - netdiscover
  - amass
  - subfinder
  - whatweb
  - wafw00f
  - feroxbuster
  - ffuf
  - wfuzz
  - john
  - hashcat
  - medusa
  - dirb
  - dnsenum
  - dnsrecon
  - fierce
  - tshark
  - scapy
  - searchsploit
  - msfvenom
  - chisel

### Optional vs Required
- Required: Python 3.10+, rich, requests, reportlab, scapy, python-whois, dnspython.
- Optional: tools such as Shodan, GitHub, and local exploit search tools are only used by optional OSINT and exploitation workflows.

## Installation
```bash
git clone https://github.com/Terminalkid09/phantom.git
cd phantom
pip install -e .
phantom
```

Alternative install with pipx:
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
set target 10.0.0.1
set scope 10.0.0.0/24
set mode full
use scan
preview
# edit or remove commands as needed
run-all
use report
export json report.json
```

## Module Reference
| Module | Command | Description | Key Commands |
|---|---|---|---|
| Shell core | `phantom` | Main interactive CLI | `set`, `show`, `note`, `history`, `export`, `use` |
| Scan | `use scan` | Network reconnaissance command generator | `preview`, `run-all` |
| OSINT | `use osint` | Passive domain/IP intelligence and API lookups | `crtsh`, `shodan`, `bgp` |
| Web | `use web` | Web enumeration and fuzzing workflow | `preview`, `run-all` |
| Brute | `use brute` | Controlled brute force wizard | `run`, `crack` |
| Exploit | `use exploit` | CVE correlation and exploitability scoring | `run`, `preview` |
| Payload | `use payload` | Payload generation and listener helper | `generate`, `run` |
| Handler | `use handler` | Reverse shell listener helper | `listen`, `nc` |
| Pivot | `use pivot` | Port forwarding and tunneling helper | `setup`, `run` |
| Analyzer | `use analyzer` | PCAP analysis and anomaly detection | `capture`, `load` |
| Report | `use report` | Export session results to JSON/HTML/PDF | `export`, `preview` |

## Legal Disclaimer
Phantom is designed for authorized penetration testing and security research only.
Use this tool only on systems you own or have explicit written permission to test.
Unauthorized use against systems you do not own is illegal under computer crime laws
in most jurisdictions. The author assumes no liability for misuse or damage caused
by this tool. Always obtain proper authorization before conducting any security testing.

## Contributing
To add a new module:
1. Create a new module under `phantom/modules/`.
2. Inherit from `phantom.modules.base_module.BaseModule`.
3. Implement `build_commands()`, `do_preview()`, and `do_run()`.
4. Add the module name in `phantom/core/shell.py` under `do_use()`.
5. Add tests in `tests/` using pytest and mocks for external interaction.

## Author
Terminalkid09 — https://github.com/Terminalkid09
