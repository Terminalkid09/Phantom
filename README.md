# Phantom 🛡️❤️

[![Version](https://img.shields.io/badge/version-1.1.0-red.svg)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Phantom** is a professional-grade Offensive Security CLI Framework designed to orchestrate the entire penetration testing lifecycle—from reconnaissance and OSINT to exploitation and reporting—into a single, unified, and interactive session.

Built for speed and flexibility, Phantom allows you to automate complex workflows while maintaining full control over every command executed.

---

## 🚀 Key Features

### 🧩 Extensible Architecture
- **Plugin System**: Seamlessly extend the framework by dropping Python modules into `~/.phantom/plugins/`.
- **10+ Built-in Modules**: Native integration for `scan`, `osint`, `web`, `brute`, `exploit`, `payload`, and more.

### ⚙️ Smart Workflows
- **Mode-Driven Execution**: Preset modes (`recon`, `osint`, `full`, `exploit`) for automated sequential testing.
- **Interactive Command Preview**: Preview, edit, or skip commands before they hit the target.
- **Aggressive Mode**: Inject custom payloads or aggressive flags dynamically into your workflow.

### 📊 Advanced Data Management
- **Scan History & Diff**: Track changes in the target's attack surface over time.
- **Intelligent Wordlist Manager**: Automatically indexes and categorizes wordlists from standard paths (SecLists, Dirb, etc.).
- **Report Engine**: Professional exports in **JSON**, **HTML**, and **PDF** formats.

### 🛡️ Safety & Reliability
- **Scope Enforcement**: Prevents accidental testing of out-of-scope targets.
- **Tool Check**: Automatically verifies if system dependencies (Nmap, SQLMap, etc.) are installed.
- **Session Persistence**: Complete session state (notes, history, results) saved to disk.

---

## ⌨️ Core Commands

| Command | Description |
| :--- | :--- |
| `set target <ip/domain>` | Define the current testing target. |
| `set mode <recon/full/...>` | Select the automation workflow. |
| `set scope <ip,cidr,...>` | Define authorized testing boundaries. |
| `run` | Execute the selected mode sequence automatically. |
| `use <module>` | Enter a specific module (e.g., `use scan`, `use exploit`). |
| `scan-diff <target>` | Compare current scan results with previous ones. |
| `wordlists list/use/search` | Manage and select wordlists for attacks. |
| `save-session <name>` | Save current target, notes, and results. |
| `save-profile <name>` | Persist your configuration and preferences. |
| `note "text"` | Add a timestamped note to the session. |
| `export <pdf/html/json>` | Generate a professional report of findings. |

---

## 🛠️ Modules Overview

| Module | Purpose | Key Tools |
| :--- | :--- | :--- |
| **Scan** | Active Reconnaissance | `nmap`, `traceroute`, `service enum` |
| **OSINT** | Passive Intelligence | `crt.sh`, `Shodan`, `BGP`, `Whois` |
| **Web** | Web Application Pentest | `gobuster`, `sqlmap`, `nikto`, `ffuf` |
| **Brute** | Credential Auditing | `hydra`, `medusa`, `john`, `hashcat` |
| **Exploit** | CVE Correlation | `searchsploit`, `NVD API`, `GitHub PoCs` |
| **Payload** | Payload Generation | `msfvenom`, `shellgen` |
| **Analyzer** | Traffic Analysis | `scapy`, `tshark` |
| **Pivot** | Post-Exploitation | `ssh tunneling`, `chisel` |

---

## 📥 Installation

### Prerequisites
- Python 3.10 or higher.
- Standard security tools (pre-installed on Kali/Parrot): `nmap`, `sqlmap`, `gobuster`, etc.

### From Source
```bash
git clone https://github.com/Terminalkid09/phantom.git
cd phantom
pip install -e .
phantom
```

---

## 🏁 Quick Start

```bash
# Start Phantom
phantom

# Configure Session
set target scanme.nmap.org
set scope 45.33.32.156
set mode full

# Run Workflow
run

# Export Findings
use report
export pdf report.pdf
```

---

## 📝 Extending Phantom (Plugins)

Creating a custom module is as simple as inheriting from `BaseModule`:

```python
from phantom.modules.base_module import BaseModule

class MyTool(BaseModule):
    module_name = "mytool"
    def build_commands(self):
        return {"CUSTOM": ["echo 'Running custom logic on {self.target}'"]}
    def do_run(self, _):
        # Implementation...
```

Drop the file in `~/.phantom/plugins/` and it will be available in the next session!

---

## ⚖️ Legal Disclaimer

Phantom is intended for **authorized penetration testing and educational purposes only**. Use this tool only on systems where you have explicit, written permission. The author is not responsible for any misuse or damage caused by this program.

---

## 👨‍💻 Author

**Terminalkid09** – [GitHub](https://github.com/Terminalkid09)
