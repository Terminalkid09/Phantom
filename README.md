# Phantom 🛡️❤️

[![Version](https://img.shields.io/badge/version-2.0.0-red.svg)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Phantom** is a professional-grade Offensive Security CLI Framework designed to orchestrate the entire penetration testing lifecycle—from reconnaissance and OSINT to exploitation, C2 operations, and reporting—into a single, unified, and interactive session.

Built for speed and flexibility, Phantom allows you to automate complex workflows while maintaining full control over every command executed.

---

## 🚀 Key Features

### 🧩 Extensible Architecture
- **Plugin System**: Seamlessly extend the framework by dropping Python modules into `~/.phantom/plugins/`.
- **12+ Built-in Modules**: Native integration for `scan`, `osint`, `wifi`, `web`, `brute`, `exploit`, `payload`, `handler`, `pivot`, `analyzer`, `report`, and `c2`.
- **AI Integration**: Optional AI-powered CVE interpretation and executive summary generation (OpenAI / Ollama).

### ⚙️ Smart Workflows
- **Mode-Driven Execution**: Preset modes (`recon`, `osint`, `full`, `exploit`) for automated sequential testing.
- **Interactive Command Preview**: Preview, edit, or skip commands before they hit the target.
- **Aggressive Mode**: Inject custom payloads or aggressive flags dynamically into your workflow.
- **Scope Enforcement**: Prevents accidental testing of out-of-scope targets.

### 📊 Advanced Data Management
- **Scan History & Diff**: Track changes in the target's attack surface over time.
- **Intelligent Wordlist Manager**: Automatically indexes and categorizes wordlists from standard paths (SecLists, Dirb, etc.).
- **Report Engine**: Professional exports in **JSON**, **HTML**, and **PDF** formats.
- **Session Persistence**: Complete session state (notes, history, results) saved to disk.

### 📡 WiFi Offensive Module
- **Monitor Mode Management**: Seamless `airmon-ng` integration to start/stop monitor mode.
- **WPA/WPA2 Cracking**: Automated handshake capture with parallel deauthentication.
- **PMKID Attack**: Modern clientless WPA attack via `hcxdumptool` — no handshake needed.
- **WPS Brute Force**: Integrated `reaver` for WPS PIN attacks.
- **Post-Crack Pivot**: After cracking a network, seamlessly transition to internal scanning.

### 🎯 C2 Operations Center
- **Async C2 Server**: `aiohttp`-based listener running in a background thread with sleep/jitter support.
- **AES-256-CBC Encryption**: All beacon ↔ server communication is encrypted end-to-end.
- **Cross-Platform C++ Beacon**: A single C++ codebase that compiles natively for **Windows**, **Linux**, **macOS**, and **Android** (ARM64). Dependencies: `ws2_32`, `iphlpapi` (Windows) and `pthread` (POSIX).
- **EDR Evasion**: Dynamic API resolution via PEB walk (Windows), compile-time XOR string obfuscation for payloads and network headers (All Platforms).
- **Context-Aware Keylogger**: Logs keystrokes intelligently on Windows.
- **Automated Delivery**: `generate <platform>` command auto-compiles the beacon and produces platform-specific droppers (PowerShell, Bash, ADB).
- **Continuous Integration**: GitLab CI pipeline configured for automated multi-platform compilation using `mingw-w64`, `g++`, `clang`, and Android NDK.
- **Recon & Pivoting**: Cross-platform file system enumeration (with a safe 1MB limit for `cat`), file transfer, and TCP port forwarding.
- **Network Resilience**: Explicit connection timeouts to prevent hanging sockets during C2 communication.

### 🛡️ Safety & Reliability
- **Scope Enforcement**: Prevents accidental testing of out-of-scope targets.
- **Tool Check**: Automatically verifies if system dependencies (Nmap, SQLMap, etc.) are installed.
- **Session Persistence**: Complete session state (notes, history, results) saved to disk.
- **Docker Ready**: Seamless deployment with pre-configured Kali Linux environment.

---

## 🐳 Docker Deployment

The fastest way to run Phantom with all its dependencies:

```bash
# Build and start with Docker Compose
docker-compose up --build

# Or run manually
docker build -t phantom .
docker run -it --privileged --net=host phantom
```

The Docker image is based on **Kali Rolling** and comes pre-installed with all security tools (nmap, sqlmap, aircrack-ng, hydra, hashcat, gobuster, nikto, ffuf, tshark, exploitdb) and the C++ build chain (g++, mingw-w64, cmake) for compiling the C2 Beacon.

---

## ⌨️ Core Commands

| Command | Description |
| :--- | :--- |
| `set target <ip/domain>` | Define the current testing target. |
| `set mode <recon/full/...>` | Select the automation workflow. |
| `set scope <ip,cidr,...>` | Define authorized testing boundaries. |
| `run` | Execute the selected mode sequence automatically. |
| `use <module>` | Enter a specific module (e.g., `use scan`, `use exploit`). |
| `c2` | Enter the C2 Operations Center. |
| `scan-diff <target>` | Compare current scan results with previous ones. |
| `wordlists list/use/search` | Manage and select wordlists for attacks. |
| `save-session <name>` | Save current target, notes, and results. |
| `save-profile <name>` | Persist your configuration and preferences. |
| `note "text"` | Add a timestamped note to the session. |
| `export <pdf/html/json>` | Generate a professional report of findings. |
| `help` | Display the formatted help panel with all commands. |

---

## 🛠️ Modules Overview

| Module | Purpose | Key Tools |
| :--- | :--- | :--- |
| **Scan** | Active Reconnaissance | `nmap`, `traceroute`, `service enum` |
| **OSINT** | Passive Intelligence | `crt.sh`, `Shodan`, `BGP`, `Whois` |
| **WiFi** | Wireless Cracking | `aircrack-ng`, `reaver`, `hcxdumptool`, `PMKID` |
| **Web** | Web Application Pentest | `gobuster`, `sqlmap`, `nikto`, `ffuf` |
| **Brute** | Credential Auditing | `hydra`, `medusa`, `john`, `hashcat` |
| **Exploit** | CVE Correlation & C2 Dropper | `searchsploit`, `NVD API`, `C2 Beacon` |
| **Payload** | Payload Generation | `msfvenom`, `shellgen` |
| **Handler** | Listener Management | `metasploit multi/handler` |
| **Analyzer** | Traffic Analysis | `scapy`, `tshark` |
| **Pivot** | Post-Exploitation | `ssh tunneling`, `chisel` |
| **Report** | Report Generation | `JSON`, `HTML`, `PDF` |
| **C2** | Command & Control | `aiohttp`, `AES-256`, `C++ Beacon` |

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

### Pentest Mode
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

### WiFi Cracking
```bash
phantom
use wifi

# Setup
airmon check
airmon start wlan0

# Scan & Attack
scan-aps
handshake AA:BB:CC:DD:EE:FF 6
crack data/sessions/handshake_AABBCCDDEEFF-01.cap

# Or use modern PMKID (no client needed)
pmkid AA:BB:CC:DD:EE:FF 6
```

### C2 Operations
```bash
# Launch C2 Interface
phantom --c2

# Start listener and generate dropper
listeners start 443
generate

# Once beacon connects
beacons
interact PHANTOM-TARGET-1A2B
keylog start
recon
keylog dump
```

### Automated Agent Deployment (from Exploit module)
```bash
phantom
use exploit
deploy-agent
# → Generates a PowerShell one-liner dropper that downloads and executes the beacon
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

## 🏗️ Project Structure

```
phantom/
├── phantom/
│   ├── core/              # Shell, session, executor, scope, C2 server/shell
│   ├── modules/           # scan, osint, wifi, web, brute, exploit, payload, ...
│   ├── plugins/           # Optional AI connector, custom extensions
│   ├── payloads/
│   │   └── beacon/        # C++ Agent source (evasion, crypto, network, keylogger)
│   └── utils/             # notifier, wordlists, parser, network helpers
├── tests/                 # 161+ pytest unit tests
├── Dockerfile             # Kali-based container with all tools pre-installed
├── docker-compose.yml     # One-command deployment
└── README.md
```

---

## ⚖️ Legal Disclaimer

Phantom is intended for **authorized penetration testing and educational purposes only**. Use this tool only on systems where you have explicit, written permission. The author is not responsible for any misuse or damage caused by this program.

---

## 👨‍💻 Author

**Terminalkid09** – [GitHub](https://github.com/Terminalkid09)
