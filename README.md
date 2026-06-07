# Phantom 🛡️❤️

[![Version](https://img.shields.io/badge/version-2.0.0-red.svg)](CHANGELOG.md)
[![GitLab CI](https://gitlab.com/Terminalkid09/phantom/badges/main/pipeline.svg)](https://gitlab.com/Terminalkid09/phantom/-/commits/main)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Phantom** is an offensive security CLI framework that orchestrates the penetration testing lifecycle — from reconnaissance and OSINT to exploitation, C2 operations, and reporting — in a single interactive session.

Built for speed and flexibility, Phantom automates multi-step workflows while keeping every external command visible and controllable.

---

## 🚀 Key Features

### 🧩 Extensible Architecture
- **Plugin System**: Drop Python modules into `~/.phantom/plugins/` or `phantom/plugins/`.
- **12+ Built-in Modules**: `scan`, `osint`, `wifi`, `web`, `brute`, `exploit`, `payload`, `handler`, `pivot`, `analyzer`, `report`, and `c2`.
- **AI Integration** (optional): CVE interpretation and executive summaries via OpenAI or Ollama.

### ⚙️ Smart Workflows
- **Mode-Driven Execution**: Preset modes (`recon`, `osint`, `full`, `exploit`) run module sequences automatically.
- **`--auto` flag**: Skip confirmation prompts during `run`.
- **Interactive Command Preview**: Preview, edit, or skip commands before execution.
- **Scope Enforcement**: Blocks out-of-scope targets before commands run.

### 📊 Advanced Data Management
- **Scan History & Diff**: Track attack-surface changes over time.
- **Wordlist Manager**: Indexes SecLists, Dirb, and custom wordlists.
- **Report Engine**: Export to **JSON**, **HTML**, and **PDF**.
- **Session Persistence**: Atomic saves of notes, history, and results.

### 📡 WiFi Offensive Module
- Monitor mode, WPA/WPA2 handshake capture, PMKID, WPS brute force, post-crack pivot.

### 🎯 C2 Operations Center
- **Async C2 Server**: `aiohttp` listener with sleep/jitter (5s ±30%).
- **AES-256-CBC**: Encrypted beacon ↔ server traffic (keys from `.env`, embedded at compile time).
- **Cross-Platform C++ Beacon**: Windows, Linux, macOS, Android (ARM64).
- **Agent capabilities**: Recon, file transfer (`download`/`upload`), TCP port forwarding, OS shell execution, context-aware keylogger (Windows).
- **`beacons`**: Active callback sessions with telemetry.
- **`payloads`**: History of generated dropper one-liners (survives screen clears).
- **`generate`**: Auto-compile beacon + platform dropper (PowerShell, Bash, ADB).
- **HTTPS**: Automatic on ports 443/8443.
- **GitLab CI**: Multi-platform beacon builds via MinGW, g++, NDK.

### 🔍 CVE Intelligence
- NVD API integration with **24h cache**, rate limiting, and optional `NVD_API_KEY`.
- Exploitability scoring (CVSS + ExploitDB + MSF + GitHub PoC).
- Light service summary during scan; full correlation in `use exploit → run`.

### 🛡️ Safety & Reliability
- Input validation on targets (anti-injection).
- Tool availability checks before execution.
- Terminal integrity handling (termios).
- Docker-ready Kali-based image.

---

## ⚙️ Configuration

Copy the example environment file and set your secrets:

```bash
cp .env.example .env
```

| Variable | Required | Description |
| :--- | :---: | :--- |
| `PHANTOM_C2_KEY` | Recommended | AES key — **exactly 32 bytes** (recompile beacons after change) |
| `PHANTOM_C2_IV` | Recommended | AES IV — **exactly 16 bytes** |
| `PHANTOM_PAYLOAD_TOKEN` | Recommended | Auth token for beacon download endpoints |
| `NVD_API_KEY` | Optional | NVD API key (50 req/30s vs 5 without) |
| `AI_PROVIDER` / `AI_API_KEY` | Optional | OpenAI or Ollama integration |

`.env` is searched in: project root → `~/.phantom/.env` → `~/.env` → package dir.

> **Important:** After changing `PHANTOM_C2_KEY` or `PHANTOM_C2_IV`, regenerate beacons with `generate` or `deploy-agent`.

---

## 🐳 Docker Deployment

```bash
# 1. Configure secrets
cp .env.example .env
# Edit .env with your C2 keys and optional NVD API key

# 2. Build and start (detached)
docker compose up --build -d

# 3. Connect to the interactive CLI
docker exec -it phantom-framework python3 -m phantom.main
```

The image is based on **Kali Rolling** with nmap, sqlmap, aircrack-ng, hydra, hashcat, gobuster, nikto, ffuf, tshark, exploitdb, and the full C++ build chain (g++, mingw-w64, Android NDK).

**After changing `.env` keys**, rebuild the image so beacons embed the new crypto material:

```bash
docker compose build --no-cache && docker compose up -d
```

C2-only mode:

```bash
docker exec -it phantom-framework python3 -m phantom.main --c2
```

---

## ⌨️ Core Commands

| Command | Description |
| :--- | :--- |
| `set target <ip/domain>` | Define the current testing target. |
| `set mode <recon/full/...>` | Select the automation workflow. |
| `set scope <ip,cidr,...>` | Define authorized testing boundaries. |
| `run` | Execute the selected mode sequence (confirms unless `--auto`). |
| `use <module>` | Enter a specific module interactively. |
| `c2` | Enter the C2 Operations Center. |
| `scan-diff <target>` | Compare scan results with previous runs. |
| `wordlists list/use/search` | Manage attack wordlists. |
| `save-session <name>` | Save target, notes, and results. |
| `export <pdf/html/json>` | Generate a report. |
| `help` | Show the command reference. |

### CLI Flags

```bash
phantom              # Main pentest shell
phantom --c2         # C2 Operations Center only
phantom --auto       # Run mode sequences without confirmation
phantom --profile X  # Load a saved profile at startup
```

---

## 🛠️ Modules Overview

| Module | Purpose | Key Tools |
| :--- | :--- | :--- |
| **Scan** | Active reconnaissance | `nmap`, `traceroute`, service enum |
| **OSINT** | Passive intelligence | `crt.sh`, Shodan, BGP, Whois |
| **WiFi** | Wireless attacks | `aircrack-ng`, `reaver`, `hcxdumptool` |
| **Web** | Web application testing | `gobuster`, `sqlmap`, `nikto`, `ffuf` |
| **Brute** | Credential auditing | `hydra`, `medusa`, `john`, `hashcat` |
| **Exploit** | CVE correlation & Actionable PoCs | `fire <cve>`, NVD, searchsploit, `deploy-agent` |
| **Payload** | Payload generation & PrivEsc | `msfvenom`, `privesc`, custom C2 droppers |

---

## 📡 C2 Operations Center (v2.0.0)

The Phantom C2 is an asynchronous Command & Control center built for stealthy operations and robust agent management.

### 🛡️ Professional Evasion & OPSEC
- **String Obfuscation**: All sensitive strings (commands, JSON keys, API paths) are XOR-encrypted at compile-time using `XOR_STR`.
- **Anti-Analysis**: Agent detects debuggers (`IsDebuggerPresent`) and VM/Sandbox environments (CPU/RAM checks) to prevent analysis.
- **Stalling Techniques**: Uses complex mathematical loops to frustrate automated sandbox detonation.
- **LOLBins Deployment**: Uses `certutil` for stealthy Windows downloads, bypassing common PowerShell monitoring.
- **Async Traffic**: C2 traffic is encrypted (AES-256-CBC) and features randomized **Jitter** to break timing signatures.

### ⌨️ C2 Shell Commands

| Command | Description |
| :--- | :--- |
| `listeners start/stop` | Manage the `aiohttp` listener (supports HTTPS). |
| `beacons` | List all active agent check-ins and telemetry. |
| `interact <id>` | Drop into an interactive session with a specific beacon. |
| `payloads` | View the history of generated dropper commands. |
| `generate <platform>` | Compile a custom agent and generate a dropper. |
| `results` | View output from queued tasks. |
| `beacon-help` | Show commands supported by the C++ agent. |

### 🎯 Actionable Exploitation
The `exploit` module now features a **PoC Repository**:
- `fire <cve_id>`: Automatically locates a local PoC for a specific CVE and executes it against the target.
- Intelligent port selection based on previous scan results.
| **Handler** | Listener management | Metasploit `multi/handler` |
| **Analyzer** | Traffic analysis | `scapy`, `tshark` |
| **Pivot** | Tunneling | SSH forwards, Chisel |
| **Report** | Report generation | JSON, HTML, PDF |
| **C2** | Command & control | Encrypted beacon, async server |

---

## 📥 Installation

### Prerequisites
- Python 3.10+
- Security tools (pre-installed on Kali/Parrot): `nmap`, `sqlmap`, `gobuster`, etc.

### From Source
```bash
git clone https://github.com/Terminalkid09/phantom.git
cd phantom
cp .env.example .env   # configure secrets
pip install -e .
phantom
```

---

## 🏁 Quick Start

### Pentest Mode
```bash
phantom
set target scanme.nmap.org
set scope 45.33.32.156
set mode full
run                    # or: phantom --auto

use report
export pdf report.pdf
```

### C2 Operations
```bash
phantom --c2

# Start listener and compile beacon + dropper
listeners start 443
generate linux

# View history of generated droppers
payloads
payloads <id-prefix>

# Active beacons
beacons
interact PHANTOM-TARGET    # prefix match supported
beacon-help                # list agent commands

# Run commands on the agent (built-in or OS shell)
whoami
shell ipconfig
ls C:\
download C:\Users\Public\file.txt   # saved to data/downloads/
results

back
```

### Deploy Agent from Exploit Module
```bash
phantom
use exploit
deploy-agent linux
# Compiles beacon, shows dropper, saves to payload history
# Then: c2 → listeners start → beacons
```

---

## 📝 Extending Phantom (Plugins)

```python
from phantom.modules.base_module import BaseModule

class MyTool(BaseModule):
    module_name = "mytool"

    def build_commands(self):
        return {"CUSTOM": ["echo 'custom logic'"]}

    def do_run(self, _):
        pass
```

Drop the file in `~/.phantom/plugins/` — it loads on next session.

Dynamic exploits go in `phantom/exploits/<category>/` with a `METADATA` dict and `run(target, port, **kwargs)` function.

---

## 🏗️ Project Structure

```
phantom/
├── phantom/
│   ├── core/              # Shell, session, executor, C2 server/shell
│   ├── modules/           # scan, osint, wifi, web, brute, exploit, ...
│   ├── plugins/           # AI connector, custom extensions
│   ├── exploits/          # Dynamic exploit scripts (Python/Bash)
│   ├── payloads/beacon/   # C++ agent (crypto, network, recon, keylogger)
│   └── utils/             # API, builder, paths, payload manager, ...
├── data/
│   ├── sessions/          # Scan XML, saved sessions
│   ├── cache/             # NVD CVE cache (24h TTL)
│   └── downloads/         # Files exfiltrated via beacon
├── scripts/               # CI helpers (beacon crypto generation)
├── tests/                 # 167+ pytest unit tests
├── .env.example           # Environment template
├── Dockerfile             # Kali-based container
├── docker-compose.yml     # One-command deployment
└── README.md
```

---

## ⚖️ Legal Disclaimer

Phantom is intended for **authorized penetration testing and educational purposes only**. Use only on systems where you have explicit, written permission. The author is not responsible for any misuse or damage caused by this program.

---

## 👨‍💻 Author

**Terminalkid09** – [GitHub](https://github.com/Terminalkid09)
