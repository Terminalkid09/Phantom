# Phantom

[![Version](https://img.shields.io/badge/version-2.0.0-red.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)]()

Phantom is an offensive security framework combining a full-featured C2 platform with a modular penetration testing CLI. The C2 beacon runs on Windows (x64), Linux (x64/x86), macOS, and Android (ARM64), communicating over AES-256-GCM encrypted channels with sleep/jitter OPSEC.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         C2 Server (aiohttp)                        │
│  HTTP/HTTPS Listener      Task Queue        Beacon Registry        │
└────────────────────┬────────────────────────────────────────────┘
                     │ AES-256-CBC encrypted channel
                     │ GET /x (payload)  POST /submit  GET /tasks
                     │
          ┌──────────┴──────────┐
          │   Windows Beacon    │
          │  (reflective load)  │
          └──────────┬──────────┘
                     │
       ┌─────────────┼─────────────┐
       │             │             │
   SOCKS5 Proxy  SMB Pipe    Browser Pivot
   (tcp relay)  (named-pipe)  (http tunnel)
```

The reflective loader is appended to the beacon PE and loaded entirely in memory:
```
[reflective_loader.bin | beacon.exe]
         ▲ entry @ offset 0     ▲ MZ at offset stored in loader
```

---

## C2 Features

### Core Capabilities

| Feature | Description |
| :--- | :--- |
| **Reflective In-Memory Loader** | PE is mapped, relocations applied, imports resolved, and DllMain called directly from memory -- no write-to-disk. Combined assembly entry + C core for performance and evasion. |
| **AES-256-GCM Encryption** | All C2 traffic encrypted with authenticated encryption. Keys embedded at compile time via `crypto_config.h`. |
| **Sleep / Jitter** | Configurable interval (min 1s) with randomized jitter (±30%) to break timing signatures. |
| **Memory Sleep Masking** | `.data` / `.rdata` sections XOR-encrypted during sleep intervals (`.text` excluded to avoid thread crashes). |
| **Indirect Syscalls (Hell's Gate)** | NT API calls resolved at runtime via PEB walking -- no ntdll import table. |
| **Hardware Breakpoint Clearing** | DR0-DR3 registers zeroed before every C2 check-in cycle. |
| **CPU Telemetry Flush** | `cpuid` instruction executed before each command dispatch to flush CPU pipeline telemetry. |
| **AMSI / ETW Patching** | Native patches `amsi.dll` and `ntdll.dll` ETW functions via indirect syscalls. |
| **VM / Sandbox Detection** | CPU count, RAM size, debugger presence checks with configurable stalling loops. |
| **Process Hollowing Dropper** | Pure PowerShell stager uses `NtCreateProcess`, `NtUnmapViewOfSection`, `NtGetContextThread`, `NtSetContextThread` -- no C#, no reflective DLL loading in the stager. |

### Network Pivoting

| Feature | Description |
| :--- | :--- |
| **SOCKS5 Proxy** | Full SOCKS5 handshake (no-auth, CONNECT) with TCP relay via `select()`. Start with `socks <port>`, stop with `socks-stop`. |
| **SMB Named-Pipe C2** | Egress-less C2 channel using `CreateNamedPipeA` with a length-prefixed protocol. Background listener thread, commands queued for main loop dispatch. Start with `smb-pipe <name>`, stop with `smb-pipe-stop`. |
| **Browser Pivot** | HTTP CONNECT proxy + direct HTTP forwarding through the beacon process. Discovers browser PIDs via `CreateToolhelp32Snapshot`. Start with `browser-pivot <port> [pid]`, stop with `browser-pivot-stop`. List browsers with `browser-list`. |
| **CDP Browser Pivot** | Chrome DevTools Protocol integration (Chrome / Chromium only — Firefox not supported). Launches Chrome with `--remote-debugging-port`, connects via WebSocket, and enables authenticated browsing through the user's Chrome session. Supports `cdp-cookies` (read all cookies), `cdp-eval` (execute JavaScript), `cdp-nav` (navigate to URL), `cdp-fetch` (make authenticated HTTP requests through Chrome). |
| **Connection Monitor** | `netstat` / `netstat-json` — real-time TCP connection listing with PID and process name resolution via `GetExtendedTcpTable`. No admin required. |
| **Cookie Stealer** | `cookies` / `cookies-json` — reads Chrome's encrypted cookie database (SQLite format parsed inline), decrypts each value with DPAPI (`CryptUnprotectData`), and returns host, name, path, and decrypted value. |
| **TCP Port Forward** | Classic `portfwd <lport> <rhost> <rport>` / `portfwd-stop`. |

### Agent Commands

| Command | Parameters | Description | Platform |
| :--- | :--- | :--- | :--- |
| `recon` | `<path>` | File system reconnaissance | All |
| `ls` / `dir` | `[path]` | List directory contents | All |
| `drives` | - | Enumerate drives / mount points | All |
| `whoami` | - | Current user and hostname | All |
| `sysinfo` | - | Comprehensive system information | All |
| `netinfo` | - | Network interfaces and configuration | All |
| `processes` | - | Running process list | All |
| `find` | `<root> <pattern>` | Recursive file search | All |
| `pwd` | - | Current working directory | All |
| `cd` | `<path>` | Change directory | All |
| `cat` | `<file>` | Display file contents (max 1MB) | All |
| `download` | `<path>` | Exfiltrate file (Base64, max 10MB) | All |
| `upload` | `<path> <b64>` | Upload file to target | All |
| `shell` / `exec` / `run` | `<cmd>` | Arbitrary OS command | All |
| `sleep` | `<ms>` | Set beacon sleep interval (min 1000ms) | All |
| `persist` | `[name]` | Establish persistence (RunKey / autostart) | Win/Linux |
| `exit` / `kill` | - | Terminate beacon | All |
| `screenshot` | - | Capture screen (BMP Base64) | Win/Linux |
| `keylog` | `<start\|stop\|dump>` | Context-aware keylogger | Win/Linux |
| `inject` | `<pid> <b64>` | Inject shellcode/binary into remote process | Win/Linux/Android |
| `migrate` | `<b64>` | Migrate beacon to new process | Win/Linux/Android |
| `mem-run` | `<b64>` | Execute shellcode/binary in memory | Win/Linux/Android |
| `portfwd` | `<lport> <rhost> <rport>` | TCP port forward | All |
| `portfwd-stop` | - | Stop all port forwards | All |
| `socks` | `<port>` | Start SOCKS5 proxy | Win |
| `socks-stop` | - | Stop SOCKS5 proxy | Win |
| `smb-pipe` | `<name>` | Start SMB named-pipe listener | Win |
| `smb-pipe-stop` | - | Stop SMB pipe listener | Win |
| `browser-pivot` | `<port> [pid]` | Start browser HTTP proxy | Win |
| `browser-pivot-stop` | - | Stop browser proxy | Win |
| `browser-list` | - | List running browser processes | Win |
| `cdp-launch` | `[port]` | Launch Chrome with remote debugging port | Win |
| `cdp-cookies` | `[port]` | Read all cookies via CDP (Chrome DevTools Protocol) | Win |
| `cdp-eval` | `<expr>` | Evaluate JavaScript in Chrome via CDP | Win |
| `cdp-nav` | `<url>` | Navigate Chrome to URL via CDP | Win |
| `cdp-fetch` | `<url>` | Fetch URL through Chrome (authenticated session) | Win |
| `netstat` | - | Active TCP connections with process names | Win |
| `netstat-json` | - | Active connections as JSON | Win |
| `cookies` | - | Decrypt Chrome cookies via DPAPI (SQLite) | Win |
| `cookies-json` | - | Decrypted cookies as JSON | Win |
| `wlan-scan` | - | Scan Wi-Fi APs | Win/Linux/Android |
| `wlan-locate` | - | Wi-Fi scan (JSON for geolocation) | Win/Linux/Android |
| `bt-scan` | - | Scan Bluetooth devices | Win/Linux/Android |
| `bt-scan-json` | - | Bluetooth scan (JSON) | Win/Linux/Android |

---

## C2 Shell Commands

| Command | Description |
| :--- | :--- |
| `listeners start/stop <port>` | Manage HTTP/S listener |
| `beacons` | List active beacon sessions |
| `interact <id>` | Enter interactive beacon session |
| `generate <platform>` | Compile beacon + dropper |
| `payloads` | Show generated payload history |
| `results` | View queued task output |
| `beacon-help` | Show agent command reference |

### Drop into C2 Mode

```bash
phantom --c2
```

---

## Installation

### Docker (Recommended)

Choose the right command for your OS:

**Linux** (host networking — full LAN access for scan modules):
```bash
cp .env.example .env
# Edit PHANTOM_C2_KEY, PHANTOM_C2_IV, PHANTOM_PAYLOAD_TOKEN
docker compose -f docker-compose.yml -f docker-compose.linux.yml up --build -d
docker exec -it phantom-framework python3 -m phantom.main
```

**Windows / macOS** (port mapping — limited to container's network namespace):
```bash
cp .env.example .env
docker compose up --build -d
docker exec -it phantom-framework python3 -m phantom.main
```

The Docker image includes Kali Rolling with the full cross-compilation toolchain (MinGW-w64, Android NDK r26c, osxcross), plus tools for every pentest phase.

### Bare Metal

```bash
git clone https://github.com/Terminalkid09/phantom.git
cd phantom
cp .env.example .env
pip install -e .
phantom
```

### Cross-Compile Beacon (Inside Docker)

```bash
# Windows (x64)
x86_64-w64-mingw32-g++ -std=c++20 -O2 -s -o beacon.exe -Isrc src/main.cpp \
    src/syscalls.o src/reflective_loader_bootstrap.o src/reflective_loader.o \
    -lwinhttp -lbcrypt -lws2_32 -lbthprops -lwlanapi -liphlpapi -lcrypt32 -static -mwindows

# Linux
g++ -std=c++17 -O2 -s -o beacon -Isrc src/main.cpp -lcurl -lssl -lcrypto -lpthread

# Android (ARM64)
aarch64-linux-android28-clang++ -std=c++17 -O2 -s -o beacon_android -Isrc src/main.cpp \
    -lcurl -lssl -lcrypto -static

# macOS (with osxcross)
o32-clang++ -std=c++17 -O2 -o beacon_macos -Isrc src/main.cpp \
    -lcurl -lssl -lcrypto -lpthread -isysroot /opt/osxcross/SDK/MacOSX.sdk
```

---

## Configuration

Copy the example environment file and set your secrets:

```bash
cp .env.example .env
```

| Variable | Required | Description |
| :--- | :---: | :--- |
| `PHANTOM_C2_KEY` | Recommended | AES-256 key -- exactly 32 bytes (recompile beacons after change) |
| `PHANTOM_C2_IV` | Recommended | AES IV -- exactly 16 bytes |
| `PHANTOM_PAYLOAD_TOKEN` | Recommended | Auth token for beacon download endpoints |
| `NVD_API_KEY` | Optional | NVD API key (50 req/30s vs 5 without) |
| `AI_PROVIDER` / `AI_API_KEY` | Optional | OpenAI or Ollama integration |

`.env` is searched in: project root, `~/.phantom/.env`, `~/.env`, package dir.

> Important: After changing PHANTOM_C2_KEY or PHANTOM_C2_IV, regenerate beacons with `generate` or `deploy-agent`.

---

## Modules Overview

| Module | Purpose | Key Tools |
| :--- | :--- | :--- |
| **Scan** | Active reconnaissance | nmap, traceroute, service enum |
| **OSINT** | Passive intelligence | crt.sh, Shodan, BGP, Whois |
| **WiFi** | Wireless attacks | aircrack-ng, reaver, hcxdumptool |
| **Web** | Web application testing | gobuster, sqlmap, nikto, ffuf |
| **Brute** | Credential auditing | hydra, medusa, john, hashcat |
| **Exploit** | CVE correlation and PoC deployment | fire \<cve\>, NVD, searchsploit, deploy-agent |
| **Payload** | Payload generation and priv esc | msfvenom, privesc, custom C2 droppers |
| **Handler** | Listener management | Metasploit multi/handler |
| **Analyzer** | Traffic analysis | scapy, tshark |
| **Pivot** | Tunneling | SSH forwards, Chisel |
| **Report** | Report generation | JSON, HTML, PDF |
| **C2** | Command and control | Encrypted beacon, async server |

### CLI Flags

```bash
phantom              # Main pentest shell
phantom --c2         # C2 Operations Center only
phantom --auto       # Run mode sequences without confirmation
phantom --profile X  # Load a saved profile at startup
```

### CVE Intelligence

- NVD API integration with 24h cache, rate limiting, and optional `NVD_API_KEY`.
- Exploitability scoring (CVSS + ExploitDB + MSF + GitHub PoC).
- Light service summary during scan; full correlation in `use exploit -> run`.

### Wireless Hardware Diagnostics

When `wlan-scan` or `bt-scan` encounters hardware issues, diagnostic information is returned.

#### WLAN Diagnostics (Windows)

The scanner reports the number of wireless interfaces found, their GUIDs and states (`connected`, `disconnected`, `not_ready`, etc.). If no access points are found, a `[DEBUG]` line shows the interface status.

**Common causes for "No access points found" on a laptop with WiFi:**
- WiFi is turned off via software toggle (Action Center) → interface state is `not_ready`
- Airplane mode is enabled
- WiFi adapter is disabled in Device Manager
- WLAN AutoConfig service is not running
- The scan timeout (8 seconds) was insufficient — scanner now polls every 2s up to 8s

**Diagnostic output example:**
```
WLAN scan: No access points found.
[DEBUG] [IFACE 0] GUID=XXXX... state=disconnected
```

#### Bluetooth Diagnostics (Windows)

| Condition | Output |
| :--- | :--- |
| No Bluetooth adapter | `BT scan: No Bluetooth devices found (adapter may be unavailable).` |
| Adapter present, no paired/discovered devices | Empty list returned |

#### Error Codes Reference

| Error | Meaning |
| :--- | :--- |
| `WlanOpenHandle failed: code=N` | WLAN API initialization failed. Check if WLAN AutoConfig service is running. |
| `WlanEnumInterfaces failed: code=N` | No 802.11 interfaces found, or permission denied. |
| `WlanScan returned error N` | Scan trigger failed; `WlanGetNetworkBssList` may still return cached data. |
| `WlanGetNetworkBssList failed` | Unable to read BSS list — interface may be disabled or unavailable. |

#### Keylogger Notes

The keylogger uses **polling** (`GetAsyncKeyState` every 20ms) rather than a `SetWindowsHookEx` hook. This means:
- Works without admin privileges
- No global hook DLL needed
- **Must follow this sequence:** `keylog start` → **wait for result** → type → `keylog dump`
- If `start` and `dump` are queued together, dump executes before any keys are polled
- The buffer captures standard ASCII, Unicode (via `ToUnicode`), and special keys (`[BKSP]`, `[ENTER]`, `[DEL]`, `[F1]`-`[F24]`, arrows, etc.)
- Buffer is cleared after each `dump`

---

## Reflective Loader Details

The reflective loader (`reflective_loader_bootstrap.asm` + `reflective_loader.c`) is responsible for mapping the beacon PE into memory without touching disk.

### Bootstrap (Assembly)

The entry point at file offset 0:
1. Walks the PEB to find `kernel32.dll` base address
2. Resolves `GetProcAddress` and `LoadLibraryA` by hash
3. Resolves `VirtualAlloc`, `VirtualFree`, and `VirtualProtect`
4. Calls the C core with a pointer to the raw PE data

### C Core (Freestanding)

Compiled with `-nostdlib -ffreestanding -fPIC` for position-independent x64 code:
1. **Header validation** -- confirms `MZ` and `PE\0\0` signatures
2. **Section mapping** -- `VirtualAlloc` at the preferred base, copies headers and sections
3. **IAT resolution** -- walks import descriptors, loads required DLLs via `LoadLibraryA`, resolves function addresses via `GetProcAddress` (with ordinal support)
4. **Base relocations** -- applies `IMAGE_BASE_RELOCATION` fixups when the PE cannot load at its preferred address
5. **TLS callbacks** -- executes TLS callback routines if present
6. **DllMain entry** -- calls the PE entry point with `DLL_PROCESS_ATTACH`

### Payload Assembly

The `builder.py` pipeline:
```
reflective_loader_bootstrap.asm ──[MinGW as]──> .o
reflective_loader.c ──[MinGW gcc -nostdlib -ffreestanding]──> .o
  └── link ──> reflective_loader.exe ──[objcopy -O binary]──> reflective_loader.bin
  └── patch DLL offset marker ──> prepend to beacon.pe ──> XOR encrypt ──> beacon_xored.bin
```

The stager downloads `beacon_xored.bin`, decrypts it in memory, and calls offset 0 directly -- no intermediate file writes.

---

## Quick Start

### Full Pentest Mode

```bash
phantom
set target example.com
set scope 93.184.216.0/24
set mode full
run

# Export findings
use report
export pdf report.pdf
```

### C2 Operations

```bash
phantom --c2
listeners start 443
generate windows
# Copy the PowerShell one-liner to target
beacons
interact PHANTOM-00
whoami
sysinfo
shell ipconfig /all
download C:\Users\Public\report.pdf
```

### Deploy Agent from Exploit Module

```bash
phantom
use exploit
deploy-agent linux
# Compiles beacon, shows dropper, saves to payload history
# Then: c2 -> listeners start -> beacons
```

---

## Extending Phantom

### Plugins

Drop a Python module into `~/.phantom/plugins/`:

```python
from phantom.modules.base_module import BaseModule

class MyTool(BaseModule):
    module_name = "mytool"

    def build_commands(self):
        return {"CUSTOM": ["echo 'custom logic'"]}

    def do_run(self, _):
        pass
```

### Custom Exploits

Add dynamic exploits in `phantom/exploits/<category>/` with a `METADATA` dict and `run(target, port, **kwargs)` function.

### AI Integration (Optional)

Set `AI_PROVIDER` and `AI_API_KEY` in `.env` for CVE interpretation and executive summaries via OpenAI or Ollama.

---

## Project Structure

```
phantom/
├── phantom/
│   ├── core/                   # Shell, C2 server, session management
│   ├── modules/                # scan, osint, wifi, web, brute, exploit, ...
│   ├── plugins/                # AI connector, custom extensions
│   ├── exploits/               # Dynamic exploit scripts
│   └── utils/                  # builder.py, c2_crypto.py, payload_manager.py
├── phantom/payloads/beacon/
│   └── src/
│       ├── main.cpp            # Beacon entry, C2 loop, command dispatch
│       ├── reflective_loader.c           # PE mapper (C, PIC)
│       ├── reflective_loader_bootstrap.asm # Assembly entry (PIC)
│       ├── syscalls.asm / .o             # Indirect syscalls
│       ├── proxy.h             # SOCKS5 proxy
│       ├── smb.h               # SMB named-pipe C2
│       ├── browser_pivot.h     # Browser HTTP proxy pivot
│       ├── portfwd.h           # TCP port forwarding
│       ├── crypto.h            # AES-256-GCM, Base64
│       ├── network.h           # HTTPS C2 transport
│       ├── evasion.h           # AMSI/ETW patch, VM detect
│       ├── injection.h         # Remote thread injection
│       ├── inmemory.h          # Shellcode execution
│       ├── keylogger.h         # Context-aware keylogger
│       ├── screenshot.h        # GDI screen capture
│       ├── persistence.h       # Registry autostart
│       ├── sleep_mask.h        # Memory encryption during sleep
│       ├── netstat.h           # TCP connection monitor
│       ├── cookie_stealer.h    # Chrome cookie decryption (DPAPI + inline SQLite)
│       ├── cdp_pivot.h         # Chrome CDP browser pivot (WebSocket)
│       ├── wlan_scan.h         # Wi-Fi scanning
│       └── bt_scan.h           # Bluetooth scanning
├── data/                       # Sessions, cache, downloads
├── Dockerfile                  # Multi-stage build
├── docker-compose.yml          # One-command deployment
└── .env.example                # Environment template
```

---

## Safety and Reliability

- Input validation on targets (anti-injection).
- Tool availability checks before execution.
- Terminal integrity handling (termios).
- Scope enforcement blocks out-of-scope targets before commands run.
- Session persistence with atomic saves of notes, history, and results.

---

## Feature Status

| Feature | Status | Notes |
| :--- | :---: | :--- |
| **Sysinfo / Pwd / Ls / Cd** | ✅ Verified | Works on all platforms |
| **Shell / Exec** | ✅ Verified | stdout captured correctly |
| **Screenshot** | ✅ Verified | Full resolution BMP (no downscale). Win: GDI. Linux: `import`/`gnome-screenshot`/`scrot`. |
| **Netstat / Netstat-JSON** | ✅ Verified | Real TCP connections with PID/process name. Win: `GetExtendedTcpTable`. Linux: `/proc/net/tcp`. |
| **Keylogger** | ✅ Verified | Win: `GetAsyncKeyState` polling. Linux: evdev `/dev/input/event*` via `select()`. |
| **WLAN Scan** | ⚠️ Needs hardware | Full diagnostics at every failure point (LoadLibrary, WlanOpenHandle, WlanEnumInterfaces, WlanScan, WlanGetNetworkBssList). 0-interface detection, per-interface GUID/state reporting, error codes. |
| **WLAN Locate** | ⚠️ Needs hardware | Diagnostic output mirrors WLAN Scan; reports "No access points found" with debug info instead of empty `[]`. |
| **BLuetooth Scan** | ⚠️ Needs hardware | No error entries pushed as devices. Returns real MAC addresses on hardware with BT. |
| **Cookies (Chrome DPAPI)** | ⚠️ Needs Chrome | Code compiles and runs; requires Chrome installed + cookies DB accessible. |
| **CDP Browser Pivot** | ⚠️ Needs Chrome | Chrome/Chromium only; WebSocket CDP protocol implemented. |
| **Inject / Migrate** | ✅ Verified | Win: process hollowing + remote thread injection via indirect syscalls. Linux/Android: ptrace + `process_vm_writev`, ELF binary detection writes to `/tmp/.ph_*` and injects `execve` shellcode. |
| **Autopersist (RunKey)** | ✅ Verified | Downloads `beacon_xored.bin` from C2 (GET `/x`) → saves to `%APPDATA%\Microsoft\Phantom\phantom.dat` → writes PowerShell loader `phantom.ps1` (Add-Type + VirtualAlloc) → Run key executes PS1 on logon. PS1 here-string syntax fixed. |
| **ntdll Unhooking** | ✅ Implemented | Reloads clean `.text` from disk via indirect syscalls |
| **AMSI / ETW Patch** | ✅ Implemented | Patches via indirect syscalls at startup |
| **Indirect Syscalls** | ✅ Implemented | Hell's Gate + gadget finder, 12+ NTAPI wrappers |
| **Stack Spoofing** | ✅ Implemented | RET gadget from ntdll, 5 Win32 wrappers |
| **Sleep Mask** | ✅ Implemented | XOR encrypts `.data`/`.rdata` during sleep |
| **Sandbox Evasion** | ✅ Implemented | CPU <2, RAM <2GB, VM driver checks |
| **Anti-Debug** | ✅ Implemented | PEB BeingDebugged, DR0-DR3 clear, CPUID flush |

---

## Legal Disclaimer

Phantom is intended for authorized penetration testing and educational purposes only. Use only on systems where you have explicit, written permission. The author is not responsible for any misuse or damage caused by this program.

---

## Author

**Terminalkid09** -- [GitHub](https://github.com/Terminalkid09)
