# Phantom

[![Version](https://img.shields.io/badge/version-3.0.0-red.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20Android%20%7C%20macOS-lightgrey.svg)]()
[![Tests](https://img.shields.io/badge/tests-verified-brightgreen.svg)]()

**Phantom** is an offensive security framework for red teams that combines a full-featured C2 platform, 12 interactive pentest modules, and an autonomous kill-chain engine — all in one tool. The C2 beacon runs on Windows, Linux, Android, and macOS, using AES-256-GCM + mTLS + per-beacon HMAC authentication.

Phantom also includes a **React + TypeScript Electron desktop app** (`electron/`) for campaign management, and an **autonomous agent** (`phantom/automation/`) that handles the full kill chain from reconnaissance to persistence without an LLM — fully offline, no data leaves your machine.

---

## Quick Start

### Docker (recommended — all dependencies included)

```bash
git clone https://github.com/Terminalkid09/phantom.git && cd phantom

# Windows (port mapping):
docker compose up --build -d
docker exec -it phantom-framework python3 -m phantom.main

# Linux / Kali (host networking for full LAN access):
docker compose -f docker-compose.yml -f docker-compose.linux.yml up --build -d
docker exec -it phantom-framework python3 -m phantom.main
```

### Bare Metal

```bash
git clone https://github.com/Terminalkid09/phantom.git && cd phantom
pip install -e .
phantom
```

> **Zero config needed.** On first run, Phantom auto-generates all C2 keys, tokens, and TLS certificates in `data/phantom_state.json` (gitignored, `0600`). You never hand-edit a `.env` for C2 keys. Only optional external APIs (NVD, SMTP, Telegram) need `.env` values — see [Configuration](#configuration).

### Windows + Kali WSL (operator toolbox bridge)

Phantom runs natively on Windows. Tools missing from the Windows PATH are
resolved through the **Kali WSL distro** automatically (`wsl -d kali-linux
nmap ...`): the agent's tool registry, the manual executor and the
credential verifiers (sshpass/smbclient) all bridge transparently. Install
your toolbox once inside WSL and Phantom finds it:

```powershell
wsl -d kali-linux sudo apt install nmap sshpass smbclient hydra ldap-utils
phantom            # native Windows shell, Kali tools just work
```

### First Commands

```bash
phantom                       # Main pentest shell
set target example.com        # Set your target — ALL types accepted:
                              #   ip | domain | url | email | username (dots ok: mario.rossi) | phone (+39...)
run                           # ADAPTIVE next step: reads target type + findings + reasoning,
                              #   proposes the best module with the reason, asks before running
run scan                      # or run a specific module directly
use <module> → preview        # review the command plan (no execution)
use <module> → run            # execute the interactive flow (preview ≠ run)

# Identity targets in the MANUAL core: email/username/phone are accepted by
# set target, `run` routes them to osint first (dossier before any network),
# and network modules warn when used against an identity target.

# AUTO-MODE has its own shell (like `c2`):
auto                              # enter the AUTO-MODE shell
targets add bob@corp.com,10.0.0.5 # multi-target list (add/rm/list)
scope add corp.com                # authorized targets
flags                             # show/change flags (aggressive, stealth, speed, agents, goal, profile, llm, experience)

# --profile models the DEFENDER stack the chain plans against:
#   smb | enterprise | cloud | financial | government | mobile
# (default: enterprise — assumes strong corporate defenses). The same
# action is treated as loud or quiet differently per profile: against
# financial/government even an active exploit scores as noisy, so the
# planner picks quieter paths first. A phone-number target (or any
# mobile-classified target) with the default profile auto-switches to
# the mobile defender model (OS sandbox, MDM/EMM, carrier SMS
# filtering) — explicit --profile choices always win.

# Run flags shape the recon depth AND the noise budget:
#   default/--stealth  -> full-range -p 1-65535 sweep (stealth uses slow -T2)
#   --speed/--aggressive -> fast top-100 ports (aggressive at higher rate)
# All scans run -sV: plain scans mislabel non-standard ports (2222 shows up
# as "EtherNetIP-1" from the nmap table) and break the service preconditions
# downstream. The chain always completes scan -> creds -> beacon deploy ->
# persistence -> reports -> C2 handoff (verified end-to-end in the lab).
plan                              # dry-run the planned kill chain
launch                            # run the chain (handoff to C2 on beacon)
resume checkpoint.json            # continue an interrupted run
export handoff.pm                 # ONE portable .pm per engagement
back                              # return to the main shell

# One-shot form still works:
auto bob@corp.com --stealth -a2   # run the chain directly

# Multi-operator handoff: the .pm bundles session + checkpoint + reports
export-session handoff.pm         # (from the main shell — ENCRYPTED by default)
# ...send handoff.pm to the other operator (any machine)...
import-session handoff.pm         # restores target/scope/notes/knowledge + reasoning
auto <target> --resume <cp>       # continue the kill chain from the checkpoint

# Auto-session: state is never lost, no action needed
#  - every open  -> registered in data/sessions/index.json
#  - every close -> encrypted .pm auto-saved (latest.pm + dated copy),
#                   even on double Ctrl+C (no prompt)
#  - next open   -> "Resume last engagement? [Y/n]" restores target/scope/
#                   knowledge + checkpoint, so `suggest`/planner work from
#                   the accumulated findings
list-sessions                      # manual .json + auto .pm bundles with metadata

# Every `auto` run writes a checkpoint each wave under data/sessions/auto_*/
# and can be resumed with `auto <target> --resume <checkpoint.json>`

phantom.c2                    # C2 Operations Center (direct entry point)
listeners start 8080          # Start HTTPS + mTLS listener
generate windows              # Compile beacon for Windows
beacons                       # List active sessions
interact PHANTOM-00           # Enter beacon terminal
audit                         # Immutable hash-chained activity log
audit verify                  # Prove the log was not altered (chain-of-custody)
```

### Trust-earned suggestions (manual core)

```text
suggest                 # evidence-tagged next steps:
                        #   why: service:tcp/445 + creds:ssh   <- findings behind it
                        #   ●●● 0.78                           <- trust score
                        #   missing:enum4linux                 <- preflight (tool absent)
                        #   ran-ok                             <- dedup vs history
plan beacon             # the planner's chain to a goal (nothing executes)
plan ad / plan creds / plan lateral
```

Every suggestion shows its reasoning — findings, trust score (evidence
strength blended with the technique's historical success rate) and
preflight state — so an operator can verify it in seconds instead of
abandoning the engine.

### Lure crafting (social / IP grabbers / AiTM / beacon delivery)

```text
craft ipgrab            # plain IP-grabber link (click = IP + fingerprint)
craft reel <link|term>  # video lure on a REAL video YOU pick: paste an
                        #   IG/TikTok/YT link to mirror, or a search term;
                        #   identifier stripped, click lands on the grabber
craft image <file|url>  # ZERO-CLICK image lure: hosts an image YOU choose;
                        #   when it RENDERS (email <img>/page/browser) the IP,
                        #   device and location are captured — no click
craft pixel             # 1x1 tracking pixel (same zero-click capture)
craft beacon [platform] # one-click beacon link DISGUISED as a reel URL;
                        #   platform defaults to `auto`: the tracker reads
                        #   the visitor's OS from the User-Agent and serves
                        #   the matching binary (pin a platform to override)
craft beacon-player [os] # upgraded delivery: the reel page plays a REAL
                        #   video; the play click downloads the beacon as
                        #   video-<code>.mp4 (fail-soft: if the C2 is down the
                        #   page just looks like it won't load)
craft aitm <login-url>  # ENTERPRISE, opt-in (phishing.aitm=true): an
                        #   AiTM reverse proxy — the tracker FETCHES the
                        #   provider's REAL login page, serves it from your
                        #   host and relays the submission upstream, keeping
                        #   the credentials AND the session cookies issued
                        #   after the second factor (that is what beats
                        #   plain MFA). Needs a domain with TLS in front;
                        #   fails against FIDO2/passkeys and pinned clients
craft hits <code>       # every hit/open/cred/session + device, browser, geo
craft sessions <code>   # sessions taken by an AiTM mount (cookies = the
                        #   logged-in browser, MFA already satisfied)
craft wait <code> [s]   # live-wait for the target
map [cidr]              # discover every device on the network
                        #   (arp-scan → nmap -sn → ping) → feeds the network map
                        #   + detects the LAN topology (star / broadcast / tree),
                        #   fingerprints each device (open ports, services, OS
                        #   guess) and ranks the most exposed ones
                        #   live status: ● alive / ○ offline (offline devices are
                        #   shown faded and are NEVER ranked as targets)
install <tool>          # install a missing tool in the current backend
                        #   (apt / brew / choco / pip auto-selected, WSL on Windows)
```

**AiTM (the enterprise path).** A lure we wrote is still OUR page — real
providers change markup, and a clone has a smell. The opt-in `craft aitm`
relay is the other family: it serves the provider's own page fetched live and
relays the login back, so the page IS authentic and the captured cookies are
the logged-in session (MFA already answered). It is **off by default**
(`phishing.aitm` / `PHANTOM_AITM`), it needs a **domain with TLS** in front
(an IP or a free hosting hostname is the technique's ceiling), and it is never
wired to the auto-mode: it is credential theft against a live service, so it
stays an operator decision on a contracted engagement. It does not defeat
phishing-resistant MFA (FIDO2/passkeys) or certificate-pinned clients.

**Honest limitation:** no image can install a beacon with zero interaction —
that is 0-day territory, not a tool feature. What Phantom ships is the
closest real thing: an **image / pixel that captures the IP, device
fingerprint and location the moment it renders** (the "zero-click" part —
rendering needs no click), real **reel-style links on videos you choose**
(the share link strips the author's identifier), and a **beacon link
disguised as a shared reel** that downloads the compiled implant in one tap.
The upgraded `craft beacon-player` goes further: the reel page plays a real
video and the play click downloads the implant as a `.mp4` — still one click
(the platform never auto-runs a download), but it survives the target
actually watching the video, and fails soft ("page won't load") when the C2
is down. In the auto-mode the same engine already prefers Instagram reels for
identity/mobile targets: it picks a real video by the target's discovered
interests and sends the identifier-free share link. Geo needs either
`PHANTOM_GEOIP_DB` (offline MaxMind) or `PHANTOM_GEO_ONLINE=1` (lazy lookup
at read time, never while the victim's page loads).

### Team handoff & tamper-evident audit

- `.pm` bundles carry the **C2 engagement intel** too: beacon table, task
  history, collected results (beacon HMAC secrets are NEVER exported and
  any secret-looking field is scrubbed).
- The C2 writes a **hash-chained append-only audit log**
  (`data/c2_audit.log`): beacon registrations, queued tasks, results and
  rejected auth. `audit verify` proves the timeline was not rewritten —
  show it to the client as chain-of-custody.

### Beacon: EDR awareness + hookless syscalls

- `edr-kill` (beacon command, hard-gated behind `--aggressive` in
  auto-mode): **detects before it acts** — enumerates the real services on
  the host (Windows `Win32_Service`, Linux `systemctl`/`ps`) and matches
  AV/EDR by keyword across name, display name and binary path, so an
  unknown/in-house product is still found — plus a read-only kernel
  driver/hook probe, then stops what it found (Windows also disarms
  Defender preferences + TamperProtection check and wipes the Defender ETW
  channel; Linux falls back to `pkill`). A disarm primitive, not a
  destructive remover: it reports `found` / `stopped` / `killed` /
  `could_not_stop` for everything. Exposed in auto-mode as the `edr_disable`
  `post` step.
- `edrcheck` (beacon command): hooked ntdll stub count + loaded EDR/AV
  kernel drivers (CrowdStrike, SentinelOne, McAfee, Defender ATP, ...)
  BEFORE acting on a foothold.
- Hardware-breakpoint unhooking: sensitive syscalls route through a debug
  register + Vectored Handler into a clean ntdll gadget — EDR userland
  hooks are bypassed without patching ntdll .text (nothing for integrity
  monitors to flag).

### Electron Desktop App

```bash
cd electron && npm install && npm run dev
```

Full GUI with Command Palette (Ctrl+K), credential vault, campaign timeline, network map, and all 12 modules. See [Electron](#electron-desktop-app).

> **API security**: the localhost API (`127.0.0.1:9876`) is bearer-protected — every
> request needs `Authorization: Bearer <PHANTOM_API_TOKEN>` (auto-generated in
> `data/phantom_state.json`). The Electron main process injects the header from
> the state file; the renderer never sees the token, so other local processes or
> websites cannot read engagement data or revoke identities. Rotate with
> `config rotate-api-token` in the C2 shell (or the API endpoint).

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         C2 Server (aiohttp)                          │
│  HTTPS + mTLS Listener    Task Queue    Beacon Registry              │
│  Pending Results          Crypto Engine  Telegram Bot (optional)     │
└──────────────────────┬───────────────────────────────────────────────┘
                       │ mTLS client auth + HMAC replay protection
                       │ AES-256-GCM, GET/POST /api/v1/*
                       │
          ┌────────────┼────────────┐
          │            │            │
    Windows Beacon  Linux Beacon  Android Beacon
    (PE, x64)       (ELF, x64/x86) (ELF, ARM64)
          │            │            │
       SOCKS5       inject       inject
       SMB Pipe     screenshot   screenshot
       Browser Piv  keylog       keylog
       CDP Pivot    (evdev)      (evdev)
       Cookie Steal
```

The beacon supports **reflective in-memory loading**: a position-independent loader is prepended to the beacon PE and maps it entirely in memory without touching disk.

---

## Features

### C2 & Beacon

| Feature | Description |
|:---|:---|
| **AES-256-GCM** | Authenticated encryption with fresh random nonce per message |
| **mTLS (default ON)** | Auto-generated CA + per-beacon client certificates + pinned server fingerprint |
| **Per-beacon HMAC** | Unique identity key per beacon; rotate without recompilation; 120s transition window |
| **Sleep / Jitter** | Configurable interval (min 1s) with ±30% randomized jitter |
| **Memory Sleep Masking** | `.data` / `.rdata` sections XOR-encrypted during sleep intervals |
| **Ekko Sleep Obfuscation** | Waitable-timer sleep via `NtWaitForMultipleObjects` + RC4-encrypted RW memory; thread never marked "Sleep()-ing" |
| **Indirect Syscalls** | Hell's Gate + Halo's Gate — NT API SSN retrieval + fallback scanning of hooked neighbors |
| **Direct Syscalls** | Embedded `syscall; ret` trampoline in own module — kernel stack return points into our `.text`, not ntdll |
| **Stack Spoofing** | RET gadget from ntdll .text section, 5 Win32 wrappers, stack residue cleanup with `_mm_lfence` |
| **HW Breakpoint Detection + Clearing** | DR7 bitmask checked; DR0-3, DR6, DR7 zeroed only if active |
| **CPU Telemetry Flush** | `cpuid` before each command dispatch |
| **NTDLL Unhooking** | Reloads clean `.text` from disk via indirect syscalls |
| **VM/Sandbox Detection** | CPU count, RAM size, debugger checks with configurable stalling |
| **Process Hollowing Dropper** | Pure PowerShell stager: `NtCreateProcess` → `NtUnmapViewOfSection` → injection |
| **PPID Spoofing** | Sacrificial processes spawned with explorer.exe parent; no EDR process-tree correlation |
| **Dynamic WinHTTP** | All WinHTTP functions resolved via PEB hash lookup; zero winhttp.lib IAT entries |
| **Module Stomping** | Overwrite signed DLL .text sections (kernelbase/advapi32) with PEB-walked APIs only |
| **Early Bird APC Injection** | `CreateProcess(SUSPENDED)` → `QueueUserAPC` → `ResumeThread`; shellcode runs before `LdrInitializeThunk` |
| **Threadless APC Injection** | `QueueUserAPC` onto existing threads — no remote thread created, no thread-count anomaly |
| **RWX Hardening** | Memory never allocated `PAGE_EXECUTE_READWRITE`; RW → write → RX flip via direct syscalls |
| **Malleable C2 Profiles** | JSON-driven profile config (URIs, UA, sleep, headers) with **target-aware auto-recommendation** |
| **Encrypted Heap (FOLIAGE)** | `SecureBuffer` with RC4 encryption + checksum; sensitive data (keys, shellcode) encrypted at rest |
| **PEB Module Unlink** | Unlink beacon from InLoadOrder / InMemoryOrder / InInitializationOrder module lists |
| **Encrypted Config** | C2_HOST + C2_PORT XOR-encrypted at compile-time with per-build rotating seed |
| **Auto-Persist** | RunKey (Win) / Cron/Systemd (Linux) — queued to beacon on first check-in |
| **Cross-Platform** | Windows (PE, x64), Linux (ELF, x64/x86), Android (ELF, ARM64), macOS |

### Beacon Commands (35+)

**Core:** `shell`, `whoami`, `sysinfo`, `ls`, `cd`, `pwd`, `cat`, `find`, `drives`, `netinfo`, `processes`, `download`, `upload`, `sleep`, `exit`

**Post-Exploitation:** `screenshot`, `keylog <start|stop|dump>`, `inject <pid> <b64>` (threadless-first), `inject-eb <exe> <b64>`, `inject-tl <pid> <b64>`, `migrate <b64>`, `mem-run <b64>`, `persist`, `cookies`, `cookies-json`, `netstat`, `netstat-json`

**Pivoting:** `socks <port>`, `socks-stop`, `smb-pipe <name>`, `portfwd <lport> <rhost> <rport>`, `browser-pivot <port>`, `cdp-launch`, `cdp-cookies`, `cdp-eval`, `cdp-nav`, `cdp-fetch`

**Media:** `gps`, `camera`, `audio <duration>`, `screen-record <duration>` (single clip), `screen-record-live` (progressive 5s segments streamed while recording — watch the target screen in real time from the C2/Electron), `screen-dump` (muxes all live segments into one `.mp4` and wipes the staging). Recordings land as real media artifacts under `data/recordings/` — playable in the **Electron Recordings tab**, via CLI `screen-watch` (local player) or `screen-open <file>`, not as base64 text.

**Wireless:** `wlan-scan`, `wlan-locate`, `bt-scan`, `bt-scan-json`

**Remote Session (GUI takeover):** `remote [host] [port] [ssl]` — the
beacon deploys the standalone Remote Session module (compiled C++,
cross-platform): full GUI streaming (screen frames land as viewable
artifacts in the C2 + Electron media strip) with configurable capture,
and input injection in 3 selectable modes — `ghost` (hidden virtual
desktop: you see and drive everything, the victim sees nothing), `steal`
(WTS session steal), `interactive` (active desktop). Streams over the
existing C2 channel (no new ports, no new connections to detect).

**Platforms:** Windows / Linux / macOS (standalone PE/ELF) and **Android**
(APK — MediaProjection capture + AccessibilityService input, same C2 channel
and frames). Android needs a one-time on-device projection consent and an
accessibility toggle (or root); this is an OS requirement, not a Phantom
limit. **iOS is not supported** — it exposes no equivalent capture or
input-injection API to a third-party app. Build with `--remote-deploy
android` (or `use exploit` → `remote android`).

**Security:** `auth-rotate <base64_secret>`

### Manual Pentest Modules (12)

| Module | Purpose | Key Tools |
|:---|:---|:---|
| **Scan** | Active reconnaissance (state-aware suggestions) | nmap, traceroute, service enum |
| **OSINT** | Passive intelligence | crt.sh, Shodan, BGP, Whois, theHarvester, Sherlock |
| **WiFi** | Wireless attacks | aircrack-ng, reaver, hcxdumptool |
| **Web** | Web application testing | gobuster, sqlmap, nikto, ffuf, `creds` (SSRF/SQLi credential extraction) |
| **Brute** | Credential auditing | hydra, medusa, john, hashcat |
| **Exploit** | CVE correlation, version-matched MSF commands, PoC deployment, `ssh` (reuse harvested creds), `remote-deploy` (standalone GUI-takeover module dropper) | NVD, searchsploit, MSF, phantom payload builder |
| **Payload** | Enterprise payload engine (multi-dialect `reverse`/`bind` + encoder + auto-listener + beacon upgrade), classic msfvenom wizard, priv esc | PayloadEngine, msfvenom, privesc, custom C2 droppers |
| **Handler** | Listener management | Metasploit multi/handler |
| **Analyzer** | Traffic analysis | scapy, tshark |
| **Pivot** | Tunneling + lateral movement | SSH forwards, `ssh <peer>` (lateral move), Chisel |
| **Wordlist** | Custom wordlist generation | Pattern engine, leetspeak/caps/suffix/reverse mutations |
| **Report** | Professional two-level reporting | JSON, HTML, PDF (raw operator + sanitized client) |

Every module suggests **state-aware commands** based on what you've already found — not a static menu. After scanning port 445, `use exploit` proposes SMB-specific exploits. After finding credentials, `use brute` suggests credential-reuse across services. See `preview` inside any module.

Manual pentesting includes a **creds → SSH → lateral bridge** so a red teamer can drive the kill chain to the beacon by hand (it is not auto-mode only):

- `use web` → `creds` — extract leaked credentials from web services (SSRF → credential files, SQLi auth-bypass + UNION dump + MD5 hash-crack) with the same deterministic engine the auto-mode agent uses, writing pairs to the shared WorldModel.
- `use exploit` → `ssh [user:pass]` — open an SSH session with a harvested pair (or explicit creds), honoring the discovered (non-standard) SSH port, and tag the cred valid for reuse.
- `use pivot` → `ssh <peer-ip>` — SSH lateral movement through the compromised foothold to hosts only reachable from it, using the harvested credential pair.
- `use payload` → `reverse [lhost] [lport]` — multi-dialect reverse shell from the **same enterprise PayloadEngine the auto-mode uses** (best dialect for the detected platform, optional base64 encoder, automatic listener, beacon upgrade path). `bind [port]` for egress-blocked targets.
- `use payload` → `privesc` — real post-exploitation escalation enumeration (sudo -l / SUID / GTFObins), not a static tool list.
- `use exploit` → `fire <cve>` — never a dead end: local PoC → **persistent MSF RPC** (`msfrpcd`, sessions survive the run) → one-shot console. `msf-fire <cve>` forces Metasploit with an OS-aware payload escalation ladder (x64 meterpreter → x86 → unix shell → module default, LHOST auto-set for reverse payloads). `msf-status` / `msf-interact <id>` list and drive the live sessions.
- `use exploit` → `chain` — the composition engine from auto-mode, exposed to the manual shell: shows the cheapest operator attack paths from the facts already held (SSRF → cloud keys, upload → webshell → RCE, SQLi → creds → SSH) with cost/noise per step; `chain preview <plan.step>` shows the exact command a step would ship before approving, `chain go <plan.step>` runs approved steps only.
- `use exploit` → `poc-sync [term]` — grow the PoC library from the ExploitDB mirror (searchsploit), METADATA-tagged so `fire` runs synced scripts like local ones.
- C2 shell → `remote-view` / `remote-open` — live ASCII watch of the Remote Session module's frame stream (the ghost desktop has no monitor: the stream is its only display) and full-res frames in the OS image viewer. In **Electron**, the beacon panel's `Remote` tab renders the stream as a live canvas — mouse/keyboard on the image become in-band input tasks.

### Autonomous Kill Chain (Auto-Mode)

Phantom's auto-mode runs the full kill chain without human input — and **without an LLM**. It uses a deterministic planner + anomaly engine, so no data ever leaves your machine.

```bash
phantom --auto <target>              # Full kill chain
phantom.auto <target>                # same, via the AUTO-MODE shell entry point
phantom.auto                         # interactive AUTO-MODE shell (multi-target
                                     #   list, flags, dry-plan, launch, resume)
phantom --c2                         # same as phantom.c2
phantom                              # manual core shell
phantom -y <...>                     # run without confirmation prompts
phantom --auto --aggressive <target> # Force aggressive exploitation
phantom --auto --no-stealth <target> # Disable stealth scanning
phantom --auto <target> --plan       # Dry-run: show plan, don't execute
phantom --auto <target> -a3          # 3 parallel sub-agents
phantom --auto <target> --agent      # Full autonomous planner mode
phantom --auto <target> --llm        # + optional LLM hypothesis advisor (local GGUF, or remote via PHANTOM_LLM_BACKEND)
phantom --auto <target> --experience # + cross-engagement learning memory (default: run-only)
phantom --auto <target> --llm --evolution # + SELF-IMPROVEMENT: stable uncovered failure patterns
                                     #   spawn a background author sub-agent that writes a
                                     #   new capability, gates it (lab included) and opens a
                                     #   reviewable PR on auto-evolution/* (max 2 PRs/day)
phantom --auto <target> --beta       # load machine-authored capabilities from OPEN
                                     #   auto-evolution PRs of this repo — after passing the
                                     #   same full gate on this machine; session-only, no install
phantom --auto <target> --verbose    # add the LIVE reasoning trace on top of the
                                     #   default action trace: every run shows the
                                     #   REAL command + why + stealth badge;
                                     #   --verbose adds inferences, hypotheses,
                                     #   confirmations/refutations
                                     #   — same stream in Electron's Auto-Mode panel
                                     #   (Verbose reasoning trace toggle)
phantom --auto <target> --goal deep  # full engagement ladder: beacon + persistence
                                     #   -> SYSTEM/root + injection -> AD (kerberoast /
                                     #   AS-REP) -> hash crack -> lateral — every stage
                                     #   runs until it succeeds or proves non-viable;
                                     #   one C2 handoff at the end, per-stage report
phantom --auto 192.168.1.0/24        # CIDR input = senior network triage FIRST:
                                     #   host discovery (nmap -sn) -> live-only -> ranked
                                     #   by attack surface (SMB/AD/DB/docker weigh more)
                                     #   -> the agent pool assaults the richest hosts,
                                     #   never a random slice of the range
```

**Target classes & platform branches** — the planner classifies every input
(and every target *discovered* mid-run) and applies a class doctrine:
`identity` · `network` · `web` · `cloud` · `ad` · `mobile` · `person`. A
**phone is a device**, so it takes the `mobile` doctrine (which still starts
with OSINT). The MDM fingerprint probes with BOTH an iOS and an Android
user-agent and records `mobile_platform`; from there the doctrine branches:

- **Android** — sideload / dropper delivery, native NDK beacon (`beacon_android`).
- **iOS** — no sideload: the beacon stage requires MDM supervision + an
  enterprise-signed app. An **unmanaged iOS target is refused the beacon
  stage** instead of pretending. `beacon_ios.dylib` / `remote_ios.dylib`
  build only on macOS + Xcode and fail honestly elsewhere (no cross-toolchain
  produces a runnable device binary).
- The MDM probe runs only when the scan shows a **concrete mobile hint**
  (MDM/APNS/GCM/enrolment service), never on every host with a port open.

**Post-exploitation expansion** — after the beacon the planner walks
`internal_recon` (interfaces/routes/ARP from the beacon) → `internal_probe`
(bounded TCP sweep of the neighbours) → `lateral_pivot`/`smb_pivot`/
`winrm_pivot`, choosing the peer that speaks the pivot's own service.
Discovered peers enter the `TargetLedger` under normal scope rules, so an
out-of-scope ARP neighbour is never selected. In `--aggressive` + SYSTEM a
`evasion` stage runs `edr_disable` (defensive-gap evidence).

**Cloud/IAM** — `cloud_creds_harvest` → `cloud_iam_enum` →
`cloud_assume_role` → `cloud_cross_account`, provider-aware for **aws**,
**gcp** and **azure** (the assumable identity found by the enum step is
auto-filled into the assume step, so the chain runs without copy-paste).

**Deep mode** (`--goal deep`, also `agent --goal deep`, the auto shell and the
Electron goal selector) does not stop at the beacon: one run walks the whole
ladder **deliver → post_exploit → ad → crack → lateral**, terminating each
stage when its goal facts exist or the planner shows the stage is
non-viable (no AD surface, no peers in scope...). Deep runs benefit from the
**cross-engagement learning loop**: the planner reads back the calibrated
weights written by PREVIOUS engagements (`data/calibrated_weights.json`),
so historically weak techniques are deprioritized before the run has its own
observations — outcomes recorded during the run are flushed at the end and
load at the next start (regret-bounded [0.5x, 1.5x]).

**AUTO-MODE shell** — `auto` with no arguments opens the dedicated interface
(mirrors the Electron Auto-Mode panel, same way `c2` separates the C2):

```
AUTO > targets add bob@corp.com,10.0.0.5   # multi-target list (core shell holds one)
AUTO > scope add corp.com                   # authorized targets
AUTO > flags aggressive on                  # per-run flags: aggressive|stealth|speed|agents|goal|profile|llm|experience
AUTO > plan                                 # dry-run the planned chain (executes nothing)
AUTO > launch                               # run the chain; beacon -> C2 handoff
AUTO > resume checkpoint.json               # continue from a checkpoint or an imported .pm
AUTO > status                               # per-target event summary (waiting/sleep states)
AUTO > export handoff.pm                    # portable bundle for another operator
AUTO > back                                 # return to the main Phantom shell
```

**Target types:** IP addresses (network chain), domains (DNS → IP → network chain), email/username/phone (OSINT → breach → persona → victim-IP → network chain).

**Phases:** Target classification → Scan → OS Detection → OSINT → Web Recon → CVE Correlation → Credential Testing → RCE Bridge → Beacon Deploy → Persistence → Loot Triage → Dual Report.

**Payload sandbox gate** — before ANY binary is materialised on the target
(`beacon_deploy`, `payload_reverse`, `payload_bind`, `beacon_via_rce`) the
auto-mode detonates it in a sandbox backend first. A negative verdict blocks
the capability for the engagement, and the static-validate backend also
proves the Linux sample is statically linked **self-contained** — "runs in
the sandbox" means "runs almost anywhere", not "the sandbox had the right
libs". The gate is **target-aware**: each artifact is classified and judged
only by the backends that can evaluate its format (a Windows PE is never
run through the Linux container, a shell script never through the Windows
VM), and the verdict reports a `coverage` line naming what was actually
proven. Under `--aggressive` the gate is explicitly skipped, never silently.

**Engines:** static format/portability check + Docker execution (ELF/scripts)
+ **Windows Defender** (MpCmdRun) + **ClamAV** (`clamscan`) + **YARA**
(`PHANTOM_YARA_RULES` / `sandbox.yara_rules`) + an optional **VM** detonation.
Every available engine must call the sample clean. `setup status` prints the
engine table, so you always see what is live.

Honesty note: these prove *execution*, *format/portability* and detection by
**every engine you have installed** — they do **not** prove evasion against
CrowdStrike/SentinelOne unless you point `PHANTOM_SANDBOX_VM_EXEC` at a VM
running that EDR (`PHANTOM_SANDBOX_VM_EDR=CrowdStrike`). The verdict's
`coverage` line always names exactly which guarantee you got.

**No-disk delivery** — `craft beacon` / `craft beacon-player` return a
`droppers` map: a per-OS stager that leaves no readable payload on disk
(Windows runs the beacon fully in memory; Linux/macOS start it then `unlink`
the copy; Android installs then removes the temp APK).

**Senior-discipline engines** — three additions that close the "junior vs
senior" gap in auto-mode:

- **Lockout-aware credential spray (`cred_spray`)** — the anti-`hydra -P`
  move: ONE password per round across every harvested/discovered account
  on every sprayable service the scan proved open (ssh/ftp/mysql/
  postgres/smb/tomcat/redis), capped at 3 attempts per account
  (enterprise lockout policy), paced, harvested-password reuse first,
  exhausted accounts backed off for the engagement. Hard-gated behind
  `--aggressive` like all online auth attacks.
- **Planner transparency** — every capability considered for a fact but
  not chosen is recorded with its concrete reason (stealth-gated,
  unplannable preconditions, already failed, backtracked, already in
  plan) and emitted on the `plan` event: the operator sees *why* a move
  was skipped, not just what was picked.
- **Post-beacon loot triage (`loot_triage`)** — after the beacon lands,
  downloaded loot in `data/downloads/` is classified (dotenv, config,
  private key, DB dump, cloud creds, scripts...) and mined for
  passwords, API/cloud keys, private keys, connection strings and JWTs
  with per-file provenance; extracted material feeds the WorldModel
  (creds/cloud_creds) and auto-derives next steps (cross-service spray,
  cloud harvest, SSH with captured keys, DB connection).

**Deeper fuzz grammar** — the web anomaly engine gained two new probe
classes: **deserialization** (Java ObjectInputStream magic/base64, Python
pickle opcodes, PHP object, .NET ViewState — parser error-path
fingerprinting, no gadget execution) and **GraphQL** (introspection
GET/POST, field-suggestion oracle, batch/duplicate operations, mutation
surface), both with mutation escalation and auto-retargeting to
discovered `/graphql` endpoints.

**Multi-tool per phase** — no capability is married to one binary. The
brain toolbelt ranks implementers per use-case and picks the best one
actually installed on the operator box (Windows native or Kali WSL):

| Capability | Best | Alternatives (auto-fallback) |
|---|---|---|
| Port scan | `masscan` (speed/aggressive, rate-capped) | `nmap` (quiet default) → `nc -zv` floor sweep |
| SSH banner | built-in socket engine (zero binaries) | `nc` |
| SMB enum | `smbmap` | `enum4linux` → `nmap --script smb-*` |
| HTTP probe | `httpx` (concurrent) | `curl` |
| SSH brute | `hydra` (aggressive-only) | `medusa` |
| Version/OS detect | `nmap -sV/-O` | — |

All implementers feed the **same parser** (`parse_nmap_ports` accepts
nmap tables, `nc -zv` connects and masscan discoveries), so the planner
never notices the swap. `setup status` shows the selection and what is
missing; a capability whose every option is absent fails cleanly with a
typed reason instead of crashing or retrying blindly.

**Reasoning brain** (`phantom/automation/brain/`) — the layer that turns
the capability registry from a checklist into a reasoner:

- **Target ledger + doctrine** (`targets.py`, `doctrine.py`): every input
  AND every mid-run discovery is classified (identity / network / web /
  cloud / mobile / ad / person); the class decides the chain shape (an
  username never gets a port scan, an IP never gets a breach lookup),
  pivots inherit scope from their authorized origin, and the pivot trail
  is recorded for the report.
- **Composition + hypotheses** (`operators.py`, `composition.py`,
  `hypotheses.py`): exploit primitives compose into attack chains the
  registry never contained (upload→webshell→RCE, SSRF→metadata→keys,
  SQLi→creds→SSH-reuse); each composed chain is a HYPOTHESIS with cheap
  discriminating probes that confirm or refute it before exploit budget
  is spent.
- **Predictive expectations** (`expectations.py`): fingerprint-conditioned
  predictions of what the target SHOULD show (nginx 1.18 ⇒ specific
  headers/errors); observed-vs-expected mismatches are findings even when
  nothing "failed" — how the weird thing gets noticed.
- **Cross-session priors** (`priors.py`): per-(technique, fingerprint
  class) success memory persisted to `data/technique_priors.json`; the
  planner reorders equally-ready moves by earned success rate, so every
  past run makes the next one smarter.
- **Stall classifier** (`stall.py`): when the chain stops advancing, the
  cause is classified (no visibility / blocked / wrong assumptions /
  wrong altitude) and the strategy class changes accordingly — not a
  canned recovery list.
- **Grammar fuzzing** (`fuzz/`): differential-oracle fuzzing with
  evolving payloads (bounded requests, wall-clock budget, findings
  project into composition facts).
- **LLM hypothesizer** (`llm/`, optional `--llm`): generates hypotheses
  OUTSIDE the registry from the WorldModel, each one validated by hard
  gates (scope, evidence, plausibility) before the planner ever sees it.

**Phase contract** (`phantom/automation/phases/`): every capability
belongs to exactly ONE kill-chain phase — `recon → osint → exploit →
foothold → beacon → post → report` — and each phase exposes
`capabilities.py / adapters.py / interpreters.py`. Phases communicate
only through typed facts and never import each other; the phase index
(`phases/__init__.py`) maps every registry capability to its owner, so
a capability can be worked on in isolation without touching other
phases. `report` owns the post-run deliverables (raw operator report +
sanitized client report).

**Enterprise payload engine** (`brain/payload/`): one engine synthesizes
every delivery primitive — reverse shells (bash/nc/socat/openssl/
python/perl/php on Linux, powershell/powercat/certutil on Windows),
bind shells (aggressive-only: they open a listener on the target),
PHANTOM's own C++ beacon stage and download-exec. Encoder support
(base64) keeps payloads alive through quote/space escaping. When an
RCE or cmdi primitive is confirmed, the agent injects the beacon
DIRECTLY through it (`beacon_via_rce`) — no reverse-shell detour.

**Web exploit surface** (beyond the CVE registry):
- **cmdi → beacon**: confirmed OS-command-injection anomalies are
  re-injected with a marker (RCE foothold proof) and then with the
  beacon dropper base64-encoded into the same parameter — the shortest
  path from detection to C2 access.
- **SQLi dump**: auth-bypass + UNION column-count dump extracts
  credentials/hashes from users tables; hash-cracked pairs feed the
  access chain.
- **IDOR engine** (`exploit/idor.py`): differential reference walk on
  `?id=` params AND `/users/1` path references — baseline vs neighbor +
  foreign references, distinct-object oracle (identity markers, size
  delta, status delta), confirmed/high severity only on strong leaks.
- **Data-extraction gate**: with `--llm` enabled the engines PROVE the
  primitive but withhold the leaked data (a local LLM reading findings
  means no guarantee the data stays on the operator box); without LLM
  (pure deterministic algorithms) extraction is always ON.

**Adaptive scoring** reorders phases based on findings:
- +25 priority for actively exploited CVEs (CISA KEV)
- +15 for critical infrastructure / domain environments
- -30 CVE correlation penalty without services discovered
- -40 beacon deploy penalty without OS detection or credentials
- Web recon skipped if no HTTP/HTTPS found

**Identity chain** (email/username/phone targets):
- OSINT via Sherlock + theHarvester + phonenumbers
- Breach check via HIBP + custom breach API
- **Cadence / re-engagement** — if the target never opens/clicks within the
  grace delay, the lead sends ONE second-chance lure with a fresh pretext
  and a new tracking link and keeps polling (only a real open/click ends the
  wait; `PHANTOM_SOCIAL_CADENCE` seconds + `PHANTOM_SOCIAL_CADENCE_MAX`
  attempts, off in speed mode)
- Phish delivery via SMTP + SMS carrier gateways
- Self-hosted IP-grabber (no third-party tracking service)
- Victim IP flows into the network chain automatically

**Professional social engineering** (`campaign_launch` / `harvest_campaign` capabilities):
- **Pretext library** — 7 believable lures (security alert, IT helpdesk, HR benefits, recruiter, package delivery, password reset, shared document), each personalized with the OSINT context actually found: target name from email, real platform, and the *real breach* the address was exposed in
- **Credential harvesting** — the self-hosted tracker serves fake login pages (`/l/<code>`, brand configurable via `PHANTOM_TRACK_BRAND`, optional OTP field) that capture username/password/OTP; harvested credentials feed the planner's credential gate for service login — phish → creds → SSH/WinRM → beacon
- **Campaign engine** — multi-target campaigns with per-target lifecycle (sent → opened → clicked → creds), open-tracking pixel, UA/OS fingerprinting, optional MaxMind geo, and campaign reports
- **Delivery hardening** — HTML emails with action buttons, contextual From display names, Message-ID/Reply-To headers
- SMS phish via email-to-SMS carrier gateways with carrier auto-detection
- **Social DM** (`dm_launch` + `dm_stage2` capabilities) — the strategy is decided by the **channel**, and the default is **attachment, not link**. Where the platform *and* our transport carry a document (**Telegram** Bot API) the capture artefact goes straight into the chat as `document.pdf.html` (the **real** extension is last so it really opens; the name reads as a PDF): **no URL anywhere**, so there is nothing for the target to read and call fake, and the IP is captured when they open the file (`plan_delivery()` decides, a `DM_PLAN` marker records why, `launch_dm_attachment()` delivers). Where files are impossible (**Instagram/TikTok/X**, where the raw URL is always shown) the contact is **two-stage**: an innocuous opener that asks for nothing ("sorry — I think I sent you a file by mistake, is it yours?") earns a reply, and the **link is held** until then — `dm_stage2` sends it, and the wait is persisted in `data/social_state.json`, so a chain that started yesterday finishes today **from a new process**. WhatsApp is reported as `transport-needed` (the platform carries documents; there is no free official API). The `innocuous` openers are the default (`wrong_recipient`, `found_file`, `is_this_you`, `mentioned_doc`); `security_verify|recruiter|collab|prize|invoice` stay available but are tagged `flagged` — they are the angles people have learned not to click. Delivered over free key-only channels (**Telegram Bot API** via `PHANTOM_TELEGRAM_BOT_TOKEN`, or a **Discord webhook** via `PHANTOM_DISCORD_WEBHOOK`); every DM carries a per-target tracking link, so a click still converts into a `victim_ip` and the network chain takes over. No transport configured → clear ERROR marker, never a hang. Custom platforms (X/Instagram/Reddit DMs) plug in via `PHANTOM_DM_TRANSPORT=<dotted.path.Class>`.
- **Coherent persona cover** (`persona_profile` capability) — a believable social profile with zero configuration: name, age *consistent with the role*, city/country matching the engagement locale, interests, a bio, and an avatar (offline Pillow gradient+initials by default; `PHANTOM_PERSONA_AVATAR=randomuser` fetches a free portrait photo cached under `data/personas/`). Same seed → same profile, so campaigns are reproducible. **Audience-aware**: `middle` / `high` / `university` / `professional` adapts the cover to the target's world — a 15-year-old gets a 15-year-old peer (school, age band, student interests), never a "Senior Developer"; inferred automatically from the discovered platform (Instagram/TikTok → student) when not specified.
- **Profile reverse-engineering** (`profile_recon` capability) — OSINT mapping of the target's social profile: fetches the profile page and determines **private / public / missing**, extracts the **bio, the link in bio, @handles and emails**, and runs sherlock on discovered handles to find the **same person on other platforms** (including public accounts of the same handle). A private profile is never scraped — it is mapped, and every new handle/email becomes a pivot lead. The profile state (private, bio, linked accounts) feeds the strategic dossier.
- **DEEP reverse-engineering** (`deep_recon` capability) — the reliable multi-layer pass on a profile, built for private accounts:
  - **State voting**: private/public/missing decided by multi-marker voting across two fetches (different UAs, human pacing) with a confidence score — one flaky CDN response cannot flip the verdict
  - **Graph mining**: tagged posts, commenters and follower counts mined from the profile's own embedded JSON (ld+json / rehydration blobs) — every handle becomes a pivot lead with its evidence source
  - **Username variants**: `mario.rossi` → `mario_rossi`, `mariorossi`, `mario.rossi1`... probed on the same platform
  - **Wayback snapshots**: ex-public profiles often leak the OLD public bio (real name, emails, linked handles) via the CDX archive
  - **Search dorks**: DuckDuckGo queries (no API key) across platform/leak/code sites
  - **Cross-account correlation**: avatar-hash equality and bio-similarity scoring between platforms prove two different handles are the same person (confidence 0.85 avatar / 0.65 bio)
  - Bounded (≤ 20 network calls), every lead carries its evidence (`variant_probe`, `wayback:<ts>`, `avatar_match:<platform>`, `ddg_dork`)
- **Identity-confidence gate** (`identity_conf` findings) — the wrong-person guardrail on cross-platform pivots: every candidate found on another platform is scored into **CONFIRMED** (avatar hash equality, cross-link, same email/phone visible — proofs a username collision cannot fake), **PROBABLE** (weak signals agreeing: name + interests), or **UNRELATED** (same handle alone — deliberately weak, the exact trap this closes). The target ledger honors the tiers: PROBABLE/UNRELATED handles can never become actionable pivots (read-only recon only) unless `--aggressive` explicitly accepts the wrong-person risk. Weak-signal sums are mathematically capped below CONFIRMED — coincidences can never add up to proof.
- **Persistent social state** (`data/social_state.json`, `0600`) — multi-day engagements span several phantom sessions, so the time-sensitive social facts live on disk — including the **two-stage conversation ledger**: which opener landed, whether the target replied, and whether the held link was already sent and are re-evaluated against **wall-clock time** on every start: the persona warmup clock (a fresh identity ages 72h before its first cold contact — 6h under `--aggressive`; the countdown is idempotent and never resets on re-run) and the follow-request ledger (a follow sent yesterday is still pending today; an accept recorded while phantom was closed is picked up on restart, `wait_follow` reloads the ledger mid-wait). Corrupt/missing file = empty state, never a crash.
- **Hardened-target surface mapping** (`surface_map` capability + automatic escalation) — when a port scan sees NO open services on a domain target (CDN/WAF-blind perimeter), the agent escalates once from port enumeration to **asset enumeration**: Certificate Transparency hosts (dev/test/legacy/VPN/SSO names, risk-scored), Wayback endpoints (admin panels, APIs, backups), JS-referenced API routes and cloud hosts, mail topology (SPF/DMARC spoofability, M365/GWS fingerprint), SSO/OIDC portals (Okta/Auth0/Azure AD tenants), VPN gateway fingerprints (Fortinet/Ivanti/Pulse/SonicWall/Cisco), DNS misconfigs (AXFR, DKIM). Every asset carries a 0..1 risk score the planner ranks into real attack paths.
- **Video-lure IP grabbing** — links to `/v/<code>` serve a page that looks exactly like an **Instagram Reel / TikTok / YouTube Short** and plays a real embedded video; the page load *is* the click, so the victim's IP is captured exactly like a normal link click. Skin via `PHANTOM_TRACK_SKIN=instagram|tiktok|youtube`, embedded video via `PHANTOM_TRACK_VIDEO_ID`.
- **Share-format video links** — `create_video_share_link()` produces the *same URL shape you get when you press "share"* on a real video: `/@user/video/<code>` (TikTok), `/reel/<code>` (Instagram), `/shorts/<code>` (YouTube). The tracker serves these paths with the platform skin; the tracking code is embedded in the path and **there is no traceable profile identifier** in the link. Victims open a "shared video" — the highest-converting IP-grab vector.
- **Real-video picker** — the lure is never a fake video: `pick_video()` chooses a **real, harmless public video the target would actually click on**, driven by the interests extracted from their profile bio (`yt-dlp ytsearch3:<topic>` when installed, a curated offline catalog of famous uploads otherwise; with `--llm` the advisor suggests the topic). The share link then renders that exact video with its real title/channel — the target sees a video relevant to them, not a generic placeholder. `/api/video-lure` exposes the picker to Electron.
- **Strategic phishing** (`dossier_analyze` capability) — one high-quality lure per target instead of a spray: a **target dossier** merges everything OSINT found (name, emails, phones, platform, company) and **correlates breaches across channels** — when the same breach name shows up for the victim's email *and* their phone, that becomes a recognition hook the target cannot ignore ("how do you know my number?"). A deterministic scorer picks the most credible pretext (delivery notice when only a phone is known, security alert when a real breach exists, recruiter when there's a public profile...), and with `--llm` the local advisor refines the hook and subject twist — every suggestion sanitized (no URLs, no placeholders, bounded length) and never able to change the channel or target.
- Strategic mode is one flag away: `campaign(strategic=True)` / `phish(strategic=True, use_video=True)` — hook + pretext from the dossier, subject twist from the advisor, From display name from the persona cover for human pretexts (recruiter).
- **Sender realism + homoglyphs** — the From identity is derived from the dossier: a **SERVICE the target uses** (platform brand + domain, e.g. `LinkedIn Security <security@linkedin.com>`) or a **PERSON they know** (a colleague at the same corporate domain when OSINT found one), never a fake-looking `.example` address and never impersonating free-mail providers. The display name and subject are then obfuscated with **Cyrillic homoglyphs** (visually identical, byte-different) so naive text filters stop matching canonical keywords like "LinkedIn" or "account" — the classic IDN-homograph trick applied to headers (`PHANTOM_PHISH_HOMOGLYPH`, on by default, off in aggressive mode).
- **Delivery hardening (anti-detection)** — the mail layer is built to pass, not just to send: `Message-ID` generated on the **sending domain** with a random local part (never a tool signature domain), the **headers real MUAs set** (`X-Mailer`, `Thread-Index`, `Content-Language`, `Accept-Language` — their absence is the loudest spam signal), **anti-burst jitter** (random 1-4.5s spacing between campaign sends so the identical-moment bulk signature never hits the MX), and **per-send HTML variation** (randomized button color/font/padding, rotating legitimate footers, noise comments — a multi-target campaign never shares one template fingerprint, which is what bulk-template detectors group on).
- **Zero-click pixel** — every email lure (single phish *and* campaigns) embeds the 1×1 open-tracking pixel: the victim's IP is captured on **email open**, no click required.
- **Sleep state for the human** — after a lure is sent the run *waits* for the target (chunked polling with visible `waiting` events): the DM/link is not the end, the click/accept is. Default horizon 600s (configurable `PHANTOM_SOCIAL_WAIT`), **30s with the fast flag** — the fast profile never sleeps.
- **Private-account flow** — `profile_recon` proving the account is private gates the email lures off and drives a dedicated chain: `dm_follow` (follow request) → `wait_follow` (sleep until the target accepts) → `dm_launch` (DM with the video share link) → `harvest_campaign` (sleep until the click) → `victim_ip`. The whole chain runs unattended, no human operator needed.

**Anomaly engine** — hunts bug *classes*, not CVE lists (13 classes, header-aware):
- **Path traversal** (plain, URL-encoded, double-encoded, overlong UTF-8, Windows, IIS, Apache variants)
- **SQLi** (error/boolean/time-based: MySQL/MSSQL/PostgreSQL + POST-form auth bypass)
- **SSTI** (`{{7*7}}`, `${…}`, `#{…}`, ERB)
- **XXE** (`file:///etc/passwd`)
- **SSRF** (`?url=http://127.0.0.1/`, file://, AWS metadata via link-local)
- **Command injection** (separators `; | $( ) \`` + time-based `sleep`)
- **Open redirect** (attacker host in the Location header — no-follow probes)
- **CRLF / header injection** (injected response header detection)
- **NoSQL injection** (Mongo operator payloads in params and JSON bodies)
- **Header-delivered SSTI** (templated User-Agent / Referer / X-Forwarded-For)
- **JNDI / Log4Shell-class** (`${jndi:ldap://…}` reflection + obfuscation variants)
- **Sensitive-file exposure** (`.git/HEAD`, `.env`, backups, phpinfo, actuator)
- **HTTP verb tampering** (TRACE / OPTIONS Allow / DELETE)
- **Header-aware scoring**: Location / injected-header / Allow signals read from real response headers (curl `-i`); open-redirect and CRLF probes deliberately do NOT follow redirects so the 3xx evidence is readable
- **Monotonic time validation**: time-based classes must be strictly slower with the deeper payload (SLEEP(5) > SLEEP(3)) — a one-off ratio vs a fast baseline is jitter, not injection
- **Discovery that reads modern apps**: robots/sitemap crawl + common paths + **JS-bundle API extraction** + **form-input parameter names** (the real injection points)
- Statistical baseline scoring + validation pass for confirmed findings
- Bounded budget: ≤ 400 requests/service, 90s wall-clock, offline-safe

**Dynamic CVE catalog** — never a hardcoded long list:
- Curated static registry (12 high-value modules: Log4Shell, Spring4Shell, Struts2, Apache 2.4.49/50, Confluence OGNL, GitLab Exif, vCenter, Elasticsearch, BlueKeep, Zerologon, Heartbleed, OpenSSH enum) with banner-product alias matching
- Anything else: live **NVD correlation** (cached, offline-safe) for every fingerprinted product@version, then **dynamic module discovery** via `msfconsole search cve:<id>` — Metasploit's own self-updating CVE→module index weaponizes the long tail
- No weaponizable module → the CVE is recorded as a knowledge finding (`kind=note`) and the bug-class anomaly path takes over

**RCE bridge** — deploys the beacon even without credentials:
- Confirmed SSTI/CVE RCE → drops C++ beacon through the code-execution channel
- SSRF to cloud metadata → harvests IAM credentials for cloud pivot
- Meterpreter session opened for RCE-class CVE plans → `sessions -c` pushes dropper

**Cloud / IAM post-exploitation** — turns a container/cloud foothold into data access:
- `cloud_creds_harvest` — capture instance IAM from inside the beacon via the metadata service (AWS IMDSv2 token + role endpoint, GCP `metadata.google.internal`, Azure managed identity)
- `cloud_s3_enum` — with the harvested IAM creds, enumerate object storage (`aws sts` + `s3 ls`, `gsutil ls`) and account access for stolen-data collection
- `k8s_escape` — probe a compromised pod for container-escape primitives (mountable service-account token, privileged cgroup `release_agent`, reachable kubelet)

**Mobile / device-management surface** — recognizes and branches into the mobile attack surface:
- `mobile_probe` — flags MDM endpoints, push gateways (APNS/GCM/FCM) and mobile-web presence so the engagement reaches phones, not just desktops

**Deep protocol fingerprinting** — 15 protocols beyond nmap -sV:
- SMB: dialect negotiation, SMBv1 check, anonymous session, signing detection
- Databases: MySQL/MSSQL/PostgreSQL/Redis/MongoDB version + auth bypass checks
- Infrastructure: Docker/Kubernetes API, DNS version.bind, SMTP EHLO capabilities
- LDAP/SMB: domain name extraction, anonymous bind, functional level detection

**Attack graph chaining** — 25 cross-service rules:
- `SSRF web → cloud metadata → IAM creds → S3 → source code → DB password`
- `SMB null session → share enum → plaintext password → SSH login → beacon`
- `MySQL default root → file read → /etc/shadow → hash crack → SSH`

**Differential analysis engine** — protocol-agnostic:
- Baseline reference request per target → mutated probe → statistical comparison
- Works on HTTP (SQLi/SSTI/traversal/SSRF/XXE) AND raw protocols (SMB/MySQL/Redis/SSH)
- Timing ratio, size ratio, status shift, body markers → anomaly score → validation pass

**Active Directory awareness**:
- DC detection via ports (88/389/636/3268/3269), LDAP rootDSE anonymous bind
- Domain functional level, namingContexts, DNS SRV, Kerberos AS-REP check
- Auto-flags: LDAP anonymous bind → user enumeration possible; Kerberos → roastable

**Intelligent fallback chain**:
- "Brute failed but account 'admin' exists" → phish admin, not re-brute
- "All strategies exhausted" → gap analysis → report what's missing
- Learned accounts from failed logins feed the next strategy

**Historical self-learning**:
- Beta-Binomial posteriors over technique success rates per OS
- Persists to `data/engagement_history.json` — Phantom gets smarter with each use
- `best_alternative()` suggests the historically most successful technique

**Experience memory — the LEARNING engine** (`phantom/automation/brain/experience/`):

Historical learning above is a *statistic* ("sqli is ~60% effective on nginx"). Experience remembers the **case**: the situation, the technique, the outcome, **why it failed** and **which move unblocked it**. That is what turns "it got stuck" into "it does not get stuck the same way twice".

- **Situation signature** (`signature.py`) — target class + product family + service set + defensive posture, plus a token bag for similarity. A case learned on one nginx+php host behind a WAF transfers to the next one, but never from a Windows DC to an Instagram profile.
- **Failure taxonomy** (`causes.py`) — a closed set (`timeout`, `waf_blocked`, `rate_limited`, `auth_required`, `not_found`, `unsupported`, `privilege`, `dependency_missing`, `scope_denied`, `gated`, `no_signal`, `parse_error`, `other`). Determined by deterministic rules over the reason/evidence/command.
- **Environmental causes never teach** — a failure caused by a missing local tool, an out-of-scope host or a disabled flag says nothing about the technique, so it is excluded from everything that reorders moves.
- **Repair learning** — for every real failure the engine records the first *later* successful move of the same run: the actual unblocking relationship, not a guess.
- **Bounded, atomic store** (`data/experience_cases.json`, gitignored) — capped and age-pruned; strong patterns are promoted into the coarse priors so the two learners never drift apart.
- **It can never authorize anything** — like the priors and the LLM advisor it only REORDERS moves the planner has already allowed. Every precondition, scope, opsec and stealth gate still applies.
- **Two storage modes** — default is **engagement-scoped** (in memory for the run only, nothing written to disk). `--experience` (or `experience on` in the AUTO shell) turns on **cross-engagement** memory.

**Self-improvement loop** (`--llm --evolution`) — the operator's "impara e migliora da solo":
- **Trigger is deterministic** — a SINGLE learnable failure whose cause is one a capability file can close (`waf_blocked`, `not_found`, `unsupported`) spawns a background author sub-agent. The planner already adapts in-run around one-off walls (retries, repairs, priors); authoring is for walls worth a *permanent* tool. The noise dampers are the full gate and the daily budgets — not a repetition count. The main chain never blocks on it.
- **The author reads on demand, not the repo dump** — the prompt carries the schema, a worked example and a tree for orientation; if the model needs a specific file (e.g. a similar built-in to imitate) it requests `READ <path>` and gets the redacted content (max 4 read rounds, 20 reads/attempt). It can WRITE only into `phantom/automation/guidance/learned/`, `tests/learned/` and `docs/evolution/`. Engine code (planner, agent, the gate itself) is outside its write reach *by construction* — the guardrails cannot be rewritten by the thing they guard.
- **Full gate, lab mandatory** — static AST allowlist (stdlib+phantom imports only, `learned.` id prefix, size caps) → registry load → offline unit subset → **dry-run against the lab through the real pipeline**. No lab reachable → no PR, no auto-load. Ever. **Every user gets a lab automatically**: the loop uses an already-running lab (your own compose on 8081, if you have one) or starts the project's own two-host stack (`lab/`, shipped with phantom) on remapped ports (18081) and tears it down after the gate — isolated, never the operator's machines, zero extra config beyond Docker itself. Without Docker installed, evolution is unavailable (stated, never faked).
- **Repair loop with a dynamic budget** — gate failures feed back into the next attempt; the attempt cap (3–5) scales with the pattern's authoring track record. On total failure: rollback + `POSTMORTEM.md`, no PR.
- **Human merge, always** — a gate-clean capability lands on branch `auto-evolution/<id>` and opens a PR into `dev` with the proposal + full gate results. Never self-merges; `PHANTOM_EVOLUTION_TOKEN` (repo-scoped) or the branch stays local with push instructions. Budgets: 5 gate runs/day, 2 PRs/day.
- **`learned/` is the production location** — the registry scans that package on every boot, so a merged PR integrates with zero plumbing; the capability auto-loads in sessions and shows up in plans with its `learned.` prefix.
- **`--beta`** — pull the branches behind OPEN auto-evolution PRs, run the same full gate locally (lab included) and load what passes for THIS session only (temp checkout under `data/evolution/`, working tree untouched). One operator's learned capability becomes every operator's beta.
- `review` in the AUTO shell shows authored patterns, budgets, learned capabilities and lab reachability.

**Optional LLM advisor** (`--llm`) — deterministic-first, the LLM never decides:
- The expert system remains the decision layer; a model *proposes* extra hypotheses, and (when enabled) names the failure cause for the ambiguous tail of the experience engine — the rules always run first.
- **Pluggable transport** — `local` (default): a GGUF model on your machine via `PHANTOM_LLM_MODEL`, zero egress. `remote`: any OpenAI-compatible endpoint (an always-on Workers-AI deployment, SambaNova, self-hosted vLLM) via `PHANTOM_LLM_BACKEND=remote`, `PHANTOM_LLM_URL`, `PHANTOM_LLM_API_KEY`, `PHANTOM_LLM_REMOTE_MODEL`.
- **Remote data is redacted, always** — on the remote path every message passes through `redact()` at the boundary where data would leave the process: IPs, hostnames, domains, emails, `DOMAIN\\user`, file paths, hashes and credential-looking strings become placeholders. The model reasons about the *situation*, not about your engagement's data. The local path is not redacted and sends nothing.
- Injection-hardened by design: strict `{capability_id, reason}` JSON schema, target content wrapped as `<UNTRUSTED_DATA>` and never mixed with instructions, ids validated against the registry, paranoid mode strips loud suggestions — a fully successful prompt injection can only add noise, never authorize an action.

**Environment recognition** — classifies the battlefield:
- Docker API (2375/2376) → `container`
- Kubernetes API (6443/10250) → `kubernetes`
- SCADA/ICS ports (502, 102, 20000, 47808) → `scada`
- SSRF to `169.254.169.254` → `cloud` (AWS) + IAM credential harvest
- Post-beacon internal probe: `/proc/1/cgroup`, `/.dockerenv`, IMDS v2 token flow

**Strategy weighting:** `network_footprint (75)` → `exploit_chain (72)` → `network_creds (70)` → `network_beacon (65)`. `exploit_chain` only activates when a service is fingerprinted (software + version).

**Sub-agents** (`-aN`): parallel workers share discovered credentials via
`ShareContext`. Auto-decides pool size from a quick dry-run plan if `-a`
is used without a count.

Sub-agent coordination (v3.8):
- **Shared findings** — high-value discoveries (victim IP, AD domain, OS,
  cloud env, beacon, RCE foothold) are broadcast to every sub-agent and
  absorbed at the top of each planning pass, so one agent's discovery
  shortens another's chain (a victim_ip found by the deepen worker
  immediately unblocks the lead's network chain).
- **Move ledger** — every real attempt is recorded per (entity,
  capability); single-shot probes (scan/banner/os/http) already run by a
  peer are not re-run, killing the duplicate-move loops.
- **Phase roles** — same-target workers specialize: deepen (enrich),
  exploit (fact-gated on services), post (fact-gated on beacon), and at
  `-a4` an AD worker (fact-gated on ad_domain) and at `-a5` a cloud
  worker (fact-gated on environment) — each with a short phase-gate
  timeout so a missing environment exits quietly instead of parking a
  thread.

**Engagement timeline** (`phantom/automation/timeline.py`) — every run now reports *what happened, in what order, and what it led to*, not just what was found. Findings, actions, failures, detection-risk events and C2 activity are merged into ONE chronological stream, each entry tagged with its kill-chain phase (resolved from the canonical phase index, so it can never drift from the registry) and a severity.

The same timeline is rendered twice: the **operator** view keeps every detail, command and piece of evidence; the **client** view shows phase and outcome only — no commands, no capability names, and credential findings are omitted entirely, because the client report states impact and never names a secret.

**Every run** prints elapsed time (`⏱ 3m 12s`) and produces a dual report with a **Cleanup & IOCs** section: staging paths, C2 URLs, listener ports, phish links, stolen cookies, persistence methods, harvested cloud keys.

### Shared Knowledge Engine

Both the autonomous agent and manual modules share the same typed `WorldModel`:

- `scan` writes `service`/`os`, `brute` writes `creds`, `exploit` writes `vuln`, `web` writes `web_app`/hunt findings
- `show knowledge` lists everything discovered
- `suggest` runs the same deterministic reasoning as the agent over YOUR findings
- `brute defaults <service>` tries known default credentials before noisy brute force
- Step-aware `run`: phases with missing preconditions are skipped with a hint
- `save <name>` / `load <name>` persists the full engagement with WorldModel
- `export all` produces the dual report (raw operator + sanitized client) with MITRE/risk view
- **Bidirectional bridge** (`phantom/core/session_bridge.py`): an auto-mode run
  merges everything it learned — services, OS, creds, beacon, persistence,
  internal peers, EDR gaps, cloud and mobile surfaces — into
  `session.knowledge_base` **and** the manual `WorldModel`, so `map`,
  `suggest`, `exploit`, `payload` and the report see the same truth. In the
  other direction, launching the auto-mode **seeds** its WorldModel from what
  the operator already found by hand: the agent does not redo manual recon.
  Both directions are idempotent and covered by `tests/test_session_bridge.py`.
  New finding kinds (internal hosts/services, cloud access/lateral, defensive
  gaps, mobile/MDM, k8s escape) now reach the client report too.

### Decision Engine Modules

Five modules feed the adaptive scoring engine:

| Module | Purpose |
|:---|:---|
| **Threat Intelligence** (`phantom/core/threatintel.py`) | OTX, NVD, CISA KEV feeds with 24h caching; CVE exploitation check |
| **Bayesian Calibration** (`phantom/core/calibration.py`) | Online Beta-Binomial weight learning with confidence intervals |
| **MITRE ATT&CK Mapper** (`phantom/core/attack_mapping.py`) | Service-to-technique mapping, kill chain phase prioritization |
| **Risk Engine** (`phantom/core/risk_engine.py`) | Business criticality, network position, asset classification |
| **Historical Learning** (`phantom/core/history.py`) | Technique success/fail tracking, alternative suggestions, temporal decay |

---

## Configuration

**Secure by default — zero configuration required.** Phantom auto-generates all secrets on first run, and a fresh checkout runs the full local chain (lab + C2 + tracker) with **no `.env` file at all**:

- `data/phantom_state.json` (gitignored, `0600`) — auto-generated secrets:
  - `PHANTOM_C2_KEY` — 32-byte AES-256 key, embedded in every beacon
  - `PHANTOM_PAYLOAD_TOKEN` — gates `/api/v1/payload*`, `/x`, `/s/android`
  - `PHANTOM_API_TOKEN` — gates `/api/v1/beacons`, `/api/v1/queue`, `/api/v1/results`
  - Beacon auth ON by default — every `generate` creates a unique per-beacon HMAC identity
  - mTLS ON by default — `CERT_OPTIONAL` at TLS layer, enforced via middleware on beacon routes
- `data/config.json` (gitignored, auto-created with defaults) — settings for the C2, tracker and social transports. Everything local ships pre-configured.

**`setup` command (console):**

```
setup            # interactive wizard: configure the OPTIONAL external channels
setup status     # show which channels are usable right now
setup auto       # write data/config.json defaults only, no prompts
```

**Transport capability detection.** Only per-engagement, external channels can be missing (SMTP creds, Telegram token, Discord webhook, SMS carrier, public tracker URL). `setup status` shows exactly what is ready; the auto-mode **degrades with a reason** instead of failing — e.g. a phish phase is skipped with `transport not configured: email — set SMTP username/password (phantom setup > email)` while the local-only chain (OSINT, persona, tracker) keeps running. Legacy `PHANTOM_*` env vars still take precedence over the file when both are present, so existing `.env` setups keep working unchanged.

**Optional env overrides** (only for external APIs):

| Variable | Purpose |
|:---|:---|
| `NVD_API_KEY` | NVD API rate limit boost (50 req/30s vs 5) |
| `PHANTOM_HIBP_API_KEY` | HaveIBeenPwned v3 breach lookup |
| `PHANTOM_BREACH_API` | Self-hosted breach dump API for credential reuse |
| `PHANTOM_SMTP_HOST/PORT/USER/PASSWORD` | SMTP relay for phish email + email-to-SMS |
| `PHANTOM_TRACK_URL` | Self-hosted IP-grabber URL (victim click tracking) |
| `PHANTOM_TELEGRAM_BOT_TOKEN` | Telegram C2 bot |
| `PHANTOM_ALLOW_UNSCOPED` | Lab/CTF escape hatch: allow commands without a scope |
| `PHANTOM_RANSOM_SIM_ALLOW` | Allow ransomware SIMULATION (scratch dirs only) |

**Console:** `config` shows state secrets. `config rotate-api-token` rotates. `config mtls-off` disables mTLS.

---

## Install (one-liner, cross-platform)

No `git clone`, no manual venv — install phantom like any modern CLI:

**Windows** (PowerShell, user-scope, no admin):
```powershell
irm https://raw.githubusercontent.com/Terminalkid09/Phantom/main/install/install.ps1 | iex
```

**Linux / macOS / WSL** (sh, user-scope):
```sh
curl -fsSL https://raw.githubusercontent.com/Terminalkid09/Phantom/main/install/install.sh | sh
```

Both installers: download the repo tarball from `main` (integrity-checked), install into `%LOCALAPPDATA%\Phantom` / `~/.phantom`, create a private venv, write the `phantom` / `phantom.c2` / `phantom.auto` launchers into the **user** PATH. **No admin, no registry beyond HKCU, nothing silent** — re-running refreshes in place.

After installing, the guided setup walks you through the toolbox:

```
phantom doctor      # read-only diagnostics: python, tools, docker, WSL, LLM transport
phantom setup       # guided: shows the missing-tool list, asks ONCE, installs non-interactively
phantom setup wsl   # Windows only: guided WSL flow (explains admin+reboot BEFORE asking, then
                    # unattended Kali toolbox config; resumable at every step)
```

Non-invasive by policy:
- the core never needs elevation; tool installs always print the exact deduplicated package list first and run `apt-get install --no-install-recommends` with `DEBIAN_FRONTEND=noninteractive`;
- WSL (`wsl --install`) inherently requires admin + one reboot — phantom asks explicitly, launches the elevated step through UAC, and tells you to re-run `phantom setup wsl` after reboot to finish the toolbox;
- tools missing = capabilities planned without them, never a crash; the manifest (`phantom/utils/tool_manifest.py`) is reviewable code — package names live there, never hardcoded at call sites;
- `phantom doctor` installs nothing, ever.

---

## Electron Desktop App

Phantom ships with a **React + TypeScript Electron desktop application** designed for multi-day campaigns. It provides capabilities the CLI cannot: visual network graphs, centralized credential vault, campaign timeline, and one-click export ZIP.

### Why Electron over CLI

| Capability | CLI | Electron |
|:---|:---|:---|
| Speed | `use s → preview → run-group` | Ctrl+K → type → Enter |
| Global Search | grep by hand | Ctrl+K fuzzy search across all modules, beacons, creds |
| Credential Management | Scattered across outputs | Centralized Vault (search, copy, toggle visibility) |
| Network Visualization | Text only | SVG interactive graph (attacker → host → services → beacons) |
| Campaign Timeline | `history` text | Chronological timeline with color-coded badges |
| Multi-day Sessions | Lost on terminal close | Full save/load + WorldModel persistence + `.pm` bundles (auto-export on close) |
| Export | Manual | One-click ZIP (session + C2 + vault + timeline + dual reports) |

### Panels (all 20 views)

**Operations:** C2 Dashboard (listener, beacons with LIVE/IDLE/EXITED telemetry + queued-task badges, generate, beacon-auth, certs, audit-log viewer, **live media strip** — screenshots / camera frames the beacon delivers render as clickable thumbnails right above the task table, not just a saved path), Session Manager (target/scope, **Suggest Next / Run** adaptive step, preflight, knowledge, wordlists), Auto-Mode (one-click kill chain, live graph, reasoning stream, dry-run)

> **Packaging note (Windows):** the desktop app's Python backend ships as a
> **onedir** PyInstaller build. This is deliberate — onefile executables use a
> self-extracting bootloader that AV engines (Defender, McAfee) routinely
> flag as heuristic false positives. If you rebuild the backend yourself,
> use `phantom/api/phantom-backend-onedir.spec`.

**Intel:** Timeline (chronological events + operator notes), Vault (centralized credentials with search/copy), Network Map (pan/zoom SVG canvas laid out like the REAL network — the scan detects the topology (star / broadcast / tree) and the nodes hang off the gateway hub accordingly; every device card shows OS guess + open services + risk; the session target is a red aura bound to its device; **live status: online hosts carry a red-dot corner badge and offline devices render faded** (liveness re-probed after every scan and every 30s, so a powered-off machine never looks like a valid target and is never ranked); animated **attack-path overlay** — the best chain to the beacon drawn as a glowing route, same graph the auto-mode planner reasons on; "Find weak spot" ranks every LIVE device by weighted attack surface and recommends where to start), Audit Log (tamper-evident C2 activity feed: SHA-256 hash-chain verdict — chain intact vs broken at record N — plus live registration/task/result records), Learning (what the experience engine has learned: episodes/learnable/success/failure counts, failure-cause distribution, reliable vs deprioritised patterns and the recent cause→repair episodes, with an explicit Reset) — plus the engagement **Timeline** rendered in both generated reports

**Media & Portability:** **Recordings** (the beacon's screen recordings — `screen-record` clips, `screen-record-live` progressive segments, `screen-dump` `.mp4` — land here as REAL playable media: a live view that auto-opens each segment as it arrives so you watch the target screen while it records, an inline `<video>` library, and save-to-disk through a native save dialog), **Bundles** (`.pm` engagement bundles: every portable session file listed with target/size/date, one-click export of the current engagement, one-click import to restore session + knowledge + auto-mode checkpoint on this or another machine — the app also auto-exports a `.pm` every time it closes, so a handoff bundle always exists)

**Modules:** 12 module panels — each with state-aware suggested commands, Run Selected / Run Group / Run All, inline Edit, per-module Preflight

**Output:** Reports (dual raw + client, export all, export campaign ZIP), Settings (WSL2/native/SSH backend, mTLS toggle, API token rotation)

### Architecture

```
Electron (React + Vite + TypeScript)
        │  HTTP + Ctrl+K Command Palette
        ▼
Python API Server  (localhost:9876, 45+ endpoints)
        │
        ├─ phantom.core.automode   → auto-mode kill chain
        ├─ phantom.core.c2_server   → C2 listener + beacon control
        ├─ phantom.core.session     → session + knowledge + vault
        ├─ phantom.modules.*        → 12 manual modules
        └─ phantom.api.backend       → WSL2 / Native / SSH dispatcher
```

External tools (nmap, Metasploit, aircrack-ng) execute through a configurable backend dispatcher, never inside Electron itself. The GUI auto-detects WSL2 Kali, falls back to native tools, or connects to a remote Kali via SSH.

> **WSL2 backend note:** commands run as **root inside the distro**
> (`wsl.exe -d <distro> -u root -- bash -lc …`). The WSL default user
> (`kali`) is not root, so a `sudo nmap …` module command used to hang
> silently waiting for a password prompt (stdin is DEVNULL) — every scan
> appeared to "run" with zero output. Running as root keeps `sudo` a no-op
> while executing the operator's requested command verbatim.

---

## C2 Shell Commands

| Command | Description |
|:---|:---|
| `listeners start/stop <port>` | Manage HTTPS + mTLS listener |
| `beacons` | List active beacon sessions with live status |
| `interact <id>` | Enter interactive beacon terminal |
| `generate <platform>` | Compile beacon + print dropper (windows/linux/android/macos) |
| `payloads` | Show generated payload history |
| `beacon-help` | Show 35+ beacon command reference |
| `beacon-auth` | Show, rotate, or revoke per-beacon HMAC keys |
| `certs` | Inspect or remove TLS certificate pair |
| `config` | Show/rotate C2 secrets, toggle mTLS |
| `telegram` | Start Telegram C2 bot |
| `results` | View queued task output for active beacon |
| `screen-watch` | Local player for screen recordings: live progressive segments + finished `.mp4` library |
| `screen-open <file>` | Open one recording artifact from `data/recordings/` |

---

## AD Graph (BloodHound-style, manual core)

The manual core ships a native AD attack graph — no BloodHound install, no
Neo4j — with the same mental model: nodes (users, groups, computers, DCs,
domain), typed edges (member_of, admin_to, session, kerberoastable,
as_rep_roastable, cracked, owns) and shortest-path analysis to Domain
Admin. It is FULLY connected to the rest of the framework:

- **auto-mode data flows in automatically** — every AD finding the agent
  produces (`ad_domain`, `ad_users`, `ad_user`, `ad_weakness`, domain
  `creds` from kerberoast/AS-REP/DCSync/hash-crack) folds into the graph;
- **manual core commands add the rest** — your own observations join the
  same graph, persisted in `data/ad_graph.json` across sessions;
- **Electron renders it** — the AD Graph panel shows the tree, edge types
  and DA paths (same backend, `/api/v1/ad/graph`).

CLI commands (`help ad` for the full syntax):

| Command | Description |
|:---|:---|
| `ad tree` | ASCII view of domain → DC → users/computers with flags |
| `ad paths` | Shortest attack paths to Domain Admin (BFS over typed edges) |
| `ad add-user <u> [--kerberoastable] [--as-rep] [--cracked] [--admin-to H] [--session-on H] [--group G]` | Record a user and its relationships |
| `ad add-dc <host>` | Register the domain controller |
| `ad add-edge <src> <type> <dst>` | Raw edge (member_of/admin_to/session/owns) |
| `ad reset` | Clear the graph for a new engagement |

Not a 1:1 BloodHound clone: no ACL-edge collection (SharpHound collectors),
no GPO/OU objects — phantom ingests what ITS chain and the operator know,
which is what an engagement needs, without shipping collector binaries.

---

## Beacon Audit & Hardening

The beacon/C2 transport has been reviewed for reliability and safety:

- **Task lease & idempotency:** queued tasks use a bounded lease; lost HTTP responses don't lose work; duplicate retries are idempotent
- **API auth:** `/api/v1/payload*`, `/x`, `/s/android` require `PHANTOM_PAYLOAD_TOKEN`; `/api/v1/beacons`, `/api/v1/queue`, `/api/v1/results` require `PHANTOM_API_TOKEN` on non-localhost
- **Result caps:** beacon bodies capped at 10 MiB; server caps retained results per beacon
- **Task watchdog:** every task runs on a worker thread with a per-command budget (30 s default, media captures duration + 15 s, camera 45 s) — a hung camera `ReadSample` or stuck shell pipe can no longer wedge the beacon loop or leave tasks stuck "sent" forever
- **Evasion ships by default:** sleep mask, stack spoofing, ekko, debugger/VM checks compile into every normal build (`disable_anti=False` default); the `rbp` inline-asm symbol bug that made the anti-evasion build fail at link time is fixed
- **Artifact sniffing:** screenshot/camera/download artifacts are saved with the REAL extension from magic bytes (a Linux JPEG camera frame is never stored as `.bmp`), so Electron renders them inline in the task view's media strip
- **Socket limits:** Linux/Android sockets have bounded connect/send/receive/response-buffer limits; failed uploads are retained in order
- **Docker safety:** C2 secrets never baked into image build args or layers
- **Key rotation:** 120-second transition window — old key accepted while beacon acknowledges new key; rotation persists via DPAPI (Win) or `0600` state file (POSIX)
- **Compromised keys:** revoke first, rebuild/re-enroll; don't trust the compromised channel to rotate itself
- **Field-tested chain:** beacon build → SSH deploy → mTLS/HMAC check-in → task execution → encrypted result verified end-to-end against the local lab (see below), with malleable URIs (rotated/random-cased) handled by the C2 content-routed catch-all

---

## Local Test Lab

`lab/` ships an **intentionally vulnerable, segmented network** — dmz →
internal → **real Samba AD domain controller** — so every offensive module
(including lateral movement and the AD chain) can be exercised against
targets you own, legally and offline:

| Host | Port (host) | Service | Weakness |
|---|---|---|---|
| `dmz` | `2222` | SSH (non-standard) | creds only via the web app |
| `dmz` | `2121` | FTP | anonymous login |
| `dmz` | `8081` | HTTP | SQLi login + SSRF file read |
| `internal` | — (pivot only) | SSH | reachable only through `dmz` |
| `dc` | — (pivot only) | AD DC `CORP.LOCAL` | kerberoast / AS-REP / DA objects seeded |

```bash
cd lab && docker compose up -d --build
```

Use it for `scan`/`brute`/`exploit`, `web` credential recovery, beacon
deployment + persistence, lateral/vertical movement, `goal=deep` auto-mode
drills and the AD chain. **Never expose the lab beyond localhost** — it exists
to be owned. See `lab/README.md` for the full kill chain, DC accounts and the
Docker/Samba fixes that keep the domain controller running.

> **Operational note:** if you override `PHANTOM_C2_KEY` / `PHANTOM_C2_NONCE` in your `.env`, build beacons from the same checkout (or export the same values to the build environment) — the beacon embeds the AES key it was built with, and a mismatch makes task decryption fail silently.

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

Add exploits in `phantom/exploits/<category>/` with a `METADATA` dict and `run(target, port, **kwargs)` function.

**Shipped PoC portfolio** (`phantom/exploits/pocs/`, used by `fire <cve>` / `execute <name>`): real, verifiable, stdlib-only checks — no templates:

| PoC | CVE | Class |
|:---|:---|:---|
| `heartbleed.py` | CVE-2014-0160 | TLS heartbeat memory leak |
| `apache_path_traversal.py` | CVE-2021-41773 | Apache 2.4.49 traversal + RCE (mod_cgi) |
| `struts2_rce.py` | CVE-2017-5638 | Struts2 Jakarta OGNL RCE |
| `log4shell.py` | CVE-2021-44228 | Log4Shell JNDI delivery + reflection (callback via `PHANTOM_LOG4J_CALLBACK`) |
| `fortios_traversal.py` | CVE-2018-13379 | FortiOS SSL-VPN session/credential leak |
| `cisco_asa_traversal.py` | CVE-2020-3452 | Cisco ASA/FTD AnyConnect file read |

Every PoC runs in an isolated subprocess with a hard timeout and fails softly on unreachable targets.

---

## Project Structure

```
phantom/
├── _run_c2.py                  # Standalone C2 REST server (no shell)
├── phantom/
│   ├── core/                   # Shell, C2 server, session, automode, knowledge
│   ├── modules/                # 12 manual pentest modules
│   ├── automation/             # Autonomous agent, planner, stealth, anomaly engine
│   ├── api/                    # Electron API bridge (45+ endpoints)
│   ├── exploits/               # Dynamic exploit scripts
│   └── utils/                  # builder.py, c2_crypto.py, paths.py
├── phantom/payloads/beacon/src/
│   ├── main.cpp                # Beacon entry, C2 loop, command dispatch
│   ├── reflective_loader.c     # PE mapper (C, PIC, freestanding)
│   ├── reflective_loader_bootstrap.asm  # Assembly entry (PIC)
│   ├── syscalls.asm/.o         # Indirect syscalls (Hell's Gate)
│   ├── crypto.h                # AES-256-GCM, Base64
│   ├── network.h               # HTTPS C2 transport (WinHTTP/curl)
│   ├── evasion.h               # NTDLL unhook, AMSI/ETW, VM detect, sleep mask
│   ├── injection.h             # Remote thread injection (indirect syscalls)
│   ├── proxy.h                 # SOCKS5 proxy
│   ├── smb.h                   # SMB named-pipe C2
│   ├── browser_pivot.h         # Browser HTTP proxy pivot
│   ├── cdp_pivot.h             # Chrome CDP WebSocket pivot
│   ├── portfwd.h               # TCP port forwarding
│   ├── keylogger.h             # Context-aware keylogger (Win/Linux/Android)
│   ├── screenshot.h            # GDI / x11 / Android screen capture
│   ├── persistence.h           # RunKey / Cron / Systemd auto-start
│   ├── sleep_mask.h            # .data/.rdata XOR encryption during sleep
│   ├── netstat.h               # TCP connection monitor
│   ├── cookie_stealer.h        # Chrome cookie decryption (DPAPI + inline SQLite)
│   ├── camera.h                # Webcam capture (DirectShow/v4l2/Android)
│   ├── audio.h                 # Audio recording (WASAPI/arecord/ffmpeg)
│   ├── screen_record.h         # Screen recording (Desktop Duplication/x11grab)
│   ├── gps.h                   # GPS coordinates (Win/Linux/Android)
│   ├── wlan_scan.h             # Wi-Fi scanning
│   └── bt_scan.h               # Bluetooth scanning
├── electron/                   # React + Vite + TypeScript desktop app
├── data/                       # Sessions, cache, certs, wordlists
├── tests/                      # 74 test files
├── Dockerfile                  # Multi-stage Kali-based build
├── docker-compose.yml          # One-command deployment
└── .env.example                # External API template
```

---

## Legal Disclaimer

Phantom is intended for authorized penetration testing and educational purposes only. Use only on systems where you have explicit, written permission. The author is not responsible for any misuse or damage caused by this program.

---

## Author

**Terminalkid09** — [GitHub](https://github.com/Terminalkid09)