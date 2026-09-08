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
flags                             # show/change flags (aggressive, stealth, speed, agents, goal, profile, llm)

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

### Lure crafting (social / IP grabbers / QR / beacon delivery)

```text
craft ipgrab            # plain IP-grabber link (click = IP + fingerprint)
craft reel <link|term>  # video lure on a REAL video YOU pick: paste an
                        #   IG/TikTok/YT link to mirror, or a search term;
                        #   identifier stripped, click lands on the grabber
craft image <file|url>  # ZERO-CLICK image lure: hosts an image YOU choose;
                        #   when it RENDERS (email <img>/page/browser) the IP,
                        #   device and location are captured — no click
craft pixel             # 1x1 tracking pixel (same zero-click capture)
craft beacon [platform] # one-click beacon link DISGUISED as a reel URL
                        #   (opens → downloads the compiled implant)
craft hits <code>       # every hit/open/cred + device, browser, geo
craft wait <code> [s]   # live-wait for the target
map [cidr]              # discover every live device on the network
                        #   (arp-scan → nmap -sn → ping) → feeds the network map
                        #   + detects the LAN topology (star / broadcast / tree),
                        #   fingerprints each device (open ports, services, OS
                        #   guess) and ranks the most exposed ones
install <tool>          # install a missing tool in the current backend
                        #   (apt / brew / choco / pip auto-selected, WSL on Windows)
```

**Honest limitation:** no image can install a beacon with zero interaction —
that is 0-day territory, not a tool feature. What Phantom ships is the
closest real thing: an **image / pixel that captures the IP, device
fingerprint and location the moment it renders** (the "zero-click" part —
rendering needs no click), real **reel-style links on videos you choose**
(the share link strips the author's identifier), and a **beacon link
disguised as a shared reel** that downloads the compiled implant in one tap.
In the auto-mode the same engine already prefers Instagram reels for
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

**Media:** `gps`, `camera`, `audio <duration>`, `screen-record <duration>`

**Wireless:** `wlan-scan`, `wlan-locate`, `bt-scan`, `bt-scan-json`

**Security:** `auth-rotate <base64_secret>`

### Manual Pentest Modules (12)

| Module | Purpose | Key Tools |
|:---|:---|:---|
| **Scan** | Active reconnaissance (state-aware suggestions) | nmap, traceroute, service enum |
| **OSINT** | Passive intelligence | crt.sh, Shodan, BGP, Whois, theHarvester, Sherlock |
| **WiFi** | Wireless attacks | aircrack-ng, reaver, hcxdumptool |
| **Web** | Web application testing | gobuster, sqlmap, nikto, ffuf, `creds` (SSRF/SQLi credential extraction) |
| **Brute** | Credential auditing | hydra, medusa, john, hashcat |
| **Exploit** | CVE correlation, version-matched MSF commands, PoC deployment, `ssh` (reuse harvested creds) | NVD, searchsploit, MSF |
| **Payload** | Payload generation and priv esc | msfvenom, privesc, custom C2 droppers |
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
- `use payload` → `privesc` — real post-exploitation escalation enumeration (sudo -l / SUID / GTFObins), not a static tool list.

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
phantom --auto <target> --llm        # + optional local-LLM hypothesis advisor
phantom --auto <target> --verbose    # stream the LIVE reasoning trace (inferences,
                                     #   hypotheses, confirmations/refutations)
                                     #   — same stream in Electron's Auto-Mode panel
phantom --auto <target> --goal deep  # full engagement ladder: beacon + persistence
                                     #   -> SYSTEM/root + injection -> AD (kerberoast /
                                     #   AS-REP) -> hash crack -> lateral — every stage
                                     #   runs until it succeeds or proves non-viable;
                                     #   one C2 handoff at the end, per-stage report
```

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
AUTO > flags aggressive on                  # per-run flags: aggressive|stealth|speed|agents|goal|profile|llm
AUTO > plan                                 # dry-run the planned chain (executes nothing)
AUTO > launch                               # run the chain; beacon -> C2 handoff
AUTO > resume checkpoint.json               # continue from a checkpoint or an imported .pm
AUTO > status                               # per-target event summary (waiting/sleep states)
AUTO > export handoff.pm                    # portable bundle for another operator
AUTO > back                                 # return to the main Phantom shell
```

**Target types:** IP addresses (network chain), domains (DNS → IP → network chain), email/username/phone (OSINT → breach → persona → victim-IP → network chain).

**Phases:** Target classification → Scan → OS Detection → OSINT → Web Recon → CVE Correlation → Credential Testing → RCE Bridge → Beacon Deploy → Persistence → Dual Report.

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
- **Social DM** (`dm_launch` capability) — short pretext DMs (security verify, recruiter, collab, giveaway, invoice) delivered over free key-only channels (**Telegram Bot API** via `PHANTOM_TELEGRAM_BOT_TOKEN`, or a **Discord webhook** via `PHANTOM_DISCORD_WEBHOOK`); every DM carries a per-target tracking link, so a click still converts into a `victim_ip` and the network chain takes over. No transport configured → clear ERROR marker, never a hang. Custom platforms (X/Instagram/Reddit DMs) plug in via `PHANTOM_DM_TRANSPORT=<dotted.path.Class>`.
- **Coherent persona cover** (`persona_profile` capability) — a believable social profile with zero configuration: name, age *consistent with the role*, city/country matching the engagement locale, interests, a bio, and an avatar (offline Pillow gradient+initials by default; `PHANTOM_PERSONA_AVATAR=randomuser` fetches a free portrait photo cached under `data/personas/`). Same seed → same profile, so campaigns are reproducible. **Audience-aware**: `middle` / `high` / `university` / `professional` adapts the cover to the target's world — a 15-year-old gets a 15-year-old peer (school, age band, student interests), never a "Senior Developer"; inferred automatically from the discovered platform (Instagram/TikTok → student) when not specified.
- **Profile reverse-engineering** (`profile_recon` capability) — OSINT mapping of the target's social profile: fetches the profile page and determines **private / public / missing**, extracts the **bio, the link in bio, @handles and emails**, and runs sherlock on discovered handles to find the **same person on other platforms** (including public accounts of the same handle). A private profile is never scraped — it is mapped, and every new handle/email becomes a pivot lead. The profile state (private, bio, linked accounts) feeds the strategic dossier.
- **Video-lure IP grabbing** — links to `/v/<code>` serve a page that looks exactly like an **Instagram Reel / TikTok / YouTube Short** and plays a real embedded video; the page load *is* the click, so the victim's IP is captured exactly like a normal link click. Skin via `PHANTOM_TRACK_SKIN=instagram|tiktok|youtube`, embedded video via `PHANTOM_TRACK_VIDEO_ID`.
- **Share-format video links** — `create_video_share_link()` produces the *same URL shape you get when you press "share"* on a real video: `/@user/video/<code>` (TikTok), `/reel/<code>` (Instagram), `/shorts/<code>` (YouTube). The tracker serves these paths with the platform skin; the tracking code is embedded in the path and **there is no traceable profile identifier** in the link. Victims open a "shared video" — the highest-converting IP-grab vector.
- **Real-video picker** — the lure is never a fake video: `pick_video()` chooses a **real, harmless public video the target would actually click on**, driven by the interests extracted from their profile bio (`yt-dlp ytsearch3:<topic>` when installed, a curated offline catalog of famous uploads otherwise; with `--llm` the advisor suggests the topic). The share link then renders that exact video with its real title/channel — the target sees a video relevant to them, not a generic placeholder. `/api/video-lure` exposes the picker to Electron.
- **Strategic phishing** (`dossier_analyze` capability) — one high-quality lure per target instead of a spray: a **target dossier** merges everything OSINT found (name, emails, phones, platform, company) and **correlates breaches across channels** — when the same breach name shows up for the victim's email *and* their phone, that becomes a recognition hook the target cannot ignore ("how do you know my number?"). A deterministic scorer picks the most credible pretext (delivery notice when only a phone is known, security alert when a real breach exists, recruiter when there's a public profile...), and with `--llm` the local advisor refines the hook and subject twist — every suggestion sanitized (no URLs, no placeholders, bounded length) and never able to change the channel or target.
- Strategic mode is one flag away: `campaign(strategic=True)` / `phish(strategic=True, use_video=True)` — hook + pretext from the dossier, subject twist from the advisor, From display name from the persona cover for human pretexts (recruiter).
- **Sender realism + homoglyphs** — the From identity is derived from the dossier: a **SERVICE the target uses** (platform brand + domain, e.g. `LinkedIn Security <security@linkedin.com>`) or a **PERSON they know** (a colleague at the same corporate domain when OSINT found one), never a fake-looking `.example` address and never impersonating free-mail providers. The display name and subject are then obfuscated with **Cyrillic homoglyphs** (visually identical, byte-different) so naive text filters stop matching canonical keywords like "LinkedIn" or "account" — the classic IDN-homograph trick applied to headers (`PHANTOM_PHISH_HOMOGLYPH`, on by default, off in aggressive mode).
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

**Optional local-LLM advisor** (`--llm`) — deterministic-first, LLM never decides:
- The expert system remains the decision layer; a local GGUF model (default: Qwen2.5-Instruct, any size via `PHANTOM_LLM_MODEL`) *proposes* extra hypotheses only
- Injection-hardened by design: output is a strict `{capability_id, reason}` JSON schema, target content is wrapped as `<UNTRUSTED_DATA>` and never mixed with instructions, ids are validated against the capability registry, and paranoid mode strips loud suggestions — a fully successful prompt injection can only add noise, never authorize an action
- Zero data egress: the model runs on your machine (`pip install llama-cpp-python`)

**Environment recognition** — classifies the battlefield:
- Docker API (2375/2376) → `container`
- Kubernetes API (6443/10250) → `kubernetes`
- SCADA/ICS ports (502, 102, 20000, 47808) → `scada`
- SSRF to `169.254.169.254` → `cloud` (AWS) + IAM credential harvest
- Post-beacon internal probe: `/proc/1/cgroup`, `/.dockerenv`, IMDS v2 token flow

**Strategy weighting:** `network_footprint (75)` → `exploit_chain (72)` → `network_creds (70)` → `network_beacon (65)`. `exploit_chain` only activates when a service is fingerprinted (software + version).

**Sub-agents** (`-aN`): parallel workers share discovered credentials via `ShareContext`. Auto-decides pool size from a quick dry-run plan if `-a` is used without a count.

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

**Secure by default — zero configuration required.** Phantom auto-generates all secrets on first run.

`data/phantom_state.json` (gitignored, `0600`):
- `PHANTOM_C2_KEY` — 32-byte AES-256 key, embedded in every beacon
- `PHANTOM_PAYLOAD_TOKEN` — gates `/api/v1/payload*`, `/x`, `/s/android`
- `PHANTOM_API_TOKEN` — gates `/api/v1/beacons`, `/api/v1/queue`, `/api/v1/results`
- Beacon auth ON by default — every `generate` creates a unique per-beacon HMAC identity
- mTLS ON by default — `CERT_OPTIONAL` at TLS layer, enforced via middleware on beacon routes

**Console:** `config` shows status. `config rotate-api-token` rotates. `config mtls-off` disables mTLS.

**Optional `.env` values** (only for external APIs):

| Variable | Purpose |
|:---|:---|
| `NVD_API_KEY` | NVD API rate limit boost (50 req/30s vs 5) |
| `PHANTOM_HIBP_API_KEY` | HaveIBeenPwned v3 breach lookup |
| `PHANTOM_BREACH_API` | Self-hosted breach dump API for credential reuse |
| `PHANTOM_SMTP_HOST/PORT/USER/PASSWORD` | SMTP relay for phish email + email-to-SMS |
| `PHANTOM_TRACK_URL` | Self-hosted IP-grabber URL (victim click tracking) |
| `PHANTOM_TELEGRAM_BOT_TOKEN` | Telegram C2 bot |

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
| Multi-day Sessions | Lost on terminal close | Full save/load + WorldModel persistence |
| Export | Manual | One-click ZIP (session + C2 + vault + timeline + dual reports) |

### Panels (all 18 views)

**Operations:** C2 Dashboard (listener, beacons with LIVE/IDLE/EXITED telemetry + queued-task badges, generate, beacon-auth, certs, audit-log viewer, **live media strip** — screenshots / camera frames the beacon delivers render as clickable thumbnails right above the task table, not just a saved path), Session Manager (target/scope, **Suggest Next / Run** adaptive step, preflight, knowledge, wordlists), Auto-Mode (one-click kill chain, live graph, reasoning stream, dry-run)

> **Packaging note (Windows):** the desktop app's Python backend ships as a
> **onedir** PyInstaller build. This is deliberate — onefile executables use a
> self-extracting bootloader that AV engines (Defender, McAfee) routinely
> flag as heuristic false positives. If you rebuild the backend yourself,
> use `phantom/api/phantom-backend-onedir.spec`.

**Intel:** Timeline (chronological events + operator notes), Vault (centralized credentials with search/copy), Network Map (pan/zoom SVG canvas laid out like the REAL network — the scan detects the topology (star / broadcast / tree) and the nodes hang off the gateway hub accordingly; every device card shows OS guess + open services + risk; the session target is a red aura bound to its device; animated **attack-path overlay** — the best chain to the beacon drawn as a glowing route, same graph the auto-mode planner reasons on; "Find weak spot" ranks every device by weighted attack surface and recommends where to start), Audit Log (tamper-evident C2 activity feed: SHA-256 hash-chain verdict — chain intact vs broken at record N — plus live registration/task/result records)

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