# Changelog

All notable changes to Phantom.

---

## [3.7.16] — 2026-09

### Manual scan produced ZERO output from Electron/CLI (WSL2 sudo hang)

The WSL2 backend invoked `wsl.exe -d <distro> -- bash -lc "sudo nmap …"`
with the distro's DEFAULT user (`kali`, not root): `sudo` printed nothing
and hung waiting for a password prompt (stdin is DEVNULL), so every scan
timed out after 2 minutes with no output at all. The backend now runs as
`-u root` inside the distro, making `sudo` a no-op — verified live: the
installed app returns real nmap output for `sudo nmap -sV -sC`.

### Auto-mode: empty `[+] os_detect:` lines + missing finding values

- `os_detect` on a host nmap cannot fingerprint ("Too many fingerprints
  match this host") produced an EMPTY success line indistinguishable from
  a real hit. A clean-but-empty run now emits a `note` event with the
  concrete reason (also handled for `no open ports`, `host seems down`, …).
- The CLI renderer now shows finding VALUES (`os:detected = Linux 5.15`),
  not just fact names — same as Electron already did.
- Empty `[+]` lines are no longer emitted at all when a run found nothing.

### Beacon: tasks stuck "sent" forever (camera / long media hangs)

The single-threaded beacon loop executed every task synchronously: a
camera Media Foundation `ReadSample` hang (or any stuck shell pipe)
wedged the whole beacon — it stopped checking in, the task stayed "sent"
forever, and every later task (gps, screenshot, …) queued behind it. Tasks
now run on a worker thread with a per-command budget (30 s default,
media captures duration + 15 s, camera 45 s); on timeout the task returns
`[TASK_TIMEOUT] … beacon continues` and the loop keeps polling.

### Beacon: real evasion was compiled OUT of every shipped binary

The `rbp` inline-asm bug (`mov %0, rbp` = a SYMBOL reference in AT&T
syntax → "undefined reference to rbp" at link) made the anti-evasion build
fail, and every caller used the `disable_anti=True` default — so sleep
mask, stack spoofing, ekko, debugger/VM checks never shipped. Fixed the
asm (`%%rbp`) and flipped the default so normal builds (CLI/Electron
generate, automode deploy) get the full evasion stack.

### Beacon artifacts: JPEG camera frames saved as `.bmp` → invisible

Linux/Android camera frames are JPEG but every save path forced `.bmp`,
so Electron served them as `image/bmp` and they never rendered. Both save
paths now sniff magic bytes (JPEG/PNG/BMP/GIF) for the real extension, and
`/api/c2/artifacts` classifies by extension instead of directory — old
screenshots under `downloads/` now render as images too. A live media
strip shows delivered screenshots/camera frames INLINE above the task
table (not just a saved path in the result text).

---

## [3.7.15] — 2026-09

### Electron — "AbortError: This operation was aborted" on every long operation

The main process aborted every renderer API request after **120 s**, so any
network scan, module run, or automode plan longer than two minutes surfaced
as `AbortError` — the user had to re-run and hope. Requests now get a
**2-hour budget** (legitimately long operations: full-range scans,
run-group batches, the automode plan endpoint). The renderer was rebuilt
and the packaged app re-verified: the readiness gate and the new timeout
are in `app.asar`.

### Network map — the phantom "target bubble" finally gone (server-side)

The server still created a fake `host_<target>` node for the session
target; when the target WAS a discovered device, the bare fake node won
the id-dedup and its metadata (OS/services) was dropped — the bubble whose
IP seemed to "change" when switching targets. The node no longer exists:
the session target is only the solid red aura bound to the real device id.

### Beacon — real Windows GPS + real camera frames

- **GPS**: full WinRT `Geolocator` implementation (async COM init, permission
  check, coordinate + accuracy) with WLAN BSSID/band fallback when the
  user has location services off — replaces the old "WWAN Service: 3"-style
  debug dump that passed as GPS output.
- **Camera**: staged Media Foundation capture (device enum → `IMFMediaSource`
  → sample grabber) returning `CAM_FRAME:<device>|MEDIA_B64:<jpeg>`; the C2
  saves it as an artifact. Falls back to the device-list-only answer when no
  WinRT/MF context is available.
- C2 side: `CAM_FRAME`/`MEDIA_B64` markers parsed, artifacts stored and
  served via `/api/artifact`; the Electron C2 panel renders them as images.

### Beacon help — every command, structured

`BEACON_COMMANDS` was a rich-formatted *string* that the `/api/c2/beacon-help`
endpoint iterated as a list of tuples — it errored and fell back to a
hardcoded 11-command list. It is now a structured list of
`(command, description)` pairs; the Electron panel shows the full catalog,
auto-loads it when the beacon panel opens, and **autocompletes while you
type** (so you no longer have to choose between seeing the list or typing).
Task leases are marked `sent` on delivery so the queue state is truthful.

### Auto-mode — visible findings, no blind repeats, clean identity runs

- **Findings are shown**: capability results carry their values into the
  event stream (`[+] http_probe: web_header:Server=nginx/1.24`) instead of
  bare fact keys; empty `Inference:`/`Hypothesis:` lines are suppressed.
- **Repeat-guard**: a capability that already produced its target fact kind
  is never re-armed when preconditions merely refresh — kills the
  `http_probe → scan → http_probe` loops seen on fast mode.
- **Identity-on-IP terminates correctly**: the planner's
  `fallback: identity -> footprint` strategy is tracked (`_fallback_goal`),
  so the agent accepts the degraded terminal state instead of spinning
  recoveries for facts that can never exist on an IP target — and only
  when the planner actually degraded (live runs keep full depth). Verified
  live against the gateway: 4 unique actions, zero repeats, no
  "no affordable path".

### Tests

- `tests/test_c2_helpers.py` (new): structured beacon command list,
  CAM_FRAME/MEDIA_B64 artifact parsing.
- `tests/test_automation_agent.py`: 24/24 green against the new
  repeat-guard + fallback tracking.
- `tests/test_craft_netmap.py`: topology + enrichment suite green
  (32 passed with the c2 helpers file).

---

## [3.7.14] — 2026-09

### Network map — real topology, real device intel, target aura bound to the device

- **Topology detection**: the network scan now infers the LAN shape —
  `star` (devices behind one gateway), `broadcast`/flat (many hosts expose
  SMB/NetBIOS to each other), `tree` (routed segments) — with gateway IP,
  confidence and a human note. The Electron map lays nodes out according
  to the detected shape (hub-and-spoke for star, tiers for tree, wide flat
  row for broadcast) and shows the topology verdict above the canvas.
- **Richer device intel**: every discovered device now gets a quick
  fingerprint during the scan (top service ports via TCP connect, a service
  banner, an OS guess from port set + banner). The map cards and detail
  panel show OS guess + open services; the WorldModel carries the same
  fields so the auto-mode planner sees them too.
- **Edges restored + hub spokes**: the connection lines are always drawn;
  star/tree layouts add faint hub→device spokes so the map reads as a
  network diagram. The attacker link is a dashed red line into the hub.
- **No phantom target bubble**: the session target is ONLY a solid red
  aura around the real device node (bound to the node id — it moves when
  the target changes). Gateway devices get a subtle dashed ring instead.
- **ARP noise filtered**: multicast/broadcast entries no longer appear as
  devices.

### Beacon generation — deploy command like the CLI

`/api/c2/generate` now returns `dropper`: the ready-to-paste one-liner
(PowerShell PIC stager for Windows, curl|chmod|nohup for Linux/macOS,
TMPDIR exec for Android) that downloads and injects the beacon from any
RCE / reverse-shell channel. The Electron Generate panel shows it in a
copyable code block with usage guidance.

### Auto-mode — session target is enough to Launch

The Launch/Dry-Run buttons now unlock when the Session panel has a target
(the session target is target #1 of the run); extra targets remain
optional. The target chips show which one is the session target.

---

## [3.7.13] — 2026-09

### Fixed — beacon generation from Electron was calling a non-existent function

`/api/c2/generate` imported `build_beacon` from `phantom.utils.builder` — a
symbol that does not exist (the real API is `compile_beacon`, which the CLI
uses). Every GUI generate failed with a 500 while the CLI kept working.
The route now mirrors the CLI path exactly: writes the C2 config for the
current endpoint (session LHOST/LPORT or the auto-detected C2 endpoint),
rebuilds only when the config changed, and returns path/size/C2 on success.
**Verified live on the installed app: linux (274 KB ELF) and windows
(1.4 MB beacon.bin) both compile and target the real LAN C2 endpoint.**

### Fixed — kill-chain order (blind probes before the scan)

The captured run opened with `ssh banner → fail → http probe → port scan`:
the planner submitted probing moves BEFORE any service was known, so they
fired blind, failed, and the whole thing read as a random order. Two gates:

- `_pick_source` (planner): while the WorldModel has NO service fact, the
  scan that produces services always wins over probing moves.
- `_priority` (agent): the same discipline in the orchestrator queue — a
  capability producing `service` outranks everything (priority 100) until
  the first service exists; after that the normal value ranking applies.

Cold plan verified: `scan_tcp → os_detect → http_probe → ssh_banner`.

### Fixed — panels starting with "fetch failed" until a manual refresh

The main process answered renderer requests during backend startup (2-4s)
with instant fetch errors. `api-request` now waits on a readiness gate
(health-probes `/api/session` up to 20s) before the first request of the
session; once ready it's a no-op. Opening the app is now clean — no refresh
required.

### Improved — map wires back + ring layout + aura that follows the target

- Edges restored (the wires stay), with a **scenographic ellipse ring**: the
  attacker at the anchor, the hub at the stage center, the other devices on
  the ring like a radar diagram instead of a rigid grid.
- The red target aura is **bound to the target host node id, not to a fixed
  coordinate**: changing the session target MOVES the aura (and the hub) to
  the matching device — no second fake "target" bubble ever appears, and the
  IP under a node can never silently disagree with the highlight.

### Improved — auto-mode target precedence in the Electron panel

The Session panel's target is now **target #1** of an auto-mode run; targets
added in the Auto-Mode panel are additional (deduplicated) — matching the
CLI semantics instead of the previous "extras replace the session target"
behavior.

---

## [3.7.12] — 2026-09

### Fixed — auto-mode scan timeout loop (the 4-minute repeats)

The run the operator captured (scan 4 min → timeout → same scan → timeout …)
had three stacked causes, all fixed:

- **Full-range scan could never finish in its 240s budget** (nmap `-sV` on
  1-65535 through WSL): it was killed at the timeout and counted as a plain
  failure. The port scan no longer carries `-sV` (dedup with version_detect);
  **version_detect now re-probes only the ports the scan actually found**
  (`-p 2222,8081`) instead of re-sweeping everything.
- **Timeout discarded all partial output**: `execute_quiet` now DRAINS the
  pipe buffers after killing a timed-out process, and the agent SALVAGES the
  findings through perception — an 85%-done sweep still delivers its open
  ports instead of being recorded as an empty failure.
- **Stall recovery re-armed recon forever**: the recovery loop re-armed failed
  recon capabilities even when they had ALREADY produced their facts earlier
  in the run, producing the exact observed loop. A failed recon move is now
  only re-armed if it never produced its facts (plus the existing
  missing-tool and poison guards).

Verified end-to-end against 127.0.0.1: every capability now runs exactly once
(ssh_banner, http_probe, scan_tcp, os_detect, web_creds, web_rce — counts all
1), version detection is seconds not minutes, no repeats.

### Fixed — module runs from the Electron panels returning empty output

`BackendDispatcher._run_argv` (module Run buttons) also discarded partial
output on timeout. Same salvage applied: partial stdout is returned with
`timed_out: true`, so a long module run shows what it found instead of
"comando sì, output no".

### Improved — weak-spot ranking honesty + UI

- The ranker now grabs a **service banner** from each device's riskiest open
  port: any readable banner adds exposure (unauthenticated info leak), a
  version number adds more, and the banner is shown on the card. Rationale:
  the criterion is now weighted services (SMB/RDP/telnet/DB/docker) + banner
  versioning — NOT just the number of open ports, which unfairly crowned a
  router with trivial admin ports.
- The cards show **risk + numeric score + open ports + banner**; the map
  header explains the ranking criterion in one line.
- Devices with **no open port among the ~60 probed** show "no risk shown"
  semantics instead of an empty LOW badge.

### Fixed — map target placeholder removed

The map no longer renders a fake "target" node (the unexplained extra dot).
The session target is now highlighted with a **red dashed aura** on the real
device it matches (`is_target` metadata), and services/creds/findings/beacons
anchor to that device. Beacons always get a position (no orphan edges).

### Improved — C2 beacon interact panel

- Task list is now **newest-first** (immediate feedback after Queue).
- Rows with a result are **click-to-expand**: the full multi-line output
  (sysinfo, ls, pwd …) opens under the row instead of being truncated to one
  line; the first line stays as a preview.
- **Beacon Help auto-loads** on panel open — no more manual refresh to see
  the command list.

---

## [3.7.11] — 2026-09

### Fixed — Electron auto-mode dying instantly (the REAL root cause)

The planner fix (3.7.10) was necessary but not sufficient: the **frozen
backend exe crashed on its first rich print** — rich's legacy Windows console
renderer encodes with the console codepage (cp1252), and the first
`notifier.success("[✔] …")` raised `UnicodeEncodeError: 'charmap' codec can't
encode '\u2714'`, killing the auto-mode thread before ANY event reached the
UI. Result: "sequence complete" after ~0.2s with zero actions, only inside the
Electron app (my pipe-based tests had UTF-8 environments and never hit it).

- `phantom/utils/notifier.py`: on Windows, set console codepage 65001, enable
  VT processing (rich switches to the ANSI renderer), and reconfigure
  stdout/stderr to UTF-8 with `errors=replace` — rich output can no longer
  crash the backend on any encoding.
- `phantom/api/server.py`: the automode run-thread now emits a `failed` event
  ("auto-mode crashed: …") into the UI stream before halting — a backend
  crash can never again look like a silent no-op.

Verified on the installed app: automode run against 127.0.0.1 now streams
real work (ssh banner → http probe → port scan finds 4 services → os detect →
behavioural hunt) instead of the silent instant halt.

### Fixed — stale renderer shipped to the installed app

The previous installer packaged a **renderer built before the NetworkMap
rewrite** (`electron-builder` was invoked without a fresh `vite build`), so the
installed app showed the old map without the weak-spot button and pan/zoom.
The build now runs `npm run build` (tsc + vite) before packaging, and the
installed asar was verified to contain the new UI.

### Improved — session target handling

- New **✕ button** next to the Target input: clears the target (leaves the
  session without one) without wiping discovered devices — matches the
  backend's explicit-clear semantics.
- Device-card **"Use as target"** is now a real one-click action (sets the
  session target directly) instead of just opening the detail panel.

---

## [3.7.10] — 2026-09

### Fixed — auto-mode halting instantly with nothing done

The reported "[■] sequence complete / Auto-mode complete" after ~0 seconds with
zero actions had a real root cause in the planner: a goal whose fact kinds are
unreachable for the target's class produced an **empty plan**, and the agent
immediately halted ("no plan"). Two directions of graceful degradation were
added to `Planner.plan_strategic`:

- **identity/social goals on a network target** (ip/domain/url) now degrade to
  footprint recon (scan_tcp → os_detect → http_probe → ssh_banner): "identity"
  on an IP starts with a scan, as the operator expects.
- **network/terminal goals** (complete_kill_chain, deliver, beacon…) on an
  **identity target** (email/username/phone — e.g. the mobile profile) degrade
  to the identity chain (osint → phish → poll → victim_ip) instead of halting.

Verified end-to-end against 127.0.0.1: full kill chain now walks hunt (found
sqli/verb anomalies) → web_creds (admin/backup) → beacon compile → deploy
attempt (check-in fails on loopback, correct) with 8 real actions, versus 0
actions before the fix. Regression tests added for both fallback directions.

### Improved — Electron Network Map canvas

Rebuilt as a **pannable/zoomable infinite-style canvas**: drag anywhere to pan,
mouse wheel to zoom-to-cursor (35%–400%), +/−/reset controls, world background
grid, pan hint + live zoom readout. The graph world is much larger and more
spread out (1560×dynamic width, 96px row pitch, wider fan-outs) instead of
everything crammed into a fixed 920px box. All existing features kept: scan,
Find-weak-spot probe, recommendation banner with Start-here, clickable device
cards + detail panel, Set-as-Session-Target, attack-path overlay.

---

## [3.7.9] — 2026-09

### Fixed: module names (`handler`, …) no longer appear as installable tools

- The preflight filter only knew shell words + module subcommands — a
  suggestion like payload's `handler <port> <payload>` still collected
  `handler` (a Phantom MODULE) as a missing tool and offered
  `apt-get install handler`. Module names and payload/handler action words
  (`generate`, `deploy`, `privesc`, …) are now in the phantom-command
  registry (executor + API), so preflight and `install` refuse them.
  Verified live on the installed app: payload + exploit preflight report
  zero missing tools.

### Added: network exposure ranking — "where do I start?"

- `rank_hosts_exposure()` / `recommend_starting_target()` in
  `phantom/core/netmap.py`: parallel TCP-connect probe of ~60 common
  service ports on every discovered device, weighted by risk class
  (SMB/RDP/Telnet/Docker/Redis/Mongo/ADB/WebLogic score higher). Self is
  excluded. Returns a sorted list with score, risk label and open ports.
- CLI `map` now ranks every device after discovery and prints the
  **recommended starting target** with a human reason + the exact next
  command (`set target <ip>` → `use scan` → `run`).
- New `/api/network/vulnerable` route (thread executor — never blocks the
  API) powering the Electron **Find weak spot** button: highlights the
  weakest device with a WEAKEST badge, shows per-card risk + open ports,
  and a "Start here" action that sets it as session target.
- Electron Network Map layout widened (920px viewBox, 3 host columns,
  larger labels) so discovered devices are readable instead of cramped.

---

## [3.7.8] — 2026-09

### Fixed: preflight no longer treats Phantom commands as installable tools

- The preflight (CLI `preflight`, Electron Session/Module panels,
  `/api/session/preflight`) collected the FIRST TOKEN of every suggested
  command as a "tool to check". Phantom module subcommands (`deploy-agent`,
  `privesc-run`, `msf-search`, `run`, `fire`, …) are not system packages,
  so clicking Install ran `apt-get install deploy-agent` → "Unable to
  locate package deploy-agent". Now tokens backed by a module `do_*`
  handler or in the phantom-command registry are skipped, and on Windows a
  tool present in the WSL toolbox is not reported missing.
- `install <tool>` refuses phantom command names with a clear message
  instead of attempting a package install.

### Fixed: discovered network devices survive target changes and restarts

- Previously hosts lived only in the in-memory WorldModel, which is reset
  whenever the operator sets a different target and is empty after an app
  restart — so the Network Map looked dead/broken.
- Discovered devices are now persisted to `data/network_hosts.json` on
  every scan and re-seeded into the WorldModel automatically (after target
  changes and when the map loads with an empty WM). The map keeps showing
  the LAN even across restarts.
- `/api/session/set` now accepts an empty target to CLEAR the session
  target (returns `cleared: true`) without wiping the device store.

---

## [3.7.7] — 2026-09

### Fixed: network devices are now identified (no more "unknown") + install-tool never touches Windows sudo

- **Device identification**: after every scan, hosts are enriched from the
  system ARP cache (MAC), a local OUI vendor table (Cisco, Apple, Raspberry
  Pi, VMware, Xiaomi, …, plus randomized-MAC detection), and reverse
  DNS/NetBIOS (`nbtstat`) — hostname falls back to vendor, never to a bare
  "unknown". Verified on a real LAN: `modemtim`, `amazon-7b57f4058`,
  `S25-di-Cristian`, `Samsung`, `Roomba-…`, `bosch-dishwasher-…` all named.
- **Network Map UX rebuilt**: discovered devices render as a grid of
  clickable cards (icon by device kind: gateway / mobile / VM / IoT) —
  clicking opens a detail panel with IP (copy), hostname, MAC, vendor,
  source and a one-click **Set as Session Target** button (also available
  by clicking nodes in the graph). The graph is larger, hosts are laid out
  in a two-column grid, and the map node labels show device names instead
  of raw IPs.
- **`install <tool>` fixed on Windows** — root cause: `install_tool` and
  `tool_install_hint` compared `platform.system()` ("Windows") against
  `"win32"` (`sys.platform`), so every Windows install fell into the Linux
  branch and executed the raw `sudo apt-get …` candidate. On Windows 11
  24H2 the disabled native `sudo.exe` intercepts it and dies with
  "Sudo è disabilitato in questo computer". Now: platform detected from
  `sys.platform`, apt always routed through `wsl -d <distro> -u root`,
  pip user-scope fallback, choco elevated via UAC, hints rewritten
  Windows-first (WSL apt first, no sudo, no brew noise), and the disabled
  sudo.exe is hidden from PATH for child processes. Regression test:
  `test_windows_install_never_uses_sudo`.

---

## [3.7.6] — 2026-09

### Fixed: network scan no longer freezes the whole API

- `/api/network/scan` now runs the sweep in a thread executor instead of
  blocking the aiohttp event loop — previously a scan (or a slow ping
  sweep on a dead CIDR) froze **every** other API call, which the Session
  panel saw as random hangs and "resets".
- The fallback `_ping_sweep` now pings in parallel worker threads (24
  concurrent, 800ms per host) instead of serially (up to minutes for a
  /24) and is bounded by the overall timeout.
- Scan results are cached for 60s per target so repeated UI polls don't
  re-scan the network on every request.

---

## [3.7.5] — 2026-09

### Fixed: Electron state persistence + craft discoverability + tool install perms

- **Panels stay mounted** (hidden when inactive) instead of being unmounted
  on tab switch — a network scan, craft output, module form or auto-mode
  view no longer resets to zero the moment you look at another tab. All
  20 views (C2 / session / auto-mode / reports / settings / timeline /
  vault / network / audit / 11 modules) keep their live state and polls
  while hidden.
- **Craft Lure card moved directly under Target** in the Session panel
  (flex `order`) so the delivery layer is visible without scrolling past
  Knowledge/Preflight.
- **`install <tool>` permission fixes**: WSL apt now runs as root
  (`wsl -d <distro> -u root apt-get`, no password needed even when the
  distro default user is non-root — previously permission-denied on
  /var/lib/dpkg), native Windows pip installs use `--user` scope, and a
  choco install that hits an access-denied retries behind a UAC
  elevation prompt instead of failing. Linux apt tries plain (root) →
  `sudo -n` → `sudo` with `DEBIAN_FRONTEND=noninteractive`.

### Added: reverse-engineering runs for email targets too

`profile_recon` (the private/public profile mapper + same-handle
cross-platform search) was gated on username targets only. It now also
fires for **email** targets, mapping the local-part handle
(`mario.rossi@corp.com` → `mario.rossi`) through the same public-profile
OSINT pipeline (sherlock + bio/link/@handle extraction).

## [3.7.4] — 2026-09

### Added: lure crafting, network mapping, tool install, mobile defender profile

(v2) Delivery reworked per operator feedback — QR delivery removed:
- **`craft reel <link|term>`** — video lure on a REAL video the OPERATOR
  picks: paste an IG/TikTok/YT share link to mirror (yt-dlp resolves the
  real video) or a search term (auto-pick); the share link strips the
  author's identifier and the click lands on the IP grabber.
- **`craft image <file|url>`** — ZERO-CLICK image lure hosting the image the
  operator chooses at `/i/<code>`: rendering it (email `<img>` / page /
  browser) captures IP + OS + device + browser + referrer (+ geo when
  configured) with no interaction.
- **`craft beacon [platform]`** is now a ONE-CLICK LINK disguised as a reel
  URL (`/reel/<code>` silently 302s to the C2 payload endpoint) instead of a
  QR; per-code silent redirects added to the tracker.
- Tracker gained per-code **image hosting** (`/i/<code>`) and **silent
  redirects**; optional lazy online geo (`PHANTOM_GEO_ONLINE=1`, ip-api, at
  read time only) alongside the MaxMind DB.
- Electron: QR removed from the Craft panel; Reel + Image inputs added;
  per-tool **Install** buttons added to the ModulePanel preflight (the 7
  missing tools on exploit were shown with no way to install).

- **`craft` workspace (CLI + Electron Session panel + `/api/craft`)** — build
  social lures ready to paste into a DM / WhatsApp / email. Fixed the
  tracker singleton so crafting and polling share the same store (a fresh
  grabber per call read an empty store).
- **`map [cidr]` + `/api/network/scan` + Electron "Scan Network"** —
  pre-engagement device discovery (arp-scan → nmap -sn → ping sweep) writes
  every live host into the shared WorldModel, so the Electron network map and
  the planner see the whole network before a target is chosen. Verified live:
  found 3 real devices on the LAN.
- **`install <tool>` + `/api/backend/install-tool` + Electron preflight
  "Install" buttons** — install a missing tool in the current backend
  environment (apt / brew / choco / pip auto-selected from the existing
  hints, routed through the WSL toolbox on Windows) with live output.
- **`--profile mobile`** — new defender model for iOS/Android targets (OS
  sandbox, mobile EDR, MDM/EMM, carrier SMS filtering, app vetting); a
  phone-number target with the default profile auto-switches to it.

## [3.7.3] — 2026-09

### Fixed: autonomous kill chain now completes scan → creds → beacon →
persistence → reports with zero manual steps (verified live against the lab)

Field-verified end-to-end (`auto 127.0.0.1` → DMZ lab): beacon check-in
`B-CCDD…` + `.profile` persistence + operator/client reports in ~72 s.
Three root causes found while chasing the loop:

- **Sandbox gated the wrong artifact.** `beacon_deploy` pre-flighted the
  *deployment command text* (a `.sh` needing sshpass/network) instead of the
  binary actually shipped to the target. Inside the networkless docker
  container it always "crashed" with `EXIT:127` and every deploy was denied
  in non-aggressive mode. The gate now scans/detonates the real artifact
  (`beacon_linux_static`), which is what AV/EDR would ever see.
- **Docker detonation misread persistent implants as crashes.** A beacon
  that stays alive is a *clean* run; the backend now runs samples under an
  inner `timeout <bound>` and maps `rc 124` (still alive at the bound) to a
  pass, while real crashes (loader errors, segfaults, garbage binaries)
  still deny.
- **Remote deploy ssh hung on the backgrounded beacon.** The one-liner
  `A && B &` runs `setsid nohup beacon` in the backgrounded subshell's
  *foreground*, so ssh waited on the beacon — when the beacon's first C2
  dial blackholed, the deploy timed out and was recorded as failed while
  the beacon was actually running. `(setsid nohup … &)` detaches inside a
  throwaway subshell: ssh returns instantly, the beacon survives.
- **EOF dispatched as a beacon task.** The C2 (and main) shell mapped a
  closed stdin to the literal command `"EOF"` and queued it to the active
  beacon (`sh: 1: EOF: not found` spam on targets); EOF now exits the shell
  cleanly, so non-interactive/auto-mode handoffs finish instead of spamming
  tasks.

### Tests

- Sandbox semantics covered: persistent-still-running-at-bound is approved,
  crashed/garbage samples are denied, container-wedge stays denied.
- `DefenderBackend` threat test covers both scan paths (MpCmdRun exit 2 and
  PowerShell Get-MpThreat).

---

## [3.7.2] — 2026-09

### Fixed: Windows AV blocked the Electron backend on launch

The onefile PyInstaller build was killed at execute time by real-time AV
("file contains a virus") — the classic onefile-bootloader heuristic false
positive. The backend now ships as **onedir** (`phantom-backend.exe` +
`_internal/`), which starts faster and is not flagged. Electron spawns it
via the same `backend/phantom-backend.exe` path, so no app code changed;
CI (`electron-release.yml`) zips/unpacks the onedir artifact per OS.

### Electron: real window frame + packaged icon

- Window restored to the **native OS frame** (`frame: true`) — the old
  `frame: false` build had no minimize/maximize/close buttons and no
  resize/snap. Custom titlebar code removed.
- Icon resolution now checks `resources/assets/` in the packaged app
  (electron-builder ships `electron/assets` as extraResources), so the
  tray/window no longer fall back to a blank image.
- Installer rebuilt and reinstalled: app boots, backend spawns, API
  healthy on 127.0.0.1:9876.

### Hygiene

- `.gitignore`: bundled wordlist archives (`data/wordlists/*.txt|*.lst`,
  downloaded at install time) and `data/persistence_rules.json.sample`
  handled correctly (runtime file ignored, template committed).
- Removed stray `build_icon_check.png`, leftover onefile exe from
  `dist/`, and an empty `aviso/` directory.

---

## [3.7.1] — 2026-09

### Verified: full live beacon battery on the operator host

Authorized live-fire test on the operator's own Windows machine (MSI,
user `ilysm`): listener on 18443 → no-disk PowerShell PIC stager →
in-memory check-in as `B-293C6A79557D8362` → **command battery: sysinfo,
edrcheck, health, whoami, cookies, cdp-cookies, screenshot, gps,
processes, persist** — all returned results. `edrcheck` reported 0 ntdll
hooks and no known EDR kernel drivers; the no-disk persist RunKey was
installed, then **removed with verification** (read before/after), the
beacon killed, listener stopped and artifacts deleted. McAfee: no blocks,
no alerts during the entire session. One gap found by the test and fixed:
beacons stayed `ACTIVE` after `exit` — see below.

### Fixed: exited beacons shown as ACTIVE

The beacon answers `exit` with a sentinel but the C2 never marked the
beacon down, so `beacons` listed dead sessions as live. Now `add_result`
flips status to `EXITED` (with `exited_at`), appends a `beacon_exited`
audit record, and the C2 shell renders `[dim red]EXITED[/]` (never
LIVE/STALE). API `_beacon_status` mirrors it; Electron beacon rows show
an `exited` badge and queued-task counts.

### Added: Electron Audit Log viewer + attack-path overlay + telemetry

- **Audit Log panel** (`AuditViewer.tsx` + `GET /api/c2/audit`): the
  hash-chained C2 audit log visualized — big tamper-evidence verdict
  (chain intact vs BROKEN at record N), live feed of
  registrations/tasks/results with per-event icons, tail-size selector.
- **Attack-path overlay** on the network map: the best chain to the
  beacon drawn as an animated glowing route (marching ants) over the
  topology — same attack graph the auto-mode planner reasons on.
- **Beacon telemetry**: EXITED badges, queued-task badges, status dot
  respects confirmed shutdown.

### Built & installed: Windows installer with real icon

`electron-builder` NSIS build verified end-to-end: multi-size icon
embedded in `Phantom.exe` resources, `icon256.png` shipped inside the
asar, silent install run (`/S`), **Phantom.lnk created on the Desktop and
Start Menu** — both carrying the new icon.

### Fixed: Electron app icon was a 16×16 placeholder

`electron/assets/icon.ico` was a single-size 16×16 stub and the builder
yml declared no `icon:` key — shortcuts/installer fell back to the stock
Electron icon, and the tray used a 1×1 transparent PNG baked in main.ts.
Now: real multi-size ICO (16→256) + `icon256.png` generated from the
project artwork, `icon` wired for win/mac/linux in `electron-builder.yml`,
asset shipped via the `files` list, window and tray both resolve the icon
through a dev/packaged-safe `iconPath()` helper. Provenance metadata
(source generator file name) stripped from the shipped assets.

### Fixed: injected toolsets broken by WSL bridge (regression)

`ToolRegistry.has()` lost its injected-toolset branch when the WSL bridge
was added: `ToolRegistry(installed={...})` (used by tests and offline
planning) always fell through to filesystem detection and every capability
failed with `tool_missing`. The injected branch is authoritative again.
Test: `test_automation_ad_operator` (the test that caught the regression)
plus the whole agent suite green.

### Fixed: credential verifiers dead on Windows even with Kali WSL

`_verify_ssh` / `_verify_smb` gated on native `shutil.which("sshpass")` —
on a Windows operator box they returned `None` (tool missing) and the
whole credential-brute layer never ran, even with sshpass sitting in the
Kali WSL distro. Both verifiers now resolve tools through the WSL toolbox
(`_wsl_tool`) and route the argv through it. Verified live: correct lab
creds return True through the bridge (previously impossible on Windows).

### Fixed: hermetic agent smoke test (test_run_autonomous_function_entry)

The public-entry smoke ran the REAL web hunt (90s curl budget per host)
with no injected runner/hunt_runner and no toolchain — production-correct
but non-hermetic and timeout-prone. Now deterministic like its siblings.

### Perf: WSL tool probes no longer pay the distro-list spawn per miss

`_wsl_which` re-listed WSL distros (a ~3.5s `wsl --list` spawn) for EVERY
missing tool; the list is now cached process-wide. First miss still pays
one probe (~4.4s), subsequent misses ~1s — matters for hosts where most
of the toolbox lives in WSL and capabilities probe several alternates.

### Verified

- Full suite: **1550 passed, 1 skipped, 0 failed** (split runs: agent
  simulations 24/24 — inherently slow, not hung; verified via faulthandler
  stack dumps that the time is spent in scripted kill-chain phases —
  core/C2/beacon 1526/1526).
- Credential verifiers live-verified against the lab SSH through the WSL
  Kali bridge (correct creds → True, wrong → False, both previously
  impossible from a Windows host).
- Beacon compile (Windows PE + Linux ELF via WSL g++) unaffected.

## [3.7.0] — 2026-09

### Added: immutable C2 audit log (chain-of-custody)

Every security-relevant C2 event (beacon registration, task queueing,
task results, rejected authentication) is appended to a **hash-chained,
append-only** JSONL log (`data/c2_audit.log`): each record carries seq,
previous-hash and its own SHA-256 — editing or deleting ANY record breaks
the chain and `audit verify` pinpoints the first bad entry. This is the
tamper-evident activity timeline client engagements require. New C2 shell
command: **`audit [verify|tail N]`**. Tests: `tests/test_audit_log.py`
(6 — chain creation, in-place tamper, deletion, tail, corrupt lines).

### Added: .pm bundles now carry C2 engagement intel

`export-session` embeds the beacon table, full task history and collected
results so another operator inherits complete engagement intelligence.
**Secrets are never exported**: beacon HMAC keys stay operator-local and
a recursive scrubber drops any secret-looking field (defense in depth for
future fields). Import surfaces the intel under
`session.knowledge_base["c2_intel"]` for the report writer and suggest
engine; live beacons are NOT adopted (they still check in to their
original listener — documented). Tests: `tests/test_pm_c2_intel.py`
(4 — round-trip, secret-scrubbing, import surfacing).

### Added: trust-earned suggestions + `plan <goal>` (manual core)

- **Evidence-tagged suggestions** (`suggest` command): every suggestion
  shows WHY (the concrete findings behind it: `service:tcp/445 + creds...`),
  a TRUST score (evidence strength blended with the technique class's
  historical success rate from the engagement history) and preflight
  state (missing tools sink in the ranking, already-ran commands are
  deduped, out-of-scope flagged). The operator verifies the reasoning in
  two seconds — the property that makes suggestion engines actually used.
- **`plan <goal>`** — the same goal-directed planner auto-mode uses lays
  out the chain to beacon/creds/ad/lateral/identity/cloud with per-step
  cost and stealth level; nothing executes. Tests: `tests/test_suggest_meta.py`
  (7).

### Added: noise circuit breaker + failure memory (auto-mode)

- **Noise circuit breaker**: every loud move (online brute, AD attack,
  aggressive scan, exploit) feeds a cumulative detection-risk score on
  the WorldModel, persisted across checkpoints. Once it crosses the
  limit the planner REORDERS candidate sources to prefer quiet moves —
  the kill chain still finishes (order, never a block) but a warming
  defender stops being hammered.
- **Failure memory**: the same capability failing with the SAME reason
  twice is treated as a deterministic dead end (previously 3) — two
  identical failures already prove the approach void with current facts.
  Tests: `tests/test_noise_breaker.py` (6).

### Added: HW-breakpoint unhooking + `edrcheck` (beacon)

- **Hardware-breakpoint unhooking** (HWBP engine class): a debug register
  is armed on a clean `syscall; ret` gadget in ntdll and a Vectored
  Handler routes execution into it — sensitive syscalls BYPASS the EDR's
  userland hooks without patching a single ntdll byte, so .text
  integrity monitors have nothing to flag. Installed at startup
  (replaces nothing; complements the disk-refresh unhook).
- **`edrcheck` beacon command**: read-only situational awareness before
  acting — counts hooked ntdll stubs (in-memory .text vs on-disk image),
  enumerates loaded kernel drivers and matches 14 known EDR/AV products
  (CrowdStrike, SentinelOne, McAfee, Defender ATP, ...). Run it first on
  a new foothold.
- Full rebuild verified (PE + shellcode + reflective loader); a
  compile-check TU executed on the live host: `ntdll_hooks=0 stubs=0`
  on an unhooked box, clean exit.

## [3.6.23] — 2026-09

### Added: cloud lateral-movement chain (planner-grade)

Three new post-beacon capabilities complete the AWS path from harvested
metadata creds to cross-account data access:

- **`cloud_iam_enum`** — read-only IAM enumeration with harvested creds:
  account ID, assumable roles (`iam:ListRoles`), account summary. Emits
  `cloud_lateral` findings with the discovered role ARNs.
- **`cloud_assume_role`** — the core cloud lateral primitive: STS
  assume-role on a discovered ARN (temporary credential set) + identity
  verification via `get-caller-identity`. Emits assumed/denied status.
- **`cloud_cross_account`** — with an assumed role: bucket inventory,
  AWS Organizations account list, Lambda functions (read-only).

Wired into the planner (`cloud` goal now includes `cloud_lateral`;
`cloud_access` sourced from both enum capabilities) and the attack graph
(`T1552.005` credentials-from-config, `T1078.004` cloud accounts). Tests:
`tests/test_cloud_lateral.py` (11) — adapter shape, interpreter parsing,
planner/attack-chain wiring, capability registration.

### Added: advanced SSRF invariants (hunt engine)

Nine new differential probes targeting **filter bypass classes**, not
specific products: redirect-based IMDS reach, decimal/short/hex IP
encodings (defeat `169\.254` regex allowlists), DNS-rebinding candidate,
gopher scheme (Redis protocol smuggling), CRLF header injection into the
fetched URL, and an IMDSv2 token attempt (`AQAEA` marker). The hunt engine
now reasons about *why* a filter failed, not just that 127.0.0.1 echoed.

### Added: MDM vendor fingerprinting (active mobile recon)

**`mobile_mdm_fingerprint`** — when `mobile_probe` finds an MDM surface,
this capability classifies the vendor (Jamf/Intune/MobileIron/
AirWatch-WorkspaceONE/Kandji/SimpleMDM), the auth mode (SAML/Entra), and
the open enrollment/API paths. The vendor class selects the follow-up
attack tree. Planner: `mdm_vendor` fact kind sourced from the capability,
`mobile` goal includes it. Tests: `tests/test_mdm_fingerprint.py` (8).

---

## [3.6.22] — 2026-09

### Electron UI: enterprise-grade visual upgrades

- **Network Map rebuilt on the shared WorldModel**: the map now renders the
  same typed findings the auto-mode reasons over — services (with ports),
  vuln findings, captured credentials, discovered hosts, beacons — instead
  of scraping raw session output. New node types (vuln, creds) with icons,
  color-coded edges (findings yellow, beacons magenta), hover details.
- **Attack Paths panel** (new `/api/attack-graph` endpoint): cross-service
  attack chains from `attack_chain.py` (e.g. `creds:admin → beacon:deployed`),
  confidence-scored, MITRE technique tagged, with a
  `missing_for_beacon` gap list. Same graph the planner uses.
- **Beacon Health card** in the C2 Interact panel: one-click `health`
  (uptime, check-in ok/fail, tasks, cadence, last error) plus a
  **set-sleep mini-control** to rotate the beacon cadence mid-session.
- **Auto-Mode panel**: goal hints inline (what each goal actually does),
  **local-LLM advisor toggle** (explicitly marked local-only, non-gating).
- Backend `/api/automode/run` now accepts `resume` and `llm` passthrough.

### C2 shell: health + cadence commands

- `health` and `set-sleep <ms> [jitter%]` wired into the interactive C2
  shell (previously beacon-only), beacon-help updated.

---

## [3.6.21] — 2026-09

### Added: sleep mask + thread-stack spoofing (field-verified live)

- **`sleep_mask.h`** upgrades the Ekko sleep to the CS 4.9 sleep-mask class:
  RW sections **and the live thread stack** are RC4-encrypted before the
  wait (single keystream, self-inverse on wake); the sleeping thread's
  return chain is **spoofed to a signed kernelbase code address**
  (ThreadStackSpoofer class) so stack scans see legitimate system frames,
  and restored after wake. Frame-pointer walk requires the new
  `-fno-omit-frame-pointer` build flag (added to the builder); walk
  failures degrade to mask-only, never crash.
- Sleep now uses a real **NtSetTimer + NtWaitForMultipleObjects** wait
  (previously the Ekko code created a timer but only waited on its timeout).
- Everything resolved via PEB hashes (new: `NtSetTimer`,
  `kernelbase.dll`), zero new imports.

### Added: beacon health self-report + C2-driven cadence rotation

- **`health`** beacon command: uptime, check-ins ok/fail, tasks done,
  current sleep/jitter, build id, last error — the operator sees beacon
  health at a glance without guessing from check-in times.
- **`set-sleep <ms> [jitter%]`**: rotate the cadence mid-session from the
  C2 (no beacon restart, no re-deploy). Live-verified: cadence 5000ms/30%
  → `set-sleep 6000 25` → next `health` reports `sleep_ms=6000 jitter=25%`.

### Field-tested live (previously unverified beacon features)

- **`browser-list`** ✅ (enumerated 13 firefox processes), **`smb-pipe`** ✅
  (named pipe created, commands drained), **`socks`/`socks-stop`** ✅
  (SOCKS5 up on 9050, port released on stop), **`browser-pivot`** ✅
  (attached to a live firefox PID, clean stop), **`cookies`** ✅ (correct
  "not installed/locked" path), **`cdp-launch`/`cdp-eval`/`cdp-cookies`** ✅
  (graceful "CDP connection failed" without a Chrome debugging session).
- Core commands (sysinfo, exec) verified healthy **under the masked sleep**.
- Cleanup after the session: RunKey, beacon processes, listener, persist
  dir, diagnostics — zero residue.

---

## [3.6.20] — 2026-09

### Added: direct entry points — `phantom.c2` / `phantom.auto`

- Two new console scripts land straight in the right shell (no flag):
  **`phantom.c2`** → C2 Operations Center, **`phantom.auto`** → AUTO-MODE
  shell. `phantom` stays the manual core. `--c2` / `--auto` flags kept
  (and now actually reach the AUTO-MODE shell).
- **`phantom --auto <target(s)> [flags]` now really runs the kill chain**
  from the CLI (the README advertised it, the flag ignored any target):
  passthrough `--stealth/--aggressive/--speed/--plan/--verbose/--goal/
  -aN/--resume/--llm/--profile-auto`. Without target it opens the
  interactive AUTO-MODE shell.
- The old `--auto` meaning ("run without confirmations") moved to
  `-y/--yes`, matching universal CLI convention.
- argv0-based dispatch: even when the scripts wrap the same `main()`, the
  launcher name routes to the correct shell.

### Fixed: manual core friction

- **`set mode` was advertised in help but not implemented** — `set mode
  recon|osint|web|exploit|full|deliver` now works with validation, and the
  usage error lists the accepted keys.
- **Bare `run` no longer double-prompts**: the adaptive next-step ran a
  `[Y/n]` confirm before handing off to the module's own interactive
  selection — two confirmations for one action. The module flow (which
  always ends in an explicit command selection) is the single gate now.

---

## [3.6.19] — 2026-09

### Fixed: native audio capture — `audio` now works live (field-verified E2E)

- **Root cause (crash)**: every COM call in `wasapi_capture.h` read vtable
  slots with `((void***)obj)[N]` — that indexes *the object struct*, not the
  vtable, so every call jumped to garbage (the first `GetDefaultAudioEndpoint`
  returned `0x0035002d00000002`). Correct pattern is `(*(void***)obj)[N]`;
  fixed on all 10 call sites. Diagnosed with a step-by-step harness
  (CoCreate → GetDefault → Activate → GetMixFormat → Initialize → drain).
- **Field fix**: this Windows image registers MMDeviceEnumerator under the
  sibling coclass `{BCDE0395-…}`, not the canonical `{BCDE0394-…}` — the
  capture now tries both CLSIDs. On trimmed/server images the canonical one
  is simply absent.
- **Verified live**: 2-second mic capture → valid 810 KB RIFF/WAVE delivered
  to the operator as `MEDIA_B64:RIFF…` through the encrypted C2 channel;
  the queued `audio 3` task round-tripped via `/api/v1/queue` → check-in →
  `/api/v1/results`. Auto-persist (no-disk stager) fired correctly at first
  check-in and was removed after the test.
- Legacy `System.Media.SoundRecorder` path removed — no external tools, no
  powershell, no `<audioclient.h>` import trace.

### Hardening (this session, folded in)
- `mem-run`/PIC execution isolated: crashing shellcode can no longer kill
  the beacon (runner thread + VEH-based isolation, error reported to the
  operator instead of a silent process death).
- Tartarus' Gate SSN resolution fallback added for partially-hooked ntdll
  neighbors (Hell's/Halo's alone miss those).
- Single-instance mutex: RunKey rebirth while a live beacon exists no longer
  spawns duplicate agents.
- Native WASAPI microphone capture replaces the broken PowerShell recorder
  dependency (this entry).

---

## [3.6.18] — 2026-09

### Fixed: beacon check-in dead on Windows hosts with protected machine certs

Field-tested live on a Windows 11 host (Defender off, McAfee real-time
`mc-neo-host` active — the on-disk EXE was quarantined in seconds, which the
in-memory dropper path bypasses by design).

- **Root cause (GLE 12044)**: with mTLS `CERT_OPTIONAL`, schannel
  auto-selects a client certificate from the machine store; on hosts whose
  certs have TPM/MDM-protected keys the handshake dies with
  `ERROR_WINHTTP_CLIENT_CERT_NO_ACCESS_PRIVATE_KEY` on **every** request,
  even ones that wanted no client cert. The beacon checked in forever and
  was never registered.
- **Fix (transport)**: explicit `WINHTTP_OPTION_CLIENT_CERT_CONTEXT = NULL`
  (documented "send no cert" semantic) suppresses the auto-selection; when
  the embedded PFX key cannot bind, the request is retried once on a
  pristine handle without the cert. The per-beacon HMAC-SHA256 signature
  (timestamp + counter + nonce anti-replay) is the strong identity — the
  client cert is now best-effort, never load-bearing. Server middleware
  aligned: mTLS client-cert requirement kept on operator API routes only;
  beacon routes authenticate via HMAC in-handler.
- **Fix (persistence self-install)**: the `persist` command downloaded the
  beacon PE **without any auth token** — on a token-protected listener it
  silently saved the 403 page as the payload EXE. The payload token is now
  embedded at build time (`C2_PAYLOAD_TOKEN`) and sent as `X-Auth-Token`
  only on `/api/v1/payload` fetches (never on routine check-ins). Live-
  verified: PE download 1,448,605 bytes, RunKey + self-hollow install OK.
- **Fix (config)**: a manual `compile_beacon()` call without `host`/`port`
  silently built a beacon pointing at `127.0.0.1:8080` (default) — the
  payload downloaded and ran but checked into nowhere. Documented the
  required arguments for out-of-shell builds.
- **Diagnostic harness**: `phantom/payloads/beacon/src/test_checkin.cpp`
  compiles the real transport headers and reports PFX import, key-prov
  presence, cert binding and a full check-in — reused for future builds.

### Verified live (this host)

| Capability | Result |
|---|---|
| PIC stager → /x download | 200, 1.46 MB, no on-disk EXE |
| In-memory execution inside PowerShell | survived real-time AV |
| Check-in + HMAC auth + registration | `New beacon registered` |
| Malleable URIs rotation | `/apI/v1/PIng`, `/JS/jQUErY-3.6.0.MIn.js`, `/FAVICoN.ICo` |
| Encrypted tasking/results channel | exec, keylog status, netstat, sleep |
| sysinfo | user/host/OS/priv/arch/uptime |
| gps | WiFi BSSID + WWAN service enumeration |
| screenshot | full-screen BMP 1536×864×4 (5.3 MB) base64 |
| camera | device enumeration (capture needs WinRT companion) |
| persist (RunKey + self-hollow) | install verified, artifacts removed |
| Encryption at rest | DPAPI-protected auth state (removed in cleanup) |

### Verified live, session 2 (same host, rebuilt beacon)

| Capability | Result |
|---|---|
| migrate (no args) | self-migration: pulls own XOR PIC from `/x` (auth token), injects into sacrificial process with PPID spoof, exits; beacon re-appears hosted in the target with identity preserved |
| migrate E2E | migrated beacon (RuntimeBroker, parent explorer.exe) checked in minutes after migration; replay guard accepted the reset counter (nonce+freshness carry replay protection) |
| inject | threadless APC into a real system process (RuntimeBroker) — `Injected via threadless APC (no new thread)`; self-injection correctly refused |
| screen-record | **native GDI+ JPEG capture** (`jpeg_enc.h`), PHREC container, ~2 fps, zero external tools (ffmpeg dependency removed) |
| mem-run | PIC shellcode executed in-process (round-trip verified; inline shellcode crashes on fault by design, same as CS `inline-execute`) |

- **Fix (replay guard, architectural)**: the anti-replay counter was strictly
  monotonic per process — a migrated, restarted or (with RunKey persistence)
  rebooted beacon resets it and the server would reject it **forever**. Replay
  protection now rides on the per-request random nonce set + ±120 s timestamp
  freshness; the counter is an advisory high-water mark used for telemetry.
- **Fix (operator API visibility)**: unknown `/api/*` paths falling into the
  malleable catch-all returned a bare `C2 OK`, silently swallowing operator
  mistakes (a mistyped task POST looks like success). They now return 404;
  decoy `C2 OK` stays for genuine malleable-looking URIs.

### Persistence rebuilt after field failure: no-disk rebirth verified E2E

Field test of the classic persist exposed a hard wall: McAfee allows the
beacon PE **on disk** (file survives untouched) but **blocks its execution**
("file contains a virus" at process start) and its remediation deletes the
RunKey seconds after install. Self-hollowing cannot help — it runs *after*
the blocked process start.

- **No-disk persistence (new default)**: `persist` now writes a RunKey that
  relaunches the **compact PowerShell stager** (embedded at build time as
  `C2_PS_STAGER_B64`). At logon the stager re-downloads the XOR PIC from
  `/x` and executes it in-memory — the exact path field-proven to survive
  real-time AV. Nothing malicious on disk, nothing to quarantine. Falls
  back to the classic PE path when no stager is embedded.
- **Self-hollow implemented for real**: `self_hollow()` in `injection.h`
  was a stub returning `false` while persistence advertised "self-hollow
  into RuntimeBroker at next login". It now reads its own image from disk,
  spawns a sacrificial `RuntimeBroker`/`svchost` with PPID spoofing,
  unmaps the host image (indirect syscalls), writes headers + sections,
  fixes the PEB ImageBase, relocates the entry point into `Rcx` and
  resumes. Used by the PE fallback path.
- **E2E rebirth verified on this host**: RunKey installed → every beacon
  process killed → RunKey command executed exactly as Winlogon would →
  same beacon identity checked in again within one sleep cycle (in-memory,
  no disk artifact). RunKey survived (the old one was remediated away);
  the encoded stager value is inert to AV.

### Cleanup

After testing, every artifact was removed and verified: beacon processes
killed, RunKey deleted, `%APPDATA%\Microsoft\Phantom` deleted,
`%LOCALAPPDATA%\Phantom` (DPAPI auth state) deleted, listener stopped,
diagnostic files removed. **Nothing persists on the test host.**

## [3.6.17] — 2026-09

### Hunt engine validated against a live external target (demo.testfire.net)

First live-fire run of the hunt engine against IBM's AltoroJ (an
intentionally vulnerable public test app): **the real SQLi auth-bypass on
`/doLogin` is found and CONFIRMED** (`302 -> /bank/main.jsp` vs the
failed-login baseline), with zero false positives. Every fix below was
proven by that run, not by simulation alone:

- **body cap 2000 → 20000 chars** — testfire's login form sits below the
  old truncation, so discovery never saw the `uid`/`passw` fields;
- **relative form actions resolved** (`action="doLogin"` on `/login.jsp`
  → `/doLogin`) — they were silently dropped before;
- **login pages are fetched during discovery** (first 2 `login/signin/
  auth/logon` links found on the home) — unauthenticated users are
  redirected there, and that is where credential forms live;
- **credential forms are probed FIRST** (new `_FORM_ENDPOINTS` priority,
  dedup via `_push`) — on the 90 s budget the wide root library used to
  expire before `/doLogin` was ever reached;
- **auth-bypass via redirect target** — post probes now run with
  `follow=False`, and a 302 landing on a member page (`dashboard`/`main`/
  `admin`/…) vs the baseline's bounce-back to `login.jsp` scores as a
  strong signal; evidence shows `302 redirect -> /bank/main.jsp`;
- a probe that 302s back to the login form scores 0 (failed attempts are
  not findings).

Pinned by 6 new tests in `test_anomaly.py` (44 total, green), plus the
54-test hunt regression suite (anomaly_enterprise, differential, webcreds,
hunter, dynamic_exploits) green.

## [3.6.16] — 2026-09

### Lab: Samba AD domain controller is up — the deep/AD chain now has a REAL target

The `dc` lab host (a Samba 4.17 AD DC provisioning `CORP.LOCAL`) finally
boots and serves Kerberos/LDAP/SMB/GC. Three Docker/Samba fixes landed:

- install `samba-vfs-modules` — `acl_xattr` (required for the sysvol NT-ACL
  set during provisioning) is not shipped by the `samba` package;
- add `CAP_SYS_ADMIN` to the `dc` compose service — provisioning writes
  `security.NTACL` xattrs, which Docker denies without that capability;
- fix the seeding script: `--must-change-at-next-login` takes no value, and
  the AS-REP user is created without `--given-name`/`--surname` so its CN
  matches the `ldbmodify` DN that sets `DONT_REQUIRE_PREAUTH`.

The DC now seeds the kerberoast (`svc_sql` + SPN), AS-REP (`norep`,
`userAccountControl` `0x400200` verified server-side over LDAPS), and DCSync
(`adadmin` in Domain Admins) targets. Live-verified against the container:
anonymous LDAP rootDSE (the `ad_enum` operation), authenticated LDAP
read/modify, and SPN discovery via `GetUserSPNs`. Honest Samba↔impacket
environment notes (AS-REP KDC enforcement and `secretsdump` prefixMap
friction on Samba 4.17) are documented in `lab/README.md` for re-verification
from a Kali box.

### Planner bug: cold `goal=crack` could never reach the beacon

`hash_crack` declared `creds` in its effects. Its `creds` output only
materializes AFTER a captured hash is cracked — an input it does not produce
itself. The backward-chainer therefore believed `creds` was already produced
once `hash_crack` was planned, silently dropped the real acquisition chain
(`web_creds`/`ssh_login` → `beacon_deploy`), and a cold `goal=crack` run
stalled after one port scan. Fixed by declaring only `cracked` as the effect
(the interpreter still emits `creds` findings at runtime). The previously
failing `test_dc_sync_and_hash_crack_full_chain` E2E (privesc → dc_sync →
hash_crack) is now green, with a planner regression test asserting a cold
`crack` plan still chains `ssh_login`/`beacon_deploy`.

### Bug: `mobile_probe` never parsed endpoint hits

The adapter emits curl `%{http_code}:<path>` — the code comes BEFORE the
colon — but the interpreter matched `:200`/`:301` (colon first), so MDM/push
endpoint hits never produced findings. The interpreter now matches
`200:`/`301:`/`302:` prefixes; `mobile` surface findings flow again.

### Bug: agent stall on unreachable targets (the real red-team case)

Three interacting defects turned "target that answers nothing" into a
multi-minute stall or an infinite loop — found by a faulthandler stack dump
inside the E2E suite:

- **`web_creds` probe battery with no reachability check** — every
  SSRF/SQLi probe carried its own 4s timeout against a dead IP. The dump now
  gates each web port with ONE short reachability request (live servers
  return a body; only network failure skips the port), so an unreachable
  target costs ~one request per port instead of a full battery.
- **no poisoning of deterministic dead ends** — a capability failing the
  same way three times is now poisoned (dropped from planning AND recovery
  re-arming), so the agent falls through to the next beacon source instead
  of re-planning `web_creds` forever.
- **no fallback from the credential path to code execution** — when a web
  service exists but every credential source is exhausted (and no beacon),
  stall recovery now escalates ONCE to the `web_rce` upload probe — the
  senior move that reaches the beacon without credentials. The
  `test_deliver_via_web_rce_without_creds` E2E (RCE without a single cred
  pair: scan → hunt/SSTI confirmation → web_rce → beacon_via_rce →
  persistence) is green again and now runs hermetically (offline hunt
  runner + bounded budgets) in ~1.6s instead of hanging.

### New direct tests for the cloud / k8s / mobile capabilities

`tests/test_cloud_k8s_mobile.py` (22 tests) locks the adapter + interpreter
contract for `cloud_creds_harvest` (AWS IMDSv2 role JSON, GCP metadata,
Azure IMDS), `cloud_s3_enum` (sts `GetCallerIdentity` ARN + bucket listings),
`mobile_probe` (MDM/push endpoints, no-false-positive) and `k8s_escape`
(service-account token, privileged cgroup, kubelet — with the exact
sa-token/sa-list-cluster and admin/read-only distinctions). These surfaces
cannot exist in a unit environment, so the contracts are now pinned and
regressions are caught without a live cloud.

### Manual core: `next` now routes the FULL capability map

The shell's reasoning-driven next-step suggestion (`next`) previously only
mapped the shallow capabilities (scan/web/brute/payload/pivot) — deeper
reasoning hypotheses (web_rce, beacon_via_rce, kerberoast, lateral pivots,
post-beacon cloud/k8s capabilities) had no module to route to and fell back
to a generic "re-enumerate" hint. The capability→module map now covers the
deep chain (web_rce/beacon_via_rce/AD capabilities → `exploit`, lateral
pivots → `pivot`, post-beacon cloud/k8s → the C2 operations center), so the
manual operator gets the same depth of guidance the autonomous agent uses.

---

## [3.6.15] — 2026-08

### Auto-mode: `goal=deep` full-engagement ladder + cross-engagement learning + social cadence

Three workflow upgrades that take the autonomous mode from "deliver" to a
complete enterprise engagement:

- **Deep mode (`--goal deep`)** — instead of stopping at beacon + persistence
  (goal `deliver`), the run walks the whole ladder back-to-back in ONE
  engagement: `deliver` (beacon + persistence) → `post_exploit`
  (SYSTEM/root + process injection through the beacon) → `ad` (domain
  enumeration + kerberoast / AS-REP roast) → `crack` (offline hash cracking)
  → `lateral` (pivot to in-scope peers). Every stage ends when its own goal
  facts exist OR the planner proves the stage is non-viable (no LDAP surface,
  no peer hosts...), so a deep run terminates with whatever depth the target
  allowed and hands the beacon over ONCE at the end. Each stage emits a
  `stage` event with its outcome; the final result contains a per-stage map
  (`deliver ✓ / post_exploit — / ad ✓ / ...`) feeding the reports.
- **Cross-engagement learning loop** — the planner now reads back the
  disk-persisted Bayesian calibration written by PREVIOUS engagements
  (`data/calibrated_weights.json`): a technique that historically failed is
  deprioritized before this run has any of its own observations, blended
  with the in-run success rate and regret-bounded to [0.5x, 1.5x] so no
  historic outlier can hijack a fresh engagement. The loop is closed:
  outcomes are recorded during the run, flushed at the end, loaded at the
  next start.
- **Social cadence (re-engagement)** — when the lead waits for a target and
  the grace delay passes with no open/click, the engine sends ONE
  second-chance lure with a fresh pretext and a new tracking link
  (`follow_up`), extends the deadline, and keeps polling; markers of the
  follow-up are never mistaken for an interaction (only a real open/click
  ends the wait). Bounded to one touch by default (`PHANTOM_SOCIAL_CADENCE`
  seconds + `PHANTOM_SOCIAL_CADENCE_MAX` attempts), disabled entirely in
  speed mode, and a re-run of a wait whose effect is already captured does a
  quick probe instead of sleeping a full horizon again.
- **Planner fix behind it** — the campaign-harvest wait and the single-shot
  grabber poll are now channel-aware: username/phone/profile (social) flows
  plan the harvest wait (cadence-capable, catches opens + creds), plain
  email flows keep the quick poll. Wait capabilities with their effect
  already in the world never re-enter the long sleep.
- Surfaced everywhere: `auto --goal deep`, `agent --goal deep`, the auto
  shell (`_GOALS`), the Electron Auto-Mode goal selector and the dry-run
  planner (each step tagged with its stage).

---

## [3.6.14] — 2026-08

### Hunt / anomaly engine: 5 → 13 bug classes, header-aware and discovery that reads modern apps

The behavioural anomaly engine — the part that finds bugs that are in NO CVE
list — grew from 5 to 13 classes, with response-header awareness and smarter
discovery. Verified live against the lab (verb + ssrf + open_redirect
confirmed, zero false positives on cmdi/crlf/nosqli/exposure):

- **8 new bug classes**: `cmdi` (command injection, separator + time-based),
  `open_redirect` (attacker host in Location — no-follow probes), `crlf`
  (header injection via injected response header), `nosqli` (Mongo operator
  payloads in params and JSON bodies), `header_ssti` (templated UA / Referer /
  X-Forwarded-For), `jndi` (Log4Shell-class reflection + case obfuscation),
  `exposure` (sensitive files: .git/HEAD, .env, backups, phpinfo, actuator),
  `verb` (TRACE / OPTIONS Allow / DELETE tampering).
- **Header-aware scoring** — `curl -i` captures real response headers; open
  redirect reads the Location header, CRLF reads the injected header name,
  verb reads the Allow header. Redirect probes deliberately do NOT follow
  3xx so the evidence is readable.
- **Monotonic time validation** — a time-based finding (SQLi SLEEP / cmdi
  sleep) is confirmed ONLY if the deeper payload is measurably slower than
  the original (SLEEP(5) > SLEEP(3)). A one-off timing ratio vs a fast
  baseline is jitter, not injection — kills the classic false positive.
- **Modern discovery** — JS bundles are fetched and scanned for `/api/...`
  paths (SPAs hide the whole API surface in one bundle), form `<input name>`
  attributes give the REAL parameter names instead of guessing `?id=`, and
  the common-path set now includes `/api/v1`, `/graphql`, `/actuator`,
  `/.well-known/`.
- **Kill-chain wiring** — the reasoning engine bridges the new classes:
  confirmed cmdi/jndi/header_ssti → `rce_foothold` (beacon via code exec),
  confirmed nosqli/exposure → `web_creds` (harvest creds from the store /
  mine secrets). Reports and severity flow generically.

### Fixed: test-order dependency in the web module command counts

`test_build_commands_with_target` asserted a fixed group count that silently
broke when `test_hunter` ran first and left scan results in the global
session (adding a "SUGGESTED (web:...)" group). The test now isolates the
session state it depends on — no more order-dependent failures.

---

## [3.6.13] — 2026-08

### Added: manual-core creds→SSH→pivot bridge + cloud/IAM/mobile kill chain

**Manual core now drives the full kill chain to the beacon by hand.** Three
operational commands close the gap that previously forced a red teamer to
leave the shell and reuse harvested creds at the terminal:

- **`use web` → `creds`** — expose the same deterministic web-credential
  engine the auto-mode uses (`web_creds`): SSRF → leaked credential files,
  SQLi auth-bypass + UNION dump + MD5 hash-crack. Found pairs are written
  to the shared WorldModel, so the exploit / payload / pivot modules can
  reuse them.
- **`use exploit` → `ssh [user:pass]`** — open an SSH session with a
  harvested pair (or an explicit one), discovered port included; verifies
  access, tags the cred valid in shared knowledge.
- **`use pivot` → `ssh <peer-ip>`** — SSH lateral movement / pivot using
  the harvested credential pair through the compromised foothold, exposing
  a tunnel back so the operator reaches hosts only visible from the box.
- **`use payload` → `privesc`** upgraded from a static tool list to real
  post-exploitation escalation (sudo -l / SUID / GTFObins enumeration).

**Auto-mode cloud/IAM + mobile + Kubernetes capabilities.** New post-
/recon capabilities registered with the planner and inference engine:

- `cloud_creds_harvest` — capture instance IAM from inside the beacon via
  the metadata service (AWS IMDSv2, GCP, Azure managed identity).
- `cloud_s3_enum` — with harvested IAM creds, enumerate object storage
  (`aws sts` + `s3 ls`, gsutil) for stolen data access.
- `k8s_escape` — probe a compromised pod for container-escape primitives
  (mountable service-account token, privileged cgroup, reachable kubelet).
- `mobile_probe` — recognize the mobile / device-management surface (MDM,
  push gateways, mobile-web) and branch the engagement into the app surface.

The reasoning engine gained `_rule_cloud_operations` and `_rule_mobile_surface`
so it deduces these next moves from environment / cloud-cred / mobile findings
— observational inference over bug classes, not a CVE list.

### Fixed: anomaly hunt deduplication

`use web` → `hunt` returned up to 21 duplicate anomalies for the same flaw
(SQLi ×11, SSRF ×8) because escaped mutations produced one finding each.
Anomalies are now grouped by `(class, endpoint)` keeping the strongest
confirmation, yielding 2 clean confirmed findings on the lab.

---

## [3.6.12] — 2026-08

### Fixed: anomaly hunt engine — validated live against the segmented lab

Field-testing the hunt engine (`HuntEngine`) against the lab's
"Corp Intranet" app exposed three real defects, all fixed:

- **curl meta-line polluted marker matching** — the trailing
  `curl -w` meta line (status, size, timing digits) was part of the
  stored body, so timing digits like `0.004905` matched the SSTI
  marker `"49"` on every 404 page. The meta line is now stripped
  before marker matching.
- **Timing false positives on fast pages** — sub-10 ms baselines
  (plain 404s) produced x2.5+ "timing" ratios from jitter alone.
  Timing signals now require an absolute baseline of >= 50 ms.
- **Baseline-contained markers counted as evidence** — a marker
  already present in the baseline body (e.g. `"49"` inside the md5
  hashes of the rendered user table) no longer scores as a new hit.
- **Redirect-based detection was impossible** — `-X POST` forced the
  method on every redirect hop, turning an SQLi auth bypass (302 ->
  /admin) into a 405. `-d` now implies POST (curl's native 302
  downgrade to GET is preserved), so bypasses are measurable.
- **POST-form SQLi had zero coverage** — the sqli library only probed
  GET query strings. Auth-form endpoints (`/login`, `/register`, ...)
  now get a POST-body probe family: failed-login baseline, quote /
  tautology / comment / UNION bypass payloads, and member-page
  markers (`user table`, `dashboard`, `admin panel`, `welcome back`)
  that fire when a bypass lands on an authenticated page.
- **SSRF parameter discovery was blind** — discovery never learns the
  parameter name, so SSRF probes guessed `?id=` and 404'd. SSRF
  probes now try the common URL-parameter names (`url`, `q`, `next`,
  `target`, `dest`, `uri`, `path`), `file://` probes reuse traversal
  markers, and SSRF-capable paths (`/export`, `/fetch`, `/proxy`, ...)
  get priority slots in the probe plan. Discovery common-path list
  extended accordingly (`_MAX_ENDPOINTS` 16 -> 20, `_MAX_REQUESTS`
  60 -> 400 to fit the larger plan).

Live lab result: the engine now **confirms** the real SSRF on
`/export?url=` (file-read of `/etc/passwd`, size x155 + `root:`
marker, validated by re-probe) and the SQLi auth bypass on `/login`
(`admin'--` landing on the member page), with the previous 404-page
false positives eliminated. 101 anomaly/exploit tests green.

---

## [3.6.11] — 2026-08

### Fixed: orchestrator drain-loop hang (test session / CLI exit)

The agent orchestrator's `run()` loop could stay alive forever when a
worker thread was stuck inside a capability (the `while not _stop.is_set()`
loop kept sleeping 0.1s because `_agents_active() > 0` never cleared).
This caused the entire pytest session — and the CLI process at exit —
to hang even after all tests/assertions passed.

- `phantom/automation/orchestrator.py` — `run()` now takes a bounded
  `drain_timeout` (default 120s): when the queue is empty but an agent
  is still running, the orchestrator stops waiting after the timeout
  instead of looping forever. New `stop()` method signals the loop.
- `phantom/automation/agent.py` — `run()` finally block now calls
  `orch.stop()` so no orchestrator thread outlives the agent run.

Verified: 24/24 agent tests pass and the process exits cleanly.

---

## [3.6.10] — 2026-08

### AD chain now works WITHOUT a beacon

The AD/domain capabilities were hard-gated behind a beacon session
(category `post`, precondition `_has_beacon()`), so a domain controller
could only be attacked from INSIDE via a foothold. Now the AD chain runs
**directly from the operator** against a reachable DC (LDAP/Kerberos) —
with a beacon session when one exists, without one when it does not.

- `phantom/automation/guidance/kit.py` — `ad_enum`, `kerberoast`,
  `as_rep_roast`, `dc_sync`, `hash_crack` moved to a new `ad` category;
  preconditions now require the AD surface (`_has_ad_service()`: scan sees
  88/389/636/3268/3269, domain known, or a beacon foothold) plus
  `_has_creds()` / `_has_ad_hash()` where needed — no more `_has_beacon()`
  gate except DCSync's SYSTEM requirement (kept: DCSync realistically needs
  a foothold).
- `phantom/automation/agent.py` — new `_execute_ad_capability` dual channel:
  queues through the C2 when a beacon session exists, otherwise runs the
  tool command operator-side via the runtime (same commands, same
  interpreters).
- `phantom/automation/planner.py` — `_precondition_facts` maps the AD
  surface to BOTH `beacon` and `service` so either path can satisfy it.
- New tests `tests/test_automation_ad_operator.py` proving `ad_enum` runs
  operator-side with NO beacon (scan sees 389), plus precondition unit
  tests. Existing AD E2E (beacon channel) and full deep-AD chain tests
  still green.
- `lab/dc/` — a Samba AD DC image (`lab-dc`) provisioned for `CORP.LOCAL`
  with SPN/AS-REP/DA test users. WIP: provisioning completes but the
  classic Samba-in-Docker sysvol-ACL/secrets wrinkle keeps `samba` from
  starting (image is present, container is disabled in compose until the
  startup fix lands).

---

## [3.6.9] — 2026-08

### Auto-mode now carries its own C2 — fully automatic beacon loop

The autonomous kill chain no longer needs the operator to prepare anything:
`run_auto_mode` now **auto-starts the C2 listener** (HTTPS + auto-generated
mTLS material, bound `0.0.0.0`) right before the agent runs, and the beacon
is compiled with the **operator's reachable address** instead of a hardcoded
`127.0.0.1`.

- `phantom/utils/network.py` — new `get_c2_endpoint()` (env override →
  `session.lhost/lport` → auto-derived operator IP via `get_lhost()`) and
  `own_ips()` (operator-local addresses).
- `phantom/automation/agent.py` — `_build_payload`/`_wrap_remote_exec` use
  `get_c2_endpoint()`; `_await_beacon` now accepts a NEW foreign
  registration (source IP ≠ operator-local) so a beacon dialing out through
  NAT checks in even when the listener sees a NAT address, not the target's.
- `phantom/core/automode.py` — auto-start the listener before the run
  (skipped for `--plan` dry-run), so a deployed beacon always has somewhere
  to check in.
- **Verified end-to-end from Kali WSL** against the two-host lab, no
  harness: scan → ssh_login (fail) → web_creds (backup creds via SQLi/SSRF)
  → beacon deploy → `BEACON UP` → persistence (`profile`) → raw + client
  reports. `deliver` completed in 4m34s with `beacon=True, persistenza=True,
  creds=1` and handoff.

---

## [3.6.8] — 2026-08

### Lab: single box → segmented two-host network

The `lab/` target changed from one vulnerable container to a small segmented
network so Phantom can be exercised with real **vertical and lateral
movement**, not just a single box.

- **`dmz`** (`172.28.0.10`; ssh 2222, ftp, web 8081 published): SQLi login +
  SSRF `/export` + upload path-traversal web app; `backup` SSH account with
  a strong password that is **not** in any wordlist (only reachable via the
  app), and a `sudo rsync` (GTFOBins) privesc → root on the DMZ.
- **`internal`** (`172.28.0.20`; no published ports): reachable only by
  pivoting from the DMZ. `dev` SSH credentials live in
  `/home/backup/.backup/pivot.txt` (lateral movement) and a SUID binary
  `/usr/local/bin/roothelper` gives root on the internal host
  (vertical movement). `/root/flag.txt` is the proof of compromise.
- The chain is verified by hand end-to-end: SQLi/SSRF → backup creds → ssh
  DMZ → sudo rsync → pivot → ssh `internal` → SUID → root → flag.
- `lab/README.md` rewritten for the multi-host scenario; `lab/` now builds
  two images (`lab-dmz`, `lab-internal`) on an isolated `172.28.0.0/24`
  docker network.

---

## [3.6.7] — 2026-08

### Fixed (web→creds bridge + test-suite hardening)

#### Auto-mode no longer dead-ends when credentials are only reachable through a web app
- The planner could not link a web app to the `creds` fact: when `ssh_login` (wordlist brute) failed — e.g. on a lab with SSH users/`passwords outside every wordlist` and a vulnerable portal as the actual access path — the plan stalled on `beacon_deploy → persistence_install` with no way to escalate. The agent never explored the web app.
- New capability **`web_creds`** (`phantom/automation/exploit/webcreds.py`): a socket-level web engine that (a) discovers SSRF-style file reaches and reads `creds`/API-key files, (b) tries SQL-injection dumps for login tables with hashes/plaintext, and (c) attempts auth-bypass on login endpoints. It runs in-process (like the hunt capabilities), emits `creds`/`web_leak` facts, and is registered as the first `creds` source in `_FACT_SOURCES` so the backward chain reaches `ssh_login → beacon_deploy` through a browser-side wall. The fetch path is non-lethal (bounded reads, 5s timeouts, no service degradation).
- Lab `lab/webapp/app.py` now exposes a real chain: portal login → SSRF parameter able to read an internal file holding a strong credential pair → SSH access → beacon. End-to-end: `scan → (ssh brute fails) → web_creds (SSRF leak) → ssh_login → beacon deploy → persistence → reports`.

#### Paranoid (`--stealth`) no longer rejects the whole kill chain
- The paranoid gate refused **every** capability with `stealth_level="aggressive"`, including the single precise moves `ssh_login`, `beacon_deploy`, `persistence_install` — the only viable route to the goal — so `--stealth` printed an empty plan and halted.
- Split capability intent: a new **`forceful`** flag marks the genuinely noisy actions (automated exploitation, legacy brute, AD attacks, lateral, impact). The paranoid gate now rejects only `forceful` capabilities; precise, low-noise moves that are required for the goal stay affordable. `--stealth` now completes deliver (beacon + persistence) — slower on purpose (2–3× cadence, `-T2` scan) but without null planning.

#### Test-suite hardening (3 failures caught by the field/full-suite runs)
- `tests/test_automation_post.py`: `_ssh/_smb_pivot_failing_runner` blocked on the generic `sshpass + nohup` pair, but the new scp beacon deploy also embeds `nohup` (chmod && nohup <beacon>), so the blocker swallowed the *deploy* — the beacon never checked in and `_await_beacon` burned its 30s retry repeatedly, hanging the pivot E2E tests. Restricting the block to the `PEER` host (+ not-scp) makes the ssh-pivot fail while the deploy registers. `test_recover_stall_noop_when_nothing_failed` was stale vs. the one-shot deep-scan escalation and now asserts the true no-op state.
- Removed stray build/runtime artifacts that had drifted into the repo tree (`data/agent.py`, `data/kit.py`, `%TEMP%pytest_all_out.txt`, `camp-cli-fail-*/`, `phantom_run_auto.py`).
- Full suite green: **1414 passed, 1 skipped, 0 failed.**

---

## [3.6.6] — 2026-08

### Fixed (auto-mode full-loop completion — first fully automatic deliver against the lab)

The autonomous kill chain now completes **scan → creds → beacon deploy → persistence → reports → handoff** with no manual intervention against the `lab/` container (SSH 2222, FTP 2121, web 8081). Field-tested from Kali WSL: `deliver` reached `beacon=True, persistenza=True, creds=1` in ~2 minutes, and the raw + client reports contain the real `beacon`, `persistence`, `creds` and `service` findings.

#### Port-scan coverage now follows the run flags
- Default and `--stealth` sweep the full range up front (`-p 1-65535`); `--speed` and `--aggressive` stay on fast top-ports (`--top-ports 100`, higher `--min-rate`). Plain `-sT` scans label non-standard ports with wrong table guesses (2222 → `EtherNetIP-1`), which broke every service precondition downstream — `-sV` is now always on so real service names/versions feed the planner.
- Stamped on the WorldModel by the agent (`wm.scan_style`), read by `_scan_port_spec()` in the scan adapters.

#### SSH credential verification broke on modern OpenSSH (CRITICAL)
- `_verify_ssh` always passed the legacy `KexAlgorithms=+diffie-hellman-group1-sha1` / `HostKeyAlgorithms=+ssh-rsa` options (for Metasploitable2-era servers). Against OpenSSH 9.x those options break auth entirely — "Permission denied" even with valid credentials, so the auto-mode could never harvest creds on modern targets.
- Also `-o BatchMode=yes` disabled sshpass's password feed on every attempt.
- Fix: try modern defaults first; re-add the legacy algorithm set only when the failure is an algorithm-negotiation error.

#### Beacon deploy over SSH (auto-mode)
- The deploy command must run ON the target — the old wrapper executed the dropper on the operator host, and a curl-dropper via ssh died of SIGHUP mid-download.
- New path: scp the compiled **static** binary (the dynamic one requires glibc ≥ 2.38 and dies on Debian bookworm-class targets; `compile_beacon` now keeps `beacon_linux_static`), then `setsid ssh … nohup beacon … </dev/null >/dev/null 2>&1 &` with full local redirection so the deploy step returns in <1 s (sshpass + `ssh -f` deadlocks on the pty). Unique staging path per attempt avoids ETXTBSY on a running beacon file.

#### Agent now observes the REAL C2, not its own empty state
- `_await_beacon`/`_BeaconSession` read the in-process `c2_state`, so an agent running in a different process than the listener could never see registrations, tasks or results.
- When the listener runs in the agent's process (the designed single-process flow: `auto` from the Phantom shell), everything now works end-to-end; loopback/NAT source IPs are accepted for lab targets.

#### Linux persistence with graceful fallback
- The cron method assumed `crontab` exists; minimal containers/stripped distros fail silently, so `persistence_install` never produced a finding. Now `cron → ~/.profile → systemd user unit` are tried in order until one confirms `PERSISTENCE_OK`.
- C2 auto-persist now queues `persist` (beacon default service name `PhantomBeacon`) instead of `persist systemd` (which created a unit literally named `systemd`).

---

## [3.6.5] — 2026-08

### Fixed (first full end-to-end C2 field test — local docker lab + Kali WSL)

Field setup: intentionally vulnerable target container (`lab/` — SSH weak creds, anonymous FTP, SQLi web app), Phantom core running in Kali WSL with real tooling (nmap/hydra/metasploit), C2 listener on the operator host. Full beacon chain exercised: build → deploy over SSH → check-in → task → result.

#### Malleable catch-all dropped the beacon body (CRITICAL)
- The beacon rotates URIs and randomizes their casing (`randomize_uri_casing`), but the C2 routed on exact paths. Most rotated POST check-ins (telemetry) fell through to the new catch-all, which consumed the body once for content sniffing; `handle_checkin` then saw `can_read_body == False`, re-read `""`, and every check-in carrying telemetry failed HMAC (signed body vs received empty body). Symptom: the beacon registered once after minutes of silent retries, then was rejected forever with exponential backoff.
- Fix: catch-all reads the payload once and passes it down (`pre_body=`) to `handle_checkin`/`handle_result`; aiohttp caches the read body, so no handler re-reads the socket.

#### Rotated malleable URIs 404ed (catch-all routing)
- `GET /JS/jquery-3.6.0.min.js`-style randomized paths had no route (aiohttp is case-sensitive); only the exact-cased lucky paths reached the check-in handler.
- Fix: catch-all GET/POST routes registered last — any unmatched URI carrying `X-Beacon-Id` is routed by CONTENT (GET → check-in; POST with decrypted `task_id` → result; POST otherwise → telemetry check-in). Path-based mTLS protection extended to any request presenting `X-Beacon-Id` (public stager downloads stay open).

#### Partial SSL_write silently dropped the beacon body (beacon C++)
- The Linux/Android network layer wrote the whole request (headers + body) with a single `SSL_write()`/`send()` and ignored the return value. TLS may accept a partial write — the server then sees a POST whose signed body is missing → guaranteed HMAC rejection on those requests (probabilistic, TLS-record dependent).
- Fix: bounded write loop for both `SSL_write` and `send` until the full request is handed off.

#### Beacon ↔ C2 key material alignment (operational note)
- `PHANTOM_C2_KEY` / `PHANTOM_C2_NONCE` overrides in the operator `.env` apply to the C2 at runtime; a beacon built from a checkout whose `.env`/state differs embeds a different AES key and can never decrypt task deliveries (silent backoff loop, HMAC still fine).
- Documented: build beacons from the operator checkout (or export the same `PHANTOM_C2_KEY`/`PHANTOM_C2_NONCE` to the build environment). Reproduced and verified: aligned-key build registers immediately, executes `whoami` and returns the encrypted result end-to-end.

#### Auto-mode field-test fixes (against the lab)
- **Full-range scan escalation:** default `scan_tcp` is top-100 ports only — non-standard SSH (2222) and custom services are invisible, so `deliver` runs on lab/hardened hosts dead-ended with "no path/move". `_recover_stall` now escalates ONCE to `nmap -p 1-65535 --min-rate` when the beacon goal is unmet and no remote-access service (SSH/RDP/WinRM/SMB) is known. Verified: second scan found `tcp/2222`.
- **SSH login on any port:** `ssh_login` precondition required the exact `tcp/22` finding; new `_has_service_kind("service", "ssh")` matches the SSH service on any discovered port.
- **Operator wordlists:** the offline brute only used built-in default credentials — real engagements bring their own lists. `load_custom_wordlists()` reads `data/wordlists/custom/<service>_users.txt` / `<service>_passwords.txt` (generic `users.txt`/`passwords.txt` as fallback), service-specific wins.
- **Dynamic service port for brute:** `_default_cred_discovery` used well-known ports (ssh→22); now prefers the port the scanner discovered (`_service_port`).
- Tests: `tests/test_automation_ssh_anyport.py` (precondition any-port, wordlist precedence, port discovery, escalation flag logic).

#### Local lab (`lab/`)
- Added `lab/`: single-container intentionally vulnerable target (SSH `victim`/`v1ct1m!` on 2222, anonymous FTP on 2121, SQLi login on 8081) + README with authorized-testing scope. Used for the beacon chain test above; reusable for exploit/brute/pivot drills.

### Verified end-to-end
- Kali WSL: nmap scan of the lab → XML → `parse_nmap_xml` (3 services), hydra found the SSH credential, credential harvest written to the shared WorldModel, SQLi confirmed against the lab web app.
- Beacon: compile (Linux x64 static + XOR payload) → scp over SSH → run → immediate registration with aligned keys → queued `whoami` executed → encrypted result returned and stored by the C2.

---

## [3.6.4] — 2026-08

### Added (field test against testfire.net)

#### Pure-Python HTTP/HTTPS fingerprint probes
- The fingerprint engine had probes for SSH/SMB/MySQL/… but **no HTTP probe** — web fingerprinting depended on `curl` (silently skipped on hosts without it). Discovered while field-testing against IBM's public demo target `testfire.net` (authorized): ports 80/443 connected but returned `unknown`.
- Added `_probe_http`/`_probe_https` (pure socket + stdlib `ssl`, no curl): parses `Server` header, HTTP status, `Location` redirect, `<title>`, and CMS/framework markers (wordpress/drupal/joomla/nginx/apache/tomcat/iis/php/shibboleth).
- Registered in `PROBE_MAP` (now 17 protocols). Verified live: `testfire.net` → `Apache-Coyote/1.1`, status 200, title `Altoro Mutual`, cms apache — on both 80 and 443 (the Python probe's TLS worked where `curl -I` returned empty).
- Tests: `tests/test_fingerprint.py` — server/title/CMS parsing against a local socket server, empty-response error path, registry count updated.

---

## [3.6.3] — 2026-08

### Fixed (static-analysis pass — pyflakes over the whole tree)

#### Runtime crashes (undefined names)
- `phantom/core/shell.py` — `time` was used (auto-mode from the shell) but never imported → `NameError` at runtime.
- `phantom/modules/base_module.py` — `notifier` used in `do_preview`/`_execute_flow` (the default flow every module inherits) but never imported → every `preview` on a module without override crashed.
- `phantom/utils/rce_deployer.py` — `shutil` used in the SMB deploy path but never imported → `NameError` when deploying via psexec/wmiexec.
- `phantom/automation/fallback.py` — `Set` used in an annotation without import.
- `phantom/automation/fingerprint/probes.py` — `Callable` used in `PROBE_MAP` annotation without import.
- `phantom/automation/social/persona.py` — `Any` used in annotations without import.

#### Shared state file format conflict (engagement_history.json)
- **`HistoricalLearner` crashed on every init when the history file was in the legacy flat-list format** — the file is written as a list by `core.history` but `automations.fallback` expected a dict-of-techniques, so the auto-mode died at startup on machines with real engagement data. `_load` now migrates the legacy list format, skips junk records, and never raises on corrupt payloads.
- `core/history.py` now also normalises the dict-of-techniques shape (written by fallback) back into records, so both writers can share the file safely in either direction.
- Regression tests added in `tests/test_fallback.py` (legacy list migration, corrupt payload).

#### Tests
- `test_c2_resilience.py::test_backoff_restored_on_recovery` asserted the old hardcoded-5000 string; updated to assert the new `base_sleep_ms` recovery (the fix from 3.6.2).

---

## [3.6.2] — 2026-08

### Fixed (deep audit)

#### Beacon C++ — wire protocol & platform parity
- **CRITICAL: HMAC canonical mismatch between beacon and C2 server.** `make_request_auth` in `network.h` joined the canonical string with literal `\n` (backslash-n) while the server's `canonical_request()` joins with real newlines — so the beacon's HMAC never matched and **every authenticated check-in was rejected with 401**. The first field test would have failed immediately. Fixed to real newlines and verified end-to-end (C++-generated signature now passes `verify_request`).
- **macOS beacon could never use HTTPS without mTLS** — it forced `CURLOPT_SSL_VERIFYPEER=1` against the self-signed C2 certificate, so every TLS check-in failed (Windows/Linux both disable verification). Now mirrors Windows/Linux without mTLS and verifies against the private CA with hostname check off when mTLS is on.
- **Operator sleep cadence was lost after an outage** — `sleep_ms` doubled as outage backoff, so `sleep 30000` silently reverted to 5s on reconnect (more check-ins = less stealth). New `base_sleep_ms` field preserves the operator cadence across outages.

#### API server (Electron) — security
- **The localhost API had no authentication** — only a CORS `*` middleware, so any local process (or a malicious website open in the operator's browser) could read targets/credentials and revoke beacon identities. Every route now requires `Authorization: Bearer <PHANTOM_API_TOKEN>` (OPTIONS preflight exempt); the Electron main process injects the header from the state file, the renderer never sees the token.

#### Tests
- New `tests/test_api_auth.py` — 401 without/wrong token, 200 with token, OPTIONS exemption, rotation invalidates the old token.
- New `tests/test_modules_logic.py` — logic-level coverage for wifi (BSSID/channel/count validation, crack errors), handler (payload mapping, duplicate listener, kill), pivot (command construction, invalid type), telegram (auth headers, API JSON parsing, error handling).

---

## [3.6.1] — 2026-08

### Fixed (full-project audit)

#### Beacon & build pipeline
- **Windows beacon now compiles again** — 4 real C++ errors in `sleep_ekko.h` (missing enums/`WaitAny`), `malleable.h` (generated config included before the namespace declaration), and `winhttp_dynamic.h` (`PFN_WinHttpQueryOption` redeclared). `beacon.bin` builds cleanly.
- **`CONFIG_SEED` now actually rotates per build** — the header documented per-build rotation but nothing generated it: every binary shipped the same hardcoded seed, so the XOR keystream protecting C2_HOST/PORT was identical across all builds. `builder.py` now rewrites a fresh random 64-bit seed on every build.
- `config_encrypted.h` and `malleable_config.h` (auto-generated) added to `.gitignore`; `c2_config.h` remains tracked-but-ignored (dead ignore — needs `git rm --cached` at next commit).

#### Test suite (was silently broken)
- `test_features_final.py` and `test_real_deploy.py` are standalone integration scripts that call `sys.exit(1)` at module level — they killed the entire pytest run. Excluded via `tests/conftest.py` `collect_ignore` + `pytest.ini` (they remain runnable manually / by the release workflow).
- **Fake social engines in `test_automation_deliver.py` / `test_automation_resume.py` updated** to the full social interface (`set_social_config`, `persona_profile`, `dossier`, `profile_recon`, `campaign`, `dm`, `dm_follow`, `wait_follow`, `harvest`, `phish(use_video=…)`) — the agent was failing every social capability against stale fakes.
- **Preflight check-in probe now proves the real authenticated path**: it enrolls a throwaway identity in an isolated registry and signs both probe requests with HMAC (counter + nonce), matching the real beacon wire protocol. Previously the HMAC-auth feature rejected unenrolled probes with 401, making the gate fail by design.
- `test_fresh_run_with_state_path_writes_checkpoint` deployed to `10.0.0.9` while its fake C2 registered `10.0.0.5` — the beacon wait loop spun until timeout. Runner now told which IP the run deploys to.
- **Environment-dependent tests made deterministic**: `test_workflow_refactor.py` and `test_enterprise_scoring.py` read the operator's REAL `calibrated_weights.json` / `engagement_history.json` (which only exist on used machines), producing negative scores and wrong `decide_next` results. They now isolate the calibration + history singletons (INITIAL_WEIGHTS, empty history) in setUp/tearDown. `test_manual_core.py` replaced the module singletons without restoring them — now restored in `finally`.

#### Core, API, CI
- **Report export path traversal**: target-derived filenames were unsanitized — a URL target (`http://host/path`) created missing subdirectories and broke `export`, and `..` could escape the reports dir. Filenames now sanitize to `[A-Za-z0-9._-]`.
- **CI would have failed out of the box**: `pytest --timeout=120` requires `pytest-timeout`, which was neither installed in the workflow nor in the Docker test deps. Added to both.

---

## [3.6.0] — 2026-08

### Changed

#### Modes removed — the core is now guided, not scripted
- `MODE_SEQUENCES`, `set mode`, `next` and the mode-driven `run` are GONE. Static sequences duplicated what the adaptive `suggest` layer already does from real findings, and sat awkwardly between manual and auto-mode (the full chain belongs to `auto`, the step-by-step control belongs to the shell).
- `run` is now ADAPTIVE: it reads the live engagement — target type (ip/domain/url vs email/username/phone via `classify_target`), knowledge findings, and the senior reasoning hypotheses (the same engine as auto-mode) — and proposes the single best next module WITH the reason, then asks before executing. `run <module>` runs a specific module directly. No target → clear hint. Identity target → OSINT first; empty network target → scan; then reasoning/module-scoring drives.
- Status bar / dashboard / prompt now show the target TYPE tag (IP/EMAIL/...) instead of a mode; profile save/load dropped `mode`.

#### `preview` ≠ `run` (module level)
- `preview` is now REVIEW-ONLY (shows the command plan, executes nothing); `run` EXECUTES the interactive flow. Previously `do_run` without `--quiet` just called `do_preview` — they were literally the same. Modules' execution flows renamed to `_execute_flow` (10 command modules); the base provides the generic flow + review-only preview.
- Exploit keeps its dedicated `do_run` (full CVE correlation) — `_execute_flow` is the interactive command selection.

#### Identity targets in the MANUAL core
- `classify_target` now distinguishes **usernames with dots** from domains via a TLD heuristic: `mario.rossi`/`giulia.b` are usernames (OSINT chain), while `testfire.net`, `sub.example.co.uk` and internal suffixes (`dc01.corp`, `web.internal`, `build.local`) stay domains — in BOTH the manual core and auto-mode (shared classifier).
- `set target` accepts every target type: phones with `+`/dashes/spaces (`+391234567890`), emails, dotted usernames.
- `run` routes identity targets to **osint first**; network modules (scan/web/exploit/brute/pivot/wifi/handler/payload) warn clearly when used against an email/username/phone target instead of running nmap nonsense on them.

#### Electron
- Session Manager dropped the mode select + static sequences; new **Suggest Next** button calls `/api/session/next` (adaptive, same logic as CLI `run`) and shows the suggested module, reason and command preview, with a Run button.

### Changed (API)
- `/api/session/next` → adaptive suggestion `{module, reason, commands}` (no execution); `/api/session/run` runs the adaptive step in background; `/api/session/preflight` without a module checks the adaptive next step; reports use the target TYPE instead of MODE.

---

## [3.5.0] — 2026-08

### Added

#### Deepen worker (work during social waits)
- New sub-agent goal `enrich`: while the lead agent sleeps waiting for the human (email open / link click / follow accept), a second agent works in parallel on deeper OSINT, breach checks, profile recon, dossier and persona cover, plus its own grabber polling — if the wait turns out unnecessary, the deepen worker proves it first.
- Deepen is deliberately passive: the `enrich` goal excludes `phish`/`dm_sent` facts, so it never launches new lures; only the lead sends, the worker enriches and polls.
- `_auto_workers` now returns 2 by default for identity targets too (previously exploit/web only) — lead + deepen even without `-a`.

#### Portable session bundles (.pm)
- `phantom/utils/session_bundle.py`: exports a complete engagement — session state + WorldModel + checkpoint + report index — into a single portable `.pm` file (gzipped JSON), and imports it back on any machine.
- Auto-mode now writes a checkpoint by default and supports `--resume`; the shell gains `export-session <path>.pm` / `import-session <path>.pm` (plus `--resume <path>` on `auto`) so a session can be handed between operators on opposite sides of the world.
- Import fully hydrates the reasoning state: the checkpoint's world model (or the manual session `_wm` when no checkpoint exists) is restored into the live knowledge base via `set_wm` — a `.pm` import now brings back findings, not just scalars (mirrors `Session.load`).

#### Encrypted .pm bundles + auto-session
- `.pm` files are now AES-256-GCM ENCRYPTED by default: key is the operator-local `PHANTOM_PM_KEY` secret (auto-generated once in `data/phantom_state.json`, gitignored, 0600; env override). Credentials/notes are never plaintext on disk or in transit; a tampered or wrong-key bundle is rejected cleanly (AES-GCM auth). Legacy plaintext bundles stay readable.
- `phantom/utils/auto_session.py`: every open is registered in `data/sessions/index.json`; every close auto-exports an encrypted .pm to `latest.pm` (always overwritten) + a dated copy `auto_<YYYY-MM-DD>.pm` that is overwritten only for the SAME engagement (same target + opening timestamp) — a new engagement gets a suffixed file, so per-day history survives.
- Hooks live in `main.py` (register + "Resume last engagement? [Y/n]" prompt on open, auto-export in `finally`) so `exit`, `quit` AND the double Ctrl+C path all persist the session without asking.
- `list-sessions` now shows the auto .pm bundles with metadata (target, findings, date, size).

#### Dedicated AUTO-MODE shell (CLI)
- `auto` with no arguments enters `phantom/core/auto_shell.py` — a first-class interface like `c2` for the C2, mirroring the Electron Auto-Mode panel 1:1
- Multi-target management (`targets add/rm/list` — the core shell holds one target, the auto shell holds a list), `scope add/rm`, `flags` (aggressive/stealth/speed/agents/goal/profile/llm, validated), `plan` (dry-run), `launch` (with C2 handoff on beacon), `resume <checkpoint|.pm>`, `status` (per-target event summary incl. waiting states), `export <file>.pm` / `import <file>.pm`, `back`
- Cyan PHANTOM wordmark banner + live status bar + context hints, same family as core (red) and C2 (magenta); double Ctrl+C exits
- One-shot `auto <targets> [flags]` remains unchanged for scripting

#### Identity targets are always in scope
- `is_identity_target` (email/username/phone/social handle) is exempted from scope pruning in both the agent and `_expand_targets` — a single identity target never wanders outside scope; the only off-target traffic is profile reverse-engineering, which maps the *same person's* public accounts (by design in scope).

---

## [3.4.0] — 2026-08

### Added

#### Real-video IP grabbing
- `video_picker.py` — picks a REAL, harmless public video the target would click on, driven by interests extracted from the profile bio: `yt-dlp ytsearch3:<topic>` when installed, a curated offline catalog of famous uploads otherwise; `--llm` refines the topic via a constrained, injection-hardened advisor call.
- Tracker lure pages now render the picked video with its real title/channel; `create_video_share_link()` carries the video metadata so `/@user/video/<code>`, `/reel/<code>`, `/shorts/<code>` serve a video that actually interests the victim.

#### Social sleep state (waiting for the human)
- `harvest_campaign` and the new `wait_follow` capability run as chunked sleeps that emit `waiting` events, breaking on the first real interaction (email open / click / follow accept).
- Horizon: 600s default, 30s under the fast flag, `PHANTOM_SOCIAL_WAIT` to override — the fast profile never sleeps.
- `dm_follow` capability + `FOLLOW_SENT:`/`FOLLOW_ACCEPTED:` markers: private accounts run follow → wait → DM → wait → victim_ip, fully unattended; email lures are gated off for private profiles.

#### Sender realism + homoglyphs
- `spoof.py` — `derive_sender()` builds the From identity from the dossier (service the target uses: platform brand + domain; person they know: a colleague at the corporate domain; company internal account; honest attacker-mailbox last resort).
- `homoglyph()` obfuscates the display name + subject with visually-identical Cyrillic lookalikes so naive text filters stop matching canonical keywords; on by default, off in aggressive mode (`PHANTOM_PHISH_HOMOGLYPH`).
- Zero-click open-tracking pixel now included in single-phish emails too (was campaigns-only).

#### Plumbing
- Planner: DM chain fixed (harvest/poll accept `dm_sent`; `_FACT_SOURCES` learns `follow_sent`/`follow_accepted`); `dm_ready` precondition ordered before the generic `ad` check (a closure-name collision bug that misplanned private-account DMs as AD work).
- Electron API: `/api/video-lure` endpoint.

---

## [3.3.0] — 2026-08

### Added

#### Coherent Persona Cover
- `generate_profile()` + `generate_avatar()` (`phantom/automation/social/persona.py`): name, age band *consistent with the job tier* (an intern is never 47), locale-matched city/country, interests, bio and avatar — deterministic per seed, reproducible campaigns
- Avatar offline-first: Pillow gradient+initials by default; `PHANTOM_PERSONA_AVATAR=randomuser` fetches a free portrait photo cached under `data/personas/avatars/`; graceful None when Pillow is missing
- New `persona_profile` capability wired into the planner + LLM advisor whitelist; marker `PERSONA_PROFILE:` → `persona_profile` finding

#### Video-Lure IP Grabbing
- Tracker route `/v/<code>` serves a page that mimics **Instagram Reels / TikTok / YouTube Shorts** (`PHANTOM_TRACK_SKIN`, embedded player via `PHANTOM_TRACK_VIDEO_ID`) and plays a real embedded video; page load records the victim's IP exactly like a click
- `IpGrabber.create_video_link()` + `use_video=True` on `phish`/`campaign` — reel/short links are the highest-converting IP-grab vector

#### Strategic Phishing (Target Dossier)
- `phantom/automation/social/dossier.py`: `TargetDossier` merges all discovered identity facts; **breach correlation across channels** — the same breach name on email *and* phone becomes a cross-channel hook ("Your email and phone were both exposed in the X breach")
- Deterministic pretext scorer ranks the library per target (phone-only → package_delivery, platform+breach → security_alert, platform-only → password_reset, company → IT/HR, public profile → recruiter)
- `SocialEngine.dossier()` + new `dossier_analyze` capability (marker `DOSSIER_RECOMMEND:` → `dossier` finding); `strategic=True` on `phish`/`campaign` uses scorer + dossier hook + optional subject twist
- LLM dossier advisor: `LLMAdvisor.analyze_dossier()` — strict `{pretext, hook, subject_twist}` schema, pretext validated against the library, hook/subject sanitized (no URLs, no braces/placeholders, no control chars, bounded length); a successful injection can only produce a bad hook, never change the channel or execute anything

#### Share-Format Video Links
- `IpGrabber.create_video_share_link()` emits the *real share URL shape* — `/@user/video/<code>` (TikTok), `/reel/<code>` (Instagram), `/shorts/<code>` (YouTube) — with the tracking code in the path and **no traceable profile identifier**
- Tracker serves these paths with the platform skin and records the victim's IP on page load

#### Audience-Aware Personas
- `generate_profile(audience=...)`: `middle` (11-14), `high` (14-19), `university` (18-25), `professional` (job-tier) with student datasets — schools by locale, age-appropriate interests/hobbies/bios; `PersonaProfile` gains `audience` + `school`
- `SocialEngine.persona_profile()` infers the audience from the discovered platform (Instagram/TikTok/Snapchat -> student) when not specified

#### Profile Reverse-Engineering
- `SocialEngine.profile_recon()` (new `profile_recon` capability): fetches the profile page, detects **private / public / missing**, extracts bio + link-in-bio + @handles + emails, and runs sherlock on discovered handles to map the **same person on other platforms** — pure OSINT, private profiles are mapped, never scraped
- Markers `PROFILE:` / `ACCOUNT_LINK:` -> `profile` / `account_link` findings; profile state feeds the strategic dossier (private profile boosts the security-alert pretext, platform fills from the profile)

#### Sender Realism
- Phish From derived from the target's corporate domain (`noreply@acme.it`) or the platform domain (`noreply@linkedin.com`); free-mail providers are never impersonated; fallback stays the configurable env default

#### Electron API
- `POST /api/persona-profile` (generate coherent cover + avatar, `audience` param) and `POST /api/dossier` (breach correlation + recommended pretext) and `POST /api/profile-recon` (profile OSINT mapping)

---

## [3.2.0] — 2026-08

### Added

#### Professional Social Engineering
- **Pretext library** (`phantom/automation/social/templates.py`): 7 believable lures (security_alert, it_helpdesk, hr_benefits, recruiter, package_delivery, password_reset, doc_share) rendered from real OSINT context — target name, platform, and the actual breach the address was found in
- **Credential harvesting**: the self-hosted tracker (`/l/<code>` login pages, `/c/<code>` capture) stores submitted username/password/OTP; `PHANTOM_TRACK_BRAND` + `PHANTOM_TRACK_OTP` env control the page
- **Campaign engine** (`SocialEngine.campaign/harvest`): multi-target campaigns with per-target lifecycle sent → opened → clicked → creds, stats and reports; new `campaign_launch` + `harvest_campaign` capabilities wired into the planner (`phish` / `victim_ip` / `creds` fact sources)
- **Advanced tracking**: 1x1 open-pixel (`/px/<code>`), UA→OS/device/browser fingerprinting, optional MaxMind geo (`PHANTOM_GEOIP_DB`), referrer capture
- **Delivery hardening**: HTML multipart emails with action button + tracking pixel, contextual From display names (`PHANTOM_PHISH_FROM`), Message-ID/Reply-To headers
- Harvested credentials become `creds` findings (service=harvest) that the planner verifies against live services — phish → creds → SSH/WinRM → beacon

#### Dynamic CVE Catalog
- Static registry expanded 7 → **12 curated modules** (Spring4Shell, Confluence OGNL, GitLab Exif, vCenter, Elasticsearch added) with **banner-product alias normalization** so real nmap/probe banners ("Apache", "GitLab") match canonical names
- `service_exploit` now falls back to **live NVD correlation** (resolver, cached) for every fingerprinted product@version not in the registry, then **discovers the weaponizing module dynamically** via `msfconsole search cve:<id>` (Metasploit's self-updating index) — the catalog is genuinely dynamic, never a hardcoded list
- Unweaponizable CVEs are recorded as `kind=note` knowledge findings so the bug-class anomaly path takes over instead of a dead end

#### Optional Local-LLM Advisor
- `phantom/automation/llm_advisor.py`: `--llm` flag; any GGUF via `PHANTOM_LLM_MODEL` (recommended Qwen2.5-Instruct); llama-cpp-python, zero data egress
- Injection-hardened: strict `{capability_id, reason}` JSON schema (extra fields dropped at parse), target content wrapped as `<UNTRUSTED_DATA>` and never mixed with instructions, registry validation, paranoid mode drops aggressive suggestions — the advisor can never authorize an action, only add hypotheses the deterministic layer verifies

#### Social DM (direct messages)
- `phantom/automation/social/social_dm.py`: short pretext DMs (security_verify, recruiter, collab, prize, invoice) with per-target tracking links; injectable transports (`TelegramDMTransport` via `PHANTOM_TELEGRAM_BOT_TOKEN`, `DiscordDMTransport` via `PHANTOM_DISCORD_WEBHOOK`, `ConsoleDMTransport` dry-run, `FakeDMTransport` for tests) and custom platform support via `PHANTOM_DM_TRANSPORT=<dotted.path.Class>`
- `SocialEngine.dm()`: per-target grabbit link, carrier of the identity chain — a DM click converts to `victim_ip` exactly like email
- New `dm_launch` capability (effects `dm_sent`), `DM_SENT:` marker interpreted into findings, planner fact source + LLM advisor whitelist updated; no transport configured → clear ERROR marker, never a hang
- Electron: new `POST /api/dm` endpoint (dry-run default from the GUI, real send when a transport is configured)

#### Real Exploit PoC Portfolio (core manual)
- Removed the `CVE_2024_TEST.py` placeholder entirely
- **6 real, verifiable, stdlib-only PoCs** in `phantom/exploits/pocs/`: Heartbleed (CVE-2014-0160), Apache 2.4.49 traversal+RCE (CVE-2021-41773), Struts2 OGNL RCE (CVE-2017-5638), Log4Shell delivery+reflection with callback mode (CVE-2021-44228), FortiOS SSL-VPN credential leak (CVE-2018-13379), Cisco ASA/FTD file read (CVE-2020-3452)
- Every PoC runs isolated in a subprocess with a hard timeout and fails softly on unreachable targets; `fire <cve>` / `execute <name>` now have a real catalog to act on

#### Install flow hardening
- `build_helper.py`: bounded subprocess timeouts (`apt-get update` 120s, install 300s) so a slow mirror can never hang the beacon build; EOF/KeyboardInterrupt-safe input; declining the install prints the manual command and skips gracefully instead of dead-ending

### Changed
- `.env.example`: `PHANTOM_TRACK_BRAND`, `PHANTOM_TRACK_OTP`, `PHANTOM_GEOIP_DB`, `PHANTOM_PHISH_FROM`, `PHANTOM_LLM_MODEL`, `PHANTOM_DISCORD_WEBHOOK`, `PHANTOM_DM_TRANSPORT`, `PHANTOM_LOG4J_CALLBACK`

---

## [3.0.0] — 2026-08

### Added

#### Beacon Evasion (v3.1 Material)
- **Direct Syscalls**: embedded `syscall; ret` trampoline in own module — kernel stack return points into our `.text` instead of ntdll, defeating foreign-syscall heuristics
- **Ekko Sleep Obfuscation**: waitable-timer sleep via `NtWaitForMultipleObjects` with RC4-encrypted RW memory during the wait — thread never appears as "Sleep()-ing"
- **Early Bird APC Injection**: shellcode queued via `QueueUserAPC` on a suspended process's main thread, runs before `LdrInitializeThunk` — no remote thread
- **Threadless APC Injection**: `QueueUserAPC` onto existing threads of a running process — no new thread created, defeats thread-count and CreateRemoteThread hooks
- **RWX Hardening**: memory never allocated `PAGE_EXECUTE_READWRITE`; RW → write → RX flip via direct syscalls on every allocation
- **Malleable C2 Profiles**: JSON-driven beacon configuration — URIs, user-agent pool, sleep cadence, HTTP headers all customizable per-build; default profile mimics a generic static site + REST API
- **Profile Advisor**: target-aware auto-recommendation engine — analyzes OS, services, and network position to recommend the optimal profile family (7 families: generic CDN, MS corporate, Linux DevOps, WordPress CMS, Apple macOS, Android Mobile, SharePoint O365); tracks success per family via Beta-Binomial posteriors for continuous improvement
- **Encrypted Heap (FOLIAGE)**: `SecureBuffer` type wraps sensitive allocations (keys, shellcode) with RC4 encryption + 32-bit checksum; plaintext only lives during active use, ciphertext at rest
- **PEB Module Unlink**: beacon removed from all three PEB module lists (InLoadOrder, InMemoryOrder, InInitializationOrder) at startup; Process Explorer / EDR module-walk heuristics no longer see it
- **PPID Spoofing**: sacrificial processes now spawn with explorer.exe parent — EDR process-tree correlation eliminated
- **Dynamic WinHTTP**: all 12 WinHTTP API functions resolved via PEB hash lookup; zero static IAT entries for winhttp.dll — binaries no longer flagged as "non-browser calling WinHttpOpen"
- **Encrypted Config**: C2_HOST + C2_PORT XOR-encrypted at compile time with per-build rotating seed; plaintext never appears in binary
- **Module Stomping v2**: rewritten to use PEB-walked module enumeration (no GetModuleHandle/GetModuleInformation IAT); directly parses PE headers for `.text` section
- **HW Breakpoint Detection**: DR7 bitmask checked before clearing — only zeros debug registers when HW breakpoints are actually active, reducing anomaly
- **Stack Residue Cleanup**: `_mm_lfence()` after stack-spoofed calls prevents lingering function pointers on the call stack
- **Reflective Loader Fix**: DllBase offset corrected from 0x20 to 0x30 in PEB walker (LDR_DATA_TABLE_ENTRY)
- **CRT Initialization Skipped**: `__main` / `__do_global_ctors` bypassed in PIC shellcode — prevents crash on unmapped `.ctors` section during injection

#### Auto-Mode (Full Autonomous Kill Chain)
- Deterministic planner agent with weighted strategy engine
- Identity chain: OSINT → breach → persona → phish → IP-grabber → network chain
- Anomaly engine: bug-class hunting (SQLi, SSTI, XXE, SSRF, path traversal) with statistical baseline + validation pass
- RCE bridge: beacon deployment through confirmed code execution (SSTI/CVE → dropper) or cloud IAM via SSRF
- **Deep protocol fingerprinting** (15 protocols: SMB, MySQL, PostgreSQL, Redis, MongoDB, SSH, FTP, SMTP, SNMP, LDAP, RDP, MSSQL, Docker, Kubernetes, DNS)
- **Attack graph chaining** (25 cross-service rules: creds→SSH, SMB null→share, SSRF→cloud creds, SSTI→RCE→beacon)
- **Differential analysis engine** (protocol-agnostic: baseline + mutation + statistical scoring + validation, HTTP and raw protocols)
- **Active Directory awareness** (LDAP rootDSE, SMB domain extraction, DNS SRV, Kerberos pre-auth, functional level detection)
- **Intelligent fallback chain** (informed by failure: "brute failed but account 'admin' exists" → phish, not re-brute)
- **Historical self-learning** (Beta-Binomial posteriors over technique success rates per OS, persists to engagement_history.json)
- **Removed AI plugin** (ai_connector.py — unused, heavy dependency; Phantom is fully offline)
- Environment recognition: Docker/Kubernetes/SCADA/cloud classification
- Dynamic command shaping with per-run path randomization
- Version-matched exploitation via CVE module registry
- Dynamic CVE resolver (NVD API with TTL disk cache)
- Stealth engine with per-profile timing governance
- Sub-agents (`-aN`) with shared credential context
- Campaign report with cleanup & IOCs section
- `--plan` (dry-run), `--aggressive`, `--no-stealth` flags

#### Enterprise Decision Engine
- Threat intelligence: NVD, OTX, CISA KEV with 24h caching
- Bayesian calibration: Beta-Binomial weight learning
- MITRE ATT&CK mapper: service-to-technique, kill chain phase prioritization
- Risk engine: business criticality, network position, asset classification
- Historical learning: technique success/fail tracking with temporal decay

#### Shared Knowledge Engine
- Typed WorldModel shared between autonomous agent and manual modules
- `show knowledge`, `suggest` (deterministic reasoning from findings), `brute defaults`
- Step-aware `run` with precondition checking
- Session save/load with embedded WorldModel

#### Manual Modules (12 total)
- State-aware dynamic command suggestions (`preview` + `suggest_commands`)
- Version-matched MSF commands in exploit module
- Default credential check in brute module
- Wordlist generator with pattern tokens and mutation engine
- Anomaly hunt in web module

#### C2 Enhancements
- mTLS by default (auto-generated CA + per-beacon client certificates)
- Per-beacon HMAC authentication with key rotation (120s transition)
- Task ID collision prevention (timestamp + random suffix)
- Session resume detection with gap reporting
- Auto-persist queued on first beacon check-in
- C2 config command (show/rotate secrets, mTLS toggle)
- `certs` command (status/uninstall)
- Dedicated `beacon-auth` command (status/rotate/revoke)
- Socket limits and result caps

#### Beacon
- AES-256-GCM encryption with random nonce
- mTLS client certificates + pinned server fingerprint
- Per-beacon HMAC identity
- NTDLL unhooking (clean `.text` reload from disk via indirect syscalls)
- Stack spoofing (RET gadget from ntdll, 5 Win32 wrappers)
- Hardware breakpoint clearing (DR0-DR3)
- CPUID telemetry flush
- Memory sleep masking (.data/.rdata XOR encryption)
- Cross-platform: Windows (PE x64), Linux (ELF x64/x86), Android (ARM64), macOS
- Chrome CDP browser pivot (WebSocket, cookies, eval, navigation)
- Cookie stealer (Chrome DPAPI + inline SQLite parsing)
- GPS, camera, audio recording, screen recording (cross-platform)
- Wi-Fi and Bluetooth scanning
- TCP connection monitor (netstat)

#### Electron Desktop App
- React + TypeScript + Vite + Electron + Tailwind + Zustand
- Command Palette (Ctrl+K) — fuzzy search across all modules, beacons, credentials
- 18 panels: C2 Dashboard, Session, Auto-Mode, Timeline, Vault, Network Map, 12 modules, Reports, Settings
- Credential Vault (search, copy, show/hide)
- Campaign Timeline (color-coded event badges, auto-refresh)
- SVG Network Map (attacker → host → services → beacons)
- Module Panel with Run Selected / Run Group / Run All / Edit / Preflight
- Beacon generation (dropdown: Win/Linux/Android/macOS)
- Beacon auth management, certs management
- Wordlist generation, knowledge view, session save/load
- Dual report export + campaign ZIP export
- Backend dispatcher (WSL2 / Native / SSH) with auto-detection
- 45+ REST API endpoints
- Cross-platform packaging: Windows (NSIS), macOS (DMG), Linux (AppImage)
- GitHub Actions release workflow (PyInstaller backend + electron-builder)

#### CLI UX
- Artistic emoji-style ghost banner
- Live status bar (target · mode · scope · counters · beacon count · elapsed time)
- Faded context hints after every command
- Double Ctrl+C exit with auto-fading hint
- Preflight tool check with cross-platform install hints
- Quiet mode for scripting
- Tab completion for `use` and `set`

#### Reporting
- Dual report: raw operator (full details) + sanitized client (methodology, findings, MITRE, hardening)
- Campaign report for multi-target engagements
- Export formats: JSON, HTML, PDF, Markdown
- Cleanup & IOCs section derived from actual run data

#### CI/CD
- 74 test files with full coverage
- GitHub Actions: Python 3.10-3.12, C++ compilation, security scan, Electron release
- Automated cross-platform beacon compilation verification

---

## [2.0.0] — 2025

### Added
- C2 server with HTTPS listener and AES encryption
- Cross-platform beacon (Windows, Linux, Android)
- Reflective in-memory loader for Windows
- 8 manual pentest modules (scan, osint, wifi, web, brute, exploit, payload, handler)
- Session management with scope enforcement
- Plugin system
- Docker deployment
- Telegram C2 bot
- Indirect syscalls (Hell's Gate)
- AMSI/ETW patching
- SOCKS5 proxy, SMB pipe C2, browser pivot
- Screenshot, keylogger, process injection

---

## [1.0.0] — 2024

### Added
- Initial release
- Basic CLI pentest shell
- Core modules (scan, exploit, payload)
- Simple C2 communication
## [3.7.4] — 2026-09-06

### Fixed — Electron "everything fetch errors" root cause

**Token desync between the Electron main process and the Python backend.**
A `PHANTOM_API_TOKEN` inherited from a parent shell (e.g. after running
tests in the same terminal) took precedence over the persisted state file
on the backend side, while the Electron main process read the state file
— the two processes disagreed → **401 on every renderer fetch** (session,
C2 state, network scan, everything).

- `phantom/utils/state.py`: the persisted token is now authoritative; a
  *different* env value is ignored (matching env values are harmless).
- `electron/main.ts`: the main process reads the token from the state
  file first (same per-user file the backend uses), env only as fallback.
- Regression test `test_api_token_env_cannot_desync_persisted_state`.
- Network scan stays async (previous fix) and was re-verified live: the
  installed app boots, authenticates, and scans without blocking.

### Fixed — network map, wordlists, CLI/C2 help

- **Network scan found 0 hosts (CLI + Electron)**: `_ping_sweep` passed
  `IPv4Address` objects to `subprocess.run` (expects strings) — every ping
  raised and the sweep returned empty in 0.1s. Fixed: 8 real LAN hosts
  discovered and seeded into the WorldModel from the installed app.
- **`wordlists list` empty on Windows**: `SEARCH_PATHS` only contained
  `/usr/share/*` (Linux). Added the project/app-data `data/wordlists`
  directory so wordlists work out of the box everywhere.
- **`/api/session/wordlists` broken**: the API called `list_entries()`,
  `search()`, `info()` — methods that did not exist (the manager only had
  CLI-printing methods). Added the data-returning API.
- **CLI help incomplete**: added the missing `agent`, `craft`, `map`,
  `install`, `wordlists` entries + a new "Tooling & Craft" table, and all
  missing modules (craft, handler, telegram, wordlist).
- **C2 help showed 15 of 30 commands**: added screenshot, keylog,
  persist/autopersist, inject (+tl/eb variants), migrate, mem-run,
  generate-shellcode, payloads, telegram, malleable.
- **`malleable` stays in the core help**: it is also usable from the core
  shell (profiles are shared by the beacon builder), not only inside C2.
