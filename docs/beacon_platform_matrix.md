# Beacon platform matrix

The beacon builds and runs on **Windows, Linux, macOS and Android** (`beacon-smoke`
jobs in CI compile a real artefact for each). Building is not the same as feature
parity, so this page is the contract: what is implemented on every OS, and what is
deliberately Windows-only.

## The enforced grid (feature × OS × arch × transport)

This table is GENERATED from `phantom/utils/beacon_matrix.py`, and checked by
`tests/test_beacon_matrix.py`: every C2 verb, every source header and every
documented Windows-only module is classified here, and the docs quote the same
data the code enforces. Regenerate with
`python scripts/beacon_matrix_verify.py --write-docs`.

What was wrong before: the CI `beacon-smoke` jobs proved that a real binary was
produced for each OS, which says nothing about WHICH capabilities it carries,
and the per-feature tables further down were a reviewed claim nobody
re-checked. The grid closes that gap in three places:

* **source level** — every verb the C2 may send belongs to exactly one
  feature row; a header the grid calls usable on POSIX must have a
  non-Windows branch, and one it calls `windows_only` must have none;
* **artefact level** — after each `beacon-smoke` build the job runs
  `scripts/beacon_matrix_verify.py --platform <os> [--arch <arch>]`, which
  checks the CONTAINER and the MACHINE field against the cell (an x86-64 ELF
  that should be aarch64 is still `\x7fELF`) and prints the parity gap of that
  OS;
* **docs level** — this block is compared verbatim with the generated table, so
  the page cannot drift from the code.

Support levels are the vocabulary that keeps it honest: `native` (the
platform's own API), `posix` (the shared POSIX path is compiled in),
`posix (degrade)` (it runs but leans on Linux-first tooling), `windows_only`
(NT-specific mechanism, no POSIX analogue) and `absent` (no path at all).

<!-- beacon-matrix:begin -->
| Feature | Kind | Windows | Linux | macOS | Android | Verbs |
|---|---|---|---|---|---|---|
| shell_exec | shell | native | native | native | native | `run`, `exec`, `shell`, `kill`, `mem-run`, `download`, `upload`, `remote`, `exit`, `sleep`, `set-sleep`, `health`, `auth-rotate` |
| filesystem | shell | native | native | native | native | `ls`, `cat`, `cd`, `cd..`, `pwd`, `dir`, `drives`, `find` |
| process_recon | collection | native | native | native | native | `processes`, `whoami`, `sysinfo`, `netinfo` |
| recon_net | collection | native | native | native | native | `recon` |
| keylogger | collection | native | posix | posix | posix | `keylog` |
| persistence | action | native | posix | posix | posix | `persist`, `unpersist` |
| edr_awareness | evasion | native | native | native | native | `edrcheck` |
| edr_kill | action | native | posix | posix | posix | `edr-kill` |
| masked_sleep | evasion | native | native | native | native | — |
| module_hiding | evasion | native | posix | absent | absent | — |
| call_stack_spoof | evasion | windows_only | absent | absent | absent | — |
| sleep_ekko_timer | evasion | windows_only | absent | absent | absent | — |
| winhttp_resolver | helper | windows_only | absent | absent | absent | — |
| wasapi_engine | helper | windows_only | absent | absent | absent | — |
| nt_syscalls | evasion | windows_only | absent | absent | absent | — |
| apc_injection | action | windows_only | absent | absent | absent | — |
| ppid_spoof | evasion | windows_only | absent | absent | absent | — |
| jpeg_encoder | helper | windows_only | absent | absent | absent | — |
| screenshot | collection | native | posix | posix (degrade) | posix | `screenshot`, `screen-dump` |
| screen_record | collection | native | posix | posix (degrade) | posix | `screen-record`, `screen-record-live`, `screen-stream`, `screen-stream-stop` |
| camera | collection | native | posix | posix (degrade) | posix | `camera` |
| audio | collection | native | posix | posix (degrade) | posix | `audio` |
| gps | collection | native | posix | posix (degrade) | posix | `gps` |
| netstat | collection | native | posix | posix (degrade) | posix | `netstat`, `netstat-json` |
| cookies | collection | native | posix | absent | absent | `cookies`, `cookies-json` |
| wlan | collection | native | posix | posix | posix (degrade) | `wlan-scan`, `wlan-locate` |
| bluetooth | collection | native | posix | posix | posix (degrade) | `bt-scan`, `bt-scan-json` |
| browser_pivot | action | native | posix | posix | posix | `browser-pivot`, `browser-pivot-stop`, `browser-list` |
| cdp_pivot | action | native | posix | posix | posix | `cdp-launch`, `cdp-nav`, `cdp-eval`, `cdp-fetch`, `cdp-cookies` |
| socks_proxy | action | native | posix | posix | posix | `socks`, `socks-stop` |
| port_forward | action | native | posix | posix | posix | `portfwd`, `portfwd-stop` |
| process_injection | action | native | posix | posix (degrade) | posix | `inject`, `inject-eb`, `inject-tl`, `migrate` |
| smb_pipe | action | windows_only | absent | absent | absent | `smb-pipe`, `smb-pipe-stop` |
| task_lifecycle | protocol | native | native | native | native | — |
| beacon_auth | protocol | native | native | native | native | — |
| transport_pinning | protocol | native | native | native | native | — |
| malleable_profile | protocol | native | native | native | native | — |

| OS | arches | transport | pin | container | artefact |
|---|---|---|---|---|---|
| windows | `x86_64`, `x86` | `winhttp` | `cert-sha256-der` | PE | `beacon.pe` |
| linux | `x86_64`, `aarch64` | `openssl` | `cert-sha256-der` | ELF | `beacon_linux` |
| macos | `arm64`, `x86_64` | `libcurl` | `pubkey-spki-sha256` | Mach-O | `beacon_macos` |
| android | `aarch64` | `openssl` | `cert-sha256-der` | ELF | `beacon_android` |
<!-- beacon-matrix:end -->

## Anti-analysis (evasion.h)

| Capability | Windows | Linux | macOS | Android |
|---|---|---|---|---|
| Debugger detection | PEB `BeingDebugged` + `CheckRemoteDebuggerPresent` | `/proc/self/status` **TracerPid** | `sysctl` `KERN_PROC_PID` → `P_TRACED` | `/proc/self/status` **TracerPid** (same as Linux) |
| VM detection | cores + RAM + VM driver files | DMI vendor/product strings (`/sys/class/dmi/id`) | `kern.hv_vmm_present` + `hw.model` | **emulator probes**: `/dev/qemu_pipe`, `/dev/goldfish_pipe`, `ro.kernel.qemu`, `ro.hardware` goldfish / ranchu, SDK `ro.product.model` |
| Process masquerade | PEB `FullDllName` rewrite | `prctl(PR_SET_NAME)` | none (no supported API) | `prctl(PR_SET_NAME)` (Android is Linux) |
| AMSI patch | `AmsiScanBuffer` patch | n/a (documented no-op) | n/a (documented no-op) | n/a (documented no-op) |
| ETW patch | `EtwEventWrite` patch | n/a (documented no-op) | n/a (documented no-op) | n/a (documented no-op) |
| Module hiding | PEB module-list unlink | dynamic loader **link_map** unlink (`_r_debug.r_map`) | no-op (dyld list is read-only) | no-op (bionic exposes no writable link_map) |
| Masked sleep | Ekko timer + code/stack RC4 | **ekko_sleep_masked** (RC4 over the idle stack region) | **ekko_sleep_masked** (same) | **ekko_sleep_masked** (same; `pthread_getattr_np` needs API 21+, the build uses API 28) |
| EDR situational awareness | `edrcheck` (ntdll hooks, drivers, ETW-TI) | `edrcheck` (**selinux**/AppArmor LSM, eBPF, audit, known agents) | `edrcheck` (SIP, EndpointSecurity system extensions, known agents) | `edrcheck` (**selinux** present on Android, known agents) |

Android-specific details:

- The emulator check lives in `anti::is_vm` (`__ANDROID__` branch): the DMI
  files used on desktop Linux are usually absent on Android images, so the
  qemu tells (pipes, `ro.kernel.qemu`, `goldfish`/`ranchu` hardware, SDK
  model) are probed directly. Any one is enough to bail.
- `pthread_getattr_np` (masked sleep) is declared from API 21; the NDK build
  (`aarch64-linux-android28-clang++`) targets API 28. If it ever fails at
  runtime `thread_stack_bounds` returns false and the beacon falls back to a
  plain `nanosleep`, so the feature degrades rather than breaks.
- Module hiding is a documented no-op: bionic does not expose a writable
  `_r_debug.r_map` through its public headers.

Anti-analysis is compiled in unless `DISABLE_ANTI` is defined at build time.

## Advanced arsenal (collection / action)

The table above is anti-analysis. The collection and action capabilities have
their own per-OS paths, and — contrary to a common misreading of the
``#ifdef _WIN32`` at the top of each header (that is only the **include**
block, not a whole-file guard) — **none of them is Windows-only**. Every one
keeps a real non-Windows branch, and `tests/test_beacon_arsenal_parity.py` pins
that so this contract cannot silently regress.

| Capability (command) | Windows | Linux | Android | macOS |
|---|---|---|---|---|
| Screenshot (`screenshot`) | GDI `BitBlt` → BMP | Wayland-first: `grim` / `gnome-screenshot` / `spectacle` → `scrot` / `import` / `xwd` (X11) → `screencap` | `screencap -p` | POSIX branch (Linux tools — degrades) |
| Screen record (`screen-record*`) | GDI frames; ffmpeg `gdigrab` | ffmpeg `x11grab` (X11) | `screenrecord` (passive fallback) | POSIX branch (ffmpeg) |
| Camera (`camera`) | Media Foundation; WIA via PowerShell | `fswebcam` / ffmpeg `v4l2` | `am … IMAGE_CAPTURE`; `v4l2-ctl` | POSIX branch (degrades) |
| Audio (`audio`) | WASAPI (raw COM) | `arecord` / `ffmpeg` alsa / `rec` | `termux-microphone-recorder` / `arecord` | POSIX branch (Linux tools) |
| GPS (`gps`) | WinRT Geolocator | gpsd `gpspipe`, `/dev/gps0`, `nmcli` | `dumpsys location` | POSIX branch (degrades) |
| netstat (`netstat`) | iphlpapi `GetExtendedTcpTable` | `/proc/net/tcp` (+ `/proc/*/fd`) | `/proc/net/tcp` | no `/proc` → empty |
| Cookies (`cookies`) | DPAPI + browser profile files | OpenSSL `EVP` over Chromium/Firefox profiles | not covered | not covered |
| WLAN (`wlan-scan` / `wlan-locate`) | Native WLAN API | `nmcli` (NetworkManager; no root) → `iw` / `iwlist` (root or CAP_NET_ADMIN) | `iw`/`iwlist` when present | same POSIX path |
| Bluetooth (`bt-scan`) | native | `hcitool` / `bluetoothctl` | when present | same POSIX path |
| Browser pivot (`browser-pivot`) | Toolhelp32 PID + TCP relay | `find_browser_pid()` over `/proc/*/comm` + relay | same | `/proc` absent → pass a PID |
| CDP (`cdp-*`) | `CreateProcess(chrome.exe)` + websocket | `google-chrome --remote-debugging-port` + BSD sockets | same POSIX path | same POSIX path |
| SOCKS5 (`socks`) / forward (`portfwd`) | WinSock | BSD sockets | BSD sockets | BSD sockets (built under macOS `-Werror`) |

Real caveats (not cosmetic):

- The POSIX branches are **Linux-first**. Several shell out to X11 tools
  (`import`, `xwd`, `x11grab`) or Linux-only sources (`/proc`, `iw`). macOS runs
  the same POSIX path and therefore **degrades** on the media/netstat
  capabilities — macOS has no dedicated branch, which is the accepted posture.
- Android is Linux without the desktop tools: the media paths try the Android
  binaries (`screencap`, `screenrecord`, `dumpsys`, `am`, `v4l2-ctl`) first,
  and cookies/CDP have no dedicated Android path.
- `smb.h` (SMB named-pipe lateral movement) is Windows-only on purpose and is
  in the accepted list below, not here.

## Deliberately Windows-only (accepted, no POSIX analogue)

These are NT-specific mechanisms and are **accepted as Windows-only**: on POSIX
the concept either does not exist, has no safe equivalent, or has a different
name — documented rather than stubbed. The test
`tests/test_beacon_posix_parity.py` pins this list so a new header either ships
a POSIX path or is added here on purpose.

- Call-stack spoofing against unwinder-based EDR ships through
  `sleep_mask.h` (`sleepmask::spoof_stack`, ThreadStackSpoofer class);
  the earlier standalone `stack_spoof.h` / `stack_spoofer.asm` pair was
  never called by the beacon and was removed as dead code. POSIX
  unwinding models differ; no equivalent is shipped there.
- `syscalls.h` — direct/indirect NT syscalls to bypass userland hooks. POSIX has
  no userland syscall-hook layer to dodge.
- `apc_injection.h` — APC injection (a Windows scheduling primitive).
- `smb.h` — SMB lateral movement helper (Windows-oriented).
- `ppid_spoof.h` — parent-PID spoofing via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`.
- `sleep_ekko.h` — the Ekko timer object; the POSIX masked sleep uses
  `ekko_sleep_masked` directly instead.
- `winhttp_dynamic.h` — dynamic WinHTTP resolution. On POSIX the transport is
  libcurl / raw sockets + OpenSSL, which is a working replacement, not a gap.
- `wasapi_capture.h` — WASAPI audio engine. `audio.h` has a real POSIX capture
  path instead, so audio collection is still available.

The HWBP + Vectored-Exception-Handler indirect-syscall bypass (`install_hwbp_engine`,
`find_clean_gadget`) is likewise Windows-only: it arms DR0 on a `syscall; ret`
gadget inside ntdll, which has no meaning on POSIX.

## Certificate pinning and a TLS-terminating front

The beacon pins the **leaf certificate fingerprint** of the C2 (`BEACON_SERVER_FINGERPRINT`,
SHA-256 over DER). The value is generated from the C2's own certificate
(`certs/server.crt` / `mtls_server.crt`).

If a front / redirector / reverse proxy sits in front of the C2, it **must
forward the raw TLS (passthrough)** so the beacon still sees the backend's
certificate. If the front terminates TLS with its own certificate, the pinned
leaf will not match and every check-in fails — in that topology the pin is
derived from the FRONT's certificate automatically: set `c2.front_cert` (or
drop `certs/front.crt`), and rotating the front is "replace that file and
rebuild". `doctor` reports which certificate the build will pin.

### Per-endpoint pins

Each rung of the ladder may carry **its own** pin. `C2_HOST_PINS` is aligned
positionally with `[C2_HOST] + C2_HOSTS` (empty field = inherit the compiled
`BEACON_SERVER_FINGERPRINT`), so independent redirectors no longer have to
share one certificate or front a passthrough. Set it from
`PHANTOM_C2_PINS` / `c2.pins` (comma-separated, gaps allowed). A rung with no
pin **and** no fallback pin is rejected (fail closed) instead of being trusted
unauthenticated.

| transport | pin primitive | shape |
|-----------|---------------|-------|
| Windows (WinHTTP) | `CryptHashCertificate` over `pbCertEncoded` | SHA-256 DER hex |
| Linux / Android (OpenSSL) | `X509_digest(EVP_sha256)` | SHA-256 DER hex |
| macOS (libcurl) | `CURLOPT_PINNEDPUBLICKEY` | `sha256//<base64(SPKI)>` |

macOS pins the **public key** because libcurl exposes no DER-certificate pin;
the generator emits the same rung's key in `C2_HOST_PUBKEY_PINS`
(`PHANTOM_C2_PUBKEY_PINS` / `c2.pubkey_pins`) so all three transports
authenticate the same peer.
