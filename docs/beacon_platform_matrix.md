# Beacon platform matrix

The beacon builds and runs on **Windows, Linux, macOS and Android** (`beacon-smoke`
jobs in CI compile a real artefact for each). Building is not the same as feature
parity, so this page is the contract: what is implemented on every OS, and what is
deliberately Windows-only.

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

## Deliberately Windows-only (accepted, no POSIX analogue)

These are NT-specific mechanisms and are **accepted as Windows-only**: on POSIX
the concept either does not exist, has no safe equivalent, or has a different
name — documented rather than stubbed. The test
`tests/test_beacon_posix_parity.py` pins this list so a new header either ships
a POSIX path or is added here on purpose.

- `stack_spoof.h` — call-stack spoofing against unwinder-based EDR. POSIX
  unwinding models differ; no equivalent is shipped.
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
