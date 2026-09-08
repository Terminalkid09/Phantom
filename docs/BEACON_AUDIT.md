# Beacon / C2 audit

**Audit date:** 2026-08-21 — updated 2026-08-22 (secure-by-default)
**Scope:** C++ beacon transport and dispatcher, Python C2 state/HTTP handlers, payload delivery, operator state, Docker secret handling, and media capability reporting.

## Fixed findings

| Area | Finding | Resolution |
| --- | --- | --- |
| Task delivery | Tasks were removed when a check-in response was created. A lost response lost the task. | Tasks are leased for a bounded interval and removed only when a result acknowledges the task. Expired leases are redelivered. |
| Result handling | A lost result response could cause duplicate stored results. | Results are idempotent by `(beacon_id, task_id)`, with bounded per-beacon retention. |
| Result validation | Unregistered beacon IDs and oversized/non-string results were accepted. | Results require a registered beacon, a valid task ID, a string output, and a 10 MiB limit. |
| PIC delivery | `/x` did not require the payload token. | `/x` and `/s/android` require token (auto-generated at first run). |
| Beacon buffering | A failed result upload overwrote a later failed result in the single pending slot. | The beacon retains an ordered pending-result queue and removes entries only after transport success. |
| POSIX transport | Connect/read/write operations had no bounded timeout and could block the beacon indefinitely. | POSIX sockets now use bounded connect, I/O, and response-buffer limits. |
| Container secrets | Docker build args were copied into image environment metadata. | C2 secrets are runtime-only and are not passed as build arguments. |
| Beacon identity | A global AES key plus self-reported ID allowed beacon impersonation. | New builds enroll a per-beacon HMAC identity with replay checks, rotation, grace expiry, revocation, and protected key-state persistence. |
| mTLS transport | TLS had no common client-certificate or pinning policy across native transports. | mTLS CA/server/client material is generated per deployment; WinHTTP, OpenSSL, and libcurl use platform-native client authentication and server trust material. |
| Operator config | Env vars were required for every C2 secret (key, tokens, auth flags). | All C2 secrets are auto-generated on first run and persisted in `data/phantom_state.json` (gitignored, `0600`). Env vars remain available as overrides. |
| Secure defaults | Beacon auth, mTLS, and API token were opt-in via env vars. | All three are **ON by default**. mTLS uses `CERT_OPTIONAL` so payload-stagers still work; enforcement is at the application middleware layer. |

## Remaining risks

These are not silently treated as fixed:

1. **Beacon authentication has two layers.** mTLS authenticates the deployment and the per-beacon HMAC rejects impersonation/replay at the application layer. An attacker who extracts both the private client material and HMAC secret can still impersonate that beacon; revoke it and rotate/re-enroll rather than trusting the compromised channel.
2. **Protect the CA and registry.** The mTLS CA private key, registry, and generated client material are deployment secrets. Losing the CA requires re-enrolling all clients; losing a client key requires revoking that beacon.
3. **Media commands are platform-dependent.** Windows camera currently reports device availability rather than returning a captured image. Audio and screen recording require validated external tools and permissions. Linux/Android device access is not guaranteed by Docker.
4. **The real deployment tests are not safe CI tests.** They can compile, execute, persist, inject, capture media, and touch host state; they must remain opt-in lab tests and must not be included in the default test command.
5. **No evasion assurance is claimed.** String obfuscation, jitter, or in-memory loading do not establish Defender/EDR bypass and were not expanded in this audit.

## Verification

- **97 tests passed** (TLS, auth, state store, C2, manual-core, enterprise).
- Beacon auth + mTLS + state-store unit coverage: **green**.
- `py_compile` on all touched core/module/utility files: **green**.
- `g++ -fsyntax-only` with auth/mTLS feature flags: **green**.
- Combined suite (state + TLS + auth + C2 + manual + enterprise): **97 passed, 0 failures**.