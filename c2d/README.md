# c2d — Phantom C2 data plane (Go)

A single static binary that speaks the **same wire protocol** as the Python
listener in `phantom/core/c2_server.py`. An unmodified C++ beacon cannot tell
which backend answered: both use the same HMAC canonical string, the same
AES-256-GCM envelope, the same routes and the same `data/` state.

## Why

The Python listener is correct but expensive to keep in the field: it needs a
`venv`, `aiohttp`, `cryptography` and the system OpenSSL — four moving parts
that drift between the operator's machines. `c2d` replaces **only the
beacon-facing data plane** with a binary whose dependency set is the Go
standard library: no interpreter, no third-party module, no OpenSSL, no
`pip`, no server banner (`aiohttp` advertises its version in `Server:`).

The language gives *deploy* and *attack surface*, not extra cryptography —
confidentiality and peer authentication are already carried by mTLS, the
pinned fingerprint and per-request HMAC.

## Scope

**Implemented (data plane):**

- `GET/POST /api/v1/ping` — check-in, telemetry intake, task lease
- `POST /api/v1/result` — encrypted result intake (idempotent per `task_id`)
- the **malleable catch-all** — content-routed, so rotated / random-cased
  beacon URIs are not 404'd
- operator REST: `GET /api/v1/beacons`, `POST /api/v1/queue`,
  `GET /api/v1/results` (mTLS + `X-Api-Token`)
- payload delivery (`/api/v1/payload*`, `/api/v1/remote_payload_*`)
- mTLS with a TLS 1.2 floor and AEAD-only suites, the same plaintext refusal
  on a non-loopback bind

**NOT ported (stays Python):**

- the shell, the automation agent/planner, the brain/experience memory
- the **capability/grant task policy** — `POST /api/v1/queue` here is guarded
  only by the operator token and mTLS. Do **not** expose that endpoint beyond
  the operator network until the policy is ported.
- artifact retention/TTL, the audit-log hashing implementation
- `/x` (PIC stager) and `/s/android` — they answer `501`, deliberately, rather
  than 404-ing silently

## Build and run

```bash
cd c2d
go build -o c2d .          # c2d.exe on Windows
./c2d                      # reads ../data (or $PHANTOM_DATA_DIR)
```

Enable it:

```bash
# phantom shell
config set c2.transport_backend go
```

With `go` selected, auto-mode **stops starting the Python listener** (two
servers on one port fight for the bind); `doctor` reports the backend and
warns if the binary is not built.

## Configuration

Read from the SAME files as Python — one source of truth:

| Source | Keys |
|---|---|
| `data/config.json` | `c2.bind`, `c2.port`, `c2.ssl`, `c2.mtls`, `c2.mtls_require_client_cert`, `c2.allow_plaintext` |
| `data/phantom_state.json` | `PHANTOM_C2_KEY` (AES key material), `PHANTOM_API_TOKEN`, `PHANTOM_PAYLOAD_TOKEN` |
| `data/beacons/beacon_registry.json` | per-beacon HMAC secrets (`status`, `secret`, `previous_secret`) |
| environment | `PHANTOM_DATA_DIR`, `PHANTOM_C2_BIND`, `PHANTOM_C2_PORT`, `PHANTOM_C2_SSL`, `PHANTOM_MTLS_REQUIRE_CLIENT_CERT`, `PHANTOM_ALLOW_PLAINTEXT`, `PHANTOM_BEACON_REGISTRY`, `PHANTOM_STATE_FILE`, `PHANTOM_BEACON_AUTH_REQUIRED` |

## Parity guarantees

Pinned by tests so a drift cannot ship silently:

- **AES key derivation** is a port of `c2_crypto._derive_to_length`, checked
  against vectors produced by the Python function.
- **The HMAC canonical string** (`METHOD\nPATH\nTIMESTAMP\nCOUNTER\nNONCE\nBODY`)
  is checked against Python-computed signatures.
- **The envelope** is `base64(nonce‖ciphertext‖tag)`, AES-256-GCM, random
  12-byte nonce, no AAD — the exact bytes `crypto::encrypt` in the beacon and
  `encrypt_data` in Python produce.
- **Anti-replay** keeps a bounded, epoch-bound nonce set (a restart must not
  reopen an old window); the counter is a high-water mark only, because a
  restarted beacon legitimately resets it.

## Tests

```bash
cd c2d && go test ./...
```

Unit tests (parity vectors, envelope, replay) plus an end-to-end harness over
`httptest` that signs a real request, leases a task, returns a result and
exercises the catch-all routing rules.
