# Threat model

This document is about **Phantom protecting the operator and the engagement** —
not about what Phantom does to a target. It names what we defend, from whom,
under which assumptions, and — honestly — what we do not defend at all.

## 1. Assets

| Asset | Why it matters |
| --- | --- |
| C2 key + nonce (`PHANTOM_C2_KEY`, `PHANTOM_C2_NONCE`) | Encrypts/decrypts beacon config and traffic. Leaks → every beacon is readable/forgeable. |
| Deployment payload token | Gates payload delivery. Leaks into a built beacon → one captured beacon unlocks every payload. |
| Per-beacon HMAC secrets | The identity of a beacon. Missing/leaked → anyone can impersonate a beacon. |
| API bearer token | Gates the local HTTP API. Leaks to a process/browser → targets, credentials, C2 control. |
| `data/phantom_state.json` | Holds all of the above. |
| Engagement data | Targets, credentials, loot, reports. This is the client's confidential material. |
| Client-facing report | Must be sanitized (no creds/commands) and must not lie about scope/protection. |
| The operator's workstation | If it is compromised, nothing below helps. |

## 2. Adversaries

- **A third party on the target network** — sees beacon traffic; may replay,
  forge, or MITM it.
- **Another local process on the operator's box** — tries to read the local
  API or the state file.
- **A hostile page / dependency in the renderer** — tries to reach the backend
  through the Electron IPC bridge.
- **A target-derived string** — a banner, hostname, or note that tries to turn
  into markup in a report or the audit log.
- **A curious or careless operator** — carries a stale override into an
  engagement, or hands a client a report that omits an override.
- **Not modelled:** a nation-state adversary on the operator's workstation, a
  malicious *maintainer*, or a physically compromised machine.

## 3. Trust boundaries

```
 target network                     operator workstation
 ┌──────────────┐   untrusted      ┌───────────────────────────────────────┐
 │   beacon     │◄────────────────►│  C2 listener  +  local HTTP API        │
 └──────────────┘   mTLS + HMAC    │        ▲                              │
                                   │        │ bearer token (main process)  │
                                   │  ┌─────┴──────┐   IPC allowlist         │
                                   │  │ Electron   │◄──────────────┐        │
                                   │  │ main       │               │        │
                                   │  └─────┬──────┘   preload bridge only  │
                                   │        │ renderer (Vite / file://)      │
                                   │  data/phantom_state.json (0600)        │
                                   └───────────────────────────────────────┘
```

Boundaries that are enforced, not assumed:

1. **target ↔ C2** — mTLS (`PHANTOM_MTLS_REQUIRED`, never downgrades to
   plaintext) plus a per-beacon HMAC identity (`phantom/utils/beacon_auth.py`)
   with replay protection (nonce epochs) and a monotonic counter.
2. **renderer ↔ backend** — the bearer token lives in the **main** process and
   never reaches the renderer; every IPC `api-request` is checked against
   `electron/electron/endpoint_allowlist.ts` before it is forwarded.
3. **operator ↔ scope** — `phantom/core/scope.py::is_in_scope` fails closed
   when no scope is declared; the lab escape hatch
   (`PHANTOM_ALLOW_UNSCOPED`) is reported in the guardrail manifest.
4. **Phantom ↔ deliverable** — reports escape target-derived strings
   (`html.escape`) and the client report never carries credentials.

## 4. Assumptions

- The operator's workstation and its user account are trusted and not already
  compromised.
- The engagement scope declared in `scope` is correct and the operator is
  authorized for it. Phantom enforces the scope you declare; it cannot know
  whether the declaration is truthful.
- TLS material and secret files are on a filesystem the operator controls.
- The operator reads the guardrail manifest. Phantom makes an override
  *visible and recorded*; it does not prevent an authorized operator from
  choosing it.

## 5. Threats and mitigations

| Threat | Mitigation (where) |
| --- | --- |
| Beacon traffic intercepted / replayed | AES-256-GCM envelope + per-beacon HMAC + nonce epochs (`phantom/core/c2_server.py`, `phantom/utils/beacon_auth.py`). |
| Unauthenticated beacon check-in | `PHANTOM_BEACON_AUTH_REQUIRED` (default on); surfaced as the `beacon_auth` guardrail. |
| Plaintext / unpinned C2 transport | `PHANTOM_MTLS_REQUIRED`; the listener refuses to start rather than downgrade. |
| Local API read by another process | Bearer token required on every route, constant-time comparison (`hmac.compare_digest`), CORS limited to the local renderer origins. |
| Renderer reaches a destructive route | Endpoint allowlist in the main process; unknown endpoints refused. |
| Secret leaks into a built beacon | `scripts/ci_beacon_token_scan.py` runs in CI against the built binary. |
| Deployment token / creds in a *client* report | Client report is a separate sanitized generator; credentials never cross into it (tests in `tests/test_automation_reporting.py`). |
| Target data becomes markup in a report | Escaping at serialization; covered by `tests/test_security_hardening.py::TestHtmlInjection`. |
| An override runs an engagement with less protection, invisibly | Guardrail manifest (`phantom/utils/guardrails.py`) rendered at launch, embedded in every report, and appended to the hash-chained audit log. |
| Silent tampering with the record | `phantom/utils/audit_log.py` is append-only and hash-chained; `verify()` detects any edit. |
| A discovered driver the planner should not load | Driver approval gate (`phantom/automation/runtime/capability_registry.py`), surfaced as the `driver_approval` guardrail. |
| A CI regression that weakens a security invariant | `security-sweep` job + `bandit` with an explicit `.bandit` baseline (unbaselined HIGH fails the job). |

## 6. What this model does NOT protect

- **A compromised operator workstation.** Malware with the operator's rights can
  read `data/phantom_state.json`, attach to the C2, and rewrite reports. Nothing
  in Phantom detects that.
- **A malicious or careless scope declaration.** Phantom checks targets against
  the scope you give it; it cannot verify authorization.
- **Detection by the target's defenders.** OPSEC and evasion are best-effort and
  target-dependent; this is not a guarantee of invisibility.
- **A leaked secret is not revocable retroactively.** Rotate the C2 key/nonce /
  payload token if you suspect exposure; already-built beacons will stop
  working.
- **Third-party tools.** `nmap`, `hydra`, `smbclient`, WSL/Kali, the LLM
  backend — their security is theirs.
- **The remote LLM advisor path.** It redacts IPs/hosts/domains/users/paths/
  secrets before sending, but the local (GGUF) backend is the only path where
  *nothing* leaves the machine. If an engagement forbids egress, use the local
  path.
