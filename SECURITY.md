# Security Policy

Phantom is offensive security tooling. It is built for professional red teams
operating **under written authorization** — engagements, purple-team exercises,
and isolated labs. That context changes what "a vulnerability" means here, so
read the scope below before reporting.

## Supported versions

| Version | Supported |
| --- | --- |
| `main` (released) | :white_check_mark: |
| `dev` (integration, what PRs land on) | :white_check_mark: — fixes land here first |
| anything older | :x: |

## What counts as a vulnerability here

Report these. They are real defects, not features.

- **Beacon → C2 authentication or cryptographic failure.** A captured or replayed
  check-in that is accepted; a beacon that can act without its per-beacon HMAC
  identity; a break in the envelope crypto (AES-256-GCM) or the key derivation.
- **Local API compromise.** Anything that lets a process *other than the
  Electron main process* read targets, credentials, or C2 state from the
  localhost API; a token comparison that is not constant-time; an endpoint
  reachable without the bearer token.
- **Secret leakage into an artifact an operator hands to a third party.** The
  deployment payload token or the C2 key/nonce appearing in a built beacon; a
  credential, key, or token reaching the *client* report; a secret written to
  a world-readable file on the operator's box.
- **Renderer escape / IPC abuse.** A path from the renderer through the
  `preload` bridge or the endpoint allowlist to something the allowlist was
  meant to block.
- **Injection into a report or the audit log.** Target-derived data turning into
  HTML/JS in a generated report, or a control name silently redacted out of an
  audit record.
- **Scope / guardrail bypass that leaves no trace.** Any way to run outside the
  declared engagement scope, or to disable a safety control *without* it being
  recorded in the guardrail manifest and the hash-chained audit log.
- **Path traversal** in artifact writing or `.pm` bundle import.
- **Supply-chain defects**: an unpinned dependency the build actually trusts, or
  a CI step that could be made to publish something it should not.

## What is NOT a vulnerability

Do not report these; they are the point of the tool.

- "This tool can execute commands / establish persistence / dump credentials on
  a target." That is what a C2 framework is for. If you can do it to a host
  **without** valid scope and authorization, that is a misconfiguration of your
  engagement, not a bug in Phantom.
- "I compiled the beacon and my AV flagged it." Expected. Detection engineering
  is part of the exercise.
- "The README explains how to do offensive things." Intended audience.
- A finding that requires the operator to have already disabled a guardrail
  (unscoped mode, no API token, unauthenticated beacons) **and** that the
  disabling was surfaced in the manifest and audit log. See the trace rule above.
- Vulnerabilities in third-party software Phantom invokes (`nmap`, `hydra`,
  `smbclient`, …). Report those upstream.

## Reporting a vulnerability

Open a **private security advisory**:

<https://github.com/Terminalkid09/Phantom/security/advisories/new>

Do **not** open a public issue for a security problem.

Please include:

- the subsystem (`phantom/core`, `phantom/api`, `phantom/automation`,
  `phantom/payloads/beacon`, `phantom/payloads/remote`, `c2d`, `electron`,
  `scripts`, …), files and line numbers where you can;
- a minimal reproduction (a command, a script, or a test that fails);
- the impact in operator terms — what an attacker gains, and what the operator
  loses in front of a client;
- the version/commit you tested.

## What happens next

- **Acknowledgement within 3 working days.**
- Triage and a severity call within 10 working days, with a provisional fix
  window. Fixes land on `dev` first, then `main`.
- **Coordinated disclosure:** we aim to ship and disclose within 90 days. We will
  tell you before we publish, and we will credit you unless you ask us not to.
- We will not pursue legal action for good-faith research that stays within your
  own systems and does not touch data you do not own. Do not test against
  infrastructure you are not authorized to touch — that is out of scope for safe
  harbor regardless of what this repository contains.

## Hardening the operator's own machine

Phantom generates its C2 key, payload token, API token, TLS material and beacon
secrets on first use, stores them in `data/phantom_state.json` (`0600`,
gitignored), and keeps the API token out of the renderer. If your deployment
differs — a shared `.env`, a token in the process table, a world-readable
`data/` — fix that first; it is the most common way an engagement leaks. Run
`guardrails` in either shell to see exactly which controls are on and which you
have overridden.
