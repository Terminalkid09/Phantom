# `c2d` — the Go data plane (contributor page)

`c2d/` is a second implementation of the **beacon-facing** C2 data plane: one
static Go binary that speaks the same wire protocol as
`phantom/core/c2_server.py`. An unmodified C++ beacon cannot tell which backend
answered — same HMAC canonical string, same AES-256-GCM envelope, same routes,
same `data/` state.

The authoritative, kept-current description lives next to the code:
[`../c2d/README.md`](../c2d/README.md) (scope, build, configuration, parity
guarantees, tests). **Read that one first**; this page exists so the docs index
has an entry point and so the honesty boundary is stated in one place.

## Why it exists

The Python listener is correct but expensive to keep in the field: `venv`,
`aiohttp`, `cryptography`, the system OpenSSL — four moving parts that drift
between machines. `c2d` replaces only the beacon-facing data plane with a binary
whose dependency set is the Go standard library. The language buys *deploy* and
*attack surface* (no server banner), not extra cryptography: confidentiality and
peer authentication are already carried by mTLS, the pinned fingerprint and the
per-request HMAC.

## What is ported, and what is not

Ported: `ping`/task lease, encrypted result intake (idempotent per `task_id`),
the malleable catch-all, the operator REST surface, payload delivery, mTLS with
a TLS 1.2 floor and the plaintext refusal on a non-loopback bind, **the
capability/grant task policy**, **result retention and task TTL**, the
**hash-chained audit trail**, and `/x` (PIC stager).

Not ported, and advertised as such: `/s/android` (it needs the Python dropper
generator). The route answers **`501`** with a machine-readable body
(`handled_by: python-control-plane`) instead of 404-ing silently, and
`GET /api/v1/capabilities` reports the truth:

```json
{ "task_policy": true, "/x": true, "stager_android": false }
```

`phantom doctor` prints that boundary for a `transport_backend=go` run, so the
limit is discovered before an engagement rather than mid-run.

## Running it

```bash
cd c2d && go build -o c2d .    # c2d.exe on Windows
./c2d                          # reads ../data, or $PHANTOM_DATA_DIR
```

```bash
# phantom shell
config set c2.transport_backend go
```

With `go` selected, auto-mode **stops starting the Python listener**: two
servers on one port would fight for the bind and the beacons would see random
failures. `doctor` reports the chosen backend and warns when the binary is not
built (`cd c2d && go build -o c2d .`). Configuration is read from the SAME files
as Python (`data/config.json`, `data/phantom_state.json`,
`data/beacons/beacon_registry.json`, plus the documented environment
overrides) — one source of truth, not a second one to keep in step.

## Why you can trust the parity

Drift between two implementations of one protocol is the failure mode this
subsystem invites, so it is pinned from both sides:

* `scripts/c2d_parity_check.py` compares the Go constants and the policy
  decision table with Python's, and re-checks the vector files;
* `c2d/policy_vectors.json` and `c2d/audit_vectors.json` hold cases and hashes
  **produced by the Python implementation**, asserted by `go test ./...` and
  re-verified by the parity script;
* `go test ./...` covers the envelope, replay window, routing rules and an
  end-to-end check-in → lease → result flow over `httptest`;
* `tests/test_c2d_policy_parity.py` keeps the Python side honest about the same
  vectors, and `tests/test_beacon_verb_contract.py` pins the verb list against
  the Python policy *and* the beacon's dispatcher.
