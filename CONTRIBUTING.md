# Contributing to Phantom

Thanks for helping. Phantom is a professional red-team framework: the bar for a
change is not "it works on my box", it is "an operator can rely on it in front
of a client". Read [SECURITY.md](SECURITY.md) first — it defines what counts as
a vulnerability here.

## Ground rules

1. **Authorized use only.** Do not use issues, PRs, or discussions to ask for
   help attacking a system you do not own. Issues asking for that are closed.
2. **Never weaken a safety control silently.** Scope gate, beacon HMAC, mTLS,
   API auth, driver approval, and the guardrail manifest are load-bearing. If
   your change lets a run bypass one, it must also *record* the bypass in the
   manifest and the audit log. An override that leaves no trace is a bug, not a
   feature.
3. **No secrets, and no engagement data, in the repo.** No keys, tokens,
   certificates, `data/` contents, `.env` files — and no artefact a session
   produced: a report, a capture, a beacon binary, a wordlist, a HID vector —
   not in a commit, a fixture, a test, or a screenshot. Phantom is meant to be
   run **from inside the operator's working copy**, so `git add -A` after an
   engagement is the single most dangerous command in this repository: it
   stages the customer's targets, credentials and loot next to the source and
   a push publishes them. That is why `.gitignore` ignores runtime output by
   **whole directory** rather than by extension — a new artefact type must not
   be able to leak because nobody listed its suffix — and why the committed
   `data/` templates (the `.sample`, the `.gitkeep`s) are excluded explicitly.
   If you add a feature that writes anything under `data/`, or anywhere else,
   cover the path in `.gitignore` in the same PR, and check with
   `git status` on a tree you have actually used.
4. **A test that cannot fail is not a test.** Assertions must fail on the
   broken code. If you fix a bug, add a test that fails before the fix.
5. **Keep the diff to the request.** Fix the cause, not the symptom; do not
   reformat unrelated code.
6. **Match the local style.** Files in this repo use CRLF line endings in
   several places — configure your editor to preserve them, and avoid
   whole-file rewrites of CRLF files.

## Development setup

Requires **Python 3.10+**.

```bash
git clone https://github.com/Terminalkid09/Phantom.git
cd Phantom
python -m venv .venv && . .venv/Scripts/activate    # Windows: .venv\Scripts\activate
pip install -e .                                    # runtime deps come from setup.py
pip install -r requirements-dev.txt                 # pytest, plugins, pyyaml, bandit
```

Electron desktop app (Node 20+):

```bash
cd electron
npm install
npm run dev        # Vite dev server
npx tsc --noEmit   # typecheck only — what CI runs
npx vite build     # production build — what CI runs
```

### Beacon / remote payload toolchain

The C++20 payloads build with `g++` or `clang++` on Linux/macOS and
MinGW-w64 (`x86_64-w64-mingw32-g++`) on Windows. The build headers are
**generated** — never hand-write or commit them:

```bash
python scripts/ci_beacon_prepare.py --dir phantom/payloads/beacon --ci-identity
python scripts/ci_beacon_prepare.py --dir phantom/payloads/remote --ci-identity
```

A fast check (the same shape CI runs) is enough for most changes. Note `-c`
rather than `-fsyntax-only`: g++ only reports an unused static function when it
really compiles, so a parse-only check quietly accepts a helper that clang —
the macOS leg of `beacon-syntax` — rejects.

```bash
x86_64-w64-mingw32-g++ -std=c++20 -c \
  -Wall -Wextra -Werror -Wno-unknown-pragmas \
  -Wno-missing-field-initializers -Wno-cast-function-type \
  -Iphantom/payloads/beacon/src phantom/payloads/beacon/src/main.cpp \
  -o /dev/null
```

## Running the tests

The suite is deliberately split. Pick the layer your change touches; CI runs
all of them.

**Unit-hermetic (the required gate — no external binaries, no network):**

```bash
python -m pytest tests -q -m "not integration_tool"
```

**Integration-tool (needs `nmap`; non-blocking, may fail for environment
reasons):**

```bash
python -m pytest tests -m "integration_tool" -v
```

**Security sweep (invariants that must never regress):**

```bash
python -m pytest tests/test_security_sweep_round2.py tests/test_p0_phase2.py \
  tests/test_c2_token_rotation.py tests/test_remote_viewer.py \
  tests/test_config_secret_perms.py tests/test_security_hardening.py \
  tests/test_electron_allowlist_sync.py tests/test_endpoint_allowlist_drift.py -v
```

Plus, before opening a PR that touches the relevant area:

```bash
python scripts/ci_beacon_lint.py       # beacon source hygiene
python scripts/ci_beacon_smoke.py --platform linux --require   # real build path
python scripts/c2d_parity_check.py     # Python <-> Go key derivation
bandit -r phantom/ -c .bandit          # no unbaselined HIGH findings
```

The full hermetic suite is large (~4 500 tests) and takes roughly 15–20
minutes serially. `pytest-xdist` is available (`-n auto`) but serial is the
default on purpose: several modules hold process-wide singletons.

## Branches and commits

- `dev` is the integration branch — **open PRs against `dev`**, not `main`.
- `main` is a released state. Only release merges land there.
- Use [Conventional Commits](https://www.conventionalcommits.org/):

  ```
  feat(c2): rotate the beacon nonce epoch on reconnect
  fix(report): the API report lost its guardrail section
  chore(ci): deselect tool-dependent tests from the hermetic job
  docs(readme): correct the bare-metal install steps
  ```

  The subject says *why*, not *what the diff says*. Scope is the subsystem
  (`c2`, `beacon`, `api`, `shell`, `report`, `electron`, `ci`, …).

## Pull request checklist

- [ ] The change is scoped to one thing and explained in the description.
- [ ] `python -m pytest tests -q -m "not integration_tool"` is green.
- [ ] New behavior has a test that fails without the change.
- [ ] Any guardrail override introduced is either blocked or recorded.
- [ ] No secrets, no generated build headers, no build artefacts committed.
- [ ] CRLF line endings preserved in files that already use them.
- [ ] Beacon changes pass `-fsyntax-only` (and `ci_beacon_lint.py` where relevant).
