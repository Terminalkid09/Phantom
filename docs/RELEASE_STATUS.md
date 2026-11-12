# Release status — `dev` (v3.0.0 line)

Snapshot: **2026-11-12**, branch `dev`. This is the single current statement of
what has been PROVEN. A green claim is repeated here only with the evidence
that produced it; anything else is named as unverified.

## Verification levels

| Level | Meaning |
| --- | --- |
| **Compiled** | A real artifact was produced for that platform; it has not been run. |
| **Lab** | Executed against the local lab (Docker: attacker `172.28.0.99`, target `172.28.0.10`). |
| **Endpoint** | Executed on a real, operator-owned machine. |
| **Reported** | Operator ran it outside the repository; the result is recorded here but no log is attached. |

## Verified today

| Area | Level | Evidence |
| --- | --- | --- |
| Python suite | Lab | Full suite on 2026-11-12: **6595 passed, 5 skipped, 115 subtests, 508.91 s** on the Windows lab (8 workers, same test selection as CI). The 5 skips are platform/toolchain-only cases. CI on Linux reports **6564 passed, 36 skipped** per interpreter, because Electron/node_modules and native tools are absent there. |
| CI `dev` | CI | Run [`43265195253`](https://github.com/Terminalkid09/Phantom/actions/runs/43265195253) at `decd7cf`: **success, 21/21 jobs** — Python 3.10/3.11/3.12, Electron build, C2, beacon smoke Windows/Linux/macOS/Android, security, Docker, integration-tools and c2d. The preceding run `43257501577` was red on a test-isolation defect (below); the fix is test-only (`0ed35b0`). One non-blocking annotation remains: pinned actions still target Node 20. |
| Auto-mode kill chain (Linux) | Lab | 2026-11-12: HTTPS/mTLS C2, real beacon check-in **`B-975383D9360DB20A`**, **`beacon=True persistence=True creds=2 actions=4`**, goal `deliver` reached in **41 s**. |
| Persistence (Linux) | Lab | The same run records `persistence_installed=True`. The beacon's native `persist` verb had already succeeded on this host; the defect was in auto-mode's separate shell path (below). |
| CLI | Lab (real PTY) | **17/17** checks: `set target`, `suggest`, real `nmap` run, quiet scan, `auto`, refusal of `run` in AUTO-MODE, Ctrl+C auto→manual, final Ctrl+C. |
| Electron desktop | Lab | `tsc --noEmit` exit 0; Playwright **1 passed (57.5 s)** across all 25 panels, with a safe action and visible busy feedback. |
| Windows beacon | Endpoint + CI | CI compiles a real PE through the release path on `windows-latest`. Live check-in on a Windows 11 host is recorded in `CHANGELOG.md` (2026-11-03); the operator re-confirmed Defender/McAfee field tests on 10–11 Nov (**Reported**). |
| McAfee / Defender | Reported | No detection on the builds and environments the operator tested. This is evidence for those environments, **not** a general immunity claim. |
| macOS / Android | Compiled | CI produces the artifact and verifies its container/architecture. Runtime is not exercised. |
| Phishing | Lab (local half) | Everything up to the send works; an end-to-end send has never been exercised. See [`PHISHING_STATUS.md`](PHISHING_STATUS.md). |
| Auto-mode benchmark | Lab (offline) | Ground-truth scenarios with a simulated runner; it does not prove effectiveness on a real target. See [`AutoModeBenchmark.md`](AutoModeBenchmark.md). |

## The red CI was a test leak (fixed 2026-11-12)

Run `43257501577` failed on all three Python legs, but the failures were one
defect: the autouse fixture in `tests/test_executor.py` patched global
`shutil.which` to return `/usr/bin/tool`. A second `monkeypatch` in the same
module was restored after the fixture, so the fake path survived into later
files. Those files then tried to execute it, or believed `nmap` was installed,
and failed only in the full run.

The fixture now replaces only the executor's view of `shutil`, and the test
that actually launches external binaries is marked `integration_tool` (it runs
in the job that installs `nmap`). The full suite is green locally, and run
`43265195253` is green across all 21 jobs. This was a test defect, not a
regression in the product.

## The persistence defect (fixed 2026-11-12)

Auto-mode was **not skipping** `persistence_install`: the step ran and the
beacon answered

```
sh: 1: Syntax error: Unterminated quoted string
```

The Linux builder ships a systemd unit with real newlines inside single quotes.
The beacon's `shell` / `exec` / `run` dispatcher read its argument with
`std::getline`, which stops at the first newline, so the target's `sh -c`
received an unterminated quote. The dispatcher now takes the whole argument
(`command_line.h`), pinned by a compile-and-run test
(`tests/test_beacon_command_line.py`). The re-run above is the end-to-end proof.

## Remaining release gates

1. **Code signing is absent.** Windows SmartScreen shows an unknown-publisher
   warning; this limitation is stated in the root README next to the installers.
2. **Clean-machine installer smoke is not automated.** `install/install.ps1`
   now validates the extracted archive *before* replacing an existing install,
   so a truncated download can no longer leave the operator with neither
   version. No CI job installs and launches the packaged app on a clean VM for
   each OS.
3. **Cross-compilation is implemented but not exercised both ways in CI.**
   Windows→Linux (Kali WSL) and Linux→Windows (MinGW) exist in the builder; CI
   builds each OS on its own runner instead of testing both cross directions.
4. **macOS and Android runtime** are compiled, not exercised.
5. **No `v3.0.0` tag exists** (tags in this repository: `v1.0.0`, `v1.1.0`,
   `v2.0.0`). The `3.0.0` section in `CHANGELOG.md` is the release note for
   this line, not evidence of a published tag.

## Verdict

The code is ready for a **v3.0.0 tag as a controlled release**: CI is green
across all 21 jobs, the kill chain is green end-to-end, the full suite is
green, and the desktop and CLI paths have been exercised. The remaining items
are distribution evidence, not code failures. Until a clean-machine install
smoke and an explicit signing/SmartScreen decision are recorded, describe the
release as *verified in the lab and on the operator's Windows endpoint*, not as
*installer-verified on a clean machine of every OS*. `main` has not been
merged or tagged as part of this verification.
