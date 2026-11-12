# Action plan — 2026-10-31

> **HISTORICAL — closed 2026-11-12. Do not read this as current state.**
> This is the plan as written on 31 Oct 2026. Its open items were superseded
> by measurements on 8–12 Nov 2026 (the full Python suite, the CLI in a real
> PTY, the Electron E2E run, the lab kill chain, and the Windows endpoint
> check-in recorded in `CHANGELOG.md`). It is kept for traceability only.
> Current status and evidence: [`RELEASE_STATUS.md`](RELEASE_STATUS.md).

Follows the previous plan (2026-10-29, now in git history and summarised in
[`../CHANGELOG.md`](../CHANGELOG.md)). This document
covers three things: what was closed today (measured, not promised), the three
questions about the HID vector with the direct answer and its limit, and what
is genuinely missing from the release, with an acceptance criterion per item.

---

## 0. Done today

| Item | Before | Now | Proof |
|---|---|---|---|
| Board selection | port mandatory, silent FQBN fallback (`arduino:avr:micro`) | `--flash auto` reads port **and** FQBN from `arduino-cli board list`; ambiguous = refused | real bench: COM3 + COM4 + Leonardo on COM7 → picks COM7 / `arduino:avr:leonardo` |
| Board after injection | stays a live keyboard, plugged in | `--eject`: `UDCON \|= (1 << DETACH)` (AVR), `usb_hid.disable()` (Pico) | **flashed to a real Leonardo**: `--flash auto` picked `COM7` / `arduino:avr:leonardo` by itself, and COM7 then disappeared from `board list` (COM3/COM4 stayed) |
| In-place reflash warning | "it types on THIS machine, unplug it NOW" even with the guards active | says which guard covers the upload; warns only when it really does type | test + reading the path |
| Cross-validation spread | only as a side script (`training.ranker --cv`) | `cv` block in the `training.eval` report, printed next to the score | `k=5 mean=0.9420 spread 0.0142` over 78 groups |

Checks run: **269** HID/flash tests green, **119** training/module tests green,
`compileall` clean, Arduino sketch actually compiled, detection tried against
the real `arduino-cli`, and one artefact **flashed onto a Leonardo that then
ejected itself**.

---

## 1. The three HID questions

### 1.1 "Does it find the right board by itself and flash it correctly even if it is not a Leonardo?"

**Now it does, for the AVR family — and it stops where it cannot know.**

`arduino-cli board list --format json` reports port, `matching_boards` and
VID/PID together. From there: one board with an FQBN → it is used; two boards
*with an FQBN* → refused, with the list (never guess: the wrong FQBN compiles
and "half works", which is the worst case); 32u4 clones that report no
`matching_boards` → the `KNOWN_32U4_CLONES` table.

The limit, stated plainly: **CH552 and ESP32 are not "a different FQBN"**. They
are a different library (`DigiKeyboard` instead of `Keyboard.h`), so changing
the FQBN would produce a sketch that does not compile. Detection stops and says
so. Those boards need a real generator, not one more entry in a map.

### 1.2 "Can the Win+R dialog stay off screen, everything in the background?"

**No. Not to zero. And it is better to say so than to sell it.**

A HID injector sends scan codes to the window that has focus. On Windows there
is no key sequence that starts a process without a visible surface — Run, the
Win+X menu, search, the Explorer address bar, a terminal: they are all windows.
Anyone promising otherwise is selling a video.

What **is already true**: after Enter the dialog closes, `powershell -w h` has
no console, the script runs in memory and the process **exits**, leaving only
the beacon. The residue is one `powershell.exe` line in Task Manager for a few
seconds.

What **was a self-inflicted wound of ours**: the human cadence at 90 ms/character
on a 231-character command keeps the text visible for **~21 seconds**. That is
the price of anti-timing-detection, and it is an explicit trade-off:
`--cadence 0` → ~0.3 s. There is no "invisible"; there is "how long it stays on
screen".

### 1.3 "Can the delay be dropped and the stick ejected, like safe-eject?"

**Yes, and it is the best of the three.** `--eject` clears the D+ pull-up:

- **AVR**: `UDCON |= (1 << DETACH)`. The host sees a disconnect, the board stays
  powered and running, and nothing re-attaches it until a power cycle.
- **Pico**: `usb_hid.disable()`. The keyboard disappears, but **only a power
  cycle brings it back** (CircuitPython does not expose `tud_disconnect`) and
  the CIRCUITPY drive may stay visible. Written into the artefact.
- **DuckyScript** (Flipper/OMG): impossible — the script does not drive USB.

With this the countdown becomes **redundant, not "removed"**: the first boot
after a flash is already silent, and with `--eject` the board *disappears*
instead of waiting 15 s. The cycle becomes: flash → ejected (no keystrokes on
your machine) → carry it → plug it back in (power cycle, the EEPROM tag
matches) → injects → ejects again (no second injection, no live keyboard).

---

## 2. Phase B — bench verification (requires hardware)

Nothing in this phase can be verified without a physical board. Order:

| # | Step | Acceptance criterion |
|---|---|---|
| B1 | `payload hid leonardo --stager windows --type-into windows --run --flash auto --eject --countdown 0` | the upload lands on `arduino:avr:leonardo` **read from the board**, and the Leonardo disappears from Device Manager immediately after — **EXECUTED 2026-10-31, both halves passed** |
| B2 | Unplug and replug on a Windows 11 VM with Defender active | the board types on the first power-up on the target, and **not** on the machine that flashed it |
| B3 | Watch the Run dialog for the whole duration | count the seconds of visibility with `--cadence 90` and with `--cadence 0`, and record them |
| B4 | Beacon up / down at the moment of injection | the bounded loop retries and the beacon comes in within the budget even with a cold C2 |
| B5 | Pro Micro clone on the bench | `--flash auto` uses `arduino:avr:micro` from the VID/PID table, not from the default |

Today's verification, for honesty: **B1 was executed and passed; B2–B5 were
not.** The flash landed on `COM7` with the FQBN read off the board, and the
Leonardo then left `board list` on its own (`COM3`/`COM4` stayed) — which is
`usbEject()` working on real silicon, and the same boot typed nothing on this
machine. What is still unproven is the half that needs the target: whether it
types there, and whether the beacon then checks in (B2, B4).

---

## 3. Phase C — ML and auto-mode: what is genuinely missing

The ceiling is not in the code, it is in the data. Today's measurements:

```
holdout:  ndcg 0.9420  vs baseline 0.9021   Δ +0.0399   CI [+0.0150, +0.0662]
grouped 5-fold CV:  mean 0.9420  spread 0.0142  [0.9207, 0.9617]  over 78 groups
golden (3 targets):  k=3, spread not informative — and that is the point
production baseline: 31 rows, 0 scoreable, corpus coverage 0.0
```

The third line is now printed by `training.eval` next to the other two
(`production baseline: not measurable: the corpus and the production scorer
share no candidate id on any row`). It is the difference between a claim and a
number: the sentence used to live in a document nobody re-checks.

The number is stable and is not a lucky partition. But:

| # | Gap | What closes it | Criterion |
|---|---|---|---|
| C1 | **Measured, and the earlier diagnosis was wrong.** The corpus and the production scorer share no candidate vocabulary: rows carry capability ids (`scan_tcp`, `web_rce`, `beacon_deploy`), `score_for` scores the access candidates `collect_candidates` builds from a service list. Intersection on the golden set: **empty**. Adding `success`/`noise`/`complexity` to the rows would change nothing, because production never reads those ids | rows in the production vocabulary, ordered by a rubric, from real service sets | `baseline_production.rows_scoreable > 0` and the delta computed on those rows (today: **31 rows, 0 scoreable, coverage 0.0**) |
| C2 | 3 targets in the golden set | golden set from real runs, ≥10 targets | `k >= 5` on the golden set, spread reported |
| C3 | Adapters not promoted, LLM inert | depends on C1/C2, not on other code | an adapter promoted by the statistical gate, not on a tie |
| C4 | Reorder cap (±12 points / 2 positions) that cannot cross a 19-point gap | make the cap adaptive and measure it on the benchmark | the 10-scenario benchmark shows the reorder where it is needed, and not where it is not |

C4 is the only item in this phase that does not depend on the data: it is the
next sensible piece of work on auto-mode. `training.ranker --cv` and the `cv`
block in `training.eval` now measure the same thing in two places: unifying them
is a removal of duplication, not a feature.

---

## 4. Phase D — release v3.0.0

| # | Item | State | Criterion |
|---|---|---|---|
| D1 | **The Windows beacon runs on Win11 + Defender** | open — WinError 225 | a real check-in on a machine with Defender active. It is the bottleneck: without it the release does not impress a red teamer, whatever the UI does |
| D2 | Single version | **closed 2026-11-02** — `SettingsPanel` reads `useAppVersion`; `3.7.3` survives only in the changelog as a historical entry | one number, read from one place |
| D3 | Untracked files committed | **closed 2026-11-02** — the tree is clean apart from operator artefacts | `git status` clean apart from artefacts |
| D4 | CHANGELOG frozen + tag `v3.0.0` | open | tag on the freeze commit |
| D5 | Install smoke on a clean machine | open | `phantom --version` + one command per module |
| D6 | Code signing | absent — SmartScreen warns | at least one certificate, or the limitation written in the README |
| D7 | Android/macOS declared but not built today | partial | `scripts/beacon_matrix_verify.py` matrix green for every declared cell |

**Honest estimate.** A technically clean v3.0.0 (D2–D5): **3–5 days**. A
release that "impresses" (D1 + D6 + D7): **2–4 weeks**, and the piece that
weighs is the Windows loader, not the interface.

Electron/UI: 23 panels, `tsc --noEmit` exit 0, `electron-builder.yml` present,
8 test files (CLI↔Electron parity, endpoint allowlist, a11y, job-state). Dense
but coherent. CLI: 60 commands across 17 modules, `help` for each, safe
non-interactive stdin.

---

## 5. What was not done, and why

- **No verification on the target.** B1 is done (flashed, detected, ejected on
  real silicon); B2–B5 need a machine to type into, and the HP run is the
  operator's, not mine to fake. The board never typed here: the first-boot
  guard and `--eject` both fired.
- **No CH552/ESP32 variant.** It needs a generator with a different HID
  library, not an entry in the FQBN map.
- **No attempt to hide the Run dialog.** It cannot be hidden at the HID layer;
  the choice exposed is `--cadence`, and the cost is written down.
