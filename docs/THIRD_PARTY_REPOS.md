# Third-party repositories — licence policy, and the four reviewed upstreams

## The constraint

Phantom is **MIT** (`LICENSE`). A dependency is a link in every sense that
matters: whatever a manifest pulls in ships inside the operator's working copy
and inside every build produced from it, under Phantom's name. So the question
is never "does this tool work", it is "under what terms would we be
distributing it".

| Repository | Licence | Verdict | What we take |
| --- | --- | --- | --- |
| [`apache/caldera`](https://github.com/apache/caldera) | Apache-2.0 | `absorbable-technique-only` | the **technique** of `mitre/human`, re-implemented |
| [`RickdeJager/stegseek`](https://github.com/RickdeJager/stegseek) | GPL-2.0 | `external-process-only` | nothing — see below |
| [`Datalux/Osintgram`](https://github.com/Datalux/Osintgram) | GPL-3.0 | `external-process-only` | the **techniques**, re-implemented on `instagrapi` |
| [`kinghacker0/WhatsApp-OSINT`](https://github.com/kinghacker0/WhatsApp-OSINT) | no LICENSE file | `rejected` | nothing |

None of the four appears in `requirements.txt`, `requirements-dev.txt` or
`setup.py`, none is imported by `phantom/`, and none is vendored. That is not a
convention — it is enforced by
[`tests/test_third_party_repo_policy.py`](../tests/test_third_party_repo_policy.py).
Adding one of them in-process therefore fails a test that names this document,
which is the point at which a reviewer should be asking the licence question.

### apache/caldera — Apache-2.0 — `absorbable-technique-only`

The only one of the four that *could* be linked. We still do not, because what
is worth taking is behaviour, not code, and Apache-2.0 still imposes NOTICE
propagation on a project whose distribution story is "the operator's own
working copy".

**Checked, no lesson to learn: timing.** Caldera's "malleability" is
`sleep_min`/`sleep_max` in `c_agent.py`. Phantom already does more: a ±30 %
`jitter` on the sleep, a User-Agent pool rotated per request, decoy URI pools
and randomised URI casing (`phantom/payloads/beacon/src/malleable.h`,
`default_profile()`). There is nothing here to copy.

**What is actually worth taking: `mitre/human`.** The abilities
`browse_web`, `ms_paint`, `open_office_calc`, `open_office_writer`,
`download_files` and `google_search` are driven through WebDriver and make a
compromised machine look like a *person at work* rather than a process. That
is the most valuable feature of the four repositories, and it is a **behaviour
specification**, which is not copyrightable. Assessment below.

### RickdeJager/stegseek — GPL-2.0 — `external-process-only`

A steghide password cracker built for CTFs: it brute-forces a passphrase
against a stego carrier. Phantom does not recover stego'd files from a host
and has no such stage in any chain, so there is nothing to steal even if the
licence allowed it. **Decision: not implemented.** The reason is scope, not
the licence — the licence only makes the scope question easier to answer.

### Datalux/Osintgram — GPL-3.0 — `external-process-only`

28 Instagram commands (post geolocation on a map, posting-time heatmaps, mutual
connections, public follower contacts, ...). This is a genuine gap: Phantom has
`phantom/automation/social/` and `external_intel.py` for infrastructure
(Shodan, crt.sh, BGP) but no *person-side* public-profile analysis.

**The path is the technique on a library we may link.** `instagrapi` is a
separate project under its own licence and is the right primitive; the mapping
(which of the 28 commands we want, and what a synthetic fixture looks like) is
ours to re-derive. Nothing here may be translated from Osintgram's source.
**Status: proposed, not implemented.** Any addition of `instagrapi` to the
manifests is a *new* dependency decision and needs its own licence line in the
table above.

### kinghacker0/WhatsApp-OSINT — no LICENSE file — `rejected`

Three reasons, in order of severity:

1. **No licence at all.** GitHub's MIT *badge* is not a licence; with no
   `LICENSE` file the default is all-rights-reserved, so it is not open source
   and cannot be reused regardless of what the README claims.
2. **It is a menu over commercial RapidAPI endpoints.** Eight commits, one
   file. There is no technique in it to learn.
3. **It sends the target's phone number to a third-party commercial API.**
   That is an OPSEC failure and a permanent log outside the operator's
   control, independent of the licence — the number is the single most
   sensitive selector of a person-target engagement.

## `mitre/human` — cost assessment (assessed, NOT implemented)

Asked-for scope: `mouse_path` (Bézier, no teleports), `idle_windows` (switch
between applications), `work_loop` with a density parameter.

### Where it would live

Not in `malleable.h` as-is. That header is the **transport** profile (URI
paths, User-Agent pool, headers, `sleep_ms`, `jitter`, casing). The right shape
is a nested `human` sub-struct on `malleable::Profile` (so the profile stays
the single C2-controllable object and the existing
`malleable_build_profile()` path carries it) with `enabled = false`, plus a new
`phantom/payloads/beacon/src/human_emulation.h` for the behaviour.

### What already exists, and what does not

- **Input synthesis exists only in the remote module.**
  `phantom/payloads/remote/src/remote_session.h` has the primitive:
  `SetCursorPos` + `SendInput` (pointer, wheel, keys, shift handling). It is a
  **teleoperation** surface — an operator drives it — and it *teleports* the
  cursor, which is exactly what `mouse_path` must replace. The beacon itself
  synthesises no input today, so this is a new module, not a flag.
- **The beacon links `user32` already** (`-luser32` in
  `builder.compile_beacon`), so Windows needs no new link dependency.

### Costs

| Dimension | Assessment |
| --- | --- |
| Windows code | `SendInput` (have it) + `GetForegroundWindow` / `EnumWindows` / `SetForegroundWindow` (all `user32`, no new link dep). Bézier must be **fixed-point**: the payload is a PIC blob and pulling in `libm`/soft-float helpers for a cursor path is a bad trade. ~40 lines (cubic + ease-in-out velocity profile), a PRNG already exists in the beacon's evasion stack. |
| Profile data | A handful of `uint16_t`/`uint32_t` fields (density, dwell min/max, path samples, enabled) — tens of bytes. Irrelevant next to the beacon's existing footprint; it is *code*, not RAM, that grows. |
| POSIX | **The real portability cost.** A keyboard/mouse cannot be synthesised portably on the target's side: X11 needs XTest (`libXtst`, a NEW link dep) or `uinput` (root/`CAP_SYS_ADMIN` + `/dev/uinput`), and **neither works under Wayland**, which needs the compositor's own virtual-input protocol or a portal handshake with an interactive grant. Decision: **Windows first**, POSIX behind a named blocker. |
| Runtime noise | This is the loudest thing the beacon can ever do — synthetic foreground changes and synthetic input are trivially visible to the real user and to any EDR that watches input APIs. Therefore: **opt-in per profile, `enabled = false`, never a default**, and reachable at runtime through the malleable profile plus an explicit task command. |
| Safety | Two hard requirements, not niceties. (1) The loop must detect **real** user activity (`GetLastInputInfo` on Windows, XScreenSaver idle on X11) and stop immediately: synthetic input that fights the person using the machine is an instant giveaway and an actual conflict. (2) An exclusion list of windows it will never foreground (security consoles, the operator's own tooling) — the same shape as the existing guardrail manifest. |

### Measurement status

`cost of memory measured on ATmega` is **not measurable here and, for the
beacon, not the right target**:

- The beacon is never on the board — `hid_builder.board_notes()` states it
  explicitly ("the beacon is never on the board"), and the Arduino sketch only
  carries the typed command in flash. A beacon-side `mouse_path` therefore has
  **zero** ATmega cost by construction.
- If the intent was *firmware-side* human-like typing (inter-keystroke jitter,
  cadence), that is a different piece of work whose ATmega cost is measurable
  with `avr-gcc`/`avr-size` — **neither is installed on this machine**, so it
  is declared, not guessed.
- For the beacon, the measurable proxy is the `.text` delta of a MinGW build
  with the module compiled in vs out, plus `sizeof(malleable::Profile)`. That
  measurement belongs with the implementation; producing a number now would be
  inventing one.

### Decision

Assessed only, by instruction ("valuta il costo prima di scrivere"). Writing it
is gated on, in order: (1) the real-user-activity stop condition designed
first; (2) a measured `.text` delta on a real Windows build; (3) Windows-only
first; (4) opt-in, never default; (5) the capability documented in
`beacon_platform_matrix.md` before it ships.
