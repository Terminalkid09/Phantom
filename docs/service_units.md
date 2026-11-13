# Service definitions — surviving a closed terminal or a reboot

`--supervise` keeps an engagement alive across a **crash**, inside one process.
It cannot survive the two interruptions a multi-day operation actually meets:
the operator closes the terminal, or the machine reboots. For those, something
outside the process has to start the run again — an OS service definition, which
Phantom renders, writes and removes, but never *activates* silently.

Three flags, one per action (auto-mode only — they describe a run):

```bash
phantom --auto 10.0.0.5 --print-service systemd      # to stdout, writes nothing
phantom --auto 10.0.0.5 --install-service systemd    # writes the definition
phantom --auto 10.0.0.5 --uninstall-service systemd  # removes it
```

`--service-name NAME` picks the unit name (`--service-name` also selects which
definition `--uninstall-service` addresses); `--service-system` renders a
system-level unit instead of a per-user one. `systemd`, `launchd` and
`schtasks` are the formats; omit the format (`--install-service` with no value)
and the host's format is used.

## What the unit runs

The operator's own invocation, reconstructed from the **parsed** arguments —
never from `sys.argv` — plus `--supervise --resume-latest`:

```ini
ExecStart="/usr/bin/python3" "-m" "phantom.main" "--auto" "10.0.0.5" \
          "--supervise" "--resume-latest"
```

Flags are carried only when they were actually passed: a unit that hardcodes a
default the operator never typed would lie about what the engagement agreed to.
Every argument is quoted by ONE helper per platform, so a target containing a
space or a `;` stays a single argument (an `ExecStart` that re-splits its own
arguments turns a target into flags in your boot configuration).

`--supervise --resume-latest` is what makes an OS-level restart safe rather than
a way around the crash budget: the relaunched process asks
`phantom/utils/auto_resume` for permission, and the budget lives in a file next
to the checkpoint — a service that restarts forever still stops with a reason
after N attempts.

## Rendering is pure, installing is one function

* **Rendering** (`render_unit`, `plan_service`) touches no filesystem and runs
  no subprocess. `--print-service` writes the unit to **stdout and nothing
  else**, so `phantom --auto <t> --print-service systemd > unit.service`
  produces a file you can drop straight into the unit directory.
* **Installing** (`install_service`) is the only function that writes.
* **Activation is never automatic.** `--install-service` prints the command to
  enable the unit (`systemctl --user daemon-reload && … enable --now …`,
  `launchctl load -w …`, `schtasks /create /xml …`); running it stays your
  visible step. A framework that silently enables a boot-level service while
  nobody is looking is a framework you cannot audit.

## What the install guarantees

Writing a boot definition is a change to the machine that outlives the process,
so the operator gets four things back:

1. **An audit entry.** `service_unit_installed` / `service_unit_removed` go to
   the same hash-chained decision log as the agent's decisions
   (`phantom/automation/decision_audit.py`, `data/decision_audit.log`), with the
   unit format, name, path and both digests below. A refusal records nothing.
2. **A hash of the invocation.** `plan_service` returns
   `digest = sha256(NUL-joined argv)` — the identity of the exact command line —
   and `content_digest = sha256(rendered bytes, encoding included)`. The install
   message prints the first one, so the file, the message and the audit entry can
   be compared later instead of trusted.
3. **A verified write.** After writing, the file is read back and hashed: if the
   bytes on disk are not the bytes that were rendered, the install raises
   instead of leaving a half-unit the OS will parse and reject at the next boot.
4. **A verified uninstall.** `uninstall_service` checks that the path is gone
   after removal and raises if a file is still standing there; "nothing to
   remove" (it never existed) is reported as such, not as a success.

## A pre-existing definition is not overwritten

`install_service` refuses to clobber a **different** file at that path — it may
be another engagement's unit, or your hand-edited copy:

```
a DIFFERENT service definition already exists at …/phantom-auto.service
(sha256 4f9c… vs 8a1d… for this invocation): refusing to overwrite it — review
it, remove it with --uninstall-service, or re-run with overwrite
```

Re-installing the **same** content is idempotent (the digests match), which is
the "I re-ran the command" case. Replacing it deliberately is an explicit call
to `install_service(plan, overwrite=True)` — not a default.

## Refusals you will actually see

| Situation | What happens |
| --- | --- |
| `--plan` + `--install-service` | refused: a plan previews a run that would start nothing |
| no targets | refused: a boot definition needs a run to start |
| a foreign format for this OS (e.g. `systemd` on Windows) | refused by `plan_service`, nothing written |
| a name that is not a filename (`../../etc/cron.d/x`) | refused: the name becomes a path |
| an argument carrying a credential (`--token …`, `API_KEY=…`) | refused: a unit is world-readable and never gets un-written |
| `c2.transport_backend=go` | the Python listener stays down on purpose (two servers, one port); run `c2d` |
| no listeners / no beacons after a reboot | the run reports it; the restart budget still applies |

## Related

* [`../docs/ROADMAP.md`](ROADMAP.md) — where this sits in the wider work.
* [`../README.md`](../README.md) — the flag reference (contract-tested against
  `phantom/main.py` by `tests/test_readme_contract.py`).
* Tests: `tests/test_service_units.py` (rendering, quoting, names) and
  `tests/test_service_unit_safety.py` (audit, digests, pre-existing unit,
  verified install/uninstall).
