# Tool drivers — registering a tool Phantom has never seen

A **driver** is a small JSON manifest that turns a tool Phantom does not
ship into a live, plannable capability — no Python change required. Phantom
scans these directories at registry-build time and synthesizes a real
`Capability` from each valid manifest: its command template becomes the
adapter, its markers become the interpreter. The adapter stays the *only*
source of a command — the template simply expresses it as data.

## Where manifests are read from

In order (first id wins, malformed files are skipped):

1. this directory (`phantom/drivers/`, the packaged set);
2. `data/drivers/` (gitignored, the operator's private set);
3. every directory in `toolbelt.drivers_dir` (os.pathsep-separated);
4. every directory in `PHANTOM_DRIVERS_DIR` (os.pathsep-separated).

Set `toolbelt.drivers` to `false` to disable everything but the packaged
set. Inspect what was found with `phantom` → `config drivers`.

A driver may **never** shadow a built-in capability id; the registry refuses
the collision (and `phantom doctor` flags it under the `drivers` check).

## Approval gate (a found manifest is NOT executable)

Discovery is not authorisation. A manifest that is merely *found* is a
**candidate**: it is listed by `config drivers` and `doctor` but is **not**
loaded into the planner. To make it executable, approve its id explicitly:

* in `data/config.json`: `"toolbelt": { "approved": "dnscan_subdomains" }`
  (comma- or os.pathsep-separated for several ids)
* or per environment: `PHANTOM_APPROVED_DRIVERS=dnscan_subdomains`
  (comma- or os.pathsep-separated).

Approval lives in config, **never** in the manifest, so a dropped file cannot
approve itself. The executable must also be the declared `tool` (see below).

## Manifest shape

```json
{
  "id": "dnscan_subdomains",
  "tool": "dnscan",
  "category": "recon",
  "description": "Passive subdomain discovery via dnscan",
  "effects": ["hostname"],
  "argv": ["dnscan", "-d", "{target}", "-r", "6", "-w", "-o", "-"],
  "requires": ["target"],
  "markers": [
    {"prefix": "DNSCAN:", "kind": "hostname",
     "key": "hostname:{name}", "fields": ["name"], "confidence": 0.6}
  ],
  "opsec_cost": 0.2,
  "detection_risk": 0.05,
  "stealth_level": "passive",
  "timeout": 60
}
```

Required fields: `id`, `tool`, `category`, a command (`argv` OR `command`,
which must interpolate at least one `{field}`), `effects` (non-empty).

* `argv` (**preferred**) — an explicit argument vector. Each element may use
  `{target}` / `{slot}`; every interpolated token is shell-quoted
  (`shlex.join`), so a value can never become shell syntax. The executable
  (`argv[0]`) must be the declared `tool`.
* `command` — a shell template, for pipelines that `argv` cannot express.
  Uses `{target}` and any `{slot}` under `inputs`. A field with no value
  fails the move with a clear reason instead of running a broken command.

The declared `tool` must be the binary actually run (checked at parse time):
`argv[0]` for `argv`, or a token of the command for `command` (so
`sudo nmap ...` and `wsl -d kali-linux nmap ...` both match, while a manifest
that names `nmap` but runs something else is refused).
* `markers` — each entry parses lines beginning with `prefix` as
  `key=value` pairs and emits a finding of `kind`. `key` is a template over
  the parsed fields (`{name}`, …); `fields` selects which pairs land in the
  finding's `value`; `confidence` defaults to `0.6`.
* `requires` — a declarative precondition list. Grammar: `"<kind>"` (any
  finding of that kind), `"<kind>:<key>"` (exact), `"<kind>:<attr>=<value>"`,
  and the special `"target"` (a non-empty engagement target).
* `category` — must be one the agent dispatches: `recon`, `osint`,
  `service`, `creds`, `exploit`, `lateral`, `persistence`, `beacon`,
  `exfil`, `social`, `post`, `ad`, `hunt`.

Category `post` drivers execute through the beacon channel; every other
category runs its synthesized command through the normal shell path.

`example.json.example` in this directory is a template — copy it into
`data/drivers/` as a `.json` file to activate it.
