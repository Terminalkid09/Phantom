# Phantom command reference

Generated from the registries in this repository, so a command that
exists in the shell is listed here, and one that does not is not.
Each row is the same text `help <command>` prints, one line at a time.

## Manual shell commands

| Command | What it does |
|---|---|
| `save_profile` | save-profile <name> — save current settings as a profile. |
| `load_profile` | load-profile <name> — load a profile. |
| `list_profiles` | List all saved profiles. |
| `set` | set target <ip/domain/email> \| set scope <cidr,...> \| set lhost <ip> \| set lport <port> |
| `show` | show [session] \| show scope \| show mode \| show knowledge |
| `note` | note "<text>" — add an inline note to the session |
| `notes` | Display all notes in the current session |
| `save_session` | save-session <name> — save current session to disk |
| `load_session` | load-session <name> — load a previously saved session |
| `list_sessions` | List all saved sessions (manual .json + auto .pm bundles) |
| `export_session` | export-session [<file.pm>] — bundle this engagement into ONE |
| `import_session` | import-session <file.pm> — open a .pm bundle exported by another |
| `history` | Show command history for this session |
| `run` | run [n \| module [args]] — one step, from the ranked moves or a module. |
| `suggest` | suggest — ranked, directly executable next moves. |
| `plan` | plan <goal> — the reasoning engine lays out the chain to a goal. |
| `preflight` | preflight [module] — check the tools a module needs and show |
| `craft` | craft <ipgrab\|reel\|image\|pixel\|beacon\|kits\|hits\|wait> — build a |
| `map` | map [cidr] — discover live hosts on the local network (or the |
| `install` | install <tool> — install a missing tool in the current backend |
| `scan_diff` | scan-diff <target> [--since YYYY-MM-DD \| --old TS --new TS] |
| `use` | use <module> — enter a module (built-in or plugin; aliases: s, o, w, e, b, p, h, v, a, r, wl) |
| `plugins` | plugins — list all loaded plugins. |
| `auto` | auto \| auto <target[,target...\|CIDR]> [flags] - Autonomous kill chain. |
| `agent` | agent <target[,target...]> [--aggressive] [--goal <goal>] [--max-agents N] |
| `bench` | bench [list\|<scenario>] [--iterations N] [--json] |
| `c2` | c2 - Enter the Phantom C2 Operations Center |
| `malleable` | malleable [show\|save\|recommend] - Manage malleable C2 profiles for beacon stealth |
| `ad` | ad [tree\|paths\|add-user <u> [opts]\|add-edge <src> <type> <dst>\|reset] |
| `wordlists` | wordlists list \| wordlists use <name> \| wordlists search <keyword> \| wordlists info <name> |
| `export` | export <json\|pdf\|html> [filename] — export session results |
| `guardrails` | guardrails [list\|enable <key>\|disable <key>\|why\|record] — safety controls |
| `deps` | deps [report\|install <tool>...] -- the external tools Phantom shells out to |
| `llm` | llm [journal [refusals] \| propose [n] \| proposals \| accept <id> \| reject <id> [reason] \| clear] |
| `social` | social [graph [--json\|--graphml FILE] [--run] \| emails <address> [--reset-only]] |
| `help` | help [command] — Show the help panel or details about a specific command. |
| `workflow` | workflow [show\|types\|next] [target-type] — inspect the LEGACY phase engine |
| `config` | config [status\|rotate-api-token\|keys\|dead-drop <url>\|dead-drop publish <host> <port>] - Operator state. |
| `tool` | tool list\|import <binary>\|approve <id>\|enable <id>\|disable <id> - Runtime tool drivers. |
| `setup` | setup [status\|auto] - Detect transports, configure optional channels |
| `coverage` | coverage [profile] - Capability coverage audit. |
| `doctor` | doctor [--net] - Environmental self-check in one command. |
| `why` | why [capability] - Why did the agent do (or veto) that move? |
| `run_diff` | run-diff <checkpointA> <checkpointB> - Compare two runs structurally. |
| `experience` | experience [list [N] \| forget <N> \| forget all] - Learning memory. |
| `back` | Return to main shell (already here) |
| `exit` | exit - Exit Phantom, optionally save current session and generate professional report |
| `quit` | exit - Exit Phantom, optionally save current session and generate professional report |

## Module commands

Entered with `use <module>`: the prompt becomes `[module:target] >`
and only the commands below exist inside it.

### `analyzer`

| Command | What it does |
|---|---|
| `privesc` | privesc — Analyze session data for potential privilege escalation vectors. |

### `base_module`

| Command | What it does |
|---|---|
| `show` | Show session - current session |

### `brute`

| Command | What it does |
|---|---|
| `defaults` | defaults [service] — try the known DEFAULT credentials for a |

### `exploit`

| Command | What it does |
|---|---|
| `msf_interact` | msf-interact <id> — interactive loop against a live MSF session |
| `msf_fire` | msf-fire <cve_id> [--port N] — Force Metasploit execution. |
| `fire` | fire <cve_id> [--port N] [--msf] [--poc] [--command CMD] — Execute |
| `deploy_agent` | deploy-agent [windows\|linux\|macos\|android] — Compile beacon and get C2 dropper one-liner. |
| `remote_deploy` | remote-deploy [windows\|linux\|macos] — Compile the standalone |
| `chain` | chain [plan\|go <n>] — Search the composition engine for attack |
| `poc_sync` | poc-sync [term\|cve:CVE-XXXX-NNNNN] — Mirror real PoC scripts for |
| `ssh` | ssh [user:pass] — open an SSH session to the target using a |
| `privesc_run` | privesc-run — actively enumerate privilege-escalation vectors on |
| `run` | Build and execute the best access path from scan results. |

### `payload`

| Command | What it does |
|---|---|
| `reverse` | reverse [lhost] [lport] — synthesize a multi-dialect reverse |
| `bind` | bind [port] — synthesize a BIND shell (target listens). |
| `hid` | hid <board> ["<command>" \| --from-payload <id> \| --stager <os>] [flags] |

### `web`

| Command | What it does |
|---|---|
| `hunt` | hunt — behavioural bug-class hunting (baseline + statistical |

### `wordlist`

| Command | What it does |
|---|---|
| `run` | Alias for generate |

## AUTO-MODE flags (`phantom --auto <target> ...`)

| Flag | What it does |
|---|---|
| `--profile` | Load engagement profile at startup (manual shell) |
| `--c2` | Launch Phantom C2 interface instead of the AUTO-MODE shell |
| `--manual` | Launch the MANUAL module shell instead of |
| `--auto` | AUTO-MODE: with target(s) run the full kill chain |
| `--stealth` | paranoid OPSEC (auto-mode) |
| `--aggressive` | loud, fast exploitation (auto-mode) |
| `--speed` | exploit first viable opening (auto-mode) |
| `--exploit-all` | auto-mode: after the normal run, consider every |
| `--exhaustive` | auto-mode LAB/DEBUG only: try every actionable |
| `--reason` | auto-mode REASONING objective: balanced |
| `--identity-active` | auto-mode DEDICATED consent for ACTIVE identity |
| `--cell-loop` | auto-mode CELL LOOP (always on): the cell |
| `--cell-stages` | auto-mode: constrain the roster to these GOALS |
| `--oM` | auto-mode LEARNING MODE: draft markdown proposals |
| `--plan` | dry-run: show plan, execute nothing (auto-mode) |
| `--verbose` | stream live reasoning trace (auto-mode) |
| `--goal` | terminal goal (auto-mode, default: deliver) |
| `--profile-auto` | target profile (auto-mode, default: enterprise) |
| `--resume` | resume from an auto-mode checkpoint (auto-mode) |
| `--resume-latest` | resume the NEWEST auto-mode checkpoint with nobody |
| `--supervise` | auto-mode: keep the run alive WITHOUT anybody |
| `--max-restarts` | auto-mode --supervise: automatic relaunches |
| `--print-service` | auto-mode: print the OS service definition for |
| `--install-service` | auto-mode: WRITE the service definition that |
| `--uninstall-service` | auto-mode: remove the service definition |
| `--service-name` | auto-mode service definition: unit name |
| `--service-system` | auto-mode service definition: a system-level |
| `--llm` | optional local-LLM advisor (auto-mode) |
| `--ai` | AI layer mode (auto-mode): off (default), local |
| `--experience` | CROSS-ENGAGEMENT learning memory (auto-mode): |
| `--evolution` | SELF-IMPROVEMENT (auto-mode): stable uncovered |
| `--beta` | BETA CAPABILITIES (auto-mode): fetch open |
| `--setup` | guided setup: 'wsl' for the Windows WSL toolbox |
| `--doctor` | diagnostics only: python, tools, docker, WSL, |

## C2 shell commands

| Command | What it does |
|---|---|
| `listeners` | listeners [start <port> [host] [use_ssl]] \| stop] - Manage C2 listener. |
| `tunnel` | tunnel [start [port]\|install\|stop] - Public hop for delivery (c2.front). |
| `certs` | certs [status\|uninstall] - Inspect or remove the TLS certificate pair. |
| `config` | config (status\|rotate-api-token\|mtls-on\|mtls-off) - Show/rotate auto-generated C2 secrets. |
| `malleable` | malleable [show\|save\|recommend] - Manage malleable C2 profiles |
| `beacons` | beacons - list active beacons with real-time status |
| `payloads` | payloads [id] - list compiled payload droppers (optionally show one by id) |
| `audit` | audit [verify\|tail N] - inspect the immutable C2 audit log. |
| `interact` | interact <beacon_id> - drop into beacon interaction mode (prefix match supported) |
| `back` | back - return to main C2 shell from interaction mode |
| `results` | results [n\|all] - show results for the active beacon (default last 10) |
| `persist` | persist [runkey\|schtask\|cron\|systemd] - Generate and queue a persistence task for the active beacon. |
| `unpersist` | unpersist [name] - Remove the persistence the beacon installed. |
| `beacon_help` | beacon-help - list commands supported by the C++ beacon agent |
| `beacon_auth` | beacon-auth <status\|rotate\|revoke> [beacon_id] - Manage beacon identity keys. |
| `autopersist` | autopersist - Automatically attempt persistence based on OS detection. |
| `generate_shellcode` | generate_shellcode [platform] - Generate Base64 shellcode for inject/migrate. |
| `remote_view` | remote-view [gui\|off] — Watch the Remote Session module's stream. |
| `remote_expire` | remote-expire <seconds\|now> — Set the remote session lifetime (P0-7): |
| `remote_open` | remote-open — open the most recent full-resolution remote frame |
| `screen_watch` | screen-watch [gui] — Watch beacon screen recordings. |
| `screen_open` | screen-open [name] — open a saved screen recording (mp4) in the |
| `inject` | inject <pid> - Inject beacon into a remote process. |
| `migrate` | migrate [pid] - Migrate beacon into a new process. |
| `mem_run` | mem-run <b64_shellcode> - Execute shellcode in memory (Windows/Linux). |
| `keylog` | keylog <start\|stop\|status\|dump> - Manage keylogger instance (Windows only) |
| `screenshot` | screenshot - Capture a screenshot of the target (Windows only) |
| `health` | health - Beacon health self-report: uptime, check-in ok/fail |
| `set_sleep` | set-sleep <ms> [jitter%] - Rotate the beacon cadence mid-session |
| `generate` | generate [windows\|linux\|macos\|android] [x64\|x86] [--profile <json>] - Generate beacon and dropper |
| `telegram` | telegram — Start the Telegram bot to manage beacons from mobile |
| `exit` | exit - Close C2 and return to main Phantom CLI (or exit completely) |
