# Phantom Lab — managed phone

**Intentionally vulnerable target for LOCAL, authorized testing only.**

A managed Android endpoint on the lab network (`172.28.0.40`, ports
`5555` adb and `8443` MDM/web). It exists because the mobile stage of Phantom
(`mobile_probe` → `mobile_mdm_fingerprint` → sandbox analysis) had no live
surface to run against, only unit fixtures.

## What is real here

| surface | what it does |
| --- | --- |
| **ADB (5555)** | the actual wire protocol: 24-byte header, magic complement, `CNXN`/`AUTH`/`OPEN`/`OKAY`/`WRTE`/`CLSE`, and the post-handshake 4-byte length prefix. `adb connect 127.0.0.1:5555` works and `adb shell id` answers `uid=2000(shell) context=u:r:shell:s0`. It accepts any RSA signature — it is a lab, not a backdoor. |
| **MDM (8443)** | `/enroll`, `/api/v2/mdm`, `/api/device`, `/config/mobile`, `/v1/push`, `/apns`, `/gcm`, `/fcm` (the paths `mobile_probe` probes) and `/api/v1/devices` (the SimpleMDM signature `mobile_mdm_fingerprint` matches). `/enroll` exposes the enrollment profile — the realistic finding. |
| **Sandbox** | per-app uid separation, an SELinux policy page (`u:r:untrusted_app:s0`, enforcing), and a uid check on data reads. A non-exported app refuses a caller with the wrong `X-Android-Uid`; the **exported** backup agent joins the caller's path without confinement, so `path=files/../../../../data/local/tmp/flag.txt` escapes its directory. |

The split is deliberate: the sandbox boundary exists and blocks the mail app,
and one exported component is misconfigured. That is what a real device
assessment finds.

## Verify

```bash
# MDM surface (what mobile_probe sees)
curl -sk https://127.0.0.1:8443/enroll | head -40
curl -sk https://127.0.0.1:8443/api/v1/devices

# Sandbox: blocked on the non-exported app …
curl -sk 'https://127.0.0.1:8443/sandbox/apps/com.corp.mail/data?path=files/notes.txt'
# … and escaped through the exported one
curl -sk 'https://127.0.0.1:8443/sandbox/apps/com.corp.backup/data?path=files/../../../../data/local/tmp/flag.txt'

# adb, if the platform tools are installed on the host
adb connect 127.0.0.1:5555
adb -s 127.0.0.1:5555 shell id
adb -s 127.0.0.1:5555 shell 'pm list packages'
```

Expected flag: `PHANTOM{phone_sandbox_escape_7781}`.

## What this exercises in Phantom

- `mobile_probe` (endpoint discovery + mobile web detection)
- `mobile_mdm_fingerprint` (vendor class, enrollment-profile exposure)
- the mobile strategy stage and its doctrine gates (unmanaged iOS is refused
  the beacon stage; a supervised Android device is not)
- auto-mode's mobile plan against a live, stateful target
