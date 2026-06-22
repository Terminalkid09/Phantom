import shutil
import subprocess
import os
import sys
from rich.console import Console

console = Console()

def _in_container():
    return os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv')

def install_dependencies(dependencies, manager="apt"):
    """Prompt the user and install dependencies.

    - Inside Docker/container: auto-installs silently (no prompt)
    - Outside container: asks if stdin is a TTY, else prints instructions
    - Avoids sudo if running as root
    - Returns True on success, False otherwise
    """
    console.print(f"[yellow][?] Dipendenze mancanti: {', '.join(dependencies)}[/]")

    # Inside Docker: auto-install without prompting
    if _in_container():
        console.print("[cyan][*] Container detected, installing dependencies automatically...[/]")
        choice = 'y'
    # Only skip interactive prompt if truly non-interactive (CI env, no tty)
    elif not sys.stdin.isatty():
        console.print("[yellow][!] Non-interactive session.\n    Please install the following packages manually:")
        if manager == 'apt':
            console.print(f"    sudo apt-get update && sudo apt-get install -y {' '.join(dependencies)}")
        else:
            console.print(f"    {manager} install {' '.join(dependencies)}")
        return False
    else:
        # Interactive: ask the user
        choice = input("Vuoi installarle automaticamente ora? [y/N]: ").strip().lower()
        if choice != 'y':
            return False

    # Determine command prefix (avoid sudo if running as root)
    try:
        use_sudo = shutil.which('sudo') is not None and os.geteuid() != 0
    except AttributeError:
        # geteuid() not available on Windows; assume we have sudo if needed
        use_sudo = shutil.which('sudo') is not None
    prefix = ["sudo"] if use_sudo else []

    if manager == 'apt':
        # Update package lists first
        try:
            console.print("[cyan][*] Aggiornamento lista pacchetti (apt-get update)...[/]")
            upd_cmd = prefix + ["apt-get", "update"]
            subprocess.run(upd_cmd, check=False)
        except Exception:
            pass

        cmd = prefix + ["apt-get", "install", "-y"] + dependencies
    else:
        cmd = prefix + [manager, "install", "-y"] + dependencies

    console.print(f"[cyan][*] Esecuzione: {' '.join(cmd)}[/]")
    try:
        subprocess.run(cmd, check=True)
        console.print("[green][+] Installazione completata.[/]")
        return True
    except subprocess.CalledProcessError as e:
        console.print("[red][!] Installazione fallita. Controlla i nomi dei pacchetti o installa manualmente.[/]")
        console.print(f"[red][!] Comando eseguito: {' '.join(cmd)}\n[red][!] Exit: {getattr(e, 'returncode', 'unknown')}[/]")
        return False

def check_header(header, flags=[]):
    """Try to compile a tiny snippet to see if a header is available."""
    try:
        # Use -c to only compile, -o /dev/null to discard output
        null_out = "NUL" if os.name == 'nt' else "/dev/null"
        subprocess.run(["g++"] + flags + ["-x", "c++", "-", "-o", null_out, "-c"], 
                       input=f"#include <{header}>\nint main(){{}}", 
                       text=True, capture_output=True, check=True)
        return True
    except Exception:
        return False

def _find_static_lib(libname: str, arch: str = "x64") -> bool:
    """Check whether a static archive (lib<name>.a) exists on the system.

    Searches the standard library directories for the host architecture.
    """
    if arch == "x86":
        search_dirs = [
            "/usr/lib/i386-linux-gnu",
            "/usr/lib32",
            "/usr/local/lib32",
            "/usr/local/lib/i386-linux-gnu",
        ]
    else:
        search_dirs = [
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib64",
            "/usr/local/lib",
            "/usr/local/lib/x86_64-linux-gnu",
            "/usr/lib",
        ]
    target = f"lib{libname}.a"
    for d in search_dirs:
        if os.path.isfile(os.path.join(d, target)):
            return True
    return False

# Maps: static library name -> apt dev package that provides the .a file.
_LINUX_STATIC_DEPS = {
    "curl":          "libcurl4-openssl-dev",
    "ssl":           "libssl-dev",
    "crypto":        "libssl-dev",
    "nghttp2":       "libnghttp2-dev",
    "zstd":          "libzstd-dev",
    "brotlidec":     "libbrotli-dev",
    "brotlienc":     "libbrotli-dev",
    "brotlicommon":  "libbrotli-dev",
    "z":             "zlib1g-dev",
    "gssapi_krb5":   "libkrb5-dev",
    "krb5":          "libkrb5-dev",
    "k5crypto":      "libkrb5-dev",
    "com_err":       "libkrb5-dev",
    "krb5support":   "libkrb5-dev",
    "keyutils":      "libkeyutils-dev",
    "idn2":          "libidn2-dev",
    "unistring":     "libunistring-dev",
    "psl":           "libpsl-dev",
}

def _install_openssl_android(ndk_home):
    """Cross-compile OpenSSL 3.4.x for Android NDK (aarch64)."""
    ndk_prebuilt = os.path.join(ndk_home, "toolchains", "llvm", "prebuilt", "linux-x86_64")
    ndk_sysroot = os.path.join(ndk_prebuilt, "sysroot")
    ndk_lib = os.path.join(ndk_sysroot, "usr", "lib", "aarch64-linux-android")
    ndk_include = os.path.join(ndk_sysroot, "usr", "include", "openssl")
    arch_include = os.path.join(ndk_sysroot, "usr", "include", "aarch64-linux-android", "openssl")
    os.makedirs(ndk_lib, exist_ok=True)
    os.makedirs(ndk_include, exist_ok=True)
    os.makedirs(os.path.dirname(arch_include), exist_ok=True)

    ssl_a = os.path.join(ndk_lib, "libssl.a")
    crypto_a = os.path.join(ndk_lib, "libcrypto.a")
    if os.path.exists(ssl_a) and os.path.exists(crypto_a) and os.path.exists(os.path.join(ndk_include, "evp.h")):
        return  # already installed

    import subprocess, tempfile, shutil
    tmp = tempfile.mkdtemp()
    tgz = os.path.join(tmp, "openssl.tgz")
    try:
        import urllib.request
        url = "https://github.com/openssl/openssl/releases/download/openssl-3.4.1/openssl-3.4.1.tar.gz"
        console.print(f"[blue]  Downloading OpenSSL 3.4.1...[/blue]")
        urllib.request.urlretrieve(url, tgz)
        shutil.unpack_archive(tgz, tmp)
        src = os.path.join(tmp, "openssl-3.4.1")
        env = os.environ.copy()
        toolchain_bin = os.path.join(ndk_prebuilt, "bin")
        env["PATH"] = toolchain_bin + os.pathsep + env.get("PATH", "")
        env["ANDROID_NDK_ROOT"] = ndk_home
        env["CC"] = "aarch64-linux-android28-clang"
        env["AR"] = "llvm-ar"
        env["RANLIB"] = "llvm-ranlib"
        console.print(f"[blue]  Configuring OpenSSL for android-arm64...[/blue]")
        subprocess.run(
            ["./Configure", "android-arm64", "no-shared", "no-asm",
             "-D__ANDROID_API__=28", f"--prefix={tmp}/install",
             f"--openssldir={tmp}/install"],
            cwd=src, env=env, capture_output=True, check=True)
        console.print(f"[blue]  Building OpenSSL (this may take a few minutes)...[/blue]")
        subprocess.run(["make", "-j4"], cwd=src, env=env, capture_output=True, check=True)
        # Copy libs
        for f in ["libssl.a", "libcrypto.a"]:
            shutil.copy2(os.path.join(src, f), os.path.join(ndk_lib, f))
        # Copy headers
        for d in [ndk_include, arch_include]:
            os.makedirs(d, exist_ok=True)
            for f in os.listdir(os.path.join(src, "include", "openssl")):
                srcf = os.path.join(src, "include", "openssl", f)
                dstf = os.path.join(d, f)
                try:
                    shutil.copy2(srcf, dstf)
                except OSError:
                    pass  # skip if dest already has a conflicting file
        # Fix CONFIGURED_API mismatch
        cfg_h = os.path.join(ndk_include, "configuration.h")
        if os.path.exists(cfg_h):
            with open(cfg_h) as f: content = f.read()
            content = content.replace("30600", "30400")
            with open(cfg_h, "w") as f: f.write(content)
        cfg_h_arch = os.path.join(arch_include, "configuration.h")
        if os.path.exists(cfg_h_arch):
            with open(cfg_h_arch) as f: content = f.read()
            content = content.replace("30600", "30400")
            with open(cfg_h_arch, "w") as f: f.write(content)
        console.print(f"[green][+] OpenSSL for Android installed.[/green]")
    except Exception as e:
        console.print(f"[red][!] OpenSSL build failed: {e}[/red]")
        console.print("[yellow][!] You may need to manually cross-compile OpenSSL for Android.[/yellow]")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


_DEPS_MARKER = "/tmp/.phantom_deps_ok"


def _deps_ready(platform):
    """Check if we already validated deps for this platform in this session."""
    import os
    return os.path.exists(f"{_DEPS_MARKER}_{platform}")


def _mark_deps_ready(platform):
    import os
    try:
        with open(f"{_DEPS_MARKER}_{platform}", "w") as f: f.write("1")
    except OSError:
        pass


def check_build_env(platform, arch="x64"):
    """Verifica dipendenze in base alla piattaforma e propone fix automatico."""
    if _deps_ready(platform):
        return True

    missing = []
    
    if platform == "linux":
        if os.name != "posix":
            console.print("[yellow][!] Warning: Cross-compiling for Linux from Windows might fail natively.[/]")
            console.print("[yellow][!] Use WSL or a Linux container if compilation fails.[/]")

        if not shutil.which("g++"): 
            missing.append("build-essential")
        
        # Determine flags and package suffix for architecture
        flags = []
        pkg_suffix = ""
        if arch == "x86" and os.name == "posix":
            import platform as py_platform
            if "64" in py_platform.machine():
                # Check if i386 architecture is added to dpkg
                try:
                    arch_check = subprocess.run(["dpkg", "--print-foreign-architectures"], capture_output=True, text=True)
                    if "i386" not in arch_check.stdout:
                        console.print("[yellow][*] Adding i386 architecture support...[/]")
                        prefix = ["sudo"] if shutil.which("sudo") else []
                        subprocess.run(prefix + ["dpkg", "--add-architecture", "i386"], check=True)
                        subprocess.run(prefix + ["apt-get", "update"], check=False)
                except Exception:
                    pass

                flags = ["-m32"]
                pkg_suffix = ":i386"
                # Check for multilib support
                if not check_header("bits/c++config.h", flags):
                    missing.append("g++-multilib")

        # Header checks using test-compilation
        if not check_header("openssl/ssl.h", flags):
            missing.append(f"libssl-dev{pkg_suffix}")

        if not check_header("zstd.h", flags):
            missing.append(f"libzstd-dev{pkg_suffix}")

        if not check_header("brotli/decode.h", flags):
            missing.append(f"libbrotli-dev{pkg_suffix}")

        # ── Static library checks (.a archives for -static linking) ───────
        # These are the transitive deps of libcurl that must be present as
        # static archives; header-only checks are not sufficient.
        for libname, pkg in _LINUX_STATIC_DEPS.items():
            if not _find_static_lib(libname, arch):
                full_pkg = f"{pkg}{pkg_suffix}"
                if full_pkg not in missing:
                    missing.append(full_pkg)
        
    elif platform == "windows":
        has_cl = shutil.which("cl") is not None
        # Check for mingw cross-compilers on Linux
        mingw_64 = shutil.which("x86_64-w64-mingw32-g++")
        mingw_32 = shutil.which("i686-w64-mingw32-g++")
        
        if os.name == 'nt':
            if not has_cl and not mingw_64 and not mingw_32:
                console.print("[red][!] 'cl.exe' (MSVC) or mingw toolchain not found in PATH.[/]")
                return False
        else:
            # On Linux targeting Windows
            if arch == "x64" and not mingw_64:
                missing.append("g++-mingw-w64-x86-64")
            elif arch == "x86" and not mingw_32:
                missing.append("g++-mingw-w64-i686")
    
    elif platform == "macos":
        # Check for osxcross
        osxcross_root = os.environ.get("OSXCROSS_ROOT", "/opt/osxcross")
        o32_cc = os.path.join(osxcross_root, "bin", "o32-clang++")
        if not os.path.exists(o32_cc):
            console.print(f"[red][!] osxcross not found at {osxcross_root}. macOS cross-compilation requires osxcross installation.[/]")
            return False
        if not os.path.exists(os.path.join(osxcross_root, "SDK")):
            console.print(f"[red][!] macOS SDK not found at {osxcross_root}/SDK. Download it using: cd {osxcross_root} && ./tools/gen_sdk_package.sh[/]")
            return False
    
    elif platform == "android":
        # Check for Android NDK
        ndk_home = os.environ.get("ANDROID_NDK_HOME", "/opt/android-ndk")
        ndk_cc = os.path.join(ndk_home, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin", "aarch64-linux-android28-clang++")
        if not os.path.exists(ndk_cc):
            console.print(f"[red][!] Android NDK not found at {ndk_home}. Download from: https://developer.android.com/ndk/downloads[/]")
            return False
        # Check for OpenSSL headers in NDK sysroot
        ndk_ssl_h = os.path.join(ndk_home, "toolchains", "llvm", "prebuilt", "linux-x86_64", "sysroot", "usr", "include", "openssl", "evp.h")
        if not os.path.exists(ndk_ssl_h):
            console.print("[yellow][*] OpenSSL headers not found in NDK. Cross-compiling OpenSSL for Android...[/yellow]")
            _install_openssl_android(ndk_home)
        
    if missing:
        # Skip static lib checks for dynamic builds — these .a files are not needed
        # unless linking with -static (which we don't use on Linux).
        # Only check headers + compiler.
        runtime_needed = [m for m in missing if not any(
            m.startswith(p) for p in ["libkrb5", "libkeyutils", "libidn2", "libunistring", "libpsl"]
        )]
        if runtime_needed:
            if os.name == 'posix':
                ok = install_dependencies(runtime_needed)
                if ok:
                    _mark_deps_ready(platform)
                return ok
            else:
                console.print(f"[red][!] Dipendenze mancanti: {', '.join(runtime_needed)}. Installale manualmente.[/]")
                return False
        # Only static libs missing — not an issue for dynamic linking
        _mark_deps_ready(platform)
        return True
    _mark_deps_ready(platform)
    return True
