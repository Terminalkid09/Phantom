import shutil
import subprocess
import os
import sys
from rich.console import Console

console = Console()

def install_dependencies(dependencies, manager="apt"):
    """Prompt the user and install dependencies. Works in container.

    - Always asks if stdin is a TTY (interactive)
    - Avoids sudo if running as root
    - Returns True on success, False otherwise
    """
    console.print(f"[yellow][?] Dipendenze mancanti: {', '.join(dependencies)}[/]")

    # Only skip interactive prompt if truly non-interactive (CI env, no tty)
    if not sys.stdin.isatty():
        console.print("[yellow][!] Non-interactive session.\n    Please install the following packages manually:")
        if manager == 'apt':
            console.print(f"    sudo apt-get update && sudo apt-get install -y {' '.join(dependencies)}")
        else:
            console.print(f"    {manager} install {' '.join(dependencies)}")
        return False

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

def check_build_env(platform, arch="x64"):
    """Verifica dipendenze in base alla piattaforma e propone fix automatico."""
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
                flags = ["-m32"]
                pkg_suffix = ":i386"
                # Check for multilib support
                if not check_header("bits/c++config.h", flags):
                    missing.append("g++-multilib")

        # Header checks using test-compilation (more reliable than hardcoded paths)
        if not check_header("curl/curl.h", flags):
            missing.append(f"libcurl4-openssl-dev{pkg_suffix}")
        
        if not check_header("openssl/ssl.h", flags):
            missing.append(f"libssl-dev{pkg_suffix}")
        
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
        
    if missing:
        if os.name == 'posix':
            return install_dependencies(missing)
        else:
            console.print(f"[red][!] Dipendenze mancanti: {', '.join(missing)}. Installale manualmente.[/]")
            return False
    return True
