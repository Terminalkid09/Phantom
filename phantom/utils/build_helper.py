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

def check_build_env(platform):
    """Verifica dipendenze in base alla piattaforma e propone fix automatico."""
    missing = []
    
    if platform == "linux":
        if not shutil.which("g++"): missing.append("build-essential")
        # Header checks for libraries
        has_curl = os.path.exists("/usr/include/curl/curl.h") or os.path.exists("/usr/include/x86_64-linux-gnu/curl/curl.h")
        if not has_curl: missing.append("libcurl4-openssl-dev")
        
        has_ssl = os.path.exists("/usr/include/openssl/ssl.h") or os.path.exists("/usr/include/x86_64-linux-gnu/openssl/ssl.h")
        if not has_ssl: missing.append("libssl-dev")
        
    elif platform == "windows":
        has_cl = shutil.which("cl") is not None
        has_mingw = shutil.which("x86_64-w64-mingw32-g++") is not None or shutil.which("mingw32-g++") is not None
        if os.name == 'nt':
            if not has_cl and not has_mingw:
                console.print("[red][!] 'cl.exe' (MSVC) or mingw toolchain not found in PATH. Install Visual Studio Build Tools or mingw-w64.[/]")
                return False
        else:
            if not has_mingw:
                missing.append("mingw-w64")
    
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
