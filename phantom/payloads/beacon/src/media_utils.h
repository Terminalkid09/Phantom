#pragma once
// ============================================================================
//  media_utils.h — Shared utilities for media capture modules
// ============================================================================

#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <cstring>
#include "crypto.h"

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#else
    #include <sys/utsname.h>
    #include <unistd.h>
#endif

// ── Shared Helper Functions ───────────────────────────────────────────────────

namespace media_utils {

inline std::string exec_cmd(const std::string& cmd) {
    std::string output;
#ifdef _WIN32
    FILE* f = _popen(cmd.c_str(), "r");
#else
    FILE* f = popen(cmd.c_str(), "r");
#endif
    if (!f) return "";
    char buf[8192];
    while (fgets(buf, sizeof(buf), f) != nullptr) {
        output += buf;
    }
#ifdef _WIN32
    _pclose(f);
#else
    pclose(f);
#endif
    return output;
}

inline std::string read_file_b64(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";
    std::vector<BYTE> buffer;
    char buf[8192];
    while (file.read(buf, sizeof(buf))) {
        buffer.insert(buffer.end(), buf, buf + file.gcount());
    }
    if (file.gcount() > 0) {
        buffer.insert(buffer.end(), buf, buf + file.gcount());
    }
    if (buffer.empty()) return "";
    return "MEDIA_B64:" + crypto::base64_encode(buffer);
}

inline bool file_exists(const std::string& path) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES;
#else
    return access(path.c_str(), F_OK) == 0;
#endif
}

inline std::string get_temp_path() {
#ifdef _WIN32
    char tmpPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tmpPath);
    return std::string(tmpPath);
#else
    const char* tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";
    return std::string(tmpdir) + "/";
#endif
}

inline std::string join_path(const std::string& base, const std::string& name) {
    std::string result = base;
#ifdef _WIN32
    if (!result.empty() && result.back() != '\\' && result.back() != '/') result += '\\';
#else
    if (!result.empty() && result.back() != '/') result += '/';
#endif
    result += name;
    return result;
}

} // namespace media_utils

// Note: XOR_STR and XOR_DEC macros are already defined in evasion.h
// This header relies on those definitions for string obfuscation
