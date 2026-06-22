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

inline std::string capture() {
    // Try X11 first (requires -lX11 at link time)
    // If X11 is not available, fall back to import or screencap

    // Try using ImageMagick's "import" command
    // or scrot, or xwd
    // Most reliable: use popen to run a command

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
