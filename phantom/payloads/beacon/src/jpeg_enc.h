#pragma once
// ============================================================================
//  jpeg_enc.h — in-memory HBITMAP → JPEG encoder via dynamically-resolved
//  GDI+ (no static imports, no gdiplus.lib dependency at load time).
//
//  Used by screen recording: frames are encoded as compact JPEGs instead of
//  raw BMPs (a 1536x864 BMP is ~5.3 MB; JPEG q45 is ~150 KB) so multi-frame
//  recordings fit inside the encrypted result channel.
// ============================================================================

#ifdef _WIN32

#include <windows.h>
#include <objbase.h>   // CreateStreamOnHGlobal / GetHGlobalFromStream
#include <vector>
#include <cstdint>

namespace jpegenc {

// GDI+ flat-API Status: Ok == 0
inline void*& gdiplus_token() { static void* t = nullptr; return t; }

struct StartupInput {
    UINT32 GdiplusVersion;
    void*  DebugEventCallback;
    BOOL   SuppressBackgroundThread;
    BOOL   SuppressExternalCodecs;
};

inline HMODULE gdiplus_module() {
    HMODULE g = GetModuleHandleA("gdiplus.dll");
    if (g) return g;
    return LoadLibraryA("gdiplus.dll");
}

inline bool ensure_started() {
    if (gdiplus_token()) return true;
    HMODULE g = gdiplus_module();
    if (!g) return false;
    using FnGdiplusStartup = long (*)(void**, const void*, void*);
    auto pStartup = reinterpret_cast<FnGdiplusStartup>(
        reinterpret_cast<void*>(GetProcAddress(g, "GdiplusStartup")));
    if (!pStartup) return false;
    StartupInput in{};
    in.GdiplusVersion = 1;
    return pStartup(&gdiplus_token(), &in, nullptr) == 0;
}

// Minimal mirror of Gdiplus::ImageCodecInfo (fixed ABI).
struct ImageCodecInfo {
    CLSID        Clsid;
    GUID         FormatID;
    const WCHAR* CodecName;
    const WCHAR* DllName;
    const WCHAR* FormatDescription;
    const WCHAR* FilenameExtension;
    const WCHAR* MimeType;
    DWORD        Flags;
    DWORD        Version;
    DWORD        SigCount;
    DWORD        SigSize;
    const BYTE*  SigPattern;
    const BYTE*  SigMask;
};

inline bool jpeg_encoder_clsid(CLSID& out) {
    HMODULE g = gdiplus_module();
    if (!g) return false;
    using FnSize = long (*)(UINT*, UINT*);
    using FnGet  = long (*)(UINT, UINT, void*);
    auto pSize = reinterpret_cast<FnSize>(reinterpret_cast<void*>(GetProcAddress(g, "GdipGetImageEncodersSize")));
    auto pGet  = reinterpret_cast<FnGet>(reinterpret_cast<void*>(GetProcAddress(g, "GdipGetImageEncoders")));
    if (!pSize || !pGet) return false;
    UINT num = 0, size = 0;
    if (pSize(&num, &size) != 0 || num == 0 || size == 0) return false;
    std::vector<BYTE> buf(size);
    if (pGet(num, size, buf.data()) != 0) return false;
    auto* infos = reinterpret_cast<ImageCodecInfo*>(buf.data());
    for (UINT i = 0; i < num; ++i) {
        if (infos[i].MimeType &&
            infos[i].MimeType[0] == L'i' &&
            wcsncmp(infos[i].MimeType, L"image/jpeg", 10) == 0) {
            out = infos[i].Clsid;
            return true;
        }
    }
    return false;
}

#pragma pack(push, 4)
struct EncoderParameter {
    GUID   guid;
    ULONG  type;      // VT_UI4 == 4
    ULONG  count;
    ULONG* value;
};
struct EncoderParameters {
    UINT             count;
    EncoderParameter parameter[1];
};
#pragma pack(pop)

inline bool encode_hbitmap(HBITMAP hBitmap, ULONG quality, std::vector<BYTE>& out) {
    if (!hBitmap || !ensure_started()) return false;
    HMODULE g = gdiplus_module();
    if (!g) return false;

    using FnCreateBmp   = long (*)(HBITMAP, HPALETTE, void**);
    using FnDispose     = long (*)(void*);
    using FnSaveStream  = long (*)(void*, void*, const void*, void*);
    auto pCreateBmp  = reinterpret_cast<FnCreateBmp>(reinterpret_cast<void*>(GetProcAddress(g, "GdipCreateBitmapFromHBITMAP")));
    auto pDispose    = reinterpret_cast<FnDispose>(reinterpret_cast<void*>(GetProcAddress(g, "GdipDisposeImage")));
    auto pSaveStream = reinterpret_cast<FnSaveStream>(reinterpret_cast<void*>(GetProcAddress(g, "GdipSaveImageToStream")));
    if (!pCreateBmp || !pDispose || !pSaveStream) return false;

    void* gpBmp = nullptr;
    if (pCreateBmp(hBitmap, nullptr, &gpBmp) != 0 || !gpBmp) return false;

    CLSID jpegClsid;
    if (!jpeg_encoder_clsid(jpegClsid)) { pDispose(gpBmp); return false; }

    const GUID EncoderQuality = {0x1d5be4b5,0xfa4a,0x452d,{0x9c,0xdd,0x5d,0xb3,0x51,0x05,0xe7,0xeb}};
    ULONG q = quality ? quality : 45;
    EncoderParameters eps;
    eps.count = 1;
    eps.parameter[0].guid  = EncoderQuality;
    eps.parameter[0].type  = 4;  // VT_UI4
    eps.parameter[0].count = 1;
    eps.parameter[0].value = &q;

    IStream* stream = nullptr;
    if (CreateStreamOnHGlobal(nullptr, TRUE, &stream) != S_OK) {
        pDispose(gpBmp);
        return false;
    }
    long st = pSaveStream(gpBmp, stream, &jpegClsid, &eps);
    pDispose(gpBmp);
    if (st != 0) { stream->Release(); return false; }

    HGLOBAL h = nullptr;
    if (GetHGlobalFromStream(stream, &h) != S_OK) { stream->Release(); return false; }
    SIZE_T n = GlobalSize(h);
    void* p = GlobalLock(h);
    if (!p) { stream->Release(); return false; }
    out.assign(static_cast<BYTE*>(p), static_cast<BYTE*>(p) + n);
    GlobalUnlock(h);
    stream->Release();
    return !out.empty();
}

} // namespace jpegenc

#endif // _WIN32
