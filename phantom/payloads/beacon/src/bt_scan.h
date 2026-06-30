#pragma once
// ============================================================================
//  bt_scan.h — Phantom Beacon Bluetooth Proximity Radar
//  ─────────────────────────────────────────────────────
//  Scans for nearby Bluetooth devices to map the physical environment.
//  Extracts device names, MAC addresses, and signal strength estimates.
//
//  Windows: Uses Winsock Bluetooth (WSALookupServiceBegin with NS_BTH)
//  Linux:   Uses hcitool scan / bluetoothctl
// ============================================================================

#include <string>
#include <vector>
#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2bth.h>
#include <bluetoothapis.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bthprops.lib")
#else
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <cstdlib>
#endif

namespace bt_scan {

struct BluetoothDevice {
std::string name;      // Device friendly name
std::string mac;       // Bluetooth MAC address
int rssi;              // Signal strength (dBm), 0 if unavailable
std::string dev_class; // Device class description
};

#ifdef _WIN32

// Format BTH_ADDR to MAC string
inline std::string format_bth_addr(BTH_ADDR addr) {
char buf[18];
snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
    (int)((addr >> 40) & 0xFF),
    (int)((addr >> 32) & 0xFF),
    (int)((addr >> 24) & 0xFF),
    (int)((addr >> 16) & 0xFF),
    (int)((addr >> 8) & 0xFF),
    (int)(addr & 0xFF));
return std::string(buf);
}

// Classify device based on CoD (Class of Device)
inline std::string classify_device(ULONG cod) {
ULONG major = (cod >> 8) & 0x1F;
switch (major) {
case 0x01: return "Computer";
case 0x02: return "Phone";
case 0x03: return "LAN/Network";
case 0x04: return "Audio/Video";
case 0x05: return "Peripheral";
case 0x06: return "Imaging";
case 0x07: return "Wearable";
case 0x08: return "Toy";
case 0x09: return "Health";
default:   return "Unknown";
}
}

inline std::vector<BluetoothDevice> scan_devices() {
std::vector<BluetoothDevice> results;

// Initialize Winsock
WSADATA wsaData;
int wsaErr = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaErr != 0) {
        WSACleanup();
        return results;
    }

// Method 1: Use Bluetooth Device Discovery API (more reliable)
BLUETOOTH_DEVICE_SEARCH_PARAMS searchParams;
ZeroMemory(&searchParams, sizeof(searchParams));
searchParams.dwSize = sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS);
searchParams.fReturnAuthenticated = TRUE;
searchParams.fReturnRemembered = TRUE;
searchParams.fReturnUnknown = TRUE;
searchParams.fReturnConnected = TRUE;
searchParams.fIssueInquiry = TRUE;
searchParams.cTimeoutMultiplier = 4; // ~5 seconds inquiry
searchParams.hRadio = NULL; // Search all radios

BLUETOOTH_DEVICE_INFO deviceInfo;
ZeroMemory(&deviceInfo, sizeof(deviceInfo));
deviceInfo.dwSize = sizeof(BLUETOOTH_DEVICE_INFO);

HBLUETOOTH_DEVICE_FIND hFind = BluetoothFindFirstDevice(&searchParams, &deviceInfo);
    if (hFind != NULL) {
        do {
            BluetoothDevice dev;
            dev.mac = format_bth_addr(deviceInfo.Address.ullLong);
            dev.rssi = 0;
            dev.dev_class = classify_device(deviceInfo.ulClassofDevice);

            char narrowName[256] = {0};
            WideCharToMultiByte(CP_UTF8, 0, deviceInfo.szName, -1,
                                narrowName, sizeof(narrowName), NULL, NULL);
            dev.name = strlen(narrowName) > 0 ? narrowName : "<unnamed>";

            results.push_back(dev);

            ZeroMemory(&deviceInfo, sizeof(deviceInfo));
            deviceInfo.dwSize = sizeof(BLUETOOTH_DEVICE_INFO);
        } while (BluetoothFindNextDevice(hFind, &deviceInfo));

        BluetoothFindDeviceClose(hFind);
    }

// Method 2: WSALookupService fallback for additional devices
WSAQUERYSETA querySet;
ZeroMemory(&querySet, sizeof(querySet));
querySet.dwSize = sizeof(querySet);
querySet.dwNameSpace = NS_BTH;
querySet.lpcsaBuffer = NULL;

    HANDLE hLookup;
    DWORD flags = LUP_CONTAINERS | LUP_RETURN_NAME | LUP_RETURN_ADDR | LUP_FLUSHCACHE;

    if (WSALookupServiceBeginA(&querySet, flags, &hLookup) == 0) {
char buffer[4096];
DWORD bufLen = sizeof(buffer);
LPWSAQUERYSETA pResult = (LPWSAQUERYSETA)buffer;

while (WSALookupServiceNextA(hLookup, flags, &bufLen, pResult) == 0) {
BluetoothDevice dev;

if (pResult->lpszServiceInstanceName) {
    dev.name = pResult->lpszServiceInstanceName;
} else {
    dev.name = "<unnamed>";
}

if (pResult->lpcsaBuffer && pResult->lpcsaBuffer->RemoteAddr.lpSockaddr) {
    SOCKADDR_BTH* pBthAddr = (SOCKADDR_BTH*)pResult->lpcsaBuffer->RemoteAddr.lpSockaddr;
    dev.mac = format_bth_addr(pBthAddr->btAddr);
}

dev.rssi = 0;
dev.dev_class = "Unknown";

// Avoid duplicates
bool duplicate = false;
for (const auto& existing : results) {
    if (existing.mac == dev.mac) { duplicate = true; break; }
}
if (!duplicate && !dev.mac.empty()) {
    results.push_back(dev);
}

bufLen = sizeof(buffer);
}

WSALookupServiceEnd(hLookup);
}

WSACleanup();
return results;
}

#elif defined(__ANDROID__)

// ── Root: use hcitool for direct BT scan ──────────────────────────────────────
inline std::vector<BluetoothDevice> scan_devices_root() {
    std::vector<BluetoothDevice> results;
    FILE* fp = popen("hcitool scan 2>/dev/null", "r");
    if (!fp) return results;

    char line[512];
    bool header = true;
    while (fgets(line, sizeof(line), fp)) {
        if (header) { header = false; continue; }
        std::string l(line);
        if (l.length() < 18) continue;
        BluetoothDevice dev;
        dev.mac = l.substr(0, 17);
        dev.rssi = 0;
        dev.dev_class = "Unknown";
        if (l.size() > 18) dev.name = l.substr(18);
        while (!dev.name.empty() && (dev.name.back() == '\n' || dev.name.back() == '\r'))
            dev.name.pop_back();
        if (dev.name.empty()) dev.name = "<unnamed>";
        results.push_back(dev);
    }
    pclose(fp);
    return results;
}

// ── Non-root: use dumpsys bluetooth (requires DUMP permission) ────────────────
inline std::vector<BluetoothDevice> scan_devices_user() {
    std::vector<BluetoothDevice> results;

    FILE* fp = popen("dumpsys bluetooth 2>/dev/null", "r");
    if (!fp) {
        BluetoothDevice errDev;
        errDev.name = "BT Scan Error: dumpsys bluetooth failed (adapter may be absent)";
        results.push_back(errDev);
        return results;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        std::string l(line);
        size_t dev_pos = l.find("Device ");
        if (dev_pos == std::string::npos) continue;

        BluetoothDevice dev;
        dev.rssi = 0;
        dev.dev_class = "Unknown";

        size_t mac_start = dev_pos + 7;
        if (l.size() >= mac_start + 17) {
            dev.mac = l.substr(mac_start, 17);
        }
        size_t name_pos = l.find("Name ", mac_start + 17);
        if (name_pos != std::string::npos) {
            dev.name = l.substr(name_pos + 5);
        } else {
            dev.name = l.substr(mac_start + 18);
        }
        while (!dev.name.empty() && (dev.name.back() == '\n' || dev.name.back() == '\r'))
            dev.name.pop_back();
        if (dev.name.empty()) dev.name = "<unnamed>";

        if (!dev.mac.empty()) results.push_back(dev);
    }
    pclose(fp);

    if (results.empty()) {
        BluetoothDevice errDev;
        errDev.name = "BT Scan: No devices found via dumpsys (bluetooth may be off)";
        results.push_back(errDev);
    }
    return results;
}

inline std::vector<BluetoothDevice> scan_devices() {
    if (getuid() == 0) return scan_devices_root();
    return scan_devices_user();
}

#else // Linux / macOS

inline std::vector<BluetoothDevice> scan_devices() {
std::vector<BluetoothDevice> results;

// Try hcitool scan first (requires root or bluetooth group)
FILE* fp = popen("hcitool scan --flush 2>/dev/null", "r");
if (!fp) {
// Fallback to bluetoothctl
fp = popen("bluetoothctl --timeout 5 scan on 2>/dev/null && bluetoothctl devices 2>/dev/null", "r");
if (!fp) return results;
}

char line[512];
// Skip header line
if (fgets(line, sizeof(line), fp) == NULL) {
pclose(fp);
return results;
}

while (fgets(line, sizeof(line), fp)) {
std::string l(line);
// hcitool format: "\tAA:BB:CC:DD:EE:FF\tDevice Name"
// bluetoothctl format: "Device AA:BB:CC:DD:EE:FF Device Name"

BluetoothDevice dev;
dev.rssi = 0;
dev.dev_class = "Unknown";

// Try hcitool format
if (l.size() > 20 && l[0] == '\t') {
dev.mac = l.substr(1, 17);
if (l.size() > 19) {
    dev.name = l.substr(19);
    // Trim
    while (!dev.name.empty() && (dev.name.back() == '\n' || dev.name.back() == '\r'))
        dev.name.pop_back();
}
}
// Try bluetoothctl format
else if (l.find("Device ") != std::string::npos) {
size_t pos = l.find("Device ");
if (pos != std::string::npos && l.size() > pos + 24) {
    dev.mac = l.substr(pos + 7, 17);
    dev.name = l.substr(pos + 25);
    while (!dev.name.empty() && (dev.name.back() == '\n' || dev.name.back() == '\r'))
        dev.name.pop_back();
}
}

if (!dev.mac.empty()) {
if (dev.name.empty()) dev.name = "<unnamed>";
results.push_back(dev);
}
}

pclose(fp);

// Try to get RSSI values via hcitool rssi
for (auto& dev : results) {
std::string cmd = "hcitool rssi " + dev.mac + " 2>/dev/null";
FILE* rssi_fp = popen(cmd.c_str(), "r");
if (rssi_fp) {
char rssi_line[128];
if (fgets(rssi_line, sizeof(rssi_line), rssi_fp)) {
    // Format: "RSSI return value: -XX"
    const char* val = strstr(rssi_line, "RSSI return value: ");
    if (val) {
        dev.rssi = atoi(val + 19);
    }
}
pclose(rssi_fp);
}
}

return results;
}

#endif

// ── Format output for C2 ───────────────────────────────────────────────────

inline std::string scan() {
auto devices = scan_devices();
if (devices.empty()) return "BT scan: No Bluetooth devices found (adapter may be unavailable).";

std::ostringstream out;
out << "=== BLUETOOTH PROXIMITY RADAR (" << devices.size() << " devices) ===\n";
out << "MAC Address       | RSSI | Class       | Name\n";
out << "------------------+------+-------------+---------------------------\n";
for (const auto& dev : devices) {
char line[256];
snprintf(line, sizeof(line), "%-18s | %4d | %-11s | %s\n",
        dev.mac.c_str(), dev.rssi, dev.dev_class.c_str(), dev.name.c_str());
out << line;
}
return out.str();
}

// ── Format as JSON ─────────────────────────────────────────────────────────

inline std::string scan_json() {
auto devices = scan_devices();
if (devices.empty()) return "BT_SCAN:[]";

std::ostringstream out;
out << "BT_SCAN:[";
for (size_t i = 0; i < devices.size(); i++) {
if (i > 0) out << ",";
// Escape name for JSON
std::string escaped_name;
for (char c : devices[i].name) {
if (c == '"') escaped_name += "\\\"";
else if (c == '\\') escaped_name += "\\\\";
else escaped_name += c;
}
out << "{\"name\":\"" << escaped_name
<< "\",\"mac\":\"" << devices[i].mac
<< "\",\"rssi\":" << devices[i].rssi
<< ",\"class\":\"" << devices[i].dev_class << "\"}";
}
out << "]";
return out.str();
}

} // namespace bt_scan
