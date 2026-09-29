// ============================================================================
//  test_transport.cpp — host-side test for the beacon TRANSPORT LOGIC
//
//  Why a separate TU: the endpoint ladder, the proxy parser and the no_proxy
//  matcher are pure logic that a live check-in cannot exercise (you cannot
//  make a C2 disappear on demand). They are also the parts most likely to be
//  silently wrong — a ladder that rotates after ONE failure burns every
//  endpoint on a flapping link, and a proxy parser that mishandles userinfo
//  dials the wrong host.
//
//  Build (Linux/WSL):
//      g++ -std=c++20 -Iphantom/payloads/beacon/src
//          phantom/payloads/beacon/src/test_transport.cpp -o /tmp/tt -lssl -lcrypto
//      /tmp/tt
//
//  Exit code 0 = every assertion held. Windows-only paths (WinHTTP) are not
//  reachable from a Linux build and are covered by the beacon-syntax job.
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

// The generated config carries C2_PAYLOAD_TOKEN (and the auth material). A
// fresh checkout has neither, so the test stands on its own with the
// fallbacks below — it only exercises transport LOGIC, never the wire.
#if __has_include("c2_config.h")
#include "c2_config.h"
#endif
#ifndef C2_PAYLOAD_TOKEN
#define C2_PAYLOAD_TOKEN ""
#endif
#ifndef C2_HOST
#define C2_HOST "127.0.0.1"
#endif
#ifndef C2_HOSTS
#define C2_HOSTS ""
#endif
#ifndef C2_PROXY
#define C2_PROXY ""
#endif
#ifndef BEACON_AUTH_ENABLED
#define BEACON_AUTH_ENABLED 0
#endif
#ifndef BEACON_MTLS_ENABLED
#define BEACON_MTLS_ENABLED 0
#endif

#include "network.h"

static int failures = 0;

static void check(bool ok, const std::string& what) {
    if (!ok) {
        std::printf("FAIL: %s\n", what.c_str());
        ++failures;
    }
}

static void check_eq(const std::string& got, const std::string& want,
                     const std::string& what) {
    if (got != want) {
        std::printf("FAIL: %s (got '%s', want '%s')\n", what.c_str(),
                    got.c_str(), want.c_str());
        ++failures;
    }
}

int main() {
    // ── split_csv ────────────────────────────────────────────────────────
    {
        auto parts = net::split_csv("a.example,b.example,,\"c.example\"");
        check(parts.size() == 3, "split_csv drops empty fields");
        check_eq(parts[0], "a.example", "split_csv first");
        check_eq(parts[1], "b.example", "split_csv second");
        check_eq(parts[2], "c.example", "split_csv strips quotes");
    }

    // ── ladder seeding ───────────────────────────────────────────────────
    {
        net::C2Config cfg;
        cfg.seed_ladder("c2.example.com", "backup1.example.net,c2.example.com,"
                                          "backup2.example.net");
        check(cfg.ladder.size() == 3, "ladder keeps primary + unique fallbacks");
        check_eq(cfg.ladder[0], "c2.example.com", "primary is first");
        check_eq(cfg.endpoint(), "c2.example.com", "endpoint() is the primary");
        check_eq(cfg.host, "c2.example.com", "apply_endpoint syncs host");
        check(cfg.failover_after == 3, "default failure budget is 3");
    }

    // ── argv override keeps the ladder behind it ──────────────────────────
    {
        net::C2Config cfg;
        cfg.seed_ladder("c2.example.com", "backup1.example.net");
        cfg.prefer_endpoint("redir.example.org");
        check(cfg.ladder.size() == 3, "override adds, never discards");
        check_eq(cfg.endpoint(), "redir.example.org", "override becomes first");
        check_eq(cfg.ladder[1], "c2.example.com", "compiled primary still queued");
    }

    // ── failover discipline ──────────────────────────────────────────────
    {
        net::C2Config cfg;
        cfg.seed_ladder("a.example", "b.example");
        check(cfg.on_failure() == false, "1st failure stays put");
        check(cfg.on_failure() == false, "2nd failure stays put");
        check(cfg.on_failure() == true, "3rd failure rotates");
        check_eq(cfg.endpoint(), "b.example", "rotation lands on the fallback");
        check(cfg.failures_here == 0, "counter resets after a move");
        cfg.on_success();
        check(cfg.failures_here == 0, "success resets the counter");
        // the same budget applies after a reset: the THIRD failure moves
        check(cfg.on_failure() == false, "1st failure after success stays put");
        check(cfg.on_failure() == false, "2nd failure after success stays put");
        check(cfg.on_failure() == true, "3rd failure after success rotates");
        // ...and the ladder WRAPS instead of parking on the endpoint it just
        // proved dead: b -> a
        check_eq(cfg.endpoint(), "a.example", "wrap-around returns to the primary");
        check(cfg.on_failure() == false && cfg.on_failure() == false &&
              cfg.on_failure() == true, "the wrapped rung gets a fresh budget");
        check_eq(cfg.endpoint(), "b.example", "and rotates back to the fallback");
    }

    // ── a single endpoint never rotates ──────────────────────────────────
    {
        net::C2Config cfg;
        cfg.seed_ladder("only.example", "");
        for (int i = 0; i < 10; ++i) {
            check(cfg.on_failure() == false, "single-endpoint ladder never rotates");
        }
        check_eq(cfg.endpoint(), "only.example", "single endpoint unchanged");
    }

    // ── split_pins_keep_empty ────────────────────────────────────────
    {
        auto parts = net::split_pins_keep_empty("aa,,cc");
        check(parts.size() == 3, "pin split keeps empty fields");
        check_eq(parts[0], "aa", "pin 0");
        check_eq(parts[1], "", "pin 1 is empty");
        check_eq(parts[2], "cc", "pin 2");
        auto none = net::split_pins_keep_empty("");
        check(none.size() == 1 && none[0].empty(), "empty pin list = one empty");
    }

    // ── per-endpoint pins ────────────────────────────────────────────────
    {
        net::C2Config cfg;
        std::string p1(64, 'a'), p2(64, 'b'), p3(64, 'c');
        cfg.seed_ladder("front.example.net",
                        "backup1.example.net,backup2.example.net",
                        p1 + "," + p2 + "," + p3);
        check_eq(cfg.active_pin(), p1, "primary uses its own pin");
        cfg.prefer_endpoint("backup2.example.net");
        check_eq(cfg.active_pin(), p3,
                 "pin follows the rung through a reorder (keyed by host)");
        check(cfg.on_failure() == false && cfg.on_failure() == false &&
              cfg.on_failure() == true, "3rd failure rotates");
        check_eq(cfg.endpoint(), "front.example.net", "rotation wraps to primary");
        check_eq(cfg.active_pin(), p1, "primary pin again after the wrap");
    }

    // ── an empty field inherits the fallback pin ─────────────────────────
    {
        net::C2Config cfg;
        std::string p1(64, 'a');
        cfg.seed_ladder("front.example.net", "backup.example.net", p1 + ",");
        check_eq(cfg.active_pin(), p1, "primary has its own pin");
        check(cfg.host_pins.count("backup.example.net") == 0,
              "an empty field leaves the rung on the fallback pin");
        cfg.failover_after = 1;
        cfg.on_failure();
        check_eq(cfg.active_pin(), cfg.compiled_pin(),
                 "the unpinned rung resolves to the compiled pin");
    }

    // ── SPKI pins travel with the same rungs (macOS/libcurl) ─────────────
    {
        net::C2Config cfg;
        std::string s1 = "sha256//" + std::string(43, 'A') + "=";
        std::string s2 = "sha256//" + std::string(43, 'B') + "=";
        cfg.seed_ladder("front.example.net", "backup.example.net", "",
                        s1 + "," + s2);
        check_eq(cfg.active_pubkey_pin(), s1, "primary SPKI pin");
        cfg.failover_after = 1;
        cfg.on_failure();
        check_eq(cfg.active_pubkey_pin(), s2, "fallback SPKI pin");
    }

    // ── proxy parsing ────────────────────────────────────────────────────
    {
        auto p = net::parse_proxy("http://proxy.corp.local:3128");
        check(p.valid, "scheme+port parses");
        check_eq(p.host, "proxy.corp.local", "proxy host");
        check(p.port == 3128, "proxy port");

        p = net::parse_proxy("socks5://user:pass@10.0.0.9:1080");
        check(p.valid, "userinfo parses");
        check_eq(p.host, "10.0.0.9", "userinfo is stripped");
        check(p.port == 1080, "port after userinfo");

        p = net::parse_proxy("proxy.corp.local:8080/ignored/path");
        check(p.valid, "path is dropped");
        check_eq(p.host, "proxy.corp.local", "host before the path");
        check(p.port == 8080, "port before the path");

        p = net::parse_proxy("proxy.corp.local");
        check(p.valid, "bare host gets the conventional port");
        check(p.port == 3128, "default proxy port");

        check(!net::parse_proxy("").valid, "empty proxy is invalid");
        check(!net::parse_proxy("http://").valid, "hostless proxy is invalid");
    }

    // ── no_proxy ─────────────────────────────────────────────────────────
    {
        setenv("no_proxy", "internal.example, corp.local ,*", 1);
        check(net::proxy_bypassed("internal.example"), "exact entry matches");
        check(net::proxy_bypassed("host.corp.local"), "suffix entry matches");
        check(net::proxy_bypassed("anything.at.all"), "* matches everything");
        setenv("no_proxy", "only.example", 1);
        check(!net::proxy_bypassed("other.example"),
              "non-matching host is proxied");
        unsetenv("no_proxy");
        unsetenv("NO_PROXY");
        check(!net::proxy_bypassed("other.example"), "no no_proxy = always proxied");
    }

    if (failures == 0) {
        std::printf("OK — transport logic: ladder, rotation, proxy parsing, "
                    "no_proxy all behave\n");
    } else {
        std::printf("%d FAILURE(S)\n", failures);
    }
    return failures == 0 ? 0 : 1;
}
