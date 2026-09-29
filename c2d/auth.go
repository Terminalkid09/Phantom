// auth.go — per-beacon HMAC-SHA256 identity + anti-replay.
//
// Byte-compatible with phantom.utils.beacon_auth: the canonical string is
//
//	METHOD\nPATH\nTIMESTAMP\nCOUNTER\nNONCE\nBODY
//
// signed with the beacon's secret and compared in constant time. On top of
// the signature the server keeps a nonce set (bounded, epoch-bound) so a
// captured request cannot be replayed even inside the freshness window.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
)

// DefaultMaxSkew is the accepted clock skew, in seconds (`max_skew` in the
// Python verifier).
const DefaultMaxSkew = 120

// Canonical builds the signed string exactly as the beacon does.
func Canonical(method, path, ts, counter, nonce, body string) []byte {
	return []byte(strings.Join([]string{
		strings.ToUpper(method), path, ts, counter, nonce, body,
	}, "\n"))
}

// Sign returns the lowercase hex HMAC-SHA256 of the canonical request.
func Sign(secret []byte, method, path, ts, counter, nonce, body string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(Canonical(method, path, ts, counter, nonce, body))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks freshness, header shape and the signature.
func Verify(secret []byte, method, path, ts, counter, nonce, sig, body string,
	now int64, maxSkew int) bool {
	cv, err := strconv.ParseInt(counter, 10, 64)
	if err != nil || cv < 0 {
		return false
	}
	tv, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	if maxSkew <= 0 {
		maxSkew = DefaultMaxSkew
	}
	if d := now - tv; d > int64(maxSkew) || -d > int64(maxSkew) {
		return false
	}
	if nonce == "" || len(nonce) > 128 || len(sig) != 64 {
		return false
	}
	expected := Sign(secret, method, path, ts, counter, nonce, body)
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(sig)))
}

// VerifyCounter parses the per-beacon counter (exposed for the store's
// high-water bookkeeping).
func VerifyCounter(counter string) (int64, bool) {
	cv, err := strconv.ParseInt(counter, 10, 64)
	if err != nil || cv < 0 {
		return 0, false
	}
	return cv, true
}

type nonceState struct {
	set   map[string]bool
	order []string
	epoch map[string]string
}

// ReplayGuard rejects a replayed nonce and nonces issued under a previous
// server epoch (a restart must not reopen an old window).
type ReplayGuard struct {
	mu      sync.Mutex
	epoch   string
	byNode  map[string]*nonceState
	counter map[string]int64
}

// NewReplayGuard starts a guard with a fresh random epoch.
func NewReplayGuard() *ReplayGuard {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return &ReplayGuard{
		epoch:   hex.EncodeToString(buf),
		byNode:  map[string]*nonceState{},
		counter: map[string]int64{},
	}
}

// Epoch exposes the current boot epoch (diagnostics/tests).
func (g *ReplayGuard) Epoch() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.epoch
}

// Check records the nonce and rejects a replay. `counterValue` only updates a
// high-water mark: a beacon is allowed to reset its counter after a restart,
// because freshness is carried by the timestamp window plus the random nonce.
func (g *ReplayGuard) Check(beaconID, nonce string, counterValue int64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.byNode[beaconID]
	if st == nil {
		st = &nonceState{set: map[string]bool{}, epoch: map[string]string{}}
		g.byNode[beaconID] = st
	}
	if st.set[nonce] {
		return errors.New("replayed nonce")
	}
	if prior, ok := st.epoch[nonce]; ok && prior != g.epoch {
		return errors.New("nonce issued under a previous epoch")
	}
	st.set[nonce] = true
	st.epoch[nonce] = g.epoch
	st.order = append(st.order, nonce)
	if len(st.order) > 256 {
		// keep the most recent 128, dropping their epoch bookkeeping too
		keep := st.order[len(st.order)-128:]
		next := &nonceState{set: map[string]bool{}, epoch: map[string]string{}}
		for _, n := range keep {
			next.set[n] = true
			next.epoch[n] = st.epoch[n]
		}
		next.order = append([]string(nil), keep...)
		g.byNode[beaconID] = next
	}
	if counterValue > g.counter[beaconID] {
		g.counter[beaconID] = counterValue
	}
	return nil
}

// Counter returns the observed high-water counter for a beacon.
func (g *ReplayGuard) Counter(beaconID string) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.counter[beaconID]
}
