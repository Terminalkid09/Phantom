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
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultMaxSkew is the accepted clock skew, in seconds (`max_skew` in the
// Python verifier).
const DefaultMaxSkew = 120

// replayTTLSeconds bounds how long a persisted nonce stays meaningful. A
// replay outside the freshness window is refused by the timestamp check
// anyway, so keeping it forever would only lock out a peer that reused a
// nonce long ago (see B-2).
const replayTTLSeconds = 300

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
	// times records when each nonce was first seen (unix seconds), so a
	// persisted entry can expire.
	times map[string]map[string]int64
	// path persists the epoch map across restarts. "" = in-memory only.
	path string
}

// NewReplayGuard starts a guard with a fresh random epoch (no persistence).
func NewReplayGuard() *ReplayGuard {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return &ReplayGuard{
		epoch:   hex.EncodeToString(buf),
		byNode:  map[string]*nonceState{},
		counter: map[string]int64{},
		times:   map[string]map[string]int64{},
	}
}

// NewReplayGuardAt starts a guard whose nonce-epoch map survives a restart.
// B-2: the in-memory nonce SET is wiped on boot, but a nonce first seen under
// the PREVIOUS epoch is reloaded and refused by the stale-epoch check — which
// is what the epoch mechanism is for and what makes it reachable at all.
func NewReplayGuardAt(path string) *ReplayGuard {
	g := NewReplayGuard()
	g.path = path
	g.load()
	return g
}

// load restores the persisted nonce epochs (not the SET: a reloaded nonce is
// refused by the epoch mismatch, exercising the same guard the test covers).
func (g *ReplayGuard) load() {
	if g.path == "" {
		return
	}
	raw, err := os.ReadFile(g.path)
	if err != nil {
		return
	}
	// value is [epoch, unix_ts]; a bare string (older format) decodes to
	// ts=0 and is pruned as stale.
	var disk struct {
		ByNode map[string]map[string]json.RawMessage `json:"by_node"`
	}
	if json.Unmarshal(raw, &disk) != nil {
		return
	}
	now := time.Now().Unix()
	g.mu.Lock()
	defer g.mu.Unlock()
	for node, entries := range disk.ByNode {
		st := g.byNode[node]
		if st == nil {
			st = &nonceState{set: map[string]bool{}, epoch: map[string]string{}}
			g.byNode[node] = st
		}
		if g.times[node] == nil {
			g.times[node] = map[string]int64{}
		}
		for nonce, rawVal := range entries {
			epoch, ts := parsePersistedEntry(rawVal)
			if epoch == "" || epoch == g.epoch {
				continue
			}
			if now-ts > replayTTLSeconds {
				continue
			}
			st.epoch[nonce] = epoch
			g.times[node][nonce] = ts
		}
	}
}

// parsePersistedEntry decodes [epoch, ts] or a bare epoch string.
func parsePersistedEntry(raw json.RawMessage) (string, int64) {
	var pair []json.RawMessage
	if json.Unmarshal(raw, &pair) == nil && len(pair) == 2 {
		var epoch string
		var ts int64
		_ = json.Unmarshal(pair[0], &epoch)
		_ = json.Unmarshal(pair[1], &ts)
		return epoch, ts
	}
	var epoch string
	if json.Unmarshal(raw, &epoch) == nil {
		return epoch, 0
	}
	return "", 0
}

// saveLocked writes the epoch map atomically. Callers must hold g.mu.
func (g *ReplayGuard) saveLocked() {
	if g.path == "" {
		return
	}
	disk := struct {
		ByNode map[string]map[string][2]any `json:"by_node"`
	}{ByNode: map[string]map[string][2]any{}}
	for node, st := range g.byNode {
		if len(st.epoch) == 0 {
			continue
		}
		cp := make(map[string][2]any, len(st.epoch))
		for n, e := range st.epoch {
			cp[n] = [2]any{e, g.times[node][n]}
		}
		disk.ByNode[node] = cp
	}
	raw, err := json.Marshal(disk)
	if err != nil {
		return
	}
	tmp := g.path + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, g.path)
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
	if g.times == nil {
		g.times = map[string]map[string]int64{}
	}
	st := g.byNode[beaconID]
	if st == nil {
		st = &nonceState{set: map[string]bool{}, epoch: map[string]string{}}
		g.byNode[beaconID] = st
	}
	if st.set[nonce] {
		return errors.New("replayed nonce")
	}
	if prior, ok := st.epoch[nonce]; ok && prior != g.epoch {
		// A no-longer-fresh entry can no longer be replayed successfully
		// (the timestamp check rejects it), so do not lock the peer out.
		// ts == 0 (no timestamp recorded) is treated as fresh: fail closed.
		if ts := g.times[beaconID][nonce]; ts == 0 ||
			time.Now().Unix()-ts <= replayTTLSeconds {
			return errors.New("nonce issued under a previous epoch")
		}
	}
	st.set[nonce] = true
	st.epoch[nonce] = g.epoch
	if g.times[beaconID] == nil {
		g.times[beaconID] = map[string]int64{}
	}
	g.times[beaconID][nonce] = time.Now().Unix()
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
		keptTimes := map[string]int64{}
		for _, n := range keep {
			keptTimes[n] = g.times[beaconID][n]
		}
		g.times[beaconID] = keptTimes
	}
	if counterValue > g.counter[beaconID] {
		g.counter[beaconID] = counterValue
	}
	g.saveLocked()
	return nil
}

// Counter returns the observed high-water counter for a beacon.
func (g *ReplayGuard) Counter(beaconID string) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.counter[beaconID]
}
