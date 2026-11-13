// audit.go — the hash-chained audit trail, ported from
// phantom/utils/audit_log.py.
//
// The Go data plane already wrote an audit trail, but as PLAIN JSONL: a record
// could be edited or removed without leaving a trace, which is exactly what a
// chain-of-custody artifact must not allow. The Python listener has hash-
// chained its log from the start, so a backend switch silently downgraded the
// evidence — the kind of gap that is invisible until someone has to prove what
// happened.
//
// The chain mirrors Python exactly:
//
//	seq   monotonically increasing, 1-based
//	prev  the previous record's hash ("" for the first)
//	hash  sha256 over the CANONICAL JSON of the record INCLUDING prev
//
// Canonical means the same thing on both sides: sorted keys, no whitespace,
// no HTML escaping. `c2d/audit_vectors.json` pins one record's digest for both
// implementations, so a drift in either one is caught by a test instead of by
// a reader who cannot tell when the file was edited.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// canonicalJSON renders a record the way Python's
// json.dumps(sort_keys=True, separators=(",", ":"), default=str) does.
//
// Go's encoding/json already sorts map keys, and SetEscapeHTML(false) matches
// Python for the characters Python escapes (`<`, `>`, `&` are NOT escaped by
// Python; Go escapes them by default). Records written here carry event names,
// ids and counters, i.e. the ASCII case both sides agree on by construction —
// and the vector file pins it.
func canonicalJSON(rec map[string]any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return ""
	}
	return strings.TrimRight(buf.String(), "\n")
}

func recordHash(rec map[string]any) string {
	body := make(map[string]any, len(rec))
	for k, v := range rec {
		if k == "hash" {
			continue
		}
		body[k] = v
	}
	sum := sha256.Sum256([]byte(canonicalJSON(body)))
	return hex.EncodeToString(sum[:])
}

// AuditLog is an append-only, hash-chained JSONL writer.
type AuditLog struct {
	mu       sync.Mutex
	path     string
	seq      int
	lastHash string
}

// NewAuditLog opens (or creates on first append) a log, continuing the chain
// of an existing file: a restart must not fork the chain.
func NewAuditLog(path string) *AuditLog {
	log := &AuditLog{path: path}
	if path != "" {
		log.seq, log.lastHash = log.tail()
	}
	return log
}

// Enabled reports whether this log writes anything.
func (a *AuditLog) Enabled() bool { return a != nil && a.path != "" }

// Path is the file the chain lives in (empty when disabled).
func (a *AuditLog) Path() string {
	if a == nil {
		return ""
	}
	return a.path
}

// tail returns (seq, hash) of the last valid record.
func (a *AuditLog) tail() (int, string) {
	f, err := os.Open(a.path)
	if err != nil {
		return 0, ""
	}
	defer f.Close()
	seq, hash := 0, ""
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if n, ok := rec["seq"].(float64); ok {
			seq = int(n)
		}
		if h, ok := rec["hash"].(string); ok {
			hash = h
		}
	}
	return seq, hash
}

// Append writes one record and returns it (best-effort: an audit failure never
// takes the listener down, and never blocks a beacon).
func (a *AuditLog) Append(event string, fields map[string]any) map[string]any {
	if !a.Enabled() {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rec := map[string]any{
		"seq":   a.seq + 1,
		"ts":    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"event": event,
	}
	for k, v := range fields {
		rec[k] = v
	}
	rec["prev"] = a.lastHash
	rec["hash"] = recordHash(rec)
	line := canonicalJSON(rec)
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil
	}
	defer f.Close()
	if _, err := f.Write(append([]byte(line), '\n')); err != nil {
		return nil
	}
	a.seq++
	a.lastHash = rec["hash"].(string)
	return rec
}

// Verify re-reads the file and checks every link: (ok, records, firstBadLine).
func (a *AuditLog) Verify() (bool, int, int) {
	if !a.Enabled() {
		return true, 0, 0
	}
	f, err := os.Open(a.path)
	if err != nil {
		return true, 0, 0
	}
	defer f.Close()
	checked, line := 0, 0
	prev := ""
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(text), &rec) != nil {
			return false, checked, line
		}
		checked++
		got, _ := rec["hash"].(string)
		want := recordHash(rec)
		if got != want {
			return false, checked, line
		}
		if seen, ok := rec["prev"].(string); ok && seen != prev {
			return false, checked, line
		}
		prev = got
	}
	return true, checked, 0
}

// events returns the distinct event names in the file (operator view).
func (a *AuditLog) events() []string {
	seen := map[string]bool{}
	f, err := os.Open(a.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		var rec map[string]any
		if json.Unmarshal([]byte(scanner.Text()), &rec) != nil {
			continue
		}
		if name, ok := rec["event"].(string); ok && name != "" {
			seen[name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
