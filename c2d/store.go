// store.go — beacons, task leasing and result intake.
//
// Mirrors phantom.core.c2_server.C2State: tasks are LEASED, not deleted (a
// lost HTTP response used to lose work permanently), results are idempotent
// per task_id, and beacon secrets are read from the SAME registry file the
// Python enroler writes.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TaskLeaseSeconds is how long a delivered task is withheld from redelivery.
const TaskLeaseSeconds = 60

type taskEntry struct {
	id       string
	command  string
	leasedAt time.Time
	sentAt   time.Time
}

// Store is the state of one listener process: in-memory, with an optional
// append-only audit trail and a state snapshot on DataDir (D-1).
type Store struct {
	mu        sync.Mutex
	beacons   map[string]map[string]any
	tasks     map[string][]*taskEntry
	results   map[string][]map[string]any
	registry  string
	auditPath string
	statePath string

	// D-1 follow-up: the snapshot used to be rewritten on EVERY mutation
	// (synchronous file I/O inside the beacon hot path). It is now flagged
	// dirty and flushed by a background ticker at most every flushEvery —
	// bounded staleness on a crash, no I/O in the check-in path.
	dirty      bool
	flushEvery time.Duration
	stopCh     chan struct{}
	stopOnce   sync.Once
}

// NewStore returns an empty store that reads beacon secrets from registry.
func NewStore(registry string) *Store {
	return &Store{
		beacons:  map[string]map[string]any{},
		tasks:    map[string][]*taskEntry{},
		results:  map[string][]map[string]any{},
		registry: registry,
	}
}

// NewStorePersistent adds a JSONL audit trail and a crash-safe state snapshot
// under dataDir, reloaded on start. The Python control plane has always kept
// an audit log; the Go data plane must not be the one blind spot (D-1).
func NewStorePersistent(registry, dataDir string) *Store {
	s := NewStore(registry)
	if dataDir != "" {
		s.auditPath = filepath.Join(dataDir, "c2_audit.jsonl")
		s.statePath = filepath.Join(dataDir, "c2_store.json")
		s.flushEvery = 500 * time.Millisecond
		s.stopCh = make(chan struct{})
	}
	s.load()
	if s.statePath != "" {
		go s.flushLoop()
	}
	return s
}

// flushLoop writes the snapshot at most once per flushEvery, only when a
// mutation happened since the last write.
func (s *Store) flushLoop() {
	t := time.NewTicker(s.flushEvery)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			s.Flush()
			return
		case <-t.C:
			s.Flush()
		}
	}
}

// Flush writes the pending snapshot now (no-op when nothing changed or when
// the store has no state file). Called by the ticker, on shutdown and by
// tests that need a synchronous on-disk view.
func (s *Store) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return
	}
	s.dirty = false
	s.saveLocked()
}

// Close stops the background flusher, flushing any pending state. Safe to
// call more than once and on a non-persistent store.
func (s *Store) Close() {
	if s.stopCh == nil {
		return
	}
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// touchLocked marks the snapshot dirty. Callers must hold s.mu.
func (s *Store) touchLocked() {
	if s.statePath != "" {
		s.dirty = true
	}
}

// auditEnabled reports whether this store writes an audit trail.
func (s *Store) auditEnabled() bool { return s.auditPath != "" }

// audit appends one JSONL record. Best-effort: an audit write failure must
// never take the listener down or block a beacon.
func (s *Store) audit(event string, fields map[string]any) {
	if s.auditPath == "" {
		return
	}
	rec := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"event": event,
	}
	for k, v := range fields {
		rec[k] = v
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(raw, '\n'))
}

// ── persistence (D-1) ───────────────────────────────────────────────────

type taskSnapshot struct {
	ID       string    `json:"id"`
	Command  string    `json:"command"`
	LeasedAt time.Time `json:"leased_at"`
	SentAt   time.Time `json:"sent_at"`
}

type storeSnapshot struct {
	Beacons map[string]map[string]any   `json:"beacons"`
	Tasks   map[string][]taskSnapshot   `json:"tasks"`
	Results map[string][]map[string]any `json:"results"`
}

// load restores the state snapshot, if one was written by a previous run.
func (s *Store) load() {
	if s.statePath == "" {
		return
	}
	raw, err := os.ReadFile(s.statePath)
	if err != nil {
		return
	}
	var snap storeSnapshot
	if json.Unmarshal(raw, &snap) != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, rec := range snap.Beacons {
		s.beacons[id] = rec
	}
	for id, list := range snap.Tasks {
		for _, t := range list {
			s.tasks[id] = append(s.tasks[id], &taskEntry{
				id: t.ID, command: t.Command,
				leasedAt: t.LeasedAt, sentAt: t.SentAt,
			})
		}
	}
	for id, list := range snap.Results {
		s.results[id] = append(s.results[id], list...)
	}
}

// saveLocked writes the snapshot atomically. Callers must hold s.mu.
func (s *Store) saveLocked() {
	if s.statePath == "" {
		return
	}
	snap := storeSnapshot{
		Beacons: s.beacons,
		Tasks:   map[string][]taskSnapshot{},
		Results: s.results,
	}
	for id, list := range s.tasks {
		for _, t := range list {
			snap.Tasks[id] = append(snap.Tasks[id], taskSnapshot{
				ID: t.id, Command: t.command,
				LeasedAt: t.leasedAt, SentAt: t.sentAt,
			})
		}
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return
	}
	tmp := s.statePath + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, s.statePath)
}

// UpdateBeacon merges info into the beacon record (creating it if new).
func (s *Store) UpdateBeacon(beaconID string, info map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.beacons[beaconID]
	if rec == nil {
		rec = map[string]any{}
		s.beacons[beaconID] = rec
	}
	rec["beacon_id"] = beaconID
	rec["status"] = "active"
	for k, v := range info {
		if v != nil && v != "" {
			rec[k] = v
		}
	}
	s.touchLocked()
}

// Beacons returns a copy of the beacon table for the operator API.
func (s *Store) Beacons() map[string]map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]map[string]any, len(s.beacons))
	for id, rec := range s.beacons {
		cp := make(map[string]any, len(rec))
		for k, v := range rec {
			cp[k] = v
		}
		out[id] = cp
	}
	return out
}

// Registered reports whether a beacon has ever checked in.
func (s *Store) Registered(beaconID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.beacons[beaconID]
	return ok
}

// QueueTask appends a command and returns its task id.
func (s *Store) QueueTask(beaconID, command string) (string, error) {
	if strings.TrimSpace(beaconID) == "" || strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("beacon_id and command required")
	}
	if len(command) > 64*1024 {
		return "", fmt.Errorf("command too long (max 64 KiB)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := newTaskID()
	s.tasks[beaconID] = append(s.tasks[beaconID],
		&taskEntry{id: id, command: command})
	s.touchLocked()
	return id, nil
}

// PendingTasks leases and returns the tasks to deliver now. A task inside an
// active lease is withheld; one whose lease expired is redelivered.
func (s *Store) PendingTasks(beaconID string) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := []map[string]any{}
	for _, t := range s.tasks[beaconID] {
		if !t.leasedAt.IsZero() && now.Sub(t.leasedAt) < TaskLeaseSeconds*time.Second {
			continue
		}
		t.leasedAt = now
		t.sentAt = now
		out = append(out, map[string]any{
			"task_id": t.id,
			"command": t.command,
		})
	}
	return out
}

// AddResult stores a result and acknowledges (removes) its task. It is
// idempotent: a retry after a lost 200 must not duplicate the output.
func (s *Store) AddResult(beaconID, taskID, output string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.results[beaconID] {
		if r["task_id"] == taskID {
			return
		}
	}
	s.results[beaconID] = append(s.results[beaconID], map[string]any{
		"task_id":   taskID,
		"output":    output,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	kept := s.tasks[beaconID][:0]
	for _, t := range s.tasks[beaconID] {
		if t.id != taskID {
			kept = append(kept, t)
		}
	}
	s.tasks[beaconID] = kept
	s.touchLocked()
}

// Results returns the cached results for a beacon.
func (s *Store) Results(beaconID string) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]map[string]any, 0, len(s.results[beaconID]))
	out = append(out, s.results[beaconID]...)
	return out
}

// ── beacon identity ─────────────────────────────────────────────────────

type registryRecord struct {
	Status            string          `json:"status"`
	Secret            string          `json:"secret"`
	PreviousSecret    string          `json:"previous_secret"`
	PreviousExpiresAt json.RawMessage `json:"previous_expires_at"`
}

// BeaconSecrets returns the active HMAC secret(s) for a beacon identity: the
// current one, plus the previous one while it has not expired (rotation).
func (s *Store) BeaconSecrets(beaconID string) [][]byte {
	if beaconID == "" {
		return nil
	}
	raw, err := os.ReadFile(s.registry)
	if err != nil {
		return nil
	}
	var reg struct {
		Beacons map[string]registryRecord `json:"beacons"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		return nil
	}
	rec, ok := reg.Beacons[beaconID]
	if !ok || rec.Status != "active" {
		return nil
	}
	var out [][]byte
	if b := decodeSecret(rec.Secret); b != nil {
		out = append(out, b)
	}
	if b := decodeSecret(rec.PreviousSecret); b != nil && !previousExpired(rec.PreviousExpiresAt) {
		out = append(out, b)
	}
	return out
}

func previousExpired(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	var ts float64
	if err := json.Unmarshal(raw, &ts); err != nil {
		return true
	}
	return ts > 0 && float64(time.Now().Unix()) > ts
}

// decodeSecret unwraps the URL-safe, unpadded base64 the Python enroler
// writes, requiring exactly 32 bytes.
func decodeSecret(value string) []byte {
	if value == "" {
		return nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "=")); err == nil {
		if len(b) == 32 {
			return b
		}
	}
	return nil
}

// newTaskID mirrors the Python format: timestamp + random suffix, so two
// enqueues in the same microsecond cannot collide.
func newTaskID() string {
	now := time.Now()
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	return fmt.Sprintf("%s%06d-%s", now.Format("20060102150405"),
		now.Nanosecond()/1000, hex.EncodeToString(suffix))
}
