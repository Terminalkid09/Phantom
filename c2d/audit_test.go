// audit_test.go — the audit trail must be TAMPER-EVIDENT, and must agree with
// the Python chain on the digest of the same record.
//
// `audit_vectors.json` is shared: the Python side computed the digest from its
// own canonical serialization, and its test re-checks the file. That is what
// makes "the two backends write the same chain" a fact instead of a hope.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalHashMatchesThePythonVector(t *testing.T) {
	raw, err := os.ReadFile("audit_vectors.json")
	if err != nil {
		t.Fatalf("audit_vectors.json: %v", err)
	}
	var doc struct {
		Canonical string         `json:"canonical"`
		Record    map[string]any `json:"record"`
		SHA256    string         `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("audit_vectors.json is not valid JSON: %v", err)
	}
	if doc.SHA256 == "" {
		t.Fatal("the vector file must pin a digest")
	}
	if got := canonicalJSON(doc.Record); got != doc.Canonical {
		t.Errorf("canonical form drifted:\n got %s\nwant %s", got, doc.Canonical)
	}
	if got := recordHash(doc.Record); got != doc.SHA256 {
		t.Errorf("digest drifted: got %s, want %s", got, doc.SHA256)
	}
}

func TestTheChainLinksEveryRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c2_audit.jsonl")
	log := NewAuditLog(path)
	first := log.Append("beacon_checkin", map[string]any{"beacon_id": "B-TEST"})
	second := log.Append("task_queued", map[string]any{
		"beacon_id": "B-TEST", "task_id": "T-1"})
	if first == nil || second == nil {
		t.Fatal("an enabled log must write")
	}
	if second["prev"] != first["hash"] {
		t.Errorf("the second record must link to the first: %v", second["prev"])
	}
	if second["seq"].(int) != 2 {
		t.Errorf("seq must advance: %v", second["seq"])
	}
	ok, checked, bad := log.Verify()
	if !ok || checked != 2 || bad != 0 {
		t.Errorf("a fresh chain must verify: ok=%v checked=%d bad=%d",
			ok, checked, bad)
	}
}

func TestTheChainContinuesAcrossARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c2_audit.jsonl")
	NewAuditLog(path).Append("beacon_checkin", map[string]any{"beacon_id": "B"})
	reopened := NewAuditLog(path)
	rec := reopened.Append("task_queued", map[string]any{"beacon_id": "B"})
	if rec["seq"].(int) != 2 {
		t.Errorf("a restart must continue the chain, not fork it: %v", rec["seq"])
	}
	if ok, _, bad := reopened.Verify(); !ok {
		t.Errorf("the continued chain must verify (bad line %d)", bad)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c2_audit.jsonl")
	log := NewAuditLog(path)
	log.Append("beacon_checkin", map[string]any{"beacon_id": "B-TEST"})
	log.Append("task_queued", map[string]any{"beacon_id": "B-TEST"})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// rewrite the FIRST record's beacon id: the hash no longer matches
	tampered := strings.Replace(string(raw), `"B-TEST"`, `"B-OTHER"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, _, bad := NewAuditLog(path).Verify()
	if ok {
		t.Fatal("an edited record must break the chain")
	}
	if bad != 1 {
		t.Errorf("the FIRST bad line must be reported, got %d", bad)
	}
}

func TestADisabledLogIsSilentAndVerifies(t *testing.T) {
	log := NewAuditLog("")
	if log.Enabled() {
		t.Error("an empty path is a disabled log")
	}
	if log.Append("x", nil) != nil {
		t.Error("a disabled log must write nothing")
	}
	if ok, checked, _ := log.Verify(); !ok || checked != 0 {
		t.Error("a disabled log verifies vacuously")
	}
}
