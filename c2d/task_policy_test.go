// task_policy_test.go — the ported policy must agree with Python, verb for
// verb and reason for reason.
//
// `policy_vectors.json` is SHARED: the Python policy generated the expectations
// (allowed / mode / reason) and its own test re-checks the file, so the two
// backends cannot drift into disagreeing about what a beacon may be asked to
// do. A Go-only test would pin only this side of the contract.
package main

import (
	"encoding/json"
	"os"
	"testing"
)

type policyVector struct {
	Name    string   `json:"name"`
	Beacon  string   `json:"beacon"`
	Grants  []string `json:"grants"`
	Command *string  `json:"command"`
	Typed   *struct {
		CapabilityID string   `json:"capability_id"`
		Args         []string `json:"args"`
		ExpiresAt    float64  `json:"expires_at"`
	} `json:"typed"`
	Allowed bool   `json:"allowed"`
	Mode    string `json:"mode"`
	Reason  string `json:"reason"`
}

func loadPolicyVectors(t *testing.T) []policyVector {
	t.Helper()
	raw, err := os.ReadFile("policy_vectors.json")
	if err != nil {
		t.Fatalf("policy_vectors.json: %v", err)
	}
	var doc struct {
		Cases []policyVector `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("policy_vectors.json is not valid JSON: %v", err)
	}
	if len(doc.Cases) < 10 {
		t.Fatalf("expected the full vector set, got %d", len(doc.Cases))
	}
	return doc.Cases
}

func TestPolicyMatchesThePythonVectors(t *testing.T) {
	for _, c := range loadPolicyVectors(t) {
		want := PolicyDecision{Allowed: c.Allowed, Reason: c.Reason, Mode: c.Mode}
		policy := NewTaskPolicy()
		if c.Grants != nil {
			policy.SetGrants(c.Beacon, c.Grants)
		}
		if c.Typed != nil {
			decision := policy.CheckTyped(c.Beacon, TypedTask{
				CapabilityID: c.Typed.CapabilityID, Args: c.Typed.Args,
				ExpiresAt: c.Typed.ExpiresAt}, 1_800_000_000)
			if decision.Allowed != want.Allowed ||
				decision.Mode != want.Mode || decision.Reason != want.Reason {
				t.Errorf("%s: got %+v, want %+v", c.Name, decision, want)
			}
			continue
		}
		command := ""
		if c.Command != nil {
			command = *c.Command
		}
		decision := policy.CheckLegacy(c.Beacon, command)
		if decision.Allowed != want.Allowed || decision.Mode != want.Mode ||
			decision.Reason != want.Reason {
			t.Errorf("%s: got %+v, want %+v", c.Name, decision, want)
		}
	}
}

func TestLegacyOpenUntilAManifestExists(t *testing.T) {
	policy := NewTaskPolicy()
	// no manifest: the documented upgrade behaviour, preserved
	if d := policy.CheckLegacy("B-TEST", "whoami"); !d.Allowed {
		t.Fatalf("legacy-open must allow a known verb: %+v", d)
	}
	policy.SetGrants("B-TEST", []string{"whoami"})
	if d := policy.CheckLegacy("B-TEST", "shell id"); d.Allowed {
		t.Fatalf("a manifest without shell must refuse the OS verb: %+v", d)
	}
	if d := policy.CheckLegacy("B-OTHER", "shell id"); !d.Allowed {
		t.Fatalf("a manifest for one beacon must not restrict another: %+v", d)
	}
	policy.ClearGrants("B-TEST")
	if d := policy.CheckLegacy("B-TEST", "shell id"); !d.Allowed {
		t.Fatalf("clearing the manifest must restore legacy-open: %+v", d)
	}
}

func TestGrantsSeededFromEnvAreConsumedOnce(t *testing.T) {
	t.Setenv("PHANTOM_BEACON_GRANTS", "B-TEST:whoami,recon;B-2:shell")
	policy := NewTaskPolicyFromEnv()
	for _, command := range []string{"whoami", "recon"} {
		if d := policy.CheckLegacy("B-TEST", command); !d.Allowed {
			t.Fatalf("seeded grant must allow %q: %+v", command, d)
		}
	}
	if d := policy.CheckLegacy("B-TEST", "shell id"); d.Allowed {
		t.Fatalf("B-TEST has no shell grant: %+v", d)
	}
	if d := policy.CheckLegacy("B-2", "shell load"); !d.Allowed {
		t.Fatalf("B-2 granted shell: %+v", d)
	}
	if _, ok := os.LookupEnv("PHANTOM_BEACON_GRANTS"); ok {
		t.Fatal("the env spec must be consumed, not re-applied on the next read")
	}
}

func TestTaskIDsAreBounded(t *testing.T) {
	if !ValidTaskID("") {
		t.Error("an empty task id is valid: the queue mints one")
	}
	if !ValidTaskID("20260101000000-000000-abcd") {
		t.Error("a normal task id must be accepted")
	}
	if ValidTaskID("has spaces") || ValidTaskID("../../etc/passwd") {
		t.Error("an unsafe task id must be refused")
	}
}
